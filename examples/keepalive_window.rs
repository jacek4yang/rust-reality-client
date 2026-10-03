//! One TCP connection, tuned by this crate's own socket policy, for measuring
//! what that policy costs.
//!
//! §4 asks for two numbers that a single test cannot produce together: how long an
//! idle path that has silently stopped carrying anything takes to become
//! *observable*, and how long an outage can last before the armed probes give up
//! on a path that is about to come back. Both are properties of a schedule — loss
//! applied at an instant, restored at another — so the schedule belongs to the
//! driver (`scripts/interop/keepalive_window.sh`, which owns `netem`) and this
//! program owns only the socket and the clock that reports what the socket said.
//!
//! The socket is therefore tuned by
//! [`configure`](rust_reality_client::transport::configure) rather than by
//! anything written here, and read back by
//! [`probe`](rust_reality_client::transport::probe): a measurement of a
//! hand-rolled socket policy would say nothing about the shipped one. The
//! production relay is not used, because what is being measured is the socket,
//! not the framing; the wait this harness arms on its own reads is a hang guard
//! for the measurement, and the only timer here — the relay in `src/transport`
//! arms none, which is the property under test.
//!
//! ```text
//! keepalive_window listen  <addr> <report> [echo|drain:SECS]
//! keepalive_window connect <addr> <report>
//! ```
//!
//! `listen` is the far end: it takes the same options, then either echoes every
//! byte it is given, or in `drain:SECS` answers the first marker and then stays
//! away from its own socket for that long, so the kernel keeps answering for it
//! while the application does not. `connect` proves the path with one round trip,
//! prints `ready <ms>`, and waits on stdin for the driver's single command:
//!
//! - `park` — read and never write again, which is what a quiet tunnel leaves the
//!   relay doing. Reports the first thing the socket says.
//! - `probe` — one more round trip, which is the question "is this connection
//!   still usable after the outage?".
//! - `bulk:<KiB>` — push that many kibibytes, then ask for all of them back,
//!   compared byte for byte. The two timings are kept apart because they mean
//!   different things: acceptance is the kernel's, delivery is the peer's.
//!
//! Results are written to `<report>` as `key=value` lines and echoed to stdout.

use std::error::Error;
use std::time::{Duration, Instant};

use rust_reality_client::transport::{Applied, configure, probe};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// The bytes a round trip carries, echoed back by the far end.
const MARKER: &[u8] = b"rrc!";
/// Bytes one copy moves at a time, and the buffer the far end reads into.
const CHUNK: usize = 8 * 1024;
/// Ceiling on any wait for the peer, so a run that never resolves reports `budget`.
const READ_BUDGET: Duration = Duration::from_secs(300);
/// Ceiling on the wait for the driver's command.
const COMMAND_BUDGET: Duration = Duration::from_secs(600);

const USAGE: &str = "usage: keepalive_window listen <addr> <report> [echo|drain:SECS] \
                     | keepalive_window connect <addr> <report>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("listen") => listen(&argv).await,
        Some("connect") => connect(&argv).await,
        _ => Err(USAGE.into()),
    }
}

/// The far end: takes the shipped options, then either echoes or stays away.
async fn listen(argv: &[String]) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let addr = arg(argv, 1)?;
    let path = arg(argv, 2)?;
    let hold = hold_for(argv.get(3).map(String::as_str))?;

    let listener = TcpListener::bind(addr).await?;
    say(
        "listening",
        &format!("{addr} hold={}ms", hold.unwrap_or_default().as_millis()),
    );
    let (mut stream, peer) = listener.accept().await?;
    drop(listener);
    let applied = tune(&stream)?;
    say("accepted", &format!("{peer} {}", flatten(&applied)));

    let outcome = echo(&mut stream, hold).await;
    let entries = vec![
        ("role", "listen".to_string()),
        ("peer", peer.to_string()),
        ("at_establishment", flatten(&applied)),
        ("at_finish", flatten(&read_back(&stream))),
        ("elapsed_ms", ms(started).to_string()),
        ("outcome", outcome.0.to_string()),
        ("bytes", outcome.1.to_string()),
        ("error", outcome.2),
    ];
    emit(path, &entries)
}

/// The near end: proves the path, then does what the driver asks of it.
async fn connect(argv: &[String]) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let addr = arg(argv, 1)?;
    let path = arg(argv, 2)?;

    let mut stream = TcpStream::connect(addr).await?;
    let applied = tune(&stream)?;
    say("tuned", &flatten(&applied));
    round_trip(&mut stream).await?;
    say("ready", &ms(started).to_string());

    let (command, command_line) = next_command().await?;
    let measured = match command {
        Command::Park => park(&mut stream).await,
        Command::Probe => probe_again(&mut stream).await,
        Command::Bulk(size) => bulk(&mut stream, size).await,
    };
    let entries = vec![
        ("role", "connect".to_string()),
        ("peer", addr.to_string()),
        ("command", command_line),
        ("at_establishment", flatten(&applied)),
        ("at_finish", flatten(&read_back(&stream))),
        ("elapsed_ms", ms(started).to_string()),
        ("outcome", measured.0.to_string()),
        ("bytes", measured.1.to_string()),
        ("error", measured.2),
    ];
    emit(path, &entries)
}

/// What the driver can ask for once the path is proven, one command per run.
#[derive(Clone, Copy, Debug)]
enum Command {
    /// Read, never write again: the state a quiet tunnel leaves the relay in.
    Park,
    /// One more round trip, which is whether the connection survived at all.
    Probe,
    /// Push this many mebibytes away, then ask for them back.
    Bulk(usize),
}

impl Command {
    fn parse(line: &str) -> Option<Self> {
        match line.trim() {
            "park" => Some(Self::Park),
            "probe" => Some(Self::Probe),
            line => line
                .strip_prefix("bulk:")
                .and_then(|kib| kib.trim_end().parse::<usize>().ok())
                // The size is the experiment. A push smaller than the peer's
                // advertised window is accepted whole and says something about
                // the kernel; one larger than it has to wait for the peer to read,
                // which says something else. Kibibytes, because the interesting
                // boundary on a default-tuned socket is in that range.
                .map(|kib| Self::Bulk(kib.max(1) * 1024)),
        }
    }
}

/// Reads the driver's one command off stdin, bounded so a dead driver ends the run.
async fn next_command() -> Result<(Command, String), Box<dyn Error>> {
    let waiting = timeout(COMMAND_BUDGET, tokio::task::spawn_blocking(read_line)).await;
    let line = match waiting {
        Err(_elapsed) => return Err("the driver sent no command".into()),
        Ok(Err(joined)) => return Err(joined.into()),
        Ok(Ok(read)) => read?,
    };
    let command =
        Command::parse(&line).ok_or_else(|| format!("unknown command {line:?}: {USAGE}"))?;
    Ok((command, line.trim().to_string()))
}

/// One line off this process's own stdin.
///
/// It runs on a blocking thread because the driver writes the command at the
/// instant the measurement starts, and until it does there is nothing else this
/// process can learn — the schedule belongs to the driver, not to a timer here.
fn read_line() -> std::io::Result<String> {
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line)?;
    if read == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "stdin closed before a command",
        ));
    }
    Ok(line)
}

/// Applies this crate's data-socket policy and reads it back before anything moves.
fn tune(stream: &TcpStream) -> Result<Applied, Box<dyn Error>> {
    configure(stream)?;
    Ok(probe(stream)?)
}

/// The same read at the end of a run, which a dead socket may refuse to answer.
fn read_back(stream: &TcpStream) -> Applied {
    probe(stream).unwrap_or_default()
}

/// Outcome, bytes, and the socket's own words.
type Measured = (&'static str, usize, String);

/// Echoes everything the peer sends until the peer or the path ends.
///
/// `hold` is the number of seconds to stay away from the socket *after answering
/// the first marker*: bytes the peer writes in that window are accepted by the
/// kernel, acknowledged as they arrive, and read by nobody. Anchoring the hold to
/// that first exchange is what makes it start at the instant the path was proven
/// rather than at the instant this process happened to start.
async fn echo(stream: &mut TcpStream, hold: Option<Duration>) -> Measured {
    let mut buffer = vec![0_u8; CHUNK];
    let mut moved = 0_usize;
    let mut answered = false;
    loop {
        let read = match timeout(READ_BUDGET, stream.read(&mut buffer)).await {
            Err(_elapsed) => return ("budget", moved, String::new()),
            Ok(Err(error)) => return ("error", moved, error.to_string()),
            Ok(Ok(0)) => return ("closed", moved, String::new()),
            Ok(Ok(read)) => read,
        };
        moved += read;
        if let Err(error) = stream.write_all(&buffer[..read]).await {
            return ("error", moved, error.to_string());
        }
        if let Err(error) = stream.flush().await {
            return ("error", moved, error.to_string());
        }
        if !answered {
            answered = true;
            if let Some(hold) = hold {
                say("holding", &format!("{}ms", hold.as_millis()));
                tokio::time::sleep(hold).await;
                say("resuming", &format!("{moved} bytes buffered and unread"));
            }
        }
    }
}

/// Reads without writing again, which is what the relay does with a quiet tunnel.
async fn park(stream: &mut TcpStream) -> Measured {
    let mut one = [0_u8; 1];
    match timeout(READ_BUDGET, stream.read(&mut one)).await {
        Err(_elapsed) => ("budget", 0, String::new()),
        Ok(Ok(0)) => ("closed", 0, String::new()),
        Ok(Ok(read)) => ("data", read, String::new()),
        Ok(Err(error)) => ("error", 0, error.to_string()),
    }
}

/// Asks for the marker again: the answer to "is this connection still usable".
async fn probe_again(stream: &mut TcpStream) -> Measured {
    let started = Instant::now();
    match round_trip(stream).await {
        Ok(()) => ("alive", MARKER.len(), String::new()),
        Err(error) => ("dead", 0, format!("{error}: after {}ms", ms(started))),
    }
}

/// Pushes 1 MiB, then asks for it back, and keeps the two timings apart.
///
/// The first number is how long the kernel took to accept the payload, and says
/// nothing about the peer: bytes the peer's application never read are still
/// acknowledged. The second is the first measurement that does say something, and
/// the payload is compared rather than counted, so a path that reordered or
/// altered anything is caught here rather than at the application.
async fn bulk(stream: &mut TcpStream, size: usize) -> Measured {
    let payload = payload(size);
    let started = Instant::now();
    if let Err(error) = stream.write_all(&payload).await {
        return ("error", 0, format!("write: {error}"));
    }
    let accepted = ms(started);
    say("bulk_accepted", &format!("{accepted}ms"));

    let draining = Instant::now();
    let read_back = timeout(READ_BUDGET, drain(stream, &payload)).await;
    let delivered = match read_back {
        Err(_elapsed) => {
            return (
                "stuck",
                size,
                format!("bulk_write_ms={accepted}, nothing came back"),
            );
        }
        Ok(Err(error)) => return ("error", size, format!("read back: {error}")),
        Ok(Ok(())) => ms(draining),
    };
    say("bulk_delivered", &format!("{delivered}ms"));

    let round = probe_again(stream).await;
    let note = format!(
        "{} bulk_write_ms={accepted} delivered_ms={delivered}",
        round.2.trim()
    );
    (round.0, size + MARKER.len() * 2, note)
}

/// Reads the payload back in the order it was sent, into one reused buffer.
async fn drain(stream: &mut TcpStream, payload: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut buffer = vec![0_u8; CHUNK];
    let mut read = 0_usize;
    while read < payload.len() {
        let some = stream.read(&mut buffer).await?;
        if some == 0 {
            return Err("the peer closed with the payload unread".into());
        }
        if buffer[..some] != payload[read..read + some] {
            return Err(format!("the payload came back altered at byte {read}").into());
        }
        read += some;
    }
    Ok(())
}

/// A push whose bytes vary, so a silent truncation cannot pass as a transfer.
fn payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| u8::try_from(index % 251).unwrap_or_default())
        .collect()
}

/// Writes the marker and reads its echo, bounded by [`READ_BUDGET`].
async fn round_trip(stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    stream.write_all(MARKER).await?;
    stream.flush().await?;
    let mut got = [0_u8; 4];
    match timeout(READ_BUDGET, stream.read_exact(&mut got)).await {
        Err(_elapsed) => Err("the marker was never echoed".into()),
        Ok(Err(error)) => Err(error.into()),
        Ok(Ok(_read)) if got != *MARKER => {
            Err(format!("the peer echoed {got:?} rather than {MARKER:?}").into())
        }
        Ok(Ok(_read)) => Ok(()),
    }
}

/// One positional argument, or the usage line.
fn arg(argv: &[String], index: usize) -> Result<&str, Box<dyn Error>> {
    argv.get(index).map(String::as_str).ok_or(USAGE.into())
}

/// The far end's `drain:SECS` mode as a hold, `None` for a plain `echo`.
fn hold_for(mode: Option<&str>) -> Result<Option<Duration>, Box<dyn Error>> {
    let Some(spec) = mode else {
        return Ok(None);
    };
    if spec == "echo" {
        return Ok(None);
    }
    let Some(secs) = spec.strip_prefix("drain:") else {
        return Err(format!("unknown listen mode {spec:?}: {USAGE}").into());
    };
    let hold: u64 = secs
        .parse()
        .map_err(|error| format!("unreadable {spec:?}: {error}: {USAGE}"))?;
    Ok(Some(Duration::from_secs(hold)))
}

/// The options as one flat `key=value;…` string, so a report line stays one field.
fn flatten(applied: &Applied) -> String {
    let seconds = |window: Option<Duration>| {
        window.map_or_else(
            || "unread".to_string(),
            |window| window.as_secs().to_string(),
        )
    };
    format!(
        "nodelay={};keepalive={};idle={};interval={};retries={}",
        applied.nodelay,
        applied.keepalive,
        seconds(applied.idle),
        seconds(applied.interval),
        applied
            .retries
            .map_or_else(|| "unread".to_string(), |count| count.to_string()),
    )
}

/// Prints a progress line, which is what the driver synchronises on.
fn say(event: &str, value: &str) {
    println!("{event} {value}");
}

/// Writes the report the driver reads: `key=value` lines, no nesting.
fn emit(path: &str, entries: &[(&str, String)]) -> Result<(), Box<dyn Error>> {
    let mut report = String::new();
    for (key, value) in entries {
        report.push_str(key);
        report.push('=');
        report.push_str(value);
        report.push('\n');
    }
    std::fs::write(path, report)?;
    say("report", path);
    Ok(())
}

/// Milliseconds since `started`, which is what the driver's schedule is measured against.
fn ms(started: Instant) -> u128 {
    started.elapsed().as_millis()
}
