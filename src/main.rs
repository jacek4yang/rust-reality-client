//! The operator's entry point: five words, and no way to leak a secret by typing
//! one of them wrongly.
//!
//! `run` serves, `check` reads a file, `doctor` asks questions of a live node,
//! `explain` says what a failure family means, and `generate` writes a template.
//! Three rules hold across all five:
//!
//! * **Nothing prints credential material.** A node is named by its label, its
//!   endpoint and its SNI. The user id is never rendered, and the short ID is
//!   rendered by length, because both select a user on a server that may be shared.
//!   The `publicKey` is the one REALITY field that is public by construction, so it
//!   may be printed.
//! * **The exit code is part of the output.** `0` means the thing you asked for
//!   happened; `1` means the thing you asked about is broken; `2` means the
//!   invocation or the file is wrong. A script can branch on that without parsing
//!   words, which is what makes `doctor` usable from a health check.
//! * **A diagnosis says what it cannot tell you.** REALITY answers a wrong key, a
//!   wrong short ID and a clock outside the accepted window in exactly one way — it
//!   relays the connection to the cover — so `doctor` reports an unattributable
//!   failure as a warning with the three candidate causes, never as a confident
//!   answer about the clock.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine as _;
use clap::{Parser, Subcommand, ValueEnum};

use rust_reality_client::config::{Config, Node};
use rust_reality_client::entropy;
use rust_reality_client::error::{Error, Failure};
use rust_reality_client::handoff::Handoff;
use rust_reality_client::logging::{Level, Logger};
use rust_reality_client::serve::{self, Server, StartError};
use rust_reality_client::transport::{Dial, DialPolicy, Environment, Tuning};

/// The file `--config` reads when the operator says nothing.
const DEFAULT_CONFIG: &str = "client.json";
/// The user id in the template, replaced by a fresh one on `generate`.
const TEMPLATE_USER_ID: &str = "00000000-0000-4000-8000-000000000000";
/// The public key in the template: 32 zero bytes, which no node can hold, so that
/// `doctor` can say out loud that the file has not been filled in.
const TEMPLATE_PUBLIC_KEY: [u8; 32] = [0; 32];

/// Exit codes, in the words the usage gives them.
const OK: u8 = 0;
const BROKEN: u8 = 1;
const WRONG: u8 = 2;

#[derive(Parser)]
#[command(
    name = "rust-reality-client",
    version = env!("CARGO_PKG_VERSION"),
    about = "A native VLESS + REALITY + xtls-rprx-vision client for the unmodified v2.0.1 server."
)]
struct Cli {
    /// How much to log: `error`, `warn`, `info` or `debug`.
    #[arg(
        long,
        short = 'L',
        global = true,
        default_value = "info",
        value_name = "LEVEL"
    )]
    log_level: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve on the configured listeners until a signal asks for a stop.
    Run {
        /// Config file; default client.json, or client.toml only when JSON is absent.
        #[arg(long, short, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Read a configuration and report every problem in it, not just the first.
    Check {
        /// Config file; default client.json, or client.toml only when JSON is absent.
        #[arg(long, short, value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Ask what is wrong: file, listeners, keys, reach and clock agreement.
    Doctor {
        /// Config file; default client.json, or client.toml only when JSON is absent.
        #[arg(long, short, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Check only this node, by its name.
        #[arg(long, value_name = "NAME")]
        node: Option<String>,
    },
    /// Say what a failure family means, and who it is about.
    Explain {
        /// One of `local`, `dns`, `connect`, `timeout`, `handshake`, `rejected`, `idle`.
        family: String,
    },
    /// Write a JSON configuration (or legacy TOML) to stdout, or to `--out`.
    Generate {
        /// Where to write it. Absent means standard output.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        /// Format; otherwise inferred from .toml output, JSON everywhere else.
        #[arg(long, value_enum)]
        format: Option<ConfigFormat>,
    },
    /// Convert a validated config to canonical JSON without changing identity.
    Migrate {
        #[arg(long, short, value_name = "PATH")]
        config: PathBuf,
        /// New destination file; existing files are never overwritten.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

#[derive(Clone, Copy, Eq, PartialEq, ValueEnum)]
enum ConfigFormat {
    Json,
    Toml,
}

fn selected_config(path: Option<PathBuf>) -> PathBuf {
    path.unwrap_or_else(|| {
        if std::fs::symlink_metadata(DEFAULT_CONFIG)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            && Path::new("client.toml").exists()
        {
            PathBuf::from("client.toml")
        } else {
            PathBuf::from(DEFAULT_CONFIG)
        }
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(level) = Level::parse(&cli.log_level) else {
        eprintln!(
            "--log-level must be one of: {}",
            Level::accepted().join(", ")
        );
        return ExitCode::from(WRONG);
    };
    let logger = Logger::stderr(level);
    ExitCode::from(dispatch(cli.command, &logger).await)
}

async fn dispatch(command: Command, logger: &Logger) -> u8 {
    match command {
        Command::Run { config } => run(&selected_config(config), logger).await,
        Command::Check { config } => check(&selected_config(config)),
        Command::Doctor { config, node } => {
            doctor(&selected_config(config), node.as_deref(), logger).await
        }
        Command::Explain { family } => explain(&family),
        Command::Generate { out, format } => generate(out.as_deref(), format),
        Command::Migrate { config, out } => migrate(&config, &out),
    }
}

/// Serves one configuration until the operator or the supervisor says stop.
async fn run(path: &Path, logger: &Logger) -> u8 {
    let config = match load(path) {
        Ok(config) => config,
        Err(problems) => return reject(&problems),
    };
    let server = match Server::start(&config, logger.clone()).await {
        Ok(server) => server,
        Err(error) => return start_failure(path, &error),
    };
    let stop = server.shutdown();
    let waiting = {
        let logger = logger.clone();
        let stop = stop.clone();
        async move {
            let name = serve::await_stop_signal(&logger).await;
            logger.event("stopping").text("signal", name).emit();
            stop.request();
        }
    };
    let (report, ()) = tokio::join!(server.run(), waiting);
    logger
        .event("stopped")
        .count("accepted", report.accepted)
        .count("carried", report.carried)
        .count("refused", report.refused)
        .count("failed", report.failed)
        .count("unresolved", report.unresolved)
        .emit();
    let outcome = format!(
        "stopped: {} accepted, {} carried, {} refused, {} failed, {} unresolved",
        report.accepted, report.carried, report.refused, report.failed, report.unresolved
    );
    // A proxy that cannot talk to its own terminal has still served its clients.
    let _ = writeln!(std::io::stdout(), "{outcome}");
    OK
}

/// Turns a listener that could not be opened into a word an operator can act on.
fn start_failure(path: &Path, error: &StartError) -> u8 {
    match error {
        StartError::NothingToListen => reject(&[format!("{}: {error}", path.display())]),
        StartError::Bind { .. } => {
            let _ = writeln!(std::io::stderr(), "{error}");
            BROKEN
        }
    }
}

/// Reports what a file says about itself, and nothing else.
fn check(path: &Path) -> u8 {
    match load(path) {
        Ok(config) => {
            for line in describe(&config) {
                let _ = writeln!(std::io::stdout(), "{line}");
            }
            OK
        }
        Err(problems) => reject(&problems),
    }
}

/// Reads and validates a file from disk.
///
/// Both halves of a failure are the same shape on purpose: an unreadable file and
/// an invalid one are answered by a list of lines, because the second can carry
/// twenty problems and an operator wants all of them in one pass.
fn load(path: &Path) -> Result<Config, Vec<String>> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| vec![format!("{}: cannot be read: {error}", path.display())])?;
    let parsed = match path.extension().and_then(|s| s.to_str()) {
        Some("json") => rust_reality_client::config::parse_json(&text),
        Some("toml") => rust_reality_client::config::parse_toml(&text),
        _ => rust_reality_client::config::parse(&text),
    };
    parsed
        .map_err(|error| error.problems().to_vec())
        .map_err(|problems| {
            problems
                .into_iter()
                .map(|problem| format!("{}: {}", problem.path, problem.message))
                .collect()
        })
}

/// What a valid configuration amounts to, in the order an operator reads it.
fn describe(config: &Config) -> Vec<String> {
    let mut lines = vec![format!(
        "ok: {} node(s), listening on {}",
        config.nodes.len(),
        listeners(config)
    )];
    for (index, node) in config.nodes.iter().enumerate() {
        lines.push(format!(
            "  node[{}] {name}: {endpoint} serverName={sni} shortId={short_id} chars \
             publicKey={key}",
            index + 1,
            name = node.name,
            endpoint = node.endpoint(),
            sni = node.reality.server_name,
            short_id = node.reality.short_id_chars(),
            key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(node.reality.public_key),
        ));
    }
    lines
}

fn listeners(config: &Config) -> String {
    let mut named = Vec::new();
    if let Some(address) = config.listen.socks5 {
        named.push(format!("socks5 {address}"));
    }
    if let Some(address) = config.listen.http {
        named.push(format!("http {address}"));
    }
    if named.is_empty() {
        return "nothing (both inbounds are disabled)".to_owned();
    }
    named.join(" and ")
}

/// Prints every problem and says the file will not start.
fn reject(problems: &[String]) -> u8 {
    for problem in problems {
        let _ = writeln!(std::io::stderr(), "{problem}");
    }
    WRONG
}

/// One answer from `doctor`.
struct Verdict {
    status: Status,
    check: &'static str,
    subject: String,
    detail: String,
}

/// How loud a verdict is, and what it does to the exit code.
///
/// The ordering is the point: `Fail` sorts above `Warn` above `Pass`, so the
/// worst verdict in a run is one `max` away.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl Verdict {
    fn pass(check: &'static str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            check,
            subject: subject.into(),
            detail: detail.into(),
        }
    }

    fn warn(check: &'static str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Warn,
            check,
            subject: subject.into(),
            detail: detail.into(),
        }
    }

    fn fail(check: &'static str, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            check,
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

/// Asks a configuration the five questions that have distinct answers.
async fn doctor(path: &Path, only: Option<&str>, logger: &Logger) -> u8 {
    let config = match load(path) {
        Ok(config) => config,
        Err(problems) => {
            let mut verdicts = Vec::new();
            for problem in &problems {
                verdicts.push(Verdict::fail(
                    "file",
                    path.display().to_string(),
                    problem.clone(),
                ));
            }
            report_verdicts(&verdicts);
            return BROKEN;
        }
    };
    let chosen = match selected(&config, only) {
        Ok(chosen) => chosen,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "{message}");
            return WRONG;
        }
    };
    let mut verdicts = vec![Verdict::pass(
        "file",
        path.display().to_string(),
        format!(
            "{} node(s) declared; {}",
            config.nodes.len(),
            "every field was understood"
        ),
    )];
    listen_checks(&config, &mut verdicts);
    let dial = Dial::new(
        Environment::detect(DialPolicy::default()),
        Tuning::for_policy(DialPolicy::default()),
    );
    for node in chosen {
        key_checks(node, &mut verdicts);
        reach_checks(node, &dial, logger, &mut verdicts).await;
    }
    report_verdicts(&verdicts);
    if verdicts
        .iter()
        .any(|verdict| verdict.status == Status::Fail)
    {
        return BROKEN;
    }
    OK
}

/// Which nodes to ask about, or `Err` for a name the file does not have.
fn selected<'a>(config: &'a Config, only: Option<&str>) -> Result<Vec<&'a Node>, String> {
    let Some(name) = only else {
        return Ok(config.nodes.iter().collect());
    };
    let chosen: Vec<&Node> = config
        .nodes
        .iter()
        .filter(|node| node.name == name)
        .collect();
    if chosen.is_empty() {
        return Err(format!(
            "--node {name} is not in this file. Names here are: {}",
            node_names(config)
        ));
    }
    Ok(chosen)
}

fn node_names(config: &Config) -> String {
    let names: Vec<&str> = config.nodes.iter().map(|node| node.name.as_str()).collect();
    names.join(", ")
}

/// Whether each listener can actually be opened, which is the question a port
/// collision makes urgent.
fn listen_checks(config: &Config, verdicts: &mut Vec<Verdict>) {
    for address in config.listen.addresses() {
        let subject = address.to_string();
        match std::net::TcpListener::bind(address) {
            Ok(_held) => {
                let status = if address.ip().is_loopback() {
                    Status::Pass
                } else {
                    Status::Warn
                };
                verdicts.push(Verdict {
                    status,
                    check: "listeners",
                    subject,
                    detail: if status == Status::Pass {
                        "the port is free".to_owned()
                    } else {
                        "the port is free, but this address lets every host that can reach it \
                         use this proxy, and this client holds node credentials"
                            .to_owned()
                    },
                });
            }
            Err(error) => verdicts.push(Verdict::fail(
                "listeners",
                subject,
                format!("cannot be bound: {error}"),
            )),
        }
    }
}

/// The two things about a node's REALITY fields that are checkable without asking
/// the node anything.
fn key_checks(node: &Node, verdicts: &mut Vec<Verdict>) {
    if node.reality.public_key == TEMPLATE_PUBLIC_KEY {
        verdicts.push(Verdict::fail(
            "keys",
            &node.name,
            "publicKey is the template's placeholder; paste the value the node's own `reality` \
             output gives, because with this one the handshake cannot succeed",
        ));
    }
    if node.reality.short_id_chars() < 2 {
        verdicts.push(Verdict::fail(
            "keys",
            &node.name,
            "shortId is empty: every REALITY identity must own at least one, and an empty \
             string is not a way to say so",
        ));
    }
}

/// Asks the node one question that has a real answer: can a tunnel be
/// authenticated, and how long did it take.
async fn reach_checks(node: &Node, dial: &Dial, logger: &Logger, verdicts: &mut Vec<Verdict>) {
    let handoff = Handoff::new(node.clone(), dial.clone());
    let started = std::time::Instant::now();
    match handoff.probe().await {
        Ok(latency) => {
            verdicts.push(Verdict::pass(
                "reach",
                &node.name,
                format!(
                    "{} answered the handshake in {} ms",
                    node.endpoint(),
                    latency.as_millis()
                ),
            ));
            verdicts.push(Verdict::pass(
                "clock",
                &node.name,
                "v2.0.1 accepts a handshake whose time differs by at most `maxTimeDiffMs` \
                 (60000 by default), so completing one proves this clock and the node's agree \
                 inside that window",
            ));
        }
        Err(error) => {
            let family = error.classify();
            logger
                .event_at(Level::Debug, "doctorProbe")
                .text("node", &node.name)
                .failure("error", &error)
                .duration("elapsed", started.elapsed())
                .emit();
            verdicts.push(unreached(node, family, &error));
        }
    }
}

/// What a failed probe licenses saying, and what it does not.
fn unreached(node: &Node, family: Failure, error: &Error) -> Verdict {
    match family {
        Failure::Dns => Verdict::fail(
            "reach",
            &node.name,
            format!("`{}` did not resolve: {error}", node.address),
        ),
        Failure::Connect => Verdict::fail(
            "reach",
            &node.name,
            format!(
                "{} was never reached: {error}. This is the node's address and port, not its \
                 REALITY settings",
                node.endpoint()
            ),
        ),
        Failure::Local => Verdict::warn(
            "reach",
            &node.name,
            format!("this client refused its own probe, so the node was never asked: {error}"),
        ),
        _ => Verdict::warn(
            "reach",
            &node.name,
            format!(
                "{} did not complete a handshake ({error}). REALITY answers a wrong publicKey, \
                 a wrong shortId and a clock outside `maxTimeDiffMs` in one way, by relaying to \
                 the cover, so this says nothing about which of the three it is: check the node's \
                 own clock, then re-copy the two fields",
                node.endpoint()
            ),
        ),
    }
}

/// Writes the answers, in the order they were earned.
fn report_verdicts(verdicts: &[Verdict]) {
    let mut pass = 0_usize;
    let mut warn = 0_usize;
    let mut fail = 0_usize;
    let mut worst = Status::Pass;
    for verdict in verdicts {
        match verdict.status {
            Status::Pass => pass += 1,
            Status::Warn => warn += 1,
            Status::Fail => fail += 1,
        }
        if verdict.status > worst {
            worst = verdict.status;
        }
        let _ = writeln!(
            std::io::stdout(),
            "{:<5} {:<9} {:<16} {}",
            verdict.status.word(),
            verdict.check,
            verdict.subject,
            verdict.detail
        );
    }
    let _ = writeln!(
        std::io::stdout(),
        "{:<5} {} checks: {} pass, {} warn, {} fail",
        worst.word(),
        verdicts.len(),
        pass,
        warn,
        fail
    );
}

impl Status {
    const fn word(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

/// Says what a failure family means and, above all, who it is about.
fn explain(word: &str) -> u8 {
    for (family, guidance) in EXPLAINED {
        if family.to_string() != word {
            continue;
        }
        let about = if family.counts_against_node() {
            "the node, as far as this client can tell"
        } else {
            "this client, not the node"
        };
        let _ = writeln!(
            std::io::stdout(),
            "{word} — counted against {about}.\n{guidance}"
        );
        return OK;
    }
    let words: Vec<String> = EXPLAINED
        .iter()
        .map(|(family, _)| family.to_string())
        .collect();
    let _ = writeln!(
        std::io::stderr(),
        "unknown family {word}. `explain` takes one of: {}",
        words.join(", ")
    );
    WRONG
}

/// What each family licenses, in the order the taxonomy lists them.
///
/// The guidance is here rather than in the error type because it is advice for an
/// operator, and the taxonomy's job is to say what happened.
const EXPLAINED: [(Failure, &str); 7] = [
    (
        Failure::Local,
        "A local rule said no before a node was asked: the connection, handshake, probe or \
         buffer limits, or a destination this client refuses to encode. Raise the limit or fix \
         the request; the node knows nothing about this and its score does not move.",
    ),
    (
        Failure::Dns,
        "The node's own host name did not resolve, so no address was ever tried. The cause is \
         between this machine and its resolver, not in the server process — but a node that \
         cannot be named is a node that cannot be used, so its score does move. Another \
         resolver, or an `address` written as an IP literal, is the way out.",
    ),
    (
        Failure::Connect,
        "TCP did not connect: no SYN was answered inside the budget. Either the address and \
         port are wrong, or the path is down. A node that is running but misconfigured answers \
         this handshake instead, which is a different family.",
    ),
    (
        Failure::Timeout,
        "TCP connected and then the exchange ran past its budget. Against a REALITY node this \
         is the shape of a connection that was relayed to the cover and left there, which is \
         also the shape of a server that is busy; the retries are cheap and the scheduler \
         hedges them, so this is a slowness signal rather than an outage.",
    ),
    (
        Failure::Handshake,
        "The TLS layer did not complete: the key agreement, the verified records or the \
         first-byte budget failed. A wrong `publicKey` or `shortId` looks exactly like a \
         cover-relayed connection here, so check what was pasted before blaming the network.",
    ),
    (
        Failure::Rejected,
        "The node read the VLESS request and refused it. This is the one family where the \
         server is definitely talking, which makes it the most informative failure in the \
         list: an expired or unknown user id, or a policy the node does not allow.",
    ),
    (
        Failure::Idle,
        "A session that had already been confirmed stopped carrying data. Nothing can be \
         moved at this point — v2.0.1 has no way to resume a session elsewhere — so the local \
         application sees the end of the connection, honestly.",
    ),
];

/// Writes the template, with a user id nobody else has.
fn generate(out: Option<&Path>, format: Option<ConfigFormat>) -> u8 {
    let format = format.unwrap_or_else(|| {
        if out.and_then(Path::extension).and_then(|s| s.to_str()) == Some("toml") {
            ConfigFormat::Toml
        } else {
            ConfigFormat::Json
        }
    });
    if let Some(extension) = out.and_then(Path::extension).and_then(|s| s.to_str()) {
        if (extension == "json" && format != ConfigFormat::Json)
            || (extension == "toml" && format != ConfigFormat::Toml)
        {
            return reject(&["--format conflicts with the output filename extension".to_owned()]);
        }
    }
    let text = match template(format) {
        Ok(text) => text,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "a user id could not be drawn: {error}");
            return BROKEN;
        }
    };
    let Some(path) = out else {
        let _ = std::io::stdout().write_all(text.as_bytes());
        return OK;
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    match options
        .open(path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
    {
        Ok(()) => {
            let _ = writeln!(std::io::stderr(), "wrote {}", path.display());
            OK
        }
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "{}: cannot be written: {error}",
                path.display()
            );
            BROKEN
        }
    }
}

/// The shipped example, with a fresh user id in place of the template's.
///
/// One source of truth means `generate | check` is a test of the example file, and
/// the example file is what the README shows.
fn template(format: ConfigFormat) -> Result<String, std::io::Error> {
    let mut bytes = [0_u8; 16];
    entropy::fill(&mut bytes).map_err(|error| std::io::Error::other(error.to_string()))?;
    // The version-4 and variant bits, so the string is a v4 id in the shape the
    // node expects.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let id = uuid::Uuid::from_bytes(bytes).to_string();
    let example = match format {
        ConfigFormat::Json => include_str!("../examples/client.json"),
        ConfigFormat::Toml => include_str!("../examples/client.toml"),
    };
    Ok(example.replace(TEMPLATE_USER_ID, &id))
}

/// Explicitly requested credential-bearing output; never print it in diagnostics.
fn migrate(input: &Path, output: &Path) -> u8 {
    if output.extension().and_then(|s| s.to_str()) == Some("toml") {
        return reject(&["migration writes JSON; choose a .json output path".to_owned()]);
    }
    let config = match load(input) {
        Ok(c) => c,
        Err(p) => return reject(&p),
    };
    let text = rust_reality_client::config::to_json(&config);
    if let Err(e) = rust_reality_client::config::parse_json(&text) {
        return reject(&[format!(
            "configuration cannot be represented as active JSON: {e}"
        )]);
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    match options.open(output).and_then(|mut f| {
        f.write_all(text.as_bytes())?;
        f.sync_all()
    }) {
        Ok(()) => {
            let _ = writeln!(
                std::io::stderr(),
                "wrote {} (credentials preserved)",
                output.display()
            );
            OK
        }
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "{}: cannot create new configuration: {e}",
                output.display()
            );
            BROKEN
        }
    }
}
