//! Deterministic byte-mutation smoke fuzz for the two attacker-facing parsers.
//!
//! This is not a coverage tool and it is not `cargo-fuzz`: neither the fuzz
//! profile nor a registry of `libfuzzer-sys` is available offline, and a CI job
//! that cannot install one is a job that lies about what it ran. What this file
//! does run anywhere is the property that made the fuzz request in the first
//! place, over tens of thousands of inputs chosen by a seeded generator:
//!
//! * **no input panics.** A panic on this path is not a failed test, it is a local
//!   denial of service: anything on the machine can open the loopback listener, so
//!   a slice index that can go out of range is a way to kill a proxy that is
//!   serving everyone else.
//! * **every input terminates.** No exchange is left waiting on a budget that a
//!   closed half-connection cannot clear, and none spins.
//! * **a client is never handed a shape it cannot parse.** The bytes an edge
//!   writes are always 0, 2 or 12 for SOCKS5 and always a well-formed status line
//!   for HTTP, because the two ways a proxy lies are a refusal parsed as a success
//!   and a truncated header parsed as a whole answer.
//! * **what the client was told agrees with what the process recorded.** Once the
//!   greeting is settled, the reply code on the wire is compared against the code
//!   the `Outcome` carries, and a node failure against [`reply_for`]. An answer and
//!   a log line that disagree is how an operator is misled about a node that is
//!   fine, and it is the invariant a fuzzer is worth running for.
//!
//! The seeds are fixed, so a failure is replayable from the bytes the message
//! prints.

use std::time::Duration;

use rust_reality_client::error::{Error, RejectReason};
use rust_reality_client::inbound::http;
use rust_reality_client::inbound::socks5::{self, NO_AUTH, VERSION, reply_for};
use rust_reality_client::inbound::{Establish, Establishment, Gate};
use rust_reality_client::protocol::vless::Destination;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

/// Inputs that are legal, or nearly so: every mutation starts from a real exchange.
const SOCKS5_CORPUS: &[&[u8]] = &[
    // Greeting, then CONNECT to 203.0.113.1:80.
    &[
        0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 203, 0, 113, 1, 0, 80,
    ],
    // Greeting, then a domain-name target.
    &[
        0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 80,
    ],
    // Greeting, then an IPv6 target.
    &[
        0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0x01, 0x1f, 0x90,
    ],
    // Greeting only, then nothing.
    &[0x05, 0x01, 0x00],
    // A method list that offers nothing this proxy has.
    &[0x05, 0x02, 0x01, 0x02],
    // SOCKS4, which is refused before anything is parsed.
    &[0x04, 0x01, 0x00],
    // Fragments, which is how a client that dies mid-write looks to a reader.
    &[0x05],
    &[0x05, 0x01],
    &[0x05, 0x01, 0x00, 0x05],
    &[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03],
    &[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 200],
];

/// Requests only, for the stage that follows a greeting this client accepted.
const REQUEST_CORPUS: &[&[u8]] = &[
    &[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 1, 0, 80],
    &[0x05, 0x01, 0x00, 0x03, 3, b'a', b'b', b'c', 0, 80],
    &[
        0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        0x1f, 0x90,
    ],
    &[0x05, 0x03, 0x00, 0x01, 203, 0, 113, 1, 0, 80],
    &[0x05, 0x02, 0x00, 0x01, 203, 0, 113, 1, 0, 80],
    &[0x05, 0x01, 0x01, 0x01, 203, 0, 113, 1, 0, 80],
    &[0x01, 0x01, 0x00, 0x01, 203, 0, 113, 1, 0, 80],
    &[0x05, 0x01, 0x00, 0x02, 0, 80],
    &[0x05, 0x01, 0x00, 0x03, 255, b'a'],
    &[0x05, 0x01, 0x00, 0x01, 203, 0, 113],
    &[],
    &[0x05],
];

/// HTTP heads, legal and otherwise.
const HTTP_CORPUS: &[&[u8]] = &[
    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    b"CONNECT 203.0.113.1:80 HTTP/1.0\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"POST http://example.com/a HTTP/1.1\r\n\r\n",
    b"CONNECT example.com HTTP/1.1\r\n\r\n",
    b"CONNECT :443 HTTP/1.1\r\n\r\n",
    b"CONNECT example.com:0 HTTP/1.1\r\n\r\n",
    b"CONNECT example.com:70000 HTTP/1.1\r\n\r\n",
    b"CONNECT exa\r\nmple.com:443 HTTP/1.1\r\n\r\n",
    b"CONNECT example.com:443 HTTP/2.0\r\n\r\n",
    b"connect example.com:443 http/1.1\r\n\r\n",
    b"\r\n",
    b"X",
    b"CONNECT example.com:443 HTTP/1.1\r\n",
];

/// How many mutated inputs an edge sees.
const MUTATIONS: usize = 6_000;

/// The bound every exchange is held to, far above what an in-memory pipe needs.
///
/// A timeout here is a real failure rather than a slow test: the only way a closed
/// half-connection can keep an exchange alive is a read that waits for bytes that
/// cannot arrive, which is the shape of a listener that fills up.
const DEADLINE: Duration = Duration::from_secs(5);

/// The address the edge believes it was bound to, for a reply's bound field.
const BOUND: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 10_808);

/// The greeting every request-stage exchange sends before its mutated request.
const GREETING: [u8; 3] = [VERSION, 1, NO_AUTH];

/// A seam that never opens a tunnel, so no input can reach a network.
struct Refusing;

impl Establish for Refusing {
    fn establish(&self, _destination: Destination, _port: u16) -> Establishment {
        Box::pin(async { Err(Error::Rejected(RejectReason::Forbidden)) })
    }
}

/// The tiny deterministic generator this file uses instead of a fuzzer.
///
/// xorshift64\*, seeded by hand. It is here because a seeded generator makes the
/// corpus a constant: the same inputs run on every commit, and a regression can be
/// replayed from the bytes the failure message prints.
struct Seed(u64);

impl Seed {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).expect("a corpus is never empty");
        usize::try_from(self.next() % bound).unwrap_or(0)
    }

    /// One byte out of the generator, which is what an input needs rather than a
    /// number to compare against.
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

/// One mutation of one corpus entry.
fn mutate(seed: &mut Seed, corpus: &[&[u8]]) -> Vec<u8> {
    let mut bytes = corpus[seed.below(corpus.len())].to_vec();
    let edits = seed.below(4);
    for _ in 0..=edits {
        if bytes.is_empty() {
            bytes.push(seed.byte());
            continue;
        }
        match seed.below(6) {
            0 => {
                let at = seed.below(bytes.len());
                bytes[at] = seed.byte();
            }
            1 => {
                let at = seed.below(bytes.len());
                bytes[at] ^= 1 << seed.below(8);
            }
            2 => bytes.truncate(seed.below(bytes.len())),
            3 => {
                let at = seed.below(bytes.len() + 1);
                bytes.insert(at, seed.byte());
            }
            4 => {
                let at = seed.below(bytes.len());
                let length = 1 + seed.below(bytes.len() - at);
                let tail = bytes[at..at + length].to_vec();
                for byte in tail {
                    bytes.insert(at, byte);
                }
            }
            _ => bytes.reverse(),
        }
    }
    bytes
}

/// Runs one handler over one input, hanging up the moment it is written.
///
/// Both edges share this: the answer is drained *before* the task is awaited,
/// because bytes only reach the client while the handler still holds its half of
/// the pipe.
async fn drive<T>(
    mut client: tokio::io::DuplexStream,
    input: &[u8],
    handler: tokio::task::JoinHandle<T>,
    edge: &str,
) -> (Vec<u8>, T) {
    let _ = client.write_all(input).await;
    let _ = client.shutdown().await;
    let mut written = Vec::new();
    let drained = tokio::time::timeout(DEADLINE, client.read_to_end(&mut written)).await;
    assert!(
        drained.is_ok(),
        "the {edge} edge left its client waiting for an end that never came"
    );
    let outcome = tokio::time::timeout(DEADLINE, handler)
        .await
        .unwrap_or_else(|_elapsed| {
            panic!("the {edge} handler was still running after {DEADLINE:?}")
        })
        .unwrap_or_else(|error| panic!("the {edge} handler died: {error}"));
    (written, outcome)
}

/// One SOCKS5 exchange, from the first byte to the reported outcome.
async fn socks5(input: &[u8]) -> (Vec<u8>, socks5::Outcome) {
    let (client, server) = duplex(8 * 1024);
    let proxy = socks5::Proxy::new(Refusing, Gate::new(8, 4));
    let handler = tokio::spawn(async move {
        let mut stream = server;
        proxy.handle(&mut stream, BOUND).await
    });
    drive(client, input, handler, "SOCKS5").await
}

/// One SOCKS5 exchange whose greeting is valid, returning only the reply block.
///
/// The two-byte method selection is read off first and deliberately thrown away,
/// which is what lets the caller compare *the reply the client parses* against the
/// outcome the process recorded, instead of against a concatenation of both.
async fn socks5_reply(request: &[u8]) -> (Vec<u8>, socks5::Outcome) {
    let (client, server) = duplex(8 * 1024);
    let proxy = socks5::Proxy::new(Refusing, Gate::new(8, 4));
    let handler = tokio::spawn(async move {
        let mut stream = server;
        proxy.handle(&mut stream, BOUND).await
    });
    let mut client = client;
    let _ = client.write_all(&GREETING).await;
    let mut selection = [0_u8; 2];
    let greeted = tokio::time::timeout(DEADLINE, client.read_exact(&mut selection)).await;
    assert!(
        greeted.is_ok(),
        "a valid greeting is always answered with a method selection"
    );
    assert_eq!(
        selection,
        [VERSION, NO_AUTH],
        "this client speaks method 0 and nothing else"
    );
    let _ = client.write_all(request).await;
    let _ = client.shutdown().await;
    let mut reply = Vec::new();
    let drained = tokio::time::timeout(DEADLINE, client.read_to_end(&mut reply)).await;
    assert!(
        drained.is_ok(),
        "the SOCKS5 edge left its client waiting for an end that never came"
    );
    let outcome = tokio::time::timeout(DEADLINE, handler)
        .await
        .unwrap_or_else(|_elapsed| {
            panic!("the SOCKS5 handler was still running after {DEADLINE:?}")
        })
        .unwrap_or_else(|error| panic!("the SOCKS5 handler died: {error}"));
    (reply, outcome)
}

/// One HTTP exchange, from the first byte to the reported outcome.
async fn http_exchange(input: &[u8]) -> (Vec<u8>, http::Outcome) {
    let (client, server) = duplex(8 * 1024);
    let proxy = http::Proxy::new(Refusing, Gate::new(8, 4));
    let handler = tokio::spawn(async move { proxy.handle(server).await });
    drive(client, input, handler, "HTTP").await
}

/// A mangled greeting never produces a half-written reply.
#[tokio::test]
async fn mutated_greetings_answer_in_shapes_a_client_can_read() {
    let mut seed = Seed(0x5EED_1234_9999_0001);
    for _ in 0..MUTATIONS {
        let input = mutate(&mut seed, SOCKS5_CORPUS);
        let (reply, outcome) = socks5(&input).await;
        let described = describe(&input, &reply);
        if reply.is_empty() {
            continue;
        }
        assert_eq!(
            reply[0], VERSION,
            "an answer that does not start with the version is parsed as the method \
             selection the client already read: {described}"
        );
        assert!(
            matches!(reply.len(), 2 | 12),
            "a SOCKS5 client reads 2 bytes and then 10, so anything else is a truncated \
             or duplicated answer: {described}"
        );
        if reply.len() == 12 {
            assert_eq!(
                reply[1], NO_AUTH,
                "a request reply only exists after a method selection this client \
                 accepted: {described}"
            );
            assert_eq!(
                reply[2], VERSION,
                "the reply block starts with the version again: {described}"
            );
        }
        assert!(
            !matches!(outcome, socks5::Outcome::Carried(_)),
            "the seam refuses every tunnel, so nothing can be carried: {described}"
        );
    }
}

/// A partial greeting earns silence, never a fabricated reply.
#[tokio::test]
async fn a_partial_greeting_is_answered_with_nothing() {
    for prefix in [vec![VERSION], vec![VERSION, 1]] {
        let (reply, _) = socks5(&prefix).await;
        assert!(
            reply.is_empty(),
            "{prefix:?} is not a greeting, and nothing may be parsed from it: got {reply:?}"
        );
    }
}

/// Once the greeting is settled, the reply code and the recorded outcome agree.
#[tokio::test]
async fn mutated_requests_are_answered_with_the_code_they_record() {
    let mut seed = Seed(0x5EED_9999_1357_2468);
    for _ in 0..MUTATIONS {
        let request = mutate(&mut seed, REQUEST_CORPUS);
        let (reply, outcome) = socks5_reply(&request).await;
        let described = describe(&request, &reply);
        if !reply.is_empty() {
            assert!(
                reply.len() == 10,
                "a reply is VER, REP, RSV, ATYP and a bound address, and a client reads its \
                 port out of whatever follows the address type: {described}"
            );
            assert_eq!(reply[0], VERSION, "the version echoes back: {described}");
        }
        match &outcome {
            socks5::Outcome::Carried(_) => {
                unreachable!("the seam refuses every tunnel, so nothing can be carried")
            }
            socks5::Outcome::Refused { rep: None, .. } => assert!(
                reply.is_empty(),
                "a refusal the protocol has no code for must say nothing rather than \
                 guess: {described}"
            ),
            socks5::Outcome::Refused {
                rep: Some(code), ..
            } => assert_eq!(
                reply.get(1).copied(),
                Some(*code),
                "the code the client was sent and the code this process recorded are \
                 different answers: {described}"
            ),
            socks5::Outcome::Failed(error) => assert_eq!(
                reply.get(1).copied(),
                Some(reply_for(error)),
                "a node failure has to reach the client as the closest code SOCKS5 has, \
                 and be recorded as the failure it is: {described}"
            ),
        }
    }
}

/// The HTTP edge answers every head it is given with a status line, or with nothing.
#[tokio::test]
async fn mutated_heads_are_answered_as_http_or_not_at_all() {
    let mut seed = Seed(0x5EED_4321_7777_0002);
    for _ in 0..MUTATIONS {
        let input = mutate(&mut seed, HTTP_CORPUS);
        let (reply, outcome) = http_exchange(&input).await;
        let described = describe(&input, &reply);
        let recorded = match &outcome {
            http::Outcome::Refused { status, .. } => *status,
            http::Outcome::Failed(_) => None,
            http::Outcome::Carried(_) => {
                unreachable!("the seam refuses every tunnel, so nothing can be carried")
            }
        };
        if reply.is_empty() {
            continue;
        }
        assert!(
            reply.starts_with(b"HTTP/1."),
            "a proxy that answers with something other than a status line is a client that \
             hangs: {described}"
        );
        let line = reply
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default()
            .to_vec();
        assert!(
            line.ends_with(b"\r"),
            "a status line that does not end in CRLF is a head the client will keep \
             waiting for: {described}"
        );
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
        assert!(
            fields.len() >= 2 && fields[1].len() == 3 && fields[1].iter().all(u8::is_ascii_digit),
            "a status line is version, three digits and a phrase: {described}"
        );
        let printed: u16 = String::from_utf8_lossy(fields[1])
            .parse()
            .unwrap_or_default();
        assert!(
            (100..=599).contains(&printed),
            "a status this client prints that HTTP does not define is a client bug: {described}"
        );
        if let Some(recorded) = recorded {
            assert_eq!(
                recorded, printed,
                "the status the client was given and the status this process recorded are \
                 different answers: {described}"
            );
        }
    }
}

/// Both buffers in one string, because a failure has to be replayable by hand.
fn describe(input: &[u8], reply: &[u8]) -> String {
    use std::fmt::Write as _;

    fn hex(bytes: &[u8]) -> String {
        let mut text = String::new();
        for byte in bytes.iter().take(48) {
            let _ = write!(text, "{byte:02x}");
        }
        if bytes.len() > 48 {
            text.push_str("..");
        }
        text
    }

    let mut text = String::from("input ");
    text.push_str(&hex(input));
    text.push_str(" answered ");
    text.push_str(&hex(reply));
    text
}
