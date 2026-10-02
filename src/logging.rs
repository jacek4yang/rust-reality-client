//! Structured logging that cannot name a secret it was never handed.
//!
//! One JSON object per line, with the keys `rust-reality` v2.0.1 itself uses —
//! `timestampUnixMs`, `level`, `event` — so an operator's existing pipeline reads
//! this client and the node side by side. Nothing else about the shape is
//! inherited: fields are added one at a time through [`Event`], and the only types
//! it accepts are a string, a number, a flag and a duration. There is no
//! print-anything escape hatch, because the values this crate holds include a user
//! id, a short ID and a traffic key, and a log line that can print *anything* will
//! eventually print one of them.
//!
//! The redaction rule is therefore structural rather than a review habit.
//! [`crate::config::Node`] renders itself without its user id and reports a short ID
//! only as a character count, and this module has no way to reach material it is not
//! given. A field that names a node is the operator's label, which is the only
//! identifier that carries meaning into a log search anyway: a user id would say
//! *which credential*, and credentials are not diagnostic material.
//!
//! Logging never fails a connection. The sink is written under a lock and its errors
//! are dropped, because a closed stderr — which is what `journalctl` rotation and
//! `| head` both produce — is not a reason to tear down a tunnel that is working.

use std::fmt::{self, Write as _};
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Error;

/// How much is logged, in ascending loudness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Level {
    /// Only events that mean something is broken.
    Error,
    /// Breakage, plus anything an operator should look at.
    Warn,
    /// The lifecycle of connections and of the process.
    Info,
    /// Per-stage timings, for a stall that has to be located.
    Debug,
}

impl Level {
    /// The word this level writes into the `level` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// Reads a level from configuration or from `--log-level`.
    ///
    /// Case-insensitive and blank-tolerant, because operators type `INFO` and paste
    /// values out of a man page. An unrecognised word is `None` rather than a
    /// default: a configuration that says `verbose` must not quietly log at the
    /// level the operator did not ask for.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "error" => Self::Error,
            "warn" | "warning" => Self::Warn,
            "info" => Self::Info,
            "debug" | "trace" => Self::Debug,
            _ => return None,
        }
        .into()
    }

    /// The words [`Level::parse`] accepts, for a message that has to list them.
    #[must_use]
    pub const fn accepted() -> &'static [&'static str] {
        &["error", "warn", "info", "debug"]
    }
}

impl fmt::Display for Level {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One value a log field may hold.
#[derive(Clone, Debug)]
enum Value {
    Text(String),
    Count(u64),
    Signed(i64),
    Flag(bool),
}

impl Value {
    fn write_json(&self, line: &mut String) {
        match self {
            Self::Text(text) => write_string(line, text),
            Self::Count(number) => {
                let _ = write!(line, "{number}");
            }
            Self::Signed(number) => {
                let _ = write!(line, "{number}");
            }
            Self::Flag(truth) => {
                let _ = write!(line, "{truth}");
            }
        }
    }
}

/// Where lines go, behind a lock so two connections cannot interleave half an
/// object.
type Sink = Arc<Mutex<dyn Write + Send>>;

/// The log stream.
///
/// Cloning is cheap and means "the same stream", which is what a task needs: the
/// accept loop hands one to every connection it spawns, and a test that wants to see
/// the lines shares the sink instead of reading a file back.
#[derive(Clone)]
pub struct Logger {
    level: Level,
    sink: Sink,
}

impl Logger {
    /// Writes to this process's standard error.
    #[must_use]
    pub fn stderr(level: Level) -> Self {
        Self::with_sink(level, Arc::new(Mutex::new(std::io::stderr())))
    }

    /// Writes to a caller-supplied sink.
    #[must_use]
    pub fn with_sink(level: Level, sink: Sink) -> Self {
        Self { level, sink }
    }

    /// The level this stream was opened at.
    #[must_use]
    pub const fn level(&self) -> Level {
        self.level
    }

    /// Whether anything would be written at `level`.
    ///
    /// A caller uses this to skip building the line at all, rather than to decide
    /// whether to log: the decision about *what* happened stays with the event.
    #[must_use]
    pub fn enabled(&self, level: Level) -> bool {
        level <= self.level
    }

    /// Starts one `info` line with the given event name.
    ///
    /// Event names are `&'static str` on purpose: a log search is a join across
    /// versions, and a name that can be built at run time is a name that changes when
    /// a variable does.
    pub fn event(&self, name: &'static str) -> Event<'_> {
        self.event_at(Level::Info, name)
    }

    /// Starts one line at an explicit level.
    pub fn event_at(&self, level: Level, name: &'static str) -> Event<'_> {
        Event {
            logger: self,
            level,
            name,
            values: Vec::new(),
        }
    }

    /// Assembles and writes one line. Kept private so that the only way to reach a
    /// sink is through an event, which is where the field names are checked.
    fn write(&self, level: Level, name: &str, values: &[(&'static str, Value)]) {
        let mut line = String::with_capacity(96 + values.len() * 24);
        line.push('{');
        write_key(&mut line, "timestampUnixMs");
        let _ = write!(line, "{}", unix_milliseconds());
        write_key_after_comma(&mut line, "level");
        write_string(&mut line, level.as_str());
        write_key_after_comma(&mut line, "event");
        write_string(&mut line, name);
        for (key, value) in values {
            write_key_after_comma(&mut line, key);
            value.write_json(&mut line);
        }
        line.push_str("}\n");

        let sink = self.sink.lock();
        // A poisoned sink means somebody panicked mid-write, which is not this line's
        // problem and does not make the line wrong.
        let mut sink: MutexGuard<dyn Write + Send> = sink.unwrap_or_else(PoisonError::into_inner);
        // One write per line, so a reader on a pipe never sees an object split across
        // two wakeups; dropping the result is the documented choice above.
        let _ = sink.write_all(line.as_bytes());
        let _ = sink.flush();
    }
}

impl fmt::Debug for Logger {
    /// Prints the shape of the stream, never what it has written.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Logger")
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

/// One line, in the process of being built.
///
/// Emitting is what writes it, and the type is `#[must_use]` so that a forgotten
/// `.emit()` is a compile error rather than a silence. That is the whole reason this
/// is a builder instead of a macro: the service layer's contract is that no
/// connection's outcome goes unreported, and the compiler is the only place that
/// contract can be checked.
#[must_use = "an event that is never emitted logs nothing"]
pub struct Event<'a> {
    logger: &'a Logger,
    level: Level,
    name: &'static str,
    values: Vec<(&'static str, Value)>,
}

impl Event<'_> {
    /// Sets this line's level.
    pub fn at(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Adds a text field.
    pub fn text(mut self, key: &'static str, value: &str) -> Self {
        self.values.push((key, Value::Text(value.to_owned())));
        self
    }

    /// Adds a count.
    pub fn count(mut self, key: &'static str, value: u64) -> Self {
        self.values.push((key, Value::Count(value)));
        self
    }

    /// Adds a signed number.
    pub fn signed(mut self, key: &'static str, value: i64) -> Self {
        self.values.push((key, Value::Signed(value)));
        self
    }

    /// Adds a boolean.
    pub fn flag(mut self, key: &'static str, value: bool) -> Self {
        self.values.push((key, Value::Flag(value)));
        self
    }

    /// Adds a duration, as whole milliseconds.
    ///
    /// Sub-millisecond precision is dropped rather than widened into a float: a log
    /// line is read by `jq`, and a fractional duration invites a comparison that is
    /// not exact on every reader.
    pub fn duration(self, key: &'static str, value: Duration) -> Self {
        self.count(key, duration_milliseconds(value))
    }

    /// Adds the three fields every failure needs: what happened, which family it
    /// belongs to, and whether the node was involved at all.
    ///
    /// The family goes next to the message because the message alone cannot answer
    /// the operator's actual question — *whose* fault is this — and
    /// [`Error::classify`] is the crate's one answer to that.
    pub fn failure(self, key: &'static str, error: &Error) -> Self {
        let family = error.classify();
        self.text(key, &error.to_string())
            .text("family", &family.to_string())
            .flag("countsAgainstNode", family.counts_against_node())
    }

    /// Writes the line, if the stream carries this level, and reports whether it did.
    ///
    /// The return value exists because a test asserts on it: the difference between
    /// "nothing happened" and "something happened and was filtered" is exactly what a
    /// log-level bug looks like from the inside. A production caller ignores it on
    /// purpose, which is why this is not `#[must_use]`.
    #[allow(clippy::must_use_candidate)]
    pub fn emit(self) -> bool {
        if !self.logger.enabled(self.level) {
            return false;
        }
        self.logger.write(self.level, self.name, &self.values);
        true
    }
}

impl fmt::Debug for Event<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Event")
            .field("level", &self.level)
            .field("name", &self.name)
            .field("fields", &self.values.len())
            .finish_non_exhaustive()
    }
}

/// Whole milliseconds, saturating rather than wrapping.
fn duration_milliseconds(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

/// Milliseconds since the Unix epoch, in the field v2.0.1 calls `timestampUnixMs`.
fn unix_milliseconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_milliseconds)
}

/// Writes `"key":` following an existing field, comma included.
fn write_key_after_comma(line: &mut String, key: &str) {
    line.push(',');
    write_key(line, key);
}

/// Writes `"key":`, the colon included.
fn write_key(line: &mut String, key: &str) {
    write_string(line, key);
    line.push(':');
}

/// Writes one JSON string, escaping everything that changes what a reader parses.
///
/// Node names and error messages are the fields that carry text this crate did not
/// author, and an operator can name a node anything. A `"` or a backslash in that
/// name would otherwise end the field early and corrupt the line for every
/// downstream parser.
fn write_string(line: &mut String, text: &str) {
    line.push('"');
    for character in text.chars() {
        match character {
            '"' => line.push_str("\\\""),
            '\\' => line.push_str("\\\\"),
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let _ = write!(line, "\\u{:04x}", control as u32);
            }
            printable => line.push(printable),
        }
    }
    line.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{HandshakeError, RejectReason};

    /// A sink that keeps whole lines, for asserting on what was written.
    ///
    /// It is a `Write` of its own rather than a shared `Vec` inside the logger, so
    /// that taking its lock never nests inside the sink lock the logger already
    /// holds.
    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<String>>>);

    impl Lines {
        /// Every line the sink has seen.
        fn taken(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// The one line the sink has seen.
        fn only(&self) -> String {
            let held = self.taken();
            assert_eq!(held.len(), 1, "expected exactly one line, got {held:?}");
            held[0].clone()
        }
    }

    impl Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let text = String::from_utf8_lossy(bytes);
            let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            for piece in text.split_inclusive('\n') {
                if !piece.ends_with('\n') {
                    // A half line means the writer did not put a whole object in one
                    // write, which a pipe reader cannot reassemble.
                    held.push(format!("UNTERMINATED:{piece}"));
                    continue;
                }
                held.push(piece.trim_end().to_owned());
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(level: Level) -> (Logger, Lines) {
        let lines = Lines::default();
        let logger = Logger::with_sink(level, Arc::new(Mutex::new(lines.clone())));
        (logger, lines)
    }

    /// Splits the timestamp off the front of a line, returning its fields.
    fn fields(line: &str) -> u64 {
        let rest = line
            .strip_prefix("{\"timestampUnixMs\":")
            .expect("a line opens with the field v2.0.1 uses");
        let (stamp, _) = rest
            .split_once(',')
            .expect("a timestamp is followed by a comma");
        stamp
            .parse()
            .expect("the timestamp is a plain integer, not a quoted number")
    }

    #[test]
    fn a_line_carries_the_server_keys_and_the_fields_in_order() {
        let (logger, lines) = capture(Level::Debug);
        let opened = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after the epoch");
        let emitted = logger
            .event("connection_carried")
            .text("node", "tokyo-1")
            .count("toRemote", 40_960)
            .duration("took", Duration::from_millis(17))
            .signed("delta", -3)
            .flag("primary", true)
            .emit();

        assert!(emitted, "an info line is admissible at a debug level");
        let line = lines.only();
        assert_eq!(
            line,
            format!(
                "{{\"timestampUnixMs\":{},\"level\":\"info\",\"event\":\"connection_carried\",\
                 \"node\":\"tokyo-1\",\"toRemote\":40960,\"took\":17,\"delta\":-3,\
                 \"primary\":true}}",
                fields(&line)
            ),
            "the line is the object, in the order it was built"
        );
        let stamp = fields(&line);
        assert!(
            stamp >= duration_milliseconds(opened) && stamp <= unix_milliseconds() + 1,
            "the stamp is this process's clock, not a constant: {stamp}"
        );
    }

    #[test]
    fn nothing_is_written_below_the_open_level() {
        let (logger, lines) = capture(Level::Warn);
        assert!(
            !logger.event("probe_succeeded").at(Level::Debug).emit(),
            "a debug line must report that it was filtered, because a test that only \
             counted lines would read a silent stream as a healthy one"
        );
        assert!(logger.event("breaker_open").at(Level::Error).emit());
        assert!(
            lines.only().contains("\"level\":\"error\""),
            "the one line that came through is the error"
        );
    }

    #[test]
    fn text_that_would_break_the_line_is_escaped() {
        let (logger, lines) = capture(Level::Debug);
        logger
            .event("config_loaded")
            .text("node", "quote\" and back\\slash and \u{1} control")
            .emit();

        let line = lines.only();
        assert!(
            line.contains(r#""node":"quote\" and back\\slash and \u0001 control""#),
            "an operator can name a node anything, and only this escaping keeps that \
             from corrupting the line: {line}"
        );
        assert!(
            !line.chars().any(|character| (character as u32) < 0x20),
            "a control character in the middle of a line splits it for every reader \
             downstream: {line:?}"
        );
        assert!(
            line.ends_with('}') && fields(&line) > 1_700_000_000_000,
            "the escaped field sits inside one complete object: {line}"
        );
    }

    #[test]
    fn a_failure_logs_the_family_and_whose_fault_it_is() {
        let (logger, lines) = capture(Level::Debug);
        logger
            .event("session_failed")
            .at(Level::Warn)
            .failure("error", &Error::Rejected(RejectReason::Unauthorized))
            .emit();
        logger
            .event("session_failed")
            .at(Level::Warn)
            .failure("error", &Error::Handshake(HandshakeError::Timeout))
            .emit();

        let held = lines.taken();
        assert_eq!(held.len(), 2);
        assert!(
            held[0].contains("request rejected")
                && held[0].contains("\"family\":\"rejected\"")
                && held[0].contains("\"countsAgainstNode\":true"),
            "{}",
            held[0]
        );
        assert!(
            held[1].contains("handshake timed out") && held[1].contains("\"family\":\"timeout\""),
            "{}",
            held[1]
        );
    }

    #[test]
    fn the_message_never_carries_credential_material() {
        // The two failures that come closest to naming a user: the node refused this
        // request, and the peer was not the configured server.
        let (logger, lines) = capture(Level::Debug);
        logger
            .event("session_failed")
            .failure("error", &Error::Rejected(RejectReason::Other(42)))
            .emit();
        logger
            .event("session_failed")
            .failure("error", &Error::Handshake(HandshakeError::IdentityMismatch))
            .emit();

        let held = lines.taken();
        assert!(held[0].contains("server status 42"), "{}", held[0]);
        assert!(
            held[1].contains("peer is not the configured REALITY server"),
            "{}",
            held[1]
        );
        for line in held {
            assert!(
                !line.contains("userId") && !line.contains("shortId"),
                "a failure line must not even name the fields it is careful about: {line}"
            );
        }
    }

    #[test]
    fn levels_are_named_the_way_an_operator_types_them() {
        assert_eq!(Level::parse("  INFO "), Some(Level::Info));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        assert_eq!(Level::parse("trace"), Some(Level::Debug));
        assert_eq!(
            Level::parse("verbose"),
            None,
            "a word that does not mean a level must not choose one for the operator"
        );
        assert_eq!(Level::Error.cmp(&Level::Debug), std::cmp::Ordering::Less);
        assert_eq!(Level::accepted().len(), 4);
    }

    #[test]
    fn a_broken_sink_costs_a_line_and_nothing_else() {
        // What `| head` and a rotated journal do to a proxy's stderr.
        let lines = Lines::default();
        let failing = Arc::new(Mutex::new(FailingSink));
        let logger = Logger::with_sink(Level::Debug, failing);
        assert!(
            logger.event("first").emit(),
            "the level still admits the line; only the write fails"
        );
        assert!(
            logger.event("second").emit(),
            "and a failed write is not fatal"
        );
        assert!(
            lines.taken().is_empty(),
            "the capture sink saw nothing, because the logger was rewired"
        );
    }

    /// A sink whose flush always fails, like a pipe whose reader has gone.
    struct FailingSink;

    impl Write for FailingSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the reader has gone",
            ))
        }
    }
}
