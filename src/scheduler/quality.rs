//! Bounded, conservative feedback from sessions, separate from handshake health.
//!
//! Only authenticated tunnel-format defects earn a routing cost. Socket resets
//! are ambiguous: LINE, LANDING and the destination cannot be distinguished here.
//! The cost never closes a breaker or changes an already-established connection.

use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use crate::error::{Error, SessionError};
use crate::transport::family::AddressFamily;
use crate::transport::relay::Progress;

/// A completion callback owned by exactly one selected session.
type Sink = Box<dyn FnOnce(&Completion) + Send>;

/// Payload-free terminal evidence. Unknown is intentionally not a node verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cause {
    /// Both directions closed normally.
    Normal,
    /// The application-side socket failed.
    Local,
    /// Authenticated record/framing validation failed on a tunnel read.
    TunnelProtocol,
    /// Transport or remote cause whose owner cannot be established.
    Unknown,
    /// The owner abandoned its future.
    Cancelled,
    /// The owner unwound during a panic.
    Panicked,
}

impl Cause {
    /// Stable bounded label for structured logs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Local => "local",
            Self::TunnelProtocol => "tunnelProtocol",
            Self::Unknown => "unknown",
            Self::Cancelled => "cancelled",
            Self::Panicked => "panicked",
        }
    }
}

/// One session's progress and terminal cause, settled at most once.
pub struct Completion {
    /// Write acceptance counts and the observed failing edge/operation.
    pub progress: Progress,
    /// Terminal attribution, never inferred from application payload.
    pub cause: Cause,
    started: Option<Instant>,
    sink: Option<Sink>,
}

impl Completion {
    /// An untracked tunnel, such as one established without a scheduler.
    #[must_use]
    pub const fn untracked() -> Self {
        Self {
            progress: Progress {
                local: crate::transport::relay::Edge {
                    written: 0,
                    failed: None,
                },
                tunnel: crate::transport::relay::Edge {
                    written: 0,
                    failed: None,
                },
            },
            cause: Cause::Cancelled,
            started: None,
            sink: None,
        }
    }

    pub(super) fn new(sink: Sink) -> Self {
        let mut completion = Self::untracked();
        completion.sink = Some(sink);
        completion
    }

    /// Begin ownership at the inbound, not in a hedge candidate that may lose.
    pub fn begin(&mut self) {
        self.started = Some(Instant::now());
    }

    /// Monotonic lifetime since inbound adoption.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.started.map_or(Duration::ZERO, |start| start.elapsed())
    }

    /// Settle after the relay returns. Drop handles cancellation and unwinding.
    pub fn finish(&mut self, error: Option<&Error>) {
        self.cause = if error.is_none() {
            Cause::Normal
        } else if self.progress.local.failed.is_some() {
            Cause::Local
        } else if self.progress.tunnel.failed == Some("read")
            && matches!(
                error,
                Some(Error::Session(
                    SessionError::RecordCorrupted
                        | SessionError::Framing(_)
                        | SessionError::UnexpectedContentType(_)
                ))
            )
        {
            Cause::TunnelProtocol
        } else {
            Cause::Unknown
        };
        self.settle();
    }

    fn settle(&mut self) {
        if let Some(sink) = self.sink.take() {
            if self.started.is_some() {
                sink(self);
            }
        }
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.cause = Cause::Panicked;
        }
        self.settle();
    }
}

impl fmt::Debug for Completion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Completion")
            .field("cause", &self.cause)
            .field("progress", &self.progress)
            .finish_non_exhaustive()
    }
}

/// One small record per node and address family. No destinations or payloads.
#[derive(Clone, Copy, Debug, Default)]
struct Family {
    seen: bool,
    faults: u8,
    until: u64,
    recovered: u64,
    last: u64,
}

/// Aggregate session counters and family-specific routing costs.
#[derive(Debug, Default)]
pub struct Quality {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    families: [Family; 2],
    completed: u64,
    unknown: u64,
    cancelled: u64,
}

impl Quality {
    pub(super) fn record(
        &self,
        family: AddressFamily,
        opened: u64,
        now: u64,
        completion: &Completion,
    ) {
        // Poisoning is not itself a remote fault. Keep the last bounded state.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.completed = state.completed.saturating_add(1);
        if matches!(completion.cause, Cause::Cancelled | Cause::Panicked) {
            state.cancelled = state.cancelled.saturating_add(1);
            return;
        }
        if completion.cause == Cause::Unknown {
            state.unknown = state.unknown.saturating_add(1);
        }
        let entry = &mut state.families[match family {
            AddressFamily::Ipv4 => 0,
            AddressFamily::Ipv6 => 1,
        }];
        if completion.cause == Cause::Local {
            return;
        }
        if now.saturating_sub(entry.last) > 300_000 {
            *entry = Family::default();
        }
        entry.seen = true;
        entry.last = now;
        if opened < entry.recovered {
            return;
        } // a pre-recovery session cannot re-poison a recovered path
        if completion.cause == Cause::TunnelProtocol {
            entry.faults = entry.faults.saturating_add(1).min(3);
            if entry.faults >= 3 {
                entry.until = now.saturating_add(30_000);
            }
        } else if completion.cause == Cause::Normal
            && completion.age() >= Duration::from_secs(30)
            && completion.progress.local.written > 0
            && completion.progress.tunnel.written > 0
        {
            entry.faults = 0;
            entry.until = 0;
            entry.recovered = now;
        }
    }

    /// A bounded cost, never a ban. A recently observed healthy family remains
    /// usable even when its sibling has failed. Handshake probes cannot clear it.
    #[must_use]
    pub fn penalty_ms(&self, now: u64) -> u64 {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .families
            .iter()
            .filter(|entry| entry.seen && now.saturating_sub(entry.last) <= 300_000)
            .map(|entry| if entry.until > now { 500 } else { 0 })
            .min()
            .unwrap_or(0)
    }
}
