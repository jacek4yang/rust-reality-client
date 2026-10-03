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
    /// Last observed downlink state; unknown for an interrupted relay.
    pub downlink: &'static str,
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
            downlink: "unknown",
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
    fault_at: u64,
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
            return;
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
            if entry.faults == 0 || now.saturating_sub(entry.fault_at) > 300_000 {
                entry.faults = 0;
                entry.fault_at = now;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransportError;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn verdict(cause: Cause) -> Completion {
        let mut completion = Completion::untracked();
        completion.begin();
        completion.cause = cause;
        completion
    }

    #[test]
    fn local_resets_remote_resets_and_normal_eof_are_not_node_convictions() {
        for (edge, error, want) in [
            (
                "local",
                Error::Transport(TransportError::Local("reset".into())),
                Cause::Local,
            ),
            (
                "tunnel",
                Error::Transport(TransportError::Socket("reset".into())),
                Cause::Unknown,
            ),
            (
                "tunnel",
                Error::Session(SessionError::PeerAlert {
                    level: 2,
                    description: 80,
                }),
                Cause::Unknown,
            ),
        ] {
            let mut c = verdict(Cause::Cancelled);
            if edge == "local" {
                c.progress.local.failed = Some("read");
            } else {
                c.progress.tunnel.failed = Some("read");
            }
            c.finish(Some(&error));
            assert_eq!(c.cause, want);
        }
        let mut c = verdict(Cause::Cancelled);
        c.finish(None);
        assert_eq!(c.cause, Cause::Normal);
    }

    #[test]
    fn protocol_attribution_requires_a_tunnel_read_not_a_local_encoder_failure() {
        for operation in ["read", "write"] {
            let mut c = verdict(Cause::Cancelled);
            c.progress.tunnel.failed = Some(operation);
            c.finish(Some(&Error::Session(SessionError::Framing("command"))));
            assert_eq!(
                c.cause,
                if operation == "read" {
                    Cause::TunnelProtocol
                } else {
                    Cause::Unknown
                }
            );
        }
    }

    #[test]
    fn cancellation_settles_once_and_unused_hedge_winner_settles_nothing() {
        let count = Arc::new(AtomicUsize::new(0));
        for begin in [false, true] {
            let count = count.clone();
            let mut c = Completion::new(Box::new(move |done| {
                assert_eq!(done.cause, Cause::Cancelled);
                count.fetch_add(1, Ordering::SeqCst);
            }));
            if begin {
                c.begin();
            }
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let count2 = count.clone();
        let mut c = Completion::new(Box::new(move |_| {
            count2.fetch_add(1, Ordering::SeqCst);
        }));
        c.begin();
        c.finish(None);
        c.finish(None);
        drop(c);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn repeated_protocol_faults_cost_but_do_not_ban_and_expire() {
        let quality = Quality::default();
        for now in 1..=3 {
            quality.record(
                AddressFamily::Ipv4,
                now,
                now,
                &verdict(Cause::TunnelProtocol),
            );
        }
        assert_eq!(quality.penalty_ms(3), 500);
        assert_eq!(quality.penalty_ms(30_003), 0);
    }

    #[test]
    fn short_success_does_not_clear_a_fault_class_and_healthy_v6_is_not_penalized() {
        let quality = Quality::default();
        for now in 1..=3 {
            quality.record(
                AddressFamily::Ipv4,
                now,
                now,
                &verdict(Cause::TunnelProtocol),
            );
        }
        quality.record(AddressFamily::Ipv4, 4, 4, &verdict(Cause::Normal));
        assert_eq!(quality.penalty_ms(4), 500);
        quality.record(AddressFamily::Ipv6, 5, 5, &verdict(Cause::Normal));
        assert_eq!(quality.penalty_ms(5), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn real_session_recovery_ignores_late_pre_recovery_faults() {
        let quality = Quality::default();
        for now in 1..=3 {
            quality.record(
                AddressFamily::Ipv4,
                now,
                now,
                &verdict(Cause::TunnelProtocol),
            );
        }
        let mut good = verdict(Cause::Normal);
        good.progress.local.written = 100;
        good.progress.tunnel.written = 100;
        tokio::time::advance(Duration::from_secs(31)).await;
        quality.record(AddressFamily::Ipv4, 4, 31_004, &good);
        for now in 31_005..31_010 {
            quality.record(AddressFamily::Ipv4, 2, now, &verdict(Cause::TunnelProtocol));
        }
        assert_eq!(quality.penalty_ms(31_010), 0);
    }

    #[test]
    fn shared_destination_failures_do_not_disable_every_entry() {
        for _ in 0..3 {
            let quality = Quality::default();
            for now in 0..100 {
                quality.record(AddressFamily::Ipv4, now, now, &verdict(Cause::Unknown));
                quality.record(AddressFamily::Ipv4, now, now, &verdict(Cause::Local));
                quality.record(AddressFamily::Ipv4, now, now, &verdict(Cause::Cancelled));
            }
            assert_eq!(quality.penalty_ms(100), 0);
        }
    }

    #[test]
    fn old_faults_expire_even_when_short_successes_keep_arriving() {
        let quality = Quality::default();
        for now in 1..=3 {
            quality.record(
                AddressFamily::Ipv4,
                now,
                now,
                &verdict(Cause::TunnelProtocol),
            );
        }
        for now in (10_000..360_000).step_by(10_000) {
            quality.record(AddressFamily::Ipv4, now, now, &verdict(Cause::Normal));
        }
        quality.record(
            AddressFamily::Ipv4,
            360_000,
            360_000,
            &verdict(Cause::TunnelProtocol),
        );
        assert_eq!(
            quality.penalty_ms(360_000),
            0,
            "one fresh fault must not inherit indefinitely old strikes"
        );
    }

    #[test]
    fn three_faults_must_share_one_bounded_window() {
        let quality = Quality::default();
        for now in [1, 299_999, 599_998] {
            quality.record(
                AddressFamily::Ipv4,
                now,
                now,
                &verdict(Cause::TunnelProtocol),
            );
        }
        assert_eq!(quality.penalty_ms(599_998), 0);
    }

    #[test]
    fn unknown_alternate_family_is_not_a_proven_healthy_escape() {
        let quality = Quality::default();
        for now in 1..=3 {
            quality.record(
                AddressFamily::Ipv4,
                now,
                now,
                &verdict(Cause::TunnelProtocol),
            );
        }
        quality.record(AddressFamily::Ipv6, 4, 4, &verdict(Cause::Unknown));
        assert_eq!(
            quality.penalty_ms(4),
            500,
            "ambiguous completion cannot clear a different failure class"
        );
    }

    #[test]
    fn concurrent_completions_are_bounded_and_counted() {
        let quality = Arc::new(Quality::default());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let quality = quality.clone();
                scope.spawn(move || {
                    for now in 0..1000 {
                        quality.record(AddressFamily::Ipv4, now, now, &verdict(Cause::Unknown));
                    }
                });
            }
        });
        let state = quality.state.lock().unwrap();
        assert_eq!(state.completed, 8000);
        assert_eq!(state.unknown, 8000);
        assert_eq!(state.families.len(), 2);
    }
}
