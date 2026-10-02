//! The edge: what a local application speaks to this client.
//!
//! Applications do not speak VLESS, so this layer exists to translate. A browser
//! or a CLI tool offers SOCKS5 ([`socks5`]), and a `HTTPS_PROXY`-style environment
//! variable points at HTTP `CONNECT`. Both are parsed by hand rather than pulled
//! from a crate, because every byte at this edge is attacker-controlled and the
//! only bound that holds for sure is the one written next to the read.
//!
//! No inbound chooses a node. That job belongs to [`Establish`], which is given a
//! destination and hands back whatever opened it. By the time an inbound answers,
//! the choosing is over: a `0x00` reply or an HTTP `200` is the moment the remote
//! session becomes immutable, and what follows is
//! [`carry`](crate::transport::carry) and nothing else.
//!
//! This module also holds [`Gate`], the only limits the edge imposes on itself. A
//! localhost listener is not a trust boundary — anything on the machine can open a
//! thousand sockets at it — so the bounds have to be taken here rather than
//! assumed of the peer.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::Error;
use crate::handoff::{Established, Handoff};
use crate::protocol::vless::Destination;

pub mod socks5;

/// The most local connections this edge serves at once.
///
/// Each one costs a task and two relay buffers — [`RELAY_BUFFER`](crate::transport::RELAY_BUFFER)
/// in each direction, so 16 KiB — which puts the whole ceiling at a few megabytes
/// of memory. It is a ceiling and not a target: the point is that a local process
/// cannot make this client's memory grow by opening sockets.
pub const MAX_LOCAL_CONNECTIONS: usize = 256;

/// The most connections that may be authenticating at once.
///
/// Authentication is the expensive part of a connection: two key agreements and a
/// handful of verified records, all CPU. Established tunnels do not hold this
/// slot, because a long download is not work of that kind. Thirty-two is enough to
/// keep a page load's first burst moving on a fast network while staying well
/// inside the capacity of a single core.
pub const MAX_CONCURRENT_HANDSHAKES: usize = 32;

/// The one thing an inbound asks of the rest of the client: open a tunnel.
///
/// The destination travels by value and the answer is a boxed `Send` future,
/// because the callers of this trait move it across tasks: an inbound serves a
/// hundred connections at once, and the scheduler races two of them against each
/// other. Boxing costs one allocation per connection, against a handshake that is
/// milliseconds of work, and buys a trait that stays object-safe without
/// `async-trait` in the dependency list.
///
/// Implementations are held to the rule the whole crate is built on. Dropping the
/// returned future abandons an attempt that has not been reported to anyone; once
/// it has returned `Ok`, the session inside belongs to that one node and nothing
/// above this trait may retry, replay or move it.
pub trait Establish: Send + Sync + 'static {
    /// Opens one tunnel to `destination` on `port`.
    fn establish(&self, destination: Destination, port: u16) -> Establishment;
}

/// One [`Establish::establish`] call in flight.
pub type Establishment = Pin<Box<dyn Future<Output = Result<Established, Error>> + Send>>;

impl Establish for Handoff {
    fn establish(&self, destination: Destination, port: u16) -> Establishment {
        let handoff = self.clone();
        Box::pin(async move { handoff.establish(&destination, port).await })
    }
}

/// What the edge is willing to have live at once.
///
/// Both budgets are handed out as permits rather than counters, so a leak shows up
/// as slots that never come back instead of as a number that drifts. Nothing here
/// blocks: a limit that is full is refused, because a queue in front of a localhost
/// listener is a way for one local process to make everyone else wait.
#[derive(Clone, Debug)]
pub struct Gate {
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
}

impl Gate {
    /// Builds a gate with the given ceilings.
    #[must_use]
    pub fn new(connections: usize, handshakes: usize) -> Self {
        Self {
            connections: Arc::new(Semaphore::new(connections)),
            handshakes: Arc::new(Semaphore::new(handshakes)),
        }
    }

    /// Takes the slot for one local connection, or `None` when the edge is full.
    #[must_use]
    pub fn admit_connection(&self) -> Option<OwnedSemaphorePermit> {
        admit(&self.connections)
    }

    /// Takes the slot for one authentication, or `None` when too many are running.
    #[must_use]
    pub fn admit_handshake(&self) -> Option<OwnedSemaphorePermit> {
        admit(&self.handshakes)
    }

    /// Slots still free for local connections — what `doctor` reports, and what a
    /// test uses to prove a permit is released.
    #[must_use]
    pub fn connections_available(&self) -> usize {
        self.connections.available_permits()
    }

    /// Slots still free for authentication.
    #[must_use]
    pub fn handshakes_available(&self) -> usize {
        self.handshakes.available_permits()
    }
}

impl Default for Gate {
    fn default() -> Self {
        Self::new(MAX_LOCAL_CONNECTIONS, MAX_CONCURRENT_HANDSHAKES)
    }
}

/// One non-blocking semaphore take.
fn admit(semaphore: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(semaphore).try_acquire_owned().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seam has to survive the only thing a listener does with it: put it in
    /// another task.
    #[test]
    fn an_establishment_can_be_moved_across_tasks() {
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<Establishment>();
        assert_send_static::<Handoff>();
    }

    /// What the seam hands back is a live tunnel, and a live tunnel is only useful
    /// if the relay task can own it.
    #[test]
    fn an_established_tunnel_can_be_moved_across_tasks() {
        fn assert_send<T: Send>() {}
        assert_send::<Established>();
    }

    #[test]
    fn a_full_gate_refuses_rather_than_queues() {
        let gate = Gate::new(1, 1);
        let connection = gate.admit_connection().expect("one slot is free");
        assert_eq!(gate.connections_available(), 0);
        assert!(
            gate.admit_connection().is_none(),
            "the second caller is refused rather than parked"
        );

        let handshake = gate.admit_handshake().expect("one slot is free");
        assert!(gate.admit_handshake().is_none());

        drop(handshake);
        assert_eq!(gate.handshakes_available(), 1, "a permit returns on drop");
        drop(connection);
        assert_eq!(gate.connections_available(), 1);
    }

    /// Authentication and carrying are different resources, and an established
    /// download must not hold one that a new connection needs.
    #[test]
    fn a_tunnel_being_carried_costs_no_authentication_capacity() {
        let gate = Gate::default();
        let connection = gate.admit_connection().expect("the edge is open");
        let handshake = gate
            .admit_handshake()
            .expect("authenticating is affordable");
        assert_eq!(gate.handshakes_available(), MAX_CONCURRENT_HANDSHAKES - 1);

        drop(handshake);
        assert_eq!(
            gate.handshakes_available(),
            MAX_CONCURRENT_HANDSHAKES,
            "the tunnel is still up, and its handshake slot came back"
        );
        assert_eq!(gate.connections_available(), MAX_LOCAL_CONNECTIONS - 1);
        drop(connection);
    }

    #[test]
    fn the_default_ceilings_are_the_ones_the_module_documents() {
        let gate = Gate::default();
        assert_eq!(gate.connections_available(), MAX_LOCAL_CONNECTIONS);
        assert_eq!(gate.handshakes_available(), MAX_CONCURRENT_HANDSHAKES);
    }
}
