//! The three properties the module documents, plus the arithmetic that guards them.
//!
//! Every environment here is built from named routes and a named starting family,
//! so no assertion depends on the IPv6 habits of the machine running the test. The
//! exceptions are the two tests that deliberately call the real route observer.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread::sleep;
use std::time::Duration;

use super::{
    AddressFamily, DialPolicy, Environment, FailureEvidence, ROUTE_IPV4, ROUTE_IPV6, Tuning,
    classify_connect_error, initial_primary, millis, saturating_increment,
};

/// An environment whose routes and starting family are stated, not observed.
fn environment(mode: DialPolicy, ipv4: bool, ipv6: bool, primary: AddressFamily) -> Environment {
    Environment::with_routes_and_primary(mode, ipv4, ipv6, primary)
}

/// The production window, which is what most assertions below are about.
fn steady(mode: DialPolicy) -> Tuning {
    Tuning::for_policy(mode)
}

/// The production code path, with a penalty short enough to watch expire.
///
/// Only the penalty differs, so an expiry assertion still walks the same path the
/// thirty-second window does.
fn windowed(mode: DialPolicy, penalty: Duration) -> Tuning {
    Tuning {
        mode,
        hard_failure_penalty: penalty,
        ..Tuning::for_policy(mode)
    }
}

fn short_window(mode: DialPolicy) -> Tuning {
    windowed(mode, Duration::from_millis(50))
}

/// How long to wait to be certain a [`short_window`] penalty has expired.
///
/// Two penalty lengths, because these assertions are about the rule and not about
/// the scheduler's latency: a runner that takes 50 ms between two adjacent
/// statements would otherwise fail a test that is passing on purpose.
fn past_the_window(tuning: &Tuning) -> Duration {
    tuning.hard_failure_penalty * 2
}

/// A dual-stack result in the order a resolver really returns them: families
/// interleaved across records, not neatly grouped.
fn mixed() -> [SocketAddr; 4] {
    [
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443),
        SocketAddr::new(Ipv6Addr::new(2001, 0x0db8, 0, 0, 0, 0, 0, 1).into(), 443),
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 443),
        SocketAddr::new(Ipv6Addr::new(2001, 0x0db8, 0, 0, 0, 0, 0, 2).into(), 443),
    ]
}

fn all_modes() -> [DialPolicy; 5] {
    [
        DialPolicy::Auto,
        DialPolicy::PreferIpv4,
        DialPolicy::PreferIpv6,
        DialPolicy::Ipv4Only,
        DialPolicy::Ipv6Only,
    ]
}

fn no_route() -> io::Error {
    io::Error::new(io::ErrorKind::NetworkUnreachable, "no route to host")
}

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused")
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "attempt budget spent")
}

#[test]
fn the_derived_timings_are_the_ones_the_node_uses() {
    // Pinned because these are not operator choices in this project either: the
    // claim that a client and a node behave alike under the same network only
    // holds while both read the same numbers.
    // v2.0.1 `src/network.rs:44-53`.
    for mode in all_modes() {
        let tuning = Tuning::for_policy(mode);
        assert_eq!(tuning.mode, mode);
        assert_eq!(tuning.fallback_delay, Duration::from_millis(250));
        assert_eq!(tuning.route_refresh, Duration::from_secs(30));
        assert_eq!(tuning.hard_failure_penalty, Duration::from_secs(30));
        assert_eq!(tuning.latency_memory, Duration::from_secs(300));
    }
    assert_eq!(
        Tuning::default(),
        Tuning::for_policy(DialPolicy::default()),
        "the default tuning is the tuning for the default policy"
    );
}

#[test]
fn policy_names_survive_a_round_trip_through_configuration() {
    for mode in all_modes() {
        assert_eq!(DialPolicy::parse(mode.as_str()), Some(mode));
    }
    assert_eq!(DialPolicy::default(), DialPolicy::Auto);
    // The spelling is the node's, so a near-miss must be a validation error
    // rather than a silently different policy.
    for spelling in ["Auto", "ipv4only", "IPv4Only", "prefer-ip", "", "auto "] {
        assert_eq!(DialPolicy::parse(spelling), None, "rejected {spelling:?}");
    }

    assert!(
        DialPolicy::Ipv4Only.allows_ipv4() && !DialPolicy::Ipv4Only.allows_ipv6(),
        "ipv4Only excludes exactly one family"
    );
    assert!(
        DialPolicy::Ipv6Only.allows_ipv6() && !DialPolicy::Ipv6Only.allows_ipv4(),
        "ipv6Only excludes exactly one family"
    );
    for mode in [
        DialPolicy::Auto,
        DialPolicy::PreferIpv4,
        DialPolicy::PreferIpv6,
    ] {
        assert!(
            mode.allows_ipv4() && mode.allows_ipv6(),
            "{mode:?} dials both families"
        );
    }
    assert_eq!(DialPolicy::Auto.prefers_ipv4(), None);
    assert_eq!(DialPolicy::PreferIpv4.prefers_ipv4(), Some(true));
    assert_eq!(DialPolicy::PreferIpv6.prefers_ipv4(), Some(false));
    assert_eq!(DialPolicy::Ipv6Only.prefers_ipv4(), Some(false));
}

#[test]
fn a_route_failure_is_not_a_refusal_and_a_timeout_is_not_evidence() {
    // The distinction that keeps one unreachable host from disabling a family:
    // only errors that say "this stack cannot get there" count against it. These
    // are the kinds the standard library produces for ENETUNREACH, EHOSTUNREACH,
    // ENETDOWN and EADDRNOTAVAIL on Linux and for the matching WSA codes on
    // Windows, measured on both rather than inferred.
    for kind in [
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::NetworkDown,
        io::ErrorKind::AddrNotAvailable,
    ] {
        assert_eq!(
            classify_connect_error(&io::Error::new(kind, "path")),
            FailureEvidence::StrongFamily,
            "{kind:?} indicts the family"
        );
    }
    for kind in [
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionReset,
    ] {
        assert_eq!(
            classify_connect_error(&io::Error::new(kind, "endpoint")),
            FailureEvidence::ReachableEndpoint,
            "{kind:?} proves packets arrived"
        );
    }
    // A spent connect budget is the most common single-connection failure and the
    // weakest possible evidence about a whole address family. `ConnectionAborted`
    // and `Uncategorized` belong here too: the first is a local teardown, and the
    // second is std's catch-all, which is exactly what an error assembled from a
    // custom message becomes.
    for error in [
        timed_out(),
        io::Error::new(io::ErrorKind::NotConnected, "peer"),
        io::Error::new(io::ErrorKind::ConnectionAborted, "torn down locally"),
        io::Error::new(io::ErrorKind::Unsupported, "not this stack's problem"),
        io::Error::other("anything else"),
    ] {
        assert_eq!(
            classify_connect_error(&error),
            FailureEvidence::DestinationOnly,
            "{error:?} indicts nobody"
        );
    }
}

#[test]
fn every_dial_mode_filters_and_orders_mixed_results() {
    for (mode, primary) in [
        (DialPolicy::Auto, AddressFamily::Ipv6),
        (DialPolicy::PreferIpv4, AddressFamily::Ipv4),
        (DialPolicy::PreferIpv6, AddressFamily::Ipv6),
        (DialPolicy::Ipv4Only, AddressFamily::Ipv4),
        (DialPolicy::Ipv6Only, AddressFamily::Ipv6),
    ] {
        let planner = environment(mode, true, true, primary);
        let plan = planner.plan(&mixed(), &steady(mode));
        let allowed = mixed()
            .iter()
            .filter(|address| match mode {
                DialPolicy::Ipv4Only => address.is_ipv4(),
                DialPolicy::Ipv6Only => address.is_ipv6(),
                _ => true,
            })
            .count();
        assert_eq!(plan.len(), allowed, "{mode:?} drops nothing it may dial");
        assert_eq!(
            plan[0].is_ipv4(),
            primary == AddressFamily::Ipv4,
            "{mode:?} starts from {primary:?}"
        );
        if mode == DialPolicy::Ipv4Only {
            assert!(
                plan.iter().all(SocketAddr::is_ipv4),
                "{mode:?} dials no IPv6"
            );
        } else if mode == DialPolicy::Ipv6Only {
            assert!(
                plan.iter().all(SocketAddr::is_ipv6),
                "{mode:?} dials no IPv4"
            );
        } else {
            // The alternate family is one candidate away, never four.
            assert_ne!(plan[0].is_ipv4(), plan[1].is_ipv4(), "{mode:?} interleaves");
        }
    }
}

#[test]
fn the_first_usable_ipv4_is_not_queued_behind_a_fourth_attempt_at_ipv6() {
    // The shape that makes a proxy feel broken: four AAAA records for a
    // black-holed tunnel ahead of one working A record. Exhausting a family
    // before starting the other would spend four rounds of the 250 ms fallback
    // budget, and often four timeouts, on the path already known to be slow.
    let addresses: Vec<SocketAddr> = [
        SocketAddr::new(Ipv6Addr::new(2001, 0x0db8, 0, 0, 0, 0, 0, 1).into(), 443),
        SocketAddr::new(Ipv6Addr::new(2001, 0x0db8, 0, 0, 0, 0, 0, 2).into(), 443),
        SocketAddr::new(Ipv6Addr::new(2001, 0x0db8, 0, 0, 0, 0, 0, 3).into(), 443),
        SocketAddr::new(Ipv6Addr::new(2001, 0x0db8, 0, 0, 0, 0, 0, 4).into(), 443),
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 443),
    ]
    .into();
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv6);
    let plan = planner.plan(&addresses, &steady(DialPolicy::Auto));

    assert_eq!(plan.len(), 5);
    assert!(plan[0].is_ipv6(), "the preference still comes first");
    assert!(plan[1].is_ipv4(), "the working path is one slot away");
    let resolved_position = addresses
        .iter()
        .position(SocketAddr::is_ipv4)
        .expect("the input has an IPv4 candidate");
    assert!(
        resolved_position > 1,
        "the plan moved the IPv4 candidate forward, the resolver did not"
    );
}

#[test]
fn a_duplicate_address_is_dialed_once() {
    let fourth = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443);
    let sixth = SocketAddr::new(Ipv6Addr::new(2001, 0x0db8, 0, 0, 0, 0, 0, 1).into(), 443);
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv4);
    let plan = planner.plan(&[fourth, sixth, fourth, fourth], &steady(DialPolicy::Auto));
    assert_eq!(plan, [fourth, sixth], "one attempt per address");
}

#[test]
fn a_result_with_one_family_left_is_planned_without_preference() {
    let fourth = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443);
    // The starting family is IPv6 and nothing IPv6 was resolved: the plan must
    // still be dialable, because refusing to try the only address that exists is
    // how a preference becomes an outage.
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv6);
    let tuning = steady(DialPolicy::Auto);
    assert_eq!(planner.plan(&[fourth], &tuning), [fourth]);
    assert!(
        planner.plan(&[], &tuning).is_empty(),
        "nothing resolved is nothing to dial"
    );
}

#[test]
fn startup_decision_uses_capability_then_stable_system_preference() {
    // v2.0.1 `src/network.rs:639-660`.
    assert_eq!(
        initial_primary(DialPolicy::Auto, ROUTE_IPV4),
        AddressFamily::Ipv4
    );
    assert_eq!(
        initial_primary(DialPolicy::Auto, ROUTE_IPV6),
        AddressFamily::Ipv6
    );
    // An explicit preference defers only to a family that has no route at all:
    // preference wins whenever it is satisfiable.
    assert_eq!(
        initial_primary(DialPolicy::PreferIpv6, ROUTE_IPV4),
        AddressFamily::Ipv4
    );
    assert_eq!(
        initial_primary(DialPolicy::PreferIpv4, ROUTE_IPV6),
        AddressFamily::Ipv6
    );
    assert_eq!(
        initial_primary(DialPolicy::PreferIpv6, ROUTE_IPV4 | ROUTE_IPV6),
        AddressFamily::Ipv6
    );
    // An operator who excluded a family is not overruled by the route table.
    assert_eq!(
        initial_primary(DialPolicy::Ipv4Only, ROUTE_IPV6),
        AddressFamily::Ipv4
    );
    assert_eq!(
        initial_primary(DialPolicy::Ipv6Only, ROUTE_IPV4),
        AddressFamily::Ipv6
    );
    // With both routes up, `Auto` inherits the platform's own ordering rather
    // than inventing one, so the assertion is that it matches, not which.
    assert_eq!(
        initial_primary(DialPolicy::Auto, ROUTE_IPV4 | ROUTE_IPV6),
        super::system_preferred_family()
    );
}

#[test]
fn one_route_failure_is_not_enough_to_demote_a_family() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv6);
    let tuning = steady(DialPolicy::Auto);
    let broken = no_route();

    planner.record_connect_error(AddressFamily::Ipv6, &broken, &tuning);
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv6,
        "one blip during a handover is not an outage"
    );
    assert!(!planner.is_penalized(AddressFamily::Ipv6, &tuning));

    planner.record_connect_error(AddressFamily::Ipv6, &broken, &tuning);
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv4,
        "two consecutive ones are"
    );
    assert!(planner.is_penalized(AddressFamily::Ipv6, &tuning));
    assert!(!planner.is_penalized(AddressFamily::Ipv4, &tuning));
}

#[test]
fn a_penalised_family_is_released_when_its_window_expires() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv6);
    let tuning = short_window(DialPolicy::Auto);
    for _ in 0..2 {
        planner.record_connect_error(AddressFamily::Ipv6, &no_route(), &tuning);
    }
    assert!(planner.is_penalized(AddressFamily::Ipv6, &tuning));
    sleep(past_the_window(&tuning));
    assert!(
        !planner.is_penalized(AddressFamily::Ipv6, &tuning),
        "a penalty is a delay, not a verdict"
    );
}

#[test]
fn a_refusal_clears_the_route_strikes() {
    // A family that delivers a rejection is a family that works; counting it
    // toward a route outage would demote the good stack because a peer is down.
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv6);
    let tuning = steady(DialPolicy::Auto);

    planner.record_connect_error(AddressFamily::Ipv6, &no_route(), &tuning);
    planner.record_connect_error(AddressFamily::Ipv6, &refused(), &tuning);
    planner.record_connect_error(AddressFamily::Ipv6, &no_route(), &tuning);
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv6,
        "the refusal reset the count"
    );
    planner.record_connect_error(AddressFamily::Ipv6, &no_route(), &tuning);
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv4,
        "two uninterrupted failures still demote"
    );
}

#[test]
fn a_destination_failure_indicts_nobody() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv6);
    let tuning = steady(DialPolicy::Auto);
    let timeout = timed_out();
    for _ in 0..5 {
        planner.record_connect_error(AddressFamily::Ipv6, &timeout, &tuning);
    }
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv6,
        "five timeouts on one destination are not a family outage"
    );
    assert!(!planner.is_penalized(AddressFamily::Ipv6, &tuning));

    // The same must hold for a cancelled hedge loser, which is why the dial layer
    // never calls this function for one: a candidate that was stopped is not a
    // candidate that failed, and treating it as the former would make every
    // successful raced connection an accusation against the other family.
    planner.record_connect_error(AddressFamily::Ipv4, &refused(), &tuning);
    assert!(!planner.is_penalized(AddressFamily::Ipv4, &tuning));
    assert_eq!(planner.primary(), AddressFamily::Ipv6);
}

#[test]
fn a_policy_that_excludes_a_family_penalises_it_forever() {
    let planner = environment(DialPolicy::Ipv4Only, true, true, AddressFamily::Ipv4);
    let tuning = short_window(DialPolicy::Ipv4Only);
    assert!(
        planner.is_penalized(AddressFamily::Ipv6, &tuning),
        "the exclusion is expressed as a penalty so no caller has to re-read it"
    );
    // Neither a success elsewhere nor the passage of time lifts it.
    planner.record_success(AddressFamily::Ipv4, Duration::from_millis(5), &tuning);
    sleep(past_the_window(&tuning));
    assert!(planner.is_penalized(AddressFamily::Ipv6, &tuning));
    assert!(!planner.is_penalized(AddressFamily::Ipv4, &tuning));
    assert!(
        !planner
            .plan(&mixed(), &tuning)
            .iter()
            .any(SocketAddr::is_ipv6)
    );
}

#[test]
fn losing_the_primary_route_switches_family_immediately() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv6);
    planner.update_routes(ROUTE_IPV4);
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv4,
        "no two strikes spent dialing a family with no route"
    );
    planner.update_routes(ROUTE_IPV4 | ROUTE_IPV6);
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv4,
        "a route reappearing is not on its own a reason to move back"
    );
}

#[test]
fn successful_recovery_restores_configured_preference_with_hysteresis() {
    let planner = environment(DialPolicy::PreferIpv6, true, true, AddressFamily::Ipv6);
    let tuning = steady(DialPolicy::PreferIpv6);
    planner.update_routes(ROUTE_IPV4);
    assert_eq!(planner.primary(), AddressFamily::Ipv4);
    planner.update_routes(ROUTE_IPV4 | ROUTE_IPV6);

    planner.record_success(AddressFamily::Ipv6, Duration::from_millis(5), &tuning);
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv4,
        "one success is not a recovery"
    );
    planner.record_success(AddressFamily::Ipv6, Duration::from_millis(5), &tuning);
    assert_eq!(planner.primary(), AddressFamily::Ipv6, "the second one is");
    assert!(
        planner.plan(&mixed(), &tuning)[0].is_ipv6(),
        "and the very next plan agrees"
    );
}

#[test]
fn a_demoted_family_gets_one_probe_per_window_however_many_dials_are_open() {
    let planner = environment(DialPolicy::PreferIpv6, true, true, AddressFamily::Ipv6);
    let tuning = short_window(DialPolicy::PreferIpv6);
    for _ in 0..2 {
        planner.record_connect_error(AddressFamily::Ipv6, &no_route(), &tuning);
    }
    assert_eq!(planner.primary(), AddressFamily::Ipv4);

    // While the penalty is live the family is not tried at all, so a dial cannot
    // spend its connect budget on a path already known to be bad.
    assert!(planner.is_penalized(AddressFamily::Ipv6, &tuning));
    assert!(planner.plan(&mixed(), &tuning)[0].is_ipv4());

    sleep(past_the_window(&tuning));
    assert!(
        planner.claim_recovery_probe(AddressFamily::Ipv6, &tuning),
        "one dial tests the recovered path"
    );
    assert!(
        !planner.claim_recovery_probe(AddressFamily::Ipv6, &tuning),
        "and only that one"
    );
    assert_eq!(
        planner.preferred_family(&tuning),
        AddressFamily::Ipv4,
        "a lost claim falls back to the family that has been working"
    );
}

#[test]
fn a_probe_that_works_is_confirmed_without_waiting_another_window() {
    let planner = environment(DialPolicy::PreferIpv6, true, true, AddressFamily::Ipv6);
    let tuning = short_window(DialPolicy::PreferIpv6);
    for _ in 0..2 {
        planner.record_connect_error(AddressFamily::Ipv6, &no_route(), &tuning);
    }
    sleep(past_the_window(&tuning));

    assert!(planner.claim_recovery_probe(AddressFamily::Ipv6, &tuning));
    planner.record_success(AddressFamily::Ipv6, Duration::from_millis(4), &tuning);
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv4,
        "one success is evidence, not a verdict"
    );
    assert!(
        planner.claim_recovery_probe(AddressFamily::Ipv6, &tuning),
        "the confirmation is due now, not one window later"
    );
    planner.record_success(AddressFamily::Ipv6, Duration::from_millis(4), &tuning);
    assert_eq!(planner.primary(), AddressFamily::Ipv6);
}

#[test]
fn the_probe_slot_never_bypasses_a_family_that_is_not_preferred_or_not_routable() {
    // `Auto` on a host that started on IPv4 has no reason to keep testing IPv6: it
    // wanted neither family in particular, so it stays where it is working.
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv4);
    let tuning = short_window(DialPolicy::Auto);
    for _ in 0..2 {
        planner.record_connect_error(AddressFamily::Ipv6, &no_route(), &tuning);
    }
    assert_eq!(planner.primary(), AddressFamily::Ipv4);
    sleep(past_the_window(&tuning));
    assert!(!planner.claim_recovery_probe(AddressFamily::Ipv6, &tuning));

    // And a family with no route is never probed, however due the claim looks.
    let stranded = environment(DialPolicy::PreferIpv6, true, false, AddressFamily::Ipv4);
    let stranded_tuning = short_window(DialPolicy::PreferIpv6);
    assert!(!stranded.claim_recovery_probe(AddressFamily::Ipv6, &stranded_tuning));
}

#[test]
fn a_slower_family_loses_primary_status_only_after_repeated_alternate_wins() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv6);
    for _ in 0..2 {
        planner.record_alternate_success(AddressFamily::Ipv4, AddressFamily::Ipv6);
        assert_eq!(
            planner.primary(),
            AddressFamily::Ipv6,
            "twice is noise on a healthy dual-stack host"
        );
    }
    planner.record_alternate_success(AddressFamily::Ipv4, AddressFamily::Ipv6);
    assert_eq!(planner.primary(), AddressFamily::Ipv4, "three is a pattern");

    // A loss for a family that is not primary is not a pattern about anything, and
    // winning against oneself proves nothing at all.
    planner.record_alternate_success(AddressFamily::Ipv6, AddressFamily::Ipv4);
    assert_eq!(planner.primary(), AddressFamily::Ipv4);
    planner.record_alternate_success(AddressFamily::Ipv4, AddressFamily::Ipv4);
    assert_eq!(planner.primary(), AddressFamily::Ipv4);
}

#[test]
fn one_fast_connection_does_not_erase_a_pattern() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv4);
    let tuning = steady(DialPolicy::Auto);
    assert_eq!(
        planner.recent_latency(AddressFamily::Ipv4, &tuning),
        None,
        "no samples, no opinion"
    );

    planner.record_success(AddressFamily::Ipv4, Duration::from_millis(80), &tuning);
    assert_eq!(
        planner.recent_latency(AddressFamily::Ipv4, &tuning),
        Some(Duration::from_millis(80)),
        "the first sample stands alone"
    );
    planner.record_success(AddressFamily::Ipv4, Duration::from_millis(8), &tuning);
    // Seven parts history to one part sample: (80 ms * 7 + 8 ms) / 8.
    assert_eq!(
        planner.recent_latency(AddressFamily::Ipv4, &tuning),
        Some(Duration::from_millis(71)),
        "a fast connection damps toward the sample, it does not become it"
    );
    assert_eq!(
        planner.recent_latency(AddressFamily::Ipv6, &tuning),
        None,
        "the other family remembers nothing about this one"
    );
}

#[test]
fn a_latency_memory_expires_because_five_minutes_ago_is_not_this_network() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv4);
    let tuning = Tuning {
        mode: DialPolicy::Auto,
        latency_memory: Duration::from_millis(100),
        ..Tuning::for_policy(DialPolicy::Auto)
    };
    planner.record_success(AddressFamily::Ipv4, Duration::from_millis(30), &tuning);
    assert!(
        planner
            .recent_latency(AddressFamily::Ipv4, &tuning)
            .is_some()
    );
    sleep(tuning.latency_memory * 2);
    assert_eq!(
        planner.recent_latency(AddressFamily::Ipv4, &tuning),
        None,
        "a sample this old describes a different network"
    );
    // An aged-out sample is replaced rather than averaged with, which is what keeps
    // a recovered path from looking slow until restart.
    planner.record_success(AddressFamily::Ipv4, Duration::from_millis(5), &tuning);
    assert_eq!(
        planner.recent_latency(AddressFamily::Ipv4, &tuning),
        Some(Duration::from_millis(5))
    );
}

#[test]
fn a_success_clears_every_strike_a_family_is_holding() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv6);
    let tuning = steady(DialPolicy::Auto);
    for _ in 0..3 {
        planner.record_alternate_success(AddressFamily::Ipv4, AddressFamily::Ipv6);
    }
    assert_eq!(planner.primary(), AddressFamily::Ipv4);
    planner.record_connect_error(AddressFamily::Ipv6, &no_route(), &tuning);
    planner.record_success(AddressFamily::Ipv6, Duration::from_millis(10), &tuning);

    // A completed connection is the strongest evidence available, and it cancels
    // both the hard and the weak counters, so the next failure has to start the
    // case over from one strike rather than resume a held grudge.
    planner.record_connect_error(AddressFamily::Ipv6, &no_route(), &tuning);
    assert!(!planner.is_penalized(AddressFamily::Ipv6, &tuning));
    assert_eq!(
        planner.primary(),
        AddressFamily::Ipv4,
        "a success on the demoted family does not undo a decision it lost on"
    );
}

#[test]
fn the_state_is_shared_rather_than_copied() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv4);
    let twin = planner.clone();
    let tuning = steady(DialPolicy::Auto);
    for _ in 0..2 {
        planner.record_connect_error(AddressFamily::Ipv4, &no_route(), &tuning);
    }
    assert_eq!(
        twin.primary(),
        AddressFamily::Ipv6,
        "the next connection starts from what this one learned"
    );
    assert!(twin.is_penalized(AddressFamily::Ipv4, &tuning));
}

#[test]
fn only_one_dial_in_a_window_re_observes_the_routes() {
    let planner = environment(DialPolicy::Auto, true, true, AddressFamily::Ipv4);
    let tuning = steady(DialPolicy::Auto);
    planner.refresh_routes(&tuning);
    let observed = planner.inner.last_route_refresh.load(Ordering::Acquire);
    assert_ne!(observed, 0, "the first dial does observe");
    planner.refresh_routes(&tuning);
    assert_eq!(
        planner.inner.last_route_refresh.load(Ordering::Acquire),
        observed,
        "a second dial in the same window does not"
    );

    // An expired window is how a caller says "look again", and the gate honours it.
    // The pause only has to outlast one millisecond, since that is the resolution
    // these stamps are kept at.
    sleep(Duration::from_millis(5));
    let now = Tuning {
        mode: DialPolicy::Auto,
        route_refresh: Duration::ZERO,
        ..Tuning::for_policy(DialPolicy::Auto)
    };
    planner.refresh_routes(&now);
    assert_ne!(
        planner.inner.last_route_refresh.load(Ordering::Acquire),
        observed,
        "one dial gets through once the window has passed"
    );
}

#[test]
fn the_real_route_observer_starts_from_a_family_it_saw() {
    // The one test here that touches the host. It asserts the property the
    // production path needs — a stated preference is never a route to nowhere —
    // without asserting which family any particular machine has.
    for mode in [
        DialPolicy::Auto,
        DialPolicy::PreferIpv4,
        DialPolicy::PreferIpv6,
    ] {
        let planner = Environment::detect(mode);
        let any_route = planner.route_available(AddressFamily::Ipv4)
            || planner.route_available(AddressFamily::Ipv6);
        if any_route {
            assert!(
                planner.route_available(planner.primary()),
                "{mode:?} chose {} without a route",
                planner.primary().as_str()
            );
        }
    }
    assert_eq!(
        Environment::detect(DialPolicy::Ipv6Only).primary(),
        AddressFamily::Ipv6,
        "an explicit policy is honoured even against the observation"
    );
    assert_eq!(
        Environment::detect(DialPolicy::Ipv4Only).primary(),
        AddressFamily::Ipv4
    );
}

#[test]
fn counters_saturate_and_durations_are_read_as_milliseconds() {
    let counter = AtomicU8::new(0);
    let mut expected = 0u8;
    for _ in 0..300 {
        expected = expected.saturating_add(1);
        assert_eq!(saturating_increment(&counter), expected);
    }
    assert_eq!(expected, u8::MAX);

    assert_eq!(millis(Duration::from_secs(1)), 1_000);
    assert_eq!(millis(Duration::from_millis(250)), 250);
    assert_eq!(millis(Duration::ZERO), 0);
    // A budget too large to express is treated as "never", because the
    // alternative — wrapping to a small number — would expire a penalty
    // immediately and look like a healthy network.
    assert_eq!(millis(Duration::MAX), u64::MAX);
}
