//! Configuration acceptance: what reads, what is refused, and what a refusal
//! may say.
//!
//! The shape of these tests follows the two reasons validation exists at all —
//! a wrong value is silent in REALITY (it becomes a cover fallback, not an
//! error), and a diagnostic that echoes a credential is a leak. So every
//! rejection here is checked for *path*, for *wording*, and for the absence of
//! the value it refused.

use base64::Engine as _;

use super::grammar::KEY_RULE;
use super::{ConfigError, DEFAULT_HTTP, DEFAULT_SOCKS5, Problem};

/// A public key as the handoff spells it.
fn key(byte: u8) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])
}

const USER: &str = "123e4567-e89b-12d3-a456-426614174000";

fn node_body(port: &str, public_key: &str) -> String {
    format!(
        r#"
[[node]]
address = "entry.example.com"
port = {port}
userId = "{USER}"
[node.reality]
publicKey = "{public_key}"
shortId = "abcd"
serverName = "www.example.com"
"#
    )
}

fn with_listen(nodes: &str) -> String {
    format!("[listen]\nsocks5 = \"{DEFAULT_SOCKS5}\"\nhttp = \"{DEFAULT_HTTP}\"\n{nodes}")
}

fn valid() -> String {
    with_listen(&node_body("443", &key(0)))
}

fn problems(text: &str) -> Vec<Problem> {
    match super::parse(text) {
        Ok(_) => Vec::new(),
        Err(error) => error.problems().to_vec(),
    }
}

fn paths(problems: &[Problem]) -> Vec<&str> {
    problems
        .iter()
        .map(|problem| problem.path.as_str())
        .collect()
}

fn first(text: &str) -> Problem {
    let found = problems(text);
    match found.as_slice() {
        [one] => one.clone(),
        [] => panic!("expected a problem, the configuration was accepted"),
        many => panic!("expected exactly one problem, got {many:?}"),
    }
}

/// The problem reported for one position, whatever else the file also got wrong.
fn problem_at(text: &str, path: &str) -> Problem {
    let found = problems(text);
    found
        .iter()
        .find(|problem| problem.path == path)
        .unwrap_or_else(|| panic!("nothing reported about {path}, got {:?}", paths(&found)))
        .clone()
}

fn only_path(text: &str) -> String {
    let found = problems(text);
    assert_eq!(
        found.len(),
        1,
        "expected one problem, got {:?}",
        paths(&found)
    );
    found[0].path.clone()
}

fn replaced(replacement: &str) -> String {
    valid().replace(&key(0), replacement)
}

#[test]
fn a_valid_configuration_reads_back_what_the_operator_wrote() {
    let config = super::parse(&valid()).expect("valid");
    assert_eq!(config.nodes.len(), 1);
    let node = &config.nodes[0];
    assert_eq!(node.name, "node-1", "an unnamed node is still addressable");
    assert_eq!(node.endpoint(), "entry.example.com:443");
    assert_eq!(node.reality.server_name, "www.example.com");
    assert_eq!(node.reality.public_key, [0_u8; 32]);
    assert_eq!(node.reality.short_id(), &[0xab, 0xcd, 0, 0, 0, 0, 0, 0]);
    assert_eq!(node.reality.short_id_chars(), 4);
    assert_eq!(
        node.user_id(),
        &[
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
            0x40, 0x00
        ]
    );
    assert_eq!(config.listen.socks5.unwrap().port(), 10_808);
    assert_eq!(config.listen.http.unwrap().port(), 10_809);
}

#[test]
fn an_omitted_listen_table_keeps_the_mandated_loopback_pair() {
    let config = super::parse(&node_body("443", &key(0))).expect("valid");
    for address in config.listen.addresses() {
        assert!(
            address.ip().is_loopback(),
            "the default must never be an open relay: {address}"
        );
    }
    assert_eq!(config.listen.addresses().count(), 2);
}

#[test]
fn an_empty_entry_disables_that_inbound_and_nothing_else() {
    let text = valid().replace(&format!("socks5 = \"{DEFAULT_SOCKS5}\""), "socks5 = \"\"");
    let config = super::parse(&text).expect("valid");
    assert_eq!(config.listen.socks5, None);
    assert!(config.listen.http.is_some(), "the other keeps its default");
    assert_eq!(config.listen.addresses().count(), 1);
}

#[test]
fn a_bind_address_outside_loopback_needs_an_explicit_statement() {
    let text = valid().replace(
        &format!("socks5 = \"{DEFAULT_SOCKS5}\""),
        "socks5 = \"0.0.0.0:10808\"",
    );
    let problem = first(&text);
    assert_eq!(problem.path, "listen.socks5");
    assert!(
        problem.message.contains("allowRemote"),
        "the remedy belongs in the message: {}",
        problem.message
    );

    let allowed = text.replace("[listen]\n", "[listen]\nallowRemote = true\n");
    let config = super::parse(&allowed).expect("an explicit opt-in is honoured");
    assert_eq!(config.listen.socks5.unwrap().port(), 10_808);

    // A flag that is not a flag does not opt anything in: the bind it was meant
    // to excuse stays reported, so fixing the typo cannot silently open a relay.
    let not_a_flag = allowed.replace("allowRemote = true", "allowRemote = \"true\"");
    assert_eq!(
        paths(&problems(&not_a_flag)),
        ["listen.allowRemote", "listen.socks5"]
    );
    assert!(
        problem_at(&not_a_flag, "listen.allowRemote")
            .message
            .contains("true or false"),
        "the remedy belongs in the message"
    );
}

#[test]
fn unknown_keys_are_named_and_xray_spelling_is_answered() {
    // Renaming a required key reports both facts: the stray name and the hole
    // it left. What matters is that the stray name carries the answer.
    let problem = problem_at(&valid().replace("publicKey", "pbk"), "node[0].reality.pbk");
    assert!(
        problem.message.contains("publicKey"),
        "a pasted Xray parameter needs its equivalent named: {}",
        problem.message
    );

    let flow = problem_at(
        &valid().replace("serverName", "flow"),
        "node[0].reality.flow",
    );
    assert!(
        flow.message.contains("xtls-rprx-vision"),
        "{}",
        flow.message
    );

    assert_eq!(
        only_path(&format!("policy = \"fast\"\n{}", valid())),
        "policy"
    );
}

#[test]
fn a_malformed_public_key_gets_the_one_message_that_describes_no_shape() {
    for bad in ["", "!!!!", &key(1)[..20], &key(1).repeat(2)] {
        let found = problems(&replaced(bad));
        assert!(!found.is_empty(), "{bad:?} is not a REALITY key");
        let problem = &found[0];
        assert_eq!(problem.path, "node[0].reality.publicKey");
        assert_eq!(problem.message, KEY_RULE);
    }
    // The wording is deliberately the only one, so that a short key and a long
    // one cannot be told apart by anyone reading the log.
    assert!(KEY_RULE.starts_with("must be URL-safe unpadded base64"));
}

#[test]
fn a_user_id_without_dashes_is_refused_rather_than_guessed() {
    let bare = USER.replace('-', "");
    let problem = first(&valid().replace(USER, &bare));
    assert_eq!(problem.path, "node[0].userId");
    assert!(problem.message.contains("36"), "{}", problem.message);
    assert!(
        !problem.message.contains(&bare),
        "the rejected value must not come back"
    );
}

#[test]
fn short_ids_and_server_names_follow_the_nodes_own_grammar() {
    assert_eq!(
        only_path(&valid().replace("abcd", "abc")),
        "node[0].reality.shortId"
    );
    assert_eq!(
        only_path(&valid().replace("abcd", "zz")),
        "node[0].reality.shortId"
    );
    let upper = valid().replace("abcd", "ABCD");
    assert!(super::parse(&upper).is_ok(), "uppercase hex is accepted");
    assert_eq!(
        super::parse(&upper).expect("valid").nodes[0]
            .reality
            .short_id(),
        &[0xab, 0xcd, 0, 0, 0, 0, 0, 0]
    );

    let problem = first(&valid().replace("www.example.com", "203.0.113.10"));
    assert_eq!(problem.path, "node[0].reality.serverName");
    assert!(
        problem.message.contains("cover"),
        "an SNI the node cannot match is a fallback, and the operator should be told so: {}",
        problem.message
    );
    assert_eq!(
        only_path(&valid().replace("www.example.com", "*.example.com")),
        "node[0].reality.serverName"
    );
}

#[test]
fn ports_outside_the_addressable_range_are_refused() {
    for port in ["0", "65536", "-1"] {
        let text = valid().replace("port = 443", &format!("port = {port}"));
        assert_eq!(only_path(&text), "node[0].port", "port {port}");
    }
    let quoted = valid().replace("port = 443", "port = \"443\"");
    assert_eq!(only_path(&quoted), "node[0].port");
    assert!(
        problems(&valid().replace("port = 443", "port = 65535")).is_empty(),
        "the largest port is addressable"
    );
}

#[test]
fn every_problem_in_the_file_is_reported_at_once() {
    let text = r#"
[[node]]
address = "not a host"
port = 0
userId = "nope"
[node.reality]
publicKey = "nope"
shortId = "z"
serverName = "*.example.com"
"#;
    let found = problems(text);
    assert_eq!(
        paths(&found),
        [
            "node[0].address",
            "node[0].port",
            "node[0].userId",
            "node[0].reality.publicKey",
            "node[0].reality.shortId",
            "node[0].reality.serverName",
        ],
        "a partial answer is how an operator keeps hunting"
    );
}

#[test]
fn a_missing_reality_table_is_named_because_that_client_cannot_fall_back() {
    let text = valid().replace("[node.reality]", "[node.other]");
    let found = problems(&text);
    assert_eq!(
        paths(&found),
        ["node[0].other", "node[0].reality"],
        "the missing table and the stray one are two facts"
    );
}

#[test]
fn an_empty_node_list_is_refused_and_a_redundant_one_explained() {
    assert_eq!(only_path("[listen]\n"), "node");

    let one = node_body("443", &key(0));
    let problem = first(&with_listen(&format!("{one}{one}")));
    assert_eq!(problem.path, "node[1].address");
    assert!(
        problem.message.contains("no redundancy"),
        "{}",
        problem.message
    );

    // The same address under a different identity is a legitimate multi-user
    // server, not a copy-paste.
    let other = one.replace("abcd", "beef");
    let config = super::parse(&with_listen(&format!("{one}{other}"))).expect("distinct users");
    assert_eq!(config.nodes.len(), 2);
    assert_eq!(config.nodes[0].user_id(), config.nodes[1].user_id());
    assert_ne!(
        config.nodes[0].reality.short_id(),
        config.nodes[1].reality.short_id(),
        "what makes two entries on one host useful is a different identity"
    );
}

#[test]
fn a_toml_error_names_a_position_but_never_a_value() {
    let text = format!("userId = \"{USER}");
    let error: ConfigError = super::parse(&text).expect_err("unterminated string");
    assert_eq!(error.problems().len(), 1);
    let message = error.to_string();
    assert!(!message.contains(USER), "{message}");
    assert!(message.contains("line 1"), "{message}");
    assert_eq!(error.problems()[0].path, "<file>");
}

#[test]
fn debugging_a_node_shows_what_it_is_and_not_who_it_authenticates() {
    let config = super::parse(&valid()).expect("valid");
    let node = &config.nodes[0];
    let rendered = format!("{node:?}");
    assert!(rendered.contains("entry.example.com:443"), "{rendered}");
    assert!(
        rendered.contains(&key(0)),
        "the public key is public material and identifies the node"
    );
    assert!(!rendered.contains("123e4567"), "a user id must not render");
    assert!(!rendered.contains("abcd"), "a short ID must not render");
    assert!(rendered.contains("REDACTED"), "{rendered}");
    assert!(!format!("{:?}", node.reality).contains("abcd"));
    assert!(!format!("{config:?}").contains(USER));
}
