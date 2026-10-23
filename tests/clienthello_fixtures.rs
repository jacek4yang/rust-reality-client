//! Structural comparison against `ClientHello`s captured from Xray v26.7.28.
//!
//! The fixtures under `tests/fixtures/clienthello/` were produced by running the
//! unmodified Xray 26.7.28 client with each profile against a loopback tee and
//! normalizing away the session ID, random, key material, GREASE values and ECH
//! payload. The source files for those profiles are pinned in
//! `docs/FINGERPRINTS.md`; this test is the independent check that our
//! serializer still emits the same observable shape.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;

use rust_reality_client::protocol::reality::{
    AuthPlaintext, CLIENT_VERSION, ClientKeyAgreement, Fingerprint, HelloRecord, build_client_hello,
};

const FIXTURES: &[&str] = &[
    "hellochrome_120",
    "hellochrome_131",
    "hellochrome_133",
    "hellofirefox_120",
    "hellofirefox_148",
    "hellosafari_26_3",
    "helloios_13",
    "helloios_14",
    "helloedge_85",
    "helloedge_106",
    "hello360_11_0",
    "helloqq_11_1",
];

const GREASE: u16 = 0x0a0a;

fn extension_name(kind: u16) -> String {
    match kind {
        0x0000 => "sni".to_owned(),
        0x0005 => "status".to_owned(),
        0x000a => "groups".to_owned(),
        0x000b => "points".to_owned(),
        0x000d => "sigalgs".to_owned(),
        0x0010 => "alpn".to_owned(),
        0x0012 => "sct".to_owned(),
        0x0015 => "padding".to_owned(),
        0x0017 => "ems".to_owned(),
        0x001b => "compress_cert".to_owned(),
        0x001c => "record_size".to_owned(),
        0x0022 => "delegated".to_owned(),
        0x0023 => "ticket".to_owned(),
        0x002b => "versions".to_owned(),
        0x002d => "psk_modes".to_owned(),
        0x0033 => "key_share".to_owned(),
        0x4469 => "alps_old".to_owned(),
        0x44cd => "alps_new".to_owned(),
        0x7550 => "channel_id".to_owned(),
        0xfe0d => "ech".to_owned(),
        0xff01 => "reneg".to_owned(),
        other if (other & 0x0f0f) == 0x0a0a => "grease".to_owned(),
        other => format!("ext_{other:04x}"),
    }
}

fn grease(value: u16) -> u16 {
    if (value & 0x0f0f) == 0x0a0a {
        GREASE
    } else {
        value
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Default)]
struct Parsed {
    ciphers: Vec<u16>,
    order: Vec<String>,
    groups: Vec<u16>,
    sigalgs: Vec<u16>,
    versions: Vec<u16>,
    alpn: Vec<String>,
    shares: Vec<(u16, usize)>,
    bodies: BTreeMap<String, String>,
}

fn parse_hello(message: &[u8]) -> Parsed {
    assert_eq!(1, message[0], "handshake type");
    let mut pos = 4;
    pos += 2 + 32;
    let session = usize::from(message[pos]);
    pos += 1 + session;
    let suites = usize::from(u16::from_be_bytes([message[pos], message[pos + 1]]));
    pos += 2;
    let mut parsed = Parsed {
        ciphers: message[pos..pos + suites]
            .chunks_exact(2)
            .map(|pair| grease(u16::from_be_bytes([pair[0], pair[1]])))
            .collect(),
        ..Parsed::default()
    };
    pos += suites;
    let compression = usize::from(message[pos]);
    pos += 1 + compression;
    let total = usize::from(u16::from_be_bytes([message[pos], message[pos + 1]]));
    pos += 2;
    let end = pos + total;
    while pos < end {
        let kind = u16::from_be_bytes([message[pos], message[pos + 1]]);
        pos += 2;
        let length = usize::from(u16::from_be_bytes([message[pos], message[pos + 1]]));
        pos += 2;
        let body = &message[pos..pos + length];
        pos += length;
        let name = extension_name(kind);
        parsed.order.push(name.clone());
        match name.as_str() {
            "groups" | "sigalgs" => {
                let count = usize::from(u16::from_be_bytes([body[0], body[1]]));
                let values: Vec<u16> = body[2..2 + count]
                    .chunks_exact(2)
                    .map(|pair| grease(u16::from_be_bytes([pair[0], pair[1]])))
                    .collect();
                if name == "groups" {
                    parsed.groups = values;
                } else {
                    parsed.sigalgs = values;
                }
            }
            "versions" => {
                let count = usize::from(body[0]);
                parsed.versions = body[1..=count]
                    .chunks_exact(2)
                    .map(|pair| grease(u16::from_be_bytes([pair[0], pair[1]])))
                    .collect();
            }
            "alpn" => {
                let count = usize::from(u16::from_be_bytes([body[0], body[1]]));
                let mut offset = 2;
                while offset < 2 + count {
                    let length = usize::from(body[offset]);
                    offset += 1;
                    parsed.alpn.push(
                        String::from_utf8(body[offset..offset + length].to_vec())
                            .expect("ALPN is ASCII"),
                    );
                    offset += length;
                }
            }
            "key_share" => {
                let count = usize::from(u16::from_be_bytes([body[0], body[1]]));
                let mut offset = 2;
                while offset < 2 + count {
                    let group = grease(u16::from_be_bytes([body[offset], body[offset + 1]]));
                    offset += 2;
                    let length = usize::from(u16::from_be_bytes([body[offset], body[offset + 1]]));
                    offset += 2 + length;
                    parsed.shares.push((group, length));
                }
            }
            _ => {}
        }
        if matches!(
            name.as_str(),
            "sni"
                | "status"
                | "points"
                | "reneg"
                | "psk_modes"
                | "compress_cert"
                | "alps_old"
                | "alps_new"
                | "ticket"
                | "sct"
                | "ems"
                | "channel_id"
        ) {
            parsed.bodies.insert(name, hex(body));
        }
    }
    assert_eq!(end, message.len(), "extension length covers the message");
    parsed
}

fn parse_fixture(text: &str) -> (String, Parsed, bool) {
    let mut name = String::new();
    let mut multiset = false;
    let mut parsed = Parsed::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "name" => value.clone_into(&mut name),
            "mode" => multiset = value == "multiset",
            "ciphers" => {
                parsed.ciphers = value
                    .split(',')
                    .map(|value| u16::from_str_radix(value.trim_start_matches("0x"), 16).unwrap())
                    .collect();
            }
            "order" => parsed.order = value.split(',').map(str::to_owned).collect(),
            "groups" | "sigalgs" | "versions" => {
                let values: Vec<u16> = value
                    .split(',')
                    .map(|value| u16::from_str_radix(value.trim_start_matches("0x"), 16).unwrap())
                    .collect();
                match key {
                    "groups" => parsed.groups = values,
                    "sigalgs" => parsed.sigalgs = values,
                    _ => parsed.versions = values,
                }
            }
            "alpn" => parsed.alpn = value.split(',').map(str::to_owned).collect(),
            "shares" => {
                parsed.shares = value
                    .split(',')
                    .map(|share| {
                        let (group, length) = share.split_once(':').expect("share");
                        (
                            u16::from_str_radix(group.trim_start_matches("0x"), 16).unwrap(),
                            length.parse().unwrap(),
                        )
                    })
                    .collect();
            }
            key if key.starts_with("body.") => {
                parsed.bodies.insert(key[5..].to_owned(), value.to_owned());
            }
            _ => {}
        }
    }
    (name, parsed, multiset)
}

fn ours(fingerprint: Fingerprint) -> HelloRecord {
    let profile = fingerprint.resolve([0x5a; 32]);
    let keys = ClientKeyAgreement::generate(profile.needs_hybrid()).expect("keys");
    let auth = AuthPlaintext {
        version: CLIENT_VERSION,
        time: 1_700_000_000,
        short_id: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    build_client_hello("www.example.com", profile, &keys, &[0x11; 32], auth)
        .expect("client hello")
        .0
}

#[test]
fn every_captured_xray_shape_matches_our_serializer() {
    for fixture_name in FIXTURES {
        let path = format!(
            "{}/tests/fixtures/clienthello/{fixture_name}.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
        let (name, captured, multiset) = parse_fixture(&text);
        assert_eq!(*fixture_name, name);
        let fingerprint = Fingerprint::parse(fixture_name)
            .unwrap_or_else(|error| panic!("{fixture_name}: {error}"));
        let record = ours(fingerprint);
        let built = parse_hello(record.message());

        assert_eq!(captured.ciphers, built.ciphers, "{fixture_name}: ciphers");
        assert_eq!(captured.groups, built.groups, "{fixture_name}: groups");
        assert_eq!(captured.sigalgs, built.sigalgs, "{fixture_name}: sigalgs");
        assert_eq!(
            captured.versions, built.versions,
            "{fixture_name}: versions"
        );
        assert_eq!(captured.alpn, built.alpn, "{fixture_name}: ALPN");

        if multiset {
            let mut expected = captured.order.clone();
            let mut actual = built.order.clone();
            assert_eq!(
                "grease",
                expected.first().expect("first extension"),
                "{fixture_name}: anchor"
            );
            assert_eq!(
                "grease",
                expected.last().expect("last extension"),
                "{fixture_name}: anchor"
            );
            // Padding presence depends on the random ECH grease payload length
            // in Chrome 120 and follows the same BoringSSL rule in both
            // implementations; compare the unpadded capability set here.
            expected.retain(|name| name != "grease" && name != "padding");
            actual.retain(|name| name != "grease" && name != "padding");
            expected.sort();
            actual.sort();
            assert_eq!(expected, actual, "{fixture_name}: extension multiset");
        } else {
            assert_eq!(
                captured.order, built.order,
                "{fixture_name}: extension order"
            );
        }

        let mut captured_shares = captured.shares.clone();
        let built_shares = built.shares.clone();
        if fixture_name.starts_with("hellofirefox") {
            let removed = captured_shares
                .iter()
                .position(|(group, length)| *group == 0x0017 && *length == 65)
                .expect("Xray Firefox carries a P-256 share");
            captured_shares.remove(removed);
            assert!(
                !built_shares.iter().any(|(group, _)| *group == 0x0017),
                "{fixture_name}: the deliberate P-256 omission"
            );
        }
        assert_eq!(
            captured_shares, built_shares,
            "{fixture_name}: key-share groups and lengths"
        );

        for (extension, body) in &captured.bodies {
            assert_eq!(
                Some(body),
                built.bodies.get(extension),
                "{fixture_name}: {extension} body"
            );
        }
    }
}
