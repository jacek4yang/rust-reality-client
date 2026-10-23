use super::*;
use crate::protocol::reality::auth::{AuthKey, AuthPlaintext, CLIENT_VERSION};
use crate::protocol::reality::hello::{ClientKeyAgreement, build_client_hello};
use crate::protocol::reality::{HelloRecord, Reader, SESSION_ID_LEN};

const NAME: &str = "www.example.com";
const SERVER_KEY: [u8; 32] = [0x11; 32];

fn plaintext() -> AuthPlaintext {
    AuthPlaintext {
        version: CLIENT_VERSION,
        time: 1_700_000_000,
        short_id: [1, 2, 3, 4, 5, 6, 7, 8],
    }
}

fn build(
    fingerprint: Fingerprint,
    seed: u8,
) -> (&'static Profile, HelloRecord, ClientKeyAgreement, AuthKey) {
    let profile = fingerprint.resolve([seed; 32]);
    let keys = ClientKeyAgreement::generate(profile.needs_hybrid()).expect("keys");
    let (record, auth_key) =
        build_client_hello(NAME, profile, &keys, &SERVER_KEY, plaintext()).expect("hello");
    (profile, record, keys, auth_key)
}

fn extension_kinds(message: &[u8]) -> Vec<u16> {
    parse_extensions(message)
        .into_iter()
        .map(|(kind, _)| kind)
        .collect()
}

fn parse_extensions(message: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut reader = Reader::new(message);
    assert_eq!(Some(1), reader.read_u8());
    let declared = reader.read_u24().expect("length");
    assert_eq!(declared, reader.remaining());
    assert!(reader.skip(2 + 32).is_some());
    let session = usize::from(reader.read_u8().expect("session length"));
    assert!(reader.skip(session).is_some());
    let suites = usize::from(reader.read_u16().expect("suites length"));
    assert!(reader.skip(suites).is_some());
    let compression = usize::from(reader.read_u8().expect("compression length"));
    assert!(reader.skip(compression).is_some());
    let total = usize::from(reader.read_u16().expect("extensions length"));
    let mut window = Reader::new(reader.read(total).expect("extensions"));
    let mut found = Vec::new();
    while !window.is_empty() {
        let kind = window.read_u16().expect("extension kind");
        let length = usize::from(window.read_u16().expect("extension length"));
        found.push((kind, window.read(length).expect("extension body").to_vec()));
    }
    found
}

fn key_share_groups(message: &[u8]) -> Vec<u16> {
    let body = parse_extensions(message)
        .into_iter()
        .find(|(kind, _)| *kind == 0x0033)
        .expect("key_share")
        .1;
    let mut reader = Reader::new(&body);
    let total = usize::from(reader.read_u16().expect("share list"));
    let mut window = Reader::new(reader.read(total).expect("shares"));
    let mut groups = Vec::new();
    while !window.is_empty() {
        groups.push(window.read_u16().expect("group"));
        let length = usize::from(window.read_u16().expect("share length"));
        assert!(window.skip(length).is_some());
    }
    groups
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a
}

const CONCRETE: [Fingerprint; 12] = [
    Fingerprint::Chrome,
    Fingerprint::Firefox,
    Fingerprint::Safari,
    Fingerprint::Ios,
    Fingerprint::Edge,
    Fingerprint::Qq,
    Fingerprint::Chrome120,
    Fingerprint::Chrome131,
    Fingerprint::Firefox120,
    Fingerprint::Ios13,
    Fingerprint::Edge106,
    Fingerprint::Browser360,
];

#[test]
fn every_concrete_profile_is_reality_capable() {
    for fingerprint in CONCRETE {
        let (profile, record, _, auth_key) = build(fingerprint, 21);
        assert!(profile.ciphers.contains(&0x1301), "{fingerprint}: AES128");
        assert!(profile.ciphers.contains(&0x1302), "{fingerprint}: AES256");
        assert!(profile.ciphers.contains(&0x1303), "{fingerprint}: ChaCha");
        assert!(
            profile.shares.contains(&ShareGroup::X25519),
            "{fingerprint}"
        );
        assert!(record.key_share_group_offered(0x001d), "{fingerprint}");
        assert!(!record.alpn().is_empty(), "{fingerprint}: ALPN");
        assert!(
            record.message().len() <= 16_384,
            "{fingerprint}: record bound"
        );
        let kinds = extension_kinds(record.message());
        let mut unique = kinds.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            kinds.len(),
            unique.len(),
            "{fingerprint}: duplicate extension"
        );
        if profile.ciphers.contains(&GREASE_PLACEHOLDER) {
            assert!(
                kinds.iter().any(|kind| is_grease(*kind)),
                "{fingerprint}: GREASE"
            );
        }

        let mut aad = record.message().to_vec();
        aad[crate::protocol::reality::SESSION_ID_OFFSET
            ..crate::protocol::reality::SESSION_ID_OFFSET + SESSION_ID_LEN]
            .fill(0);
        let opened = auth_key
            .open_session_id(record.random(), &aad, record.session_id())
            .expect("authenticator opens");
        assert_eq!(plaintext(), opened, "{fingerprint}");
    }
}

#[test]
fn hybrid_profiles_offer_the_hybrid_share_and_others_do_not() {
    for fingerprint in CONCRETE {
        let (profile, record, _, _) = build(fingerprint, 22);
        assert_eq!(
            profile.needs_hybrid(),
            record.key_share_group_offered(0x11ec),
            "{fingerprint}"
        );
    }
}

#[test]
fn firefox_omits_the_p256_share_but_keeps_it_in_groups() {
    let profile = Fingerprint::Firefox148.resolve([23; 32]);
    let keys = ClientKeyAgreement::generate(profile.needs_hybrid()).expect("keys");
    let (record, _) =
        build_client_hello(NAME, profile, &keys, &SERVER_KEY, plaintext()).expect("hello");
    let groups = key_share_groups(record.message());
    assert!(!groups.contains(&0x0017), "P-256 is not a share");
    assert!(groups.contains(&0x001d));
    assert!(groups.contains(&0x11ec));
    let extension = parse_extensions(record.message())
        .into_iter()
        .find(|(kind, _)| *kind == 0x000a)
        .expect("supported_groups")
        .1;
    assert!(
        extension.windows(2).any(|pair| pair == [0x00, 0x17]),
        "P-256 stays in supported_groups"
    );
}

#[test]
fn chrome_shuffles_but_keeps_grease_positions_and_capabilities() {
    let profile = Fingerprint::Chrome133.resolve([24; 32]);
    let mut sequences = Vec::new();
    for _ in 0..32_u8 {
        let keys = ClientKeyAgreement::generate(profile.needs_hybrid()).expect("keys");
        let (record, _) =
            build_client_hello(NAME, profile, &keys, &SERVER_KEY, plaintext()).expect("hello");
        let kinds = extension_kinds(record.message());
        assert!(is_grease(kinds[0]), "first GREASE stays first");
        assert!(
            is_grease(*kinds.last().expect("extensions")),
            "last GREASE stays last"
        );
        sequences.push(
            kinds
                .into_iter()
                .filter(|kind| !is_grease(*kind))
                .collect::<Vec<_>>(),
        );
    }
    let first = &sequences[0];
    assert!(
        sequences.iter().any(|sequence| sequence != first),
        "the non-GREASE order must vary between handshakes"
    );
}

#[test]
fn boring_padding_lands_on_the_boringssl_target() {
    let profile = Fingerprint::Ios13.resolve([25; 32]);
    let keys = ClientKeyAgreement::generate(profile.needs_hybrid()).expect("keys");
    let (record, _) =
        build_client_hello(NAME, profile, &keys, &SERVER_KEY, plaintext()).expect("hello");
    if extension_kinds(record.message()).contains(&0x0015) {
        assert_eq!(0x200, record.message().len());
    }
}

#[test]
fn grease_values_have_the_required_shape_and_are_distinct() {
    for fingerprint in CONCRETE {
        let profile = fingerprint.resolve([26; 32]);
        for seed in 0..8_u8 {
            let plan = profile.plan_with_seed([seed; 32]);
            assert!(is_grease(plan.grease_cipher));
            assert!(is_grease(plan.grease_group));
            assert!(is_grease(plan.grease_extension1));
            assert!(is_grease(plan.grease_extension2));
            assert!(is_grease(plan.grease_version));
            assert_ne!(plan.grease_extension1, plan.grease_extension2);
        }
    }
}

#[test]
fn randomized_is_stable_per_seed_and_always_reality_capable() {
    for seed in 0..1_000_u32 {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&seed.to_le_bytes());
        let profile = randomized::build(bytes, seed % 2 == 0);
        assert!(profile.ciphers.contains(&0x1301));
        assert!(profile.ciphers.contains(&0x1302));
        assert!(profile.ciphers.contains(&0x1303));
        assert!(profile.shares.contains(&ShareGroup::X25519));
        assert!(
            !profile
                .shares
                .iter()
                .any(|share| matches!(share, ShareGroup::Grease))
        );
        assert!(
            profile
                .extensions
                .iter()
                .any(|ext| matches!(ext, Ext::KeyShare))
        );
    }
    let first = randomized::build([7; 32], true);
    let second = randomized::build([7; 32], true);
    assert_eq!(first.ciphers, second.ciphers);
    assert_eq!(
        format!("{:?}", first.extensions),
        format!("{:?}", second.extensions)
    );
}

#[test]
fn names_map_to_the_intended_shapes_and_unusable_names_are_refused() {
    assert_eq!(Ok(Fingerprint::Chrome133), Fingerprint::parse("chrome"));
    assert_eq!(
        Ok(Fingerprint::Chrome133),
        Fingerprint::parse("hellochrome_auto")
    );
    assert_eq!(
        Ok(Fingerprint::Chrome133),
        Fingerprint::parse("hellochrome_133")
    );
    assert_eq!(Ok(Fingerprint::Firefox148), Fingerprint::parse("firefox"));
    assert_eq!(Ok(Fingerprint::Ios14), Fingerprint::parse("helloios_auto"));
    assert_eq!(
        Ok(Fingerprint::Browser360),
        Fingerprint::parse("hello360_11_0")
    );
    assert_eq!(
        Ok(Fingerprint::RandomizedNoAlpn),
        Fingerprint::parse("randomizednoalpn")
    );
    for name in [
        "android",
        "helloandroid_11_okhttp",
        "360",
        "hello360_auto",
        "hello360_7_5",
        "unsafe",
        "hellochrome_58",
        "hellofirefox_105",
        "",
        "Edge",
    ] {
        assert!(Fingerprint::parse(name).is_err(), "{name}");
    }
    assert_eq!(Fingerprint::Chrome.name(), "chrome");
    assert_eq!(Fingerprint::Random.name(), "random");
}

#[test]
fn every_profile_reports_a_bounded_record_and_a_32_byte_session_id() {
    for fingerprint in CONCRETE {
        let (_, record, _, _) = build(fingerprint, 27);
        assert_eq!(SESSION_ID_LEN, record.session_id().len());
        assert!(record.record().len() <= 16_384 + 5, "{fingerprint}");
    }
}
