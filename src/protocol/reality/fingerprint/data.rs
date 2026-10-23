//! The concrete profile tables.
//!
//! Each list is a direct transliteration of one `case` in uTLS
//! `u_parrots.go` at commit `aa6edf4...`; extension constructors become
//! [`Ext`] values and key-share entries become [`ShareGroup`]. The only
//! intentional difference is documented in `mod.rs`: Firefox's P-256 share is
//! not emitted.

use super::{ConcreteTable, EchKind, Ext, Fingerprint, GREASE_PLACEHOLDER, Profile, ShareGroup};

const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

// TLS cipher suite IDs from uTLS `cipher_suites.go`.
const CHROME_CIPHERS: &[u16] = &[
    GREASE_PLACEHOLDER,
    0x1301,
    0x1302,
    0x1303,
    0xc02b,
    0xc02f,
    0xc02c,
    0xc030,
    0xcca9,
    0xcca8,
    0xc013,
    0xc014,
    0x009c,
    0x009d,
    0x002f,
    0x0035,
];
const FIREFOX_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const SAFARI_CIPHERS: &[u16] = &[
    GREASE_PLACEHOLDER,
    0x1302,
    0x1303,
    0x1301,
    0xc02c,
    0xc02b,
    0xcca9,
    0xc030,
    0xc02f,
    0xcca8,
    0xc00a,
    0xc009,
    0xc014,
    0xc013,
    0x009d,
    0x009c,
    0x0035,
    0x002f,
    0xc008,
    0xc012,
    0x000a,
];
const IOS13_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xcca9, 0xc030, 0xc02f,
    0xc028, 0xc027, 0xc014, 0xc013, 0xcca8, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0xc008,
    0xc012, 0x000a,
];
const IOS14_CIPHERS: &[u16] = &[
    GREASE_PLACEHOLDER,
    0x1301,
    0x1302,
    0x1303,
    0xc02c,
    0xc02b,
    0xcca9,
    0xc030,
    0xc02f,
    0xcca8,
    0xc024,
    0xc023,
    0xc00a,
    0xc009,
    0xc028,
    0xc027,
    0xc014,
    0xc013,
    0x009d,
    0x009c,
    0x003d,
    0x003c,
    0x0035,
    0x002f,
    0xc008,
    0xc012,
    0x000a,
];
const EDGE_CIPHERS: &[u16] = CHROME_CIPHERS;
const BROWSER360_CIPHERS: &[u16] = &[
    GREASE_PLACEHOLDER,
    0x1301,
    0x1302,
    0x1303,
    0xc02b,
    0xc02f,
    0xc02c,
    0xc030,
    0xcca9,
    0xcca8,
    0xc013,
    0xc014,
    0x009c,
    0x009d,
    0x002f,
    0x0035,
    0x000a,
];

const SA_CHROME: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const SA_FIREFOX: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const SA_IOS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const SA_SAFARI: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const SA_360: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const DELEGATED: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];

/// The profiles Xray v26.7.28 offers for `random`.
pub(crate) const MODERN: [Fingerprint; 11] = [
    Fingerprint::Chrome120,
    Fingerprint::Chrome131,
    Fingerprint::Chrome133,
    Fingerprint::Firefox120,
    Fingerprint::Firefox148,
    Fingerprint::Ios13,
    Fingerprint::Ios14,
    Fingerprint::Edge106,
    Fingerprint::Safari263,
    Fingerprint::Browser360,
    Fingerprint::Qq111,
];

pub(super) fn concrete() -> ConcreteTable {
    ConcreteTable {
        chrome120: chrome120(),
        chrome131: chrome131(),
        chrome133: chrome133(),
        firefox120: firefox120(),
        firefox148: firefox148(),
        safari263: safari263(),
        ios13: ios13(),
        ios14: ios14(),
        edge85: edge85(),
        edge106: edge106(),
        browser360: browser360(),
        qq111: qq111(),
    }
}

fn make(
    id: Fingerprint,
    ciphers: &[u16],
    extensions: Vec<Ext>,
    shares: &[ShareGroup],
    shuffle: bool,
    padding: bool,
) -> Profile {
    Profile {
        id,
        ciphers: ciphers.to_vec(),
        compression: vec![0],
        extensions,
        alpn: ALPN.iter().map(|protocol| protocol.to_vec()).collect(),
        shares: shares.to_vec(),
        shuffle,
        padding,
    }
}

fn chrome120() -> Profile {
    make(
        Fingerprint::Chrome120,
        CHROME_CIPHERS,
        vec![
            Ext::Grease,
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![GREASE_PLACEHOLDER, 0x001d, 0x0017, 0x0018]),
            Ext::Points(vec![0]),
            Ext::Ticket,
            Ext::Alpn,
            Ext::Status,
            Ext::Sigalgs(SA_CHROME.to_vec()),
            Ext::Sct,
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303]),
            Ext::CompressCert(vec![2]),
            Ext::Alps(super::EXT_ALPS_OLD),
            Ext::Ech(EchKind::Chrome),
            Ext::Grease,
            Ext::Padding,
        ],
        &[ShareGroup::Grease, ShareGroup::X25519],
        true,
        true,
    )
}

fn chrome131() -> Profile {
    make(
        Fingerprint::Chrome131,
        CHROME_CIPHERS,
        vec![
            Ext::Grease,
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![GREASE_PLACEHOLDER, 0x11ec, 0x001d, 0x0017, 0x0018]),
            Ext::Points(vec![0]),
            Ext::Ticket,
            Ext::Alpn,
            Ext::Status,
            Ext::Sigalgs(SA_CHROME.to_vec()),
            Ext::Sct,
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303]),
            Ext::CompressCert(vec![2]),
            Ext::Alps(super::EXT_ALPS_OLD),
            Ext::Ech(EchKind::Chrome),
            Ext::Grease,
        ],
        &[ShareGroup::Grease, ShareGroup::Hybrid, ShareGroup::X25519],
        true,
        false,
    )
}

fn chrome133() -> Profile {
    make(
        Fingerprint::Chrome133,
        CHROME_CIPHERS,
        vec![
            Ext::Grease,
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![GREASE_PLACEHOLDER, 0x11ec, 0x001d, 0x0017, 0x0018]),
            Ext::Points(vec![0]),
            Ext::Ticket,
            Ext::Alpn,
            Ext::Status,
            Ext::Sigalgs(SA_CHROME.to_vec()),
            Ext::Sct,
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303]),
            Ext::CompressCert(vec![2]),
            Ext::Alps(super::EXT_ALPS_NEW),
            Ext::Ech(EchKind::Chrome),
            Ext::Grease,
        ],
        &[ShareGroup::Grease, ShareGroup::Hybrid, ShareGroup::X25519],
        true,
        false,
    )
}

fn firefox120() -> Profile {
    make(
        Fingerprint::Firefox120,
        FIREFOX_CIPHERS,
        vec![
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
            Ext::Points(vec![0]),
            Ext::Ticket,
            Ext::Alpn,
            Ext::Status,
            Ext::Delegated(DELEGATED.to_vec()),
            Ext::KeyShare,
            Ext::Versions(vec![0x0304, 0x0303]),
            Ext::Sigalgs(SA_FIREFOX.to_vec()),
            Ext::PskModes(vec![1]),
            Ext::RecordSizeLimit(0x4001),
            Ext::Ech(EchKind::Firefox),
        ],
        &[ShareGroup::X25519],
        false,
        false,
    )
}

fn firefox148() -> Profile {
    make(
        Fingerprint::Firefox148,
        FIREFOX_CIPHERS,
        vec![
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
            Ext::Points(vec![0]),
            Ext::Alpn,
            Ext::Status,
            Ext::Delegated(DELEGATED.to_vec()),
            Ext::Sct,
            Ext::KeyShare,
            Ext::Versions(vec![0x0304, 0x0303]),
            Ext::Sigalgs(SA_FIREFOX.to_vec()),
            Ext::RecordSizeLimit(0x4001),
            Ext::CompressCert(vec![1, 2, 3]),
            Ext::Ech(EchKind::Firefox),
        ],
        &[ShareGroup::Hybrid, ShareGroup::X25519],
        false,
        false,
    )
}

fn safari263() -> Profile {
    make(
        Fingerprint::Safari263,
        SAFARI_CIPHERS,
        vec![
            Ext::Grease,
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![
                GREASE_PLACEHOLDER,
                0x11ec,
                0x001d,
                0x0017,
                0x0018,
                0x0019,
            ]),
            Ext::Points(vec![0]),
            Ext::Alpn,
            Ext::Status,
            Ext::Sigalgs(SA_SAFARI.to_vec()),
            Ext::Sct,
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303]),
            Ext::CompressCert(vec![1]),
            Ext::Grease,
        ],
        &[ShareGroup::Grease, ShareGroup::Hybrid, ShareGroup::X25519],
        false,
        false,
    )
}

fn ios13() -> Profile {
    make(
        Fingerprint::Ios13,
        IOS13_CIPHERS,
        vec![
            Ext::Reneg,
            Ext::Sni,
            Ext::Ems,
            Ext::Sigalgs(SA_IOS.to_vec()),
            Ext::Status,
            Ext::Sct,
            Ext::Alpn,
            Ext::Points(vec![0]),
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![0x0304, 0x0303, 0x0302, 0x0301]),
            Ext::Groups(vec![0x001d, 0x0017, 0x0018, 0x0019]),
            Ext::Padding,
        ],
        &[ShareGroup::X25519],
        false,
        true,
    )
}

fn ios14() -> Profile {
    make(
        Fingerprint::Ios14,
        IOS14_CIPHERS,
        vec![
            Ext::Grease,
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![GREASE_PLACEHOLDER, 0x001d, 0x0017, 0x0018, 0x0019]),
            Ext::Points(vec![0]),
            Ext::Alpn,
            Ext::Status,
            Ext::Sigalgs(SA_IOS.to_vec()),
            Ext::Sct,
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303, 0x0302, 0x0301]),
            Ext::Grease,
            Ext::Padding,
        ],
        &[ShareGroup::Grease, ShareGroup::X25519],
        false,
        true,
    )
}

fn edge85() -> Profile {
    make(
        Fingerprint::Edge85,
        EDGE_CIPHERS,
        vec![
            Ext::Grease,
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![GREASE_PLACEHOLDER, 0x001d, 0x0017, 0x0018]),
            Ext::Points(vec![0]),
            Ext::Ticket,
            Ext::Alpn,
            Ext::Status,
            Ext::Sigalgs(SA_CHROME.to_vec()),
            Ext::Sct,
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303, 0x0302, 0x0301]),
            Ext::CompressCert(vec![2]),
            Ext::Grease,
            Ext::Padding,
        ],
        &[ShareGroup::Grease, ShareGroup::X25519],
        false,
        true,
    )
}

fn edge106() -> Profile {
    make(
        Fingerprint::Edge106,
        EDGE_CIPHERS,
        vec![
            Ext::Grease,
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![GREASE_PLACEHOLDER, 0x001d, 0x0017, 0x0018]),
            Ext::Points(vec![0]),
            Ext::Ticket,
            Ext::Alpn,
            Ext::Status,
            Ext::Sigalgs(SA_CHROME.to_vec()),
            Ext::Sct,
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303]),
            Ext::CompressCert(vec![2]),
            Ext::Alps(super::EXT_ALPS_OLD),
            Ext::Grease,
            Ext::Padding,
        ],
        &[ShareGroup::Grease, ShareGroup::X25519],
        false,
        true,
    )
}

fn browser360() -> Profile {
    make(
        Fingerprint::Browser360,
        BROWSER360_CIPHERS,
        vec![
            Ext::Grease,
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![GREASE_PLACEHOLDER, 0x001d, 0x0017, 0x0018]),
            Ext::Points(vec![0]),
            Ext::Ticket,
            Ext::Alpn,
            Ext::Status,
            Ext::Sigalgs(SA_360.to_vec()),
            Ext::Sct,
            Ext::ChannelId(super::EXT_CHANNEL_ID),
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303, 0x0302, 0x0301]),
            Ext::CompressCert(vec![2]),
            Ext::Grease,
            Ext::Padding,
        ],
        &[ShareGroup::Grease, ShareGroup::X25519],
        false,
        true,
    )
}

fn qq111() -> Profile {
    make(
        Fingerprint::Qq111,
        CHROME_CIPHERS,
        vec![
            Ext::Grease,
            Ext::Sni,
            Ext::Ems,
            Ext::Reneg,
            Ext::Groups(vec![GREASE_PLACEHOLDER, 0x001d, 0x0017, 0x0018]),
            Ext::Points(vec![0]),
            Ext::Ticket,
            Ext::Alpn,
            Ext::Status,
            Ext::Sigalgs(SA_CHROME.to_vec()),
            Ext::Sct,
            Ext::KeyShare,
            Ext::PskModes(vec![1]),
            Ext::Versions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303, 0x0302, 0x0301]),
            Ext::CompressCert(vec![2]),
            Ext::Alps(super::EXT_ALPS_OLD),
            Ext::Grease,
            Ext::Padding,
        ],
        &[ShareGroup::Grease, ShareGroup::X25519],
        false,
        true,
    )
}
