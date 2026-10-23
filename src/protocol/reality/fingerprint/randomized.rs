//! Xray's `randomized` / `randomizednoalpn` shape, ported from uTLS
//! `generateRandomizedSpec`.
//!
//! The capability set is generated once per process from the first seed, just
//! as Xray does. Only GREASE, padding and the other per-handshake fields vary
//! between connections.

use super::{EXT_ALPS_OLD, Ext, Fingerprint, Profile, Rng, ShareGroup};
use crate::protocol::reality::X25519_MLKEM768_GROUP;

const TLS13: [u16; 3] = [0x1301, 0x1302, 0x1303];

/// TLS 1.2 suites uTLS can place in a randomized hello. The list is the
/// supported subset of its `cipherSuites` table; RC4 and the disabled CBC
/// suites are omitted, matching uTLS's TLS 1.3 path.
const TLS12: &[u16] = &[
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d,
    0x002f, 0x0035, 0xc023, 0xc027, 0x003c, 0x000a, 0xc012, 0xc008,
];

fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

#[allow(clippy::too_many_lines)]
pub(super) fn build(seed: [u8; 32], with_alpn: bool) -> Profile {
    let mut rng = Rng::new(seed);

    let mut ciphers = Vec::with_capacity(3 + TLS12.len());
    for cipher in TLS13 {
        ciphers.push(cipher);
    }
    let mut tls12 = TLS12.to_vec();
    rng.shuffle(&mut tls12);
    ciphers.extend(tls12);

    // Xray forces TLS 1.3. Keep every TLS 1.3 suite so any cover selection the
    // server permits is actually offered; thin the TLS 1.2 tail instead.
    let mut kept = Vec::with_capacity(ciphers.len());
    kept.extend_from_slice(&ciphers[..3]);
    let full_len = ciphers.len();
    for (offset, cipher) in ciphers[3..].iter().enumerate() {
        let position = offset + 3;
        let removal = 4_000 * position / full_len;
        if rng.below(10_000) >= removal {
            kept.push(*cipher);
        }
    }
    ciphers = kept;

    let min_tls10 = rng.coin(5_000);
    let versions = if min_tls10 {
        vec![0x0304, 0x0303, 0x0302, 0x0301]
    } else {
        vec![0x0304, 0x0303]
    };

    let hybrid = rng.coin(7_100);
    let mut groups = Vec::new();
    if hybrid {
        groups.push(X25519_MLKEM768_GROUP);
    }
    groups.push(0x001d);
    groups.push(0x0017);
    groups.push(0x0018);
    if rng.coin(4_600) {
        groups.push(0x0019);
    }

    let mut sigalgs = vec![0x0403, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601];
    if rng.coin(6_300) {
        sigalgs.push(0x0203);
    }
    if rng.coin(5_900) {
        sigalgs.push(0x0603);
    }
    sigalgs.push(0x0804);
    if rng.coin(9_000) {
        sigalgs.push(0x0805);
        sigalgs.push(0x0806);
    }
    rng.shuffle(&mut sigalgs);

    let mut shares = Vec::new();
    if hybrid {
        shares.push(ShareGroup::Hybrid);
    }
    shares.push(ShareGroup::X25519);

    let mut extensions = vec![
        Ext::Sni,
        Ext::Ticket,
        Ext::Sigalgs(sigalgs),
        Ext::Points(vec![0]),
        Ext::Groups(groups),
    ];
    if with_alpn {
        extensions.push(Ext::Alpn);
    }
    extensions.push(Ext::Padding);
    if rng.coin(7_400) {
        extensions.push(Ext::Status);
    }
    if rng.coin(4_600) {
        extensions.push(Ext::Sct);
    }
    if rng.coin(7_500) {
        extensions.push(Ext::Reneg);
    }
    if rng.coin(7_700) {
        extensions.push(Ext::Ems);
    }
    extensions.push(Ext::KeyShare);
    extensions.push(Ext::PskModes(vec![1]));
    extensions.push(Ext::Versions(versions));
    if with_alpn && rng.coin(3_300) {
        extensions.push(Ext::Alps(EXT_ALPS_OLD));
    }
    rng.shuffle(&mut extensions);

    Profile {
        id: if with_alpn {
            Fingerprint::Randomized
        } else {
            Fingerprint::RandomizedNoAlpn
        },
        ciphers,
        compression: vec![0],
        extensions,
        alpn: if with_alpn {
            alpn_protocols()
        } else {
            Vec::new()
        },
        shares,
        shuffle: false,
        padding: true,
    }
}
