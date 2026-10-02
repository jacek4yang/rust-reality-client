//! The grammars a node handoff is checked against.
//!
//! Every rule here is the mirror image of a check the v2.0.1 server applies to
//! its own configuration or to a byte string it reads from a client, cited
//! where each function. The client must be strict for a specific reason: a
//! value the node would reject does not produce an error, it produces a
//! **fallback to the cover**, which is indistinguishable from a dead node from
//! the client's side. Validation is the only place that can say so plainly.

use std::net::{IpAddr, SocketAddr};

use base64::Engine as _;

/// Length of every key the configuration accepts, in bytes.
///
/// v2.0.1 `src/config/syntax.rs:18`.
const KEY_BYTES: usize = 32;

/// The single wording used by every key error.
///
/// v2.0.1 `src/config/syntax.rs:61-71`: the decoder returns `None` for anything
/// that is not exactly one key *without saying which way it was wrong*, because
/// the shape of a key is information about a secret. The client keeps that
/// discipline for the private half it never stores, and applies it to the
/// public half too so one message covers both.
pub(crate) const KEY_RULE: &str = "must be URL-safe unpadded base64 decoding to exactly 32 bytes";

/// Decodes a REALITY key: URL-safe alphabet, no padding, exactly 32 bytes.
///
/// v2.0.1 `src/config/syntax.rs:59-68`. Padded input, the standard alphabet's
/// `+` and `/`, embedded whitespace and any other length are all refused — its
/// own test `:291` refuses a standard-alphabet padded encoding of the very same
/// bytes.
///
/// Note what is *not* checked: no small-order, all-zero or otherwise
/// "invalid point" screening. Upstream declares every 32-byte string a usable
/// configured key (`src/crypto/x25519.rs:76-87`, test `:224-238`) and rejects
/// only a **non-contributory agreed output** at exchange time
/// (`src/crypto/x25519.rs:20-23`, `src/protocol/reality/auth.rs:494-497`). A
/// client that screened points at parse time would refuse keys its server
/// accepts, which is a divergence, not a hardening.
pub(crate) fn decode_key(value: &str) -> Option<[u8; KEY_BYTES]> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()?;
    if decoded.len() != KEY_BYTES {
        return None;
    }
    decoded.try_into().ok()
}

/// Returns whether `value` is a REALITY short ID.
///
/// v2.0.1 `src/config/syntax.rs:49-57`: two to sixteen characters, an even
/// number of them, all ASCII hex — uppercase included, because the wire decoder
/// accepts `A-F` as readily as `a-f` (`src/protocol/reality/auth.rs:594-601`).
/// The empty string is **not** a way to say "no short ID": every identity must
/// own at least one (`src/config/semantics.rs:229-234`).
pub(crate) fn is_short_id(value: &str) -> bool {
    (2..=16).contains(&value.len())
        && value.len() % 2 == 0
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Decodes a short ID to the eight bytes that travel on the wire.
///
/// v2.0.1 `src/protocol/reality/auth.rs:578-592` writes into `[0_u8; 8]` and
/// fills only as many pairs as were configured, so a short ID is **padded on
/// the right with zeros**: `ab` becomes `ab00000000000000`. That is what makes
/// `ab` and `ab00` the same owner, which the server detects and rejects as
/// `DuplicateShortId` (`:451-457`).
pub(crate) fn short_id_bytes(value: &str) -> Option<[u8; 8]> {
    if !is_short_id(value) {
        return None;
    }
    let mut output = [0_u8; 8];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        output[index] = high << 4 | low;
    }
    Some(output)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Returns whether `value` is a canonical hyphenated UUID.
///
/// v2.0.1 `src/config/syntax.rs:21-27`: exactly 36 characters, `-` at 8, 13, 18
/// and 23, ASCII hex elsewhere — uppercase accepted. A user id is therefore
/// never accepted bare, and the server compares the decoded `Uuid`, so case is
/// not significant in the value, only in the spelling.
pub(crate) fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// Decodes a user id into the sixteen raw bytes the wire needs.
///
/// The public API always hands the request encoder raw bytes, so no textual
/// form of the credential reaches the hot path.
pub(crate) fn uuid_bytes(value: &str) -> Option<[u8; 16]> {
    if !is_uuid(value) {
        return None;
    }
    let mut output = [0_u8; 16];
    // Counted over the digits that remain, not the source positions: the dashes
    // sit at odd offsets too, so position parity would misalign every pair
    // after the first group.
    let mut digits = 0_usize;
    for (position, byte) in value.bytes().enumerate() {
        if matches!(position, 8 | 13 | 18 | 23) {
            continue;
        }
        let digit = hex_digit(byte)?;
        let slot = &mut output[digits / 2];
        if digits % 2 == 0 {
            *slot = digit;
        } else {
            *slot = *slot << 4 | digit;
        }
        digits += 1;
    }
    Some(output)
}

/// Returns whether `label` is one DNS label.
///
/// v2.0.1 `src/server_name.rs:58-66`.
fn is_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Returns whether `value` is an ASCII DNS name.
///
/// v2.0.1 `src/config/syntax.rs:30-45`.
pub(crate) fn is_hostname(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && !value.split('.').any(|label| !is_dns_label(label))
}

/// Returns whether `value` is a name or an IP literal.
///
/// v2.0.1 `src/config/syntax.rs:48-50`: an IP literal is not a DNS name, but a
/// node address may be either.
pub(crate) fn is_hostname_or_ip(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok() || is_hostname(value)
}

/// Returns whether `value` is one concrete name that SNI may carry.
///
/// v2.0.1 `src/server_name.rs:6-12`. The client sends a name rather than a
/// pattern, so this — not the wildcard form — is the rule it must satisfy; and
/// the server compares case-insensitively without lowercasing, normalising a
/// trailing dot, or applying IDNA (`:30-41`), so a non-ASCII or dotted-tail SNI
/// is not a stylistic problem but a guaranteed fallback.
pub(crate) fn is_concrete_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(is_dns_label)
}

/// Parses a numeric `host:port` bind address.
///
/// A listener is bound by number: `SocketAddr` accepts `127.0.0.1:10808` and
/// `[::1]:10808` and nothing else, which is also what makes the loopback rule
/// below checkable without a resolver.
pub(crate) fn bind_address(value: &str) -> Option<SocketAddr> {
    let address = value.parse::<SocketAddr>().ok()?;
    (address.port() != 0).then_some(address)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::{
        KEY_RULE, bind_address, decode_key, is_concrete_server_name, is_hostname, is_short_id,
        is_uuid, short_id_bytes, uuid_bytes,
    };

    /// 32 bytes whose URL-safe image carries both characters the standard
    /// alphabet spells differently: `0xff` yields `_` and the `0xfe` tail yields
    /// `-`.
    const URL_SAFE_BYTES: [u8; 32] = {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0xff;
        bytes[1] = 0xff;
        bytes[2] = 0xfe;
        bytes
    };

    fn key_of(byte: u8) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])
    }

    #[test]
    fn keys_are_url_safe_unpadded_and_exactly_thirty_two_bytes() {
        assert_eq!(decode_key(&key_of(7)), Some([7_u8; 32]));
        // The alphabet's own two characters, which the standard alphabet does
        // not have.
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(URL_SAFE_BYTES);
        assert!(
            url_safe.contains('-') && url_safe.contains('_'),
            "{url_safe} was meant to exercise both"
        );
        assert_eq!(decode_key(&url_safe), Some(URL_SAFE_BYTES));
        assert_eq!(decode_key(""), None);
        assert_eq!(key_of(7).len(), 43, "32 bytes need no padding");
        assert_eq!(
            decode_key(&key_of(7)[..42]),
            None,
            "one character short is a different byte count"
        );
        assert_eq!(decode_key("!!!!"), None);
        // Standard alphabet with padding encodes the same bytes and is refused
        // anyway, which is what makes the shared message the right one.
        assert_eq!(
            decode_key(&base64::engine::general_purpose::STANDARD.encode([0xff_u8; 32])),
            None
        );
        assert_eq!(decode_key(&format!("{}=", key_of(7))), None);
        assert_eq!(decode_key(&key_of(7).repeat(2)), None);
        assert_eq!(
            KEY_RULE,
            "must be URL-safe unpadded base64 decoding to exactly 32 bytes"
        );
    }

    /// A low-order or all-zero point is a *config value the server accepts*.
    /// Screening it here would refuse a key the node is really configured with.
    #[test]
    fn no_point_validity_is_screened_at_parse_time() {
        assert_eq!(decode_key(&key_of(0)), Some([0_u8; 32]));
        assert_eq!(decode_key(&key_of(1)), Some([1_u8; 32]));
    }

    #[test]
    fn short_ids_are_even_hex_and_pad_on_the_right() {
        assert!(is_short_id("ab"));
        assert!(is_short_id("AB"), "the wire decoder accepts uppercase");
        assert!(is_short_id("0123456789abcdef"));
        assert!(!is_short_id("a"), "odd lengths have no byte image");
        assert!(!is_short_id(""));
        assert!(!is_short_id("gg"));
        assert!(!is_short_id("0123456789abcdef0"));

        assert_eq!(short_id_bytes("ab"), Some([0xab, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(short_id_bytes("AB"), short_id_bytes("ab"));
        // The collision the server calls DuplicateShortId: a shorter id and a
        // longer one that pads out to the same eight bytes.
        assert_eq!(short_id_bytes("ab"), short_id_bytes("ab00"));
        assert_eq!(
            short_id_bytes("0123456789abcdef"),
            Some([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
        );
        assert_eq!(short_id_bytes("a"), None);
    }

    #[test]
    fn user_ids_are_canonical_hyphenated_uuids() {
        let text = "123e4567-e89b-12d3-a456-426614174000";
        assert!(is_uuid(text));
        assert_eq!(
            uuid_bytes(text),
            Some([
                0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
                0x40, 0x00
            ])
        );
        assert!(is_uuid(text.to_uppercase().as_str()));
        assert_eq!(
            uuid_bytes(&text.to_uppercase()),
            uuid_bytes(text),
            "case is spelling, not value"
        );
        assert!(
            !is_uuid(text.replace('-', "").as_str()),
            "bare hex is refused"
        );
        assert!(!is_uuid("123e4567e89b-12d3-a456-426614174000"));
        assert!(!is_uuid(&text[..35]));
        assert_eq!(uuid_bytes(&text.replace('-', "")), None);
    }

    #[test]
    fn names_follow_the_servers_dns_charset() {
        assert!(is_hostname("www.example.com"));
        assert!(is_hostname("a-Z0.9"));
        assert!(!is_hostname(""));
        assert!(!is_hostname(".example.com"), "an empty label");
        assert!(!is_hostname("-example.com"), "a leading hyphen");
        assert!(!is_hostname("example-.com"), "a trailing hyphen");
        assert!(!is_hostname("exa mple.com"), "a space is not a label byte");
        assert!(!is_hostname(&"a".repeat(64)), "a label over 63");
        assert!(
            !is_hostname(&format!("{}.com", "a".repeat(250))),
            "over 253"
        );
        assert!(!is_hostname("exámple.com"), "non-ascii");

        // A name may be an IP literal as a node address but never as SNI.
        assert!(super::is_hostname_or_ip("203.0.113.10"));
        assert!(super::is_hostname_or_ip("example.com"));
        assert!(is_concrete_server_name("example.com"));
        assert!(
            !is_concrete_server_name("203.0.113.10"),
            "SNI is not an address"
        );
        assert!(
            !is_concrete_server_name("*.example.com"),
            "a pattern is not a name"
        );
        assert!(
            !is_concrete_server_name("example.com."),
            "a trailing dot is not stripped by the matcher"
        );
        assert!(is_concrete_server_name("localhost"));
    }

    #[test]
    fn bind_addresses_are_numeric_and_never_port_zero() {
        assert_eq!(
            bind_address("127.0.0.1:10808").map(|address| address.port()),
            Some(10_808)
        );
        assert!(bind_address("[::1]:10808").is_some());
        assert_eq!(bind_address("127.0.0.1:0"), None);
        assert_eq!(
            bind_address("localhost:10808"),
            None,
            "a name needs no resolver here"
        );
        assert_eq!(bind_address("127.0.0.1"), None);
    }
}
