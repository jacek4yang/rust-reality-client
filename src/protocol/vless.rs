//! VLESS request header encoding and response validation.
//!
//! The wire order and the acceptance rules come from rust-reality v2.0.1
//! `src/protocol/vless/decode.rs` and `validate.rs`: the version, user id,
//! Addons length, Addons protobuf, then command, port and destination. The
//! request is written **unframed** into TLS plaintext — Vision framing begins
//! only with the bytes that follow it in the same record.

/// VLESS protocol version this client speaks.
pub const VERSION: u8 = 0;

/// The only command the production inbound accepts: TCP.
pub const COMMAND_TCP: u8 = 1;

/// Maximum request header size the server accepts, from its
/// `MAX_REQUEST_HEADER_SIZE`.
pub const MAX_REQUEST_HEADER_SIZE: usize = 533;

/// Wire type tag for an IPv4 destination.
pub const ATYPE_IPV4: u8 = 1;
/// Wire type tag for a domain destination.
pub const ATYPE_DOMAIN: u8 = 2;
/// Wire type tag for an IPv6 destination.
pub const ATYPE_IPV6: u8 = 3;

/// The flow string the server requires for Vision.
pub const VISION_FLOW: &str = "xtls-rprx-vision";

/// A destination the client was asked to reach.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Destination {
    /// A host name, as it should appear on the wire.
    Domain(String),
    /// A literal IPv4 address.
    IPv4([u8; 4]),
    /// A literal IPv6 address.
    IPv6([u8; 16]),
}

impl Destination {
    /// Builds a destination from a host and port, keeping literals as literals.
    ///
    /// A bracketed IPv6 host loses its brackets, which are a URL syntax
    /// artifact rather than part of the address.
    #[must_use]
    pub fn parse(host: &str, port: u16) -> Option<(Self, u16)> {
        let host = host.trim();
        if host.is_empty() || port == 0 {
            return None;
        }
        if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
            return Some((Self::IPv4(address.octets()), port));
        }
        if let Some(stripped) = host.strip_prefix('[') {
            let literal = stripped.strip_suffix(']')?;
            let address = literal.parse::<std::net::Ipv6Addr>().ok()?;
            return Some((Self::IPv6(address.octets()), port));
        }
        if let Ok(address) = host.parse::<std::net::Ipv6Addr>() {
            return Some((Self::IPv6(address.octets()), port));
        }
        if is_valid_domain(host) {
            return Some((Self::Domain(host.to_owned()), port));
        }
        None
    }

    /// Byte length of this destination's wire encoding, tag included.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        match self {
            Self::Domain(host) => 2 + host.len(),
            Self::IPv4(_) => 5,
            Self::IPv6(_) => 17,
        }
    }
}

/// Returns whether the server's domain charset accepts `host`.
///
/// Mirrors rust-reality v2.0.1 `decode.rs`: alphanumeric, `-`, `.`, `_`.
#[must_use]
pub const fn is_valid_domain(host: &str) -> bool {
    let bytes = host.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_') {
            return false;
        }
        index += 1;
    }
    true
}

/// Encodes the Addons protobuf carrying a single flow string.
///
/// Xray-core's `Addons` puts the flow in protobuf field 1, length-delimited.
/// Returns `None` when the flow cannot fit the one-byte field lengths, which a
/// validated configuration never produces but the public API must not assume.
#[must_use]
pub fn encode_addons(flow: &str) -> Option<Vec<u8>> {
    let length = u8::try_from(flow.len()).ok()?;
    let mut output = Vec::with_capacity(2 + flow.len());
    output.push(0x0a);
    output.push(length);
    output.extend_from_slice(flow.as_bytes());
    Some(output)
}

/// Encodes one VLESS TCP request header.
///
/// The caller supplies the user id as 16 raw bytes, never as a formatted
/// string, so that no textual form of the credential exists on the hot path.
///
/// Returns `None` when a field is longer than its one-byte wire length permits;
/// the caller reports that as a local error rather than sending a truncated
/// destination.
#[must_use]
pub fn encode_request(
    user_id: &[u8; 16],
    addons: &[u8],
    destination: &Destination,
    port: u16,
) -> Option<Vec<u8>> {
    let addons_len = u8::try_from(addons.len()).ok()?;
    let mut output = Vec::with_capacity(MAX_REQUEST_HEADER_SIZE);
    output.push(VERSION);
    output.extend_from_slice(user_id);
    output.push(addons_len);
    output.extend_from_slice(addons);
    output.push(COMMAND_TCP);
    output.extend_from_slice(&port.to_be_bytes());
    match destination {
        Destination::Domain(host) => {
            output.push(ATYPE_DOMAIN);
            output.push(u8::try_from(host.len()).ok()?);
            output.extend_from_slice(host.as_bytes());
        }
        Destination::IPv4(address) => {
            output.push(ATYPE_IPV4);
            output.extend_from_slice(address);
        }
        Destination::IPv6(address) => {
            output.push(ATYPE_IPV6);
            output.extend_from_slice(address);
        }
    }
    Some(output)
}

/// Validates the two-byte response header the server sends once it has accepted
/// the request **and** connected to the destination.
///
/// rust-reality v2.0.1 emits exactly `[VERSION, 0]` there, which is why that
/// pair is the correct end-to-end readiness signal for hedged establishment: a
/// winner is only declared after a node has proved it can reach the target.
///
/// # Errors
///
/// Returns [`crate::error::RejectReason`] for any other status.
pub fn validate_response(header: &[u8]) -> Result<(), crate::error::Error> {
    use crate::error::{Error, RejectReason};
    if header.len() < 2 {
        return Err(Error::Rejected(RejectReason::Other(0)));
    }
    if header[0] != VERSION {
        return Err(Error::Rejected(RejectReason::Other(u16::from(header[0]))));
    }
    match header[1] {
        0 => Ok(()),
        1 => Err(Error::Rejected(RejectReason::Unauthorized)),
        2 => Err(Error::Rejected(RejectReason::Forbidden)),
        3 => Err(Error::Rejected(RejectReason::DestinationUnreachable)),
        other => Err(Error::Rejected(RejectReason::Other(u16::from(other)))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ATYPE_DOMAIN, ATYPE_IPV4, ATYPE_IPV6, COMMAND_TCP, Destination, MAX_REQUEST_HEADER_SIZE,
        VERSION, VISION_FLOW, encode_addons, encode_request, is_valid_domain, validate_response,
    };

    const USER: [u8; 16] = [0x11; 16];

    #[test]
    fn request_wire_order_matches_the_upstream_decoder() {
        let addons = encode_addons(VISION_FLOW).expect("flow fits its length field");
        let request = encode_request(
            &USER,
            &addons,
            &Destination::Domain("www.example.com".to_owned()),
            443,
        )
        .expect("destination fits its length field");
        assert_eq!(request[0], VERSION);
        assert_eq!(&request[1..17], &USER);
        assert_eq!(request[17] as usize, addons.len());
        assert_eq!(&request[18..18 + addons.len()], &addons[..]);
        let tail = 18 + addons.len();
        assert_eq!(request[tail], COMMAND_TCP);
        assert_eq!(&request[tail + 1..tail + 3], &[0x01, 0xbb]);
        assert_eq!(request[tail + 3], ATYPE_DOMAIN);
        assert_eq!(request[tail + 4], 15);
        assert_eq!(&request[tail + 5..], b"www.example.com");
        assert!(request.len() <= MAX_REQUEST_HEADER_SIZE);
    }

    #[test]
    fn addons_carry_the_flow_in_protobuf_field_one() {
        assert_eq!(
            encode_addons(VISION_FLOW),
            Some([&[0x0a_u8, 16][..], b"xtls-rprx-vision"].concat())
        );
        assert_eq!(encode_addons(&"x".repeat(300)), None);
    }

    /// `version + uuid + addons_len + command` precede the big-endian port,
    /// which precedes the address type tag.
    const PORT_OFFSET: usize = 1 + 16 + 1 + 1;
    const ADDRESS_TYPE_OFFSET: usize = PORT_OFFSET + 2;

    #[test]
    fn literal_addresses_use_their_own_type_tags() {
        let v4 = encode_request(&USER, &[], &Destination::IPv4([203, 0, 113, 10]), 80)
            .expect("ipv4 fits");
        assert_eq!(&v4[PORT_OFFSET..ADDRESS_TYPE_OFFSET], &[0, 80]);
        assert_eq!(v4[ADDRESS_TYPE_OFFSET], ATYPE_IPV4);
        assert_eq!(&v4[ADDRESS_TYPE_OFFSET + 1..], &[203, 0, 113, 10]);

        let v6 = encode_request(
            &USER,
            &[],
            &Destination::IPv6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            443,
        )
        .expect("ipv6 fits");
        assert_eq!(&v6[PORT_OFFSET..ADDRESS_TYPE_OFFSET], &[1, 0xbb]);
        assert_eq!(v6[ADDRESS_TYPE_OFFSET], ATYPE_IPV6);
        assert_eq!(v6.len(), ADDRESS_TYPE_OFFSET + 1 + 16);
        assert_eq!(v6[v6.len() - 16], 0x20);
    }

    /// A hand-built oversized domain must fail closed instead of wrapping its
    /// length byte and silently address the wrong host.
    #[test]
    fn overlong_fields_are_refused_not_truncated() {
        assert_eq!(
            encode_request(&USER, &[], &Destination::Domain("a".repeat(256)), 443),
            None
        );
        assert!(
            encode_request(&USER, &[], &Destination::Domain("a".repeat(255)), 443).is_some(),
            "255 is the largest addressable domain"
        );
    }

    #[test]
    fn destinations_classify_literals_and_names() {
        assert_eq!(
            Destination::parse("203.0.113.10", 443),
            Some((Destination::IPv4([203, 0, 113, 10]), 443))
        );
        assert_eq!(
            Destination::parse("[2001:db8::1]", 443),
            Some((
                Destination::IPv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                443
            ))
        );
        assert_eq!(
            Destination::parse("example.com", 443),
            Some((Destination::Domain("example.com".to_owned()), 443))
        );
        assert_eq!(Destination::parse("example.com", 0), None);
        assert_eq!(Destination::parse("", 443), None);
        assert_eq!(Destination::parse("not a host", 443), None);
    }

    #[test]
    fn domain_charset_matches_upstream() {
        assert!(is_valid_domain("a-Z_0.9"));
        assert!(!is_valid_domain("a b"));
        assert!(!is_valid_domain("a/b"));
        assert!(!is_valid_domain("aé"));
        assert!(!is_valid_domain(""));
    }

    #[test]
    fn response_acceptance_is_exactly_version_and_zero() {
        assert!(validate_response(&[0, 0]).is_ok());
        assert!(validate_response(&[0, 0, 0xff, 0xff]).is_ok());
        for status in [1_u8, 2, 3, 9] {
            assert!(validate_response(&[0, status]).is_err());
        }
        assert!(validate_response(&[1, 0]).is_err());
        assert!(validate_response(&[0]).is_err());
        assert!(validate_response(&[]).is_err());
    }

    #[test]
    fn wire_len_agrees_with_the_encoding() {
        for destination in [
            Destination::Domain("example.com".to_owned()),
            Destination::IPv4([1, 2, 3, 4]),
            Destination::IPv6([7; 16]),
        ] {
            let request = encode_request(&USER, &[], &destination, 1).expect("fits");
            assert_eq!(request.len(), 18 + 1 + 2 + destination.wire_len());
        }
    }
}
