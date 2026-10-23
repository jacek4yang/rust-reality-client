//! Browser `ClientHello` profiles derived from pinned uTLS data.
//!
//! The profile tables in [`data`] are transliterations of
//! `refraction-networking/utls` at commit
//! `aa6edf4b11af82e110eea845bb2983d30138d651`, the revision Xray-core
//! v26.7.28 pins. Nobody here invents a byte: extension order, bodies,
//! cipher lists and GREASE rules are copied from `u_parrots.go`,
//! `u_tls_extensions.go`, `u_ech.go` and `u_conn.go` at that revision.
//!
//! Two properties are deliberately adjusted for REALITY:
//!
//! * every shape keeps a standalone 32-byte X25519 key share, which is what
//!   the server authenticates against;
//! * Firefox's P-256 key share is omitted (it stays in `supported_groups`)
//!   because the server accepts only X25519 and X25519MLKEM768 cover
//!   selections.

mod data;
mod randomized;

use std::fmt;
use std::sync::{LazyLock, OnceLock};

use crate::crypto::X25519_PUBLIC_LEN;
use crate::protocol::reality::{X25519_GROUP, X25519_MLKEM768_GROUP};

/// The uTLS revision every table in this module comes from.
pub const UTLS_COMMIT: &str = "aa6edf4b11af82e110eea845bb2983d30138d651";

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_RECORD_SIZE_LIMIT: u16 = 0x001c;
const EXT_DELEGATED_CREDENTIALS: u16 = 0x0022;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ALPS_OLD: u16 = 0x4469;
const EXT_ALPS_NEW: u16 = 0x44cd;
const EXT_CHANNEL_ID: u16 = 0x7550;
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION: u16 = 0xff01;

/// The placeholder every profile table uses for a per-handshake GREASE value.
pub(crate) const GREASE_PLACEHOLDER: u16 = 0x0a0a;

/// One name accepted in `[node.reality].fingerprint`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fingerprint {
    /// Xray's `chrome` preset (Chrome 133).
    Chrome,
    /// Xray's `firefox` preset (Firefox 148).
    Firefox,
    /// Xray's `safari` preset (Safari 26.3).
    Safari,
    /// Xray's `ios` preset (iOS 14).
    Ios,
    /// Xray's `edge` preset (Edge 85).
    Edge,
    /// Xray's `qq` preset (QQ 11.1).
    Qq,
    /// Chrome 120.
    Chrome120,
    /// Chrome 131.
    Chrome131,
    /// Chrome 133.
    Chrome133,
    /// Firefox 120.
    Firefox120,
    /// Firefox 148.
    Firefox148,
    /// Safari 26.3.
    Safari263,
    /// iOS 13.
    Ios13,
    /// iOS 14.
    Ios14,
    /// Edge 85.
    Edge85,
    /// Edge 106.
    Edge106,
    /// 360 Browser 11.0.
    Browser360,
    /// QQ Browser 11.1.
    Qq111,
    /// One modern profile, chosen once per process.
    Random,
    /// uTLS randomized shape with ALPN.
    Randomized,
    /// uTLS randomized shape without ALPN.
    RandomizedNoAlpn,
}

impl Fingerprint {
    /// Parses one Xray-compatible name or alias.
    ///
    /// Names that Xray exposes but REALITY cannot authenticate are refused
    /// with the reason and, when one exists, the nearest viable name. An
    /// unknown name is never silently replaced by a different shape.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when the name is unknown or unusable.
    pub fn parse(name: &str) -> Result<Self, FingerprintNameError> {
        let parsed = match name {
            "chrome" | "hellochrome_auto" | "hellochrome_133" => Self::Chrome133,
            "firefox" | "hellofirefox_auto" | "hellofirefox_148" => Self::Firefox148,
            "safari" | "hellosafari_auto" | "hellosafari_26_3" => Self::Safari263,
            "ios" | "helloios_auto" | "helloios_14" => Self::Ios14,
            "edge" | "helloedge_auto" | "helloedge_85" => Self::Edge85,
            "qq" | "helloqq_auto" | "helloqq_11_1" => Self::Qq111,
            "hellochrome_120" => Self::Chrome120,
            "hellochrome_131" => Self::Chrome131,
            "hellofirefox_120" => Self::Firefox120,
            "helloios_13" => Self::Ios13,
            "helloedge_106" => Self::Edge106,
            "hello360_11_0" => Self::Browser360,
            "random" => Self::Random,
            "randomized" => Self::Randomized,
            "randomizednoalpn" => Self::RandomizedNoAlpn,
            "android" | "helloandroid_11_okhttp" => {
                return Err(FingerprintNameError::Unusable(
                    "Android 11 OkHttp offers no TLS 1.3 key share, so REALITY cannot \
                     authenticate it; use \"chrome\" or \"ios\"",
                ));
            }
            "360" | "hello360_auto" | "hello360_7_5" => {
                return Err(FingerprintNameError::Unusable(
                    "Xray's 360 preset is the 7.5 shape, which offers no TLS 1.3 key \
                     share; use \"hello360_11_0\"",
                ));
            }
            "unsafe" => {
                return Err(FingerprintNameError::Unusable(
                    "Xray's \"unsafe\" is the Go standard-library handshake, not a browser \
                     fingerprint; this client has no equivalent",
                ));
            }
            other
                if other.starts_with("hellochrome_")
                    || other.starts_with("hellofirefox_")
                    || other.starts_with("helloios_")
                    || other.starts_with("helloedge_")
                    || other.starts_with("hellosafari_")
                    || other.starts_with("helloqq_")
                    || other.starts_with("hello360_")
                    || other.starts_with("hello") =>
            {
                return Err(FingerprintNameError::Unusable(
                    "legacy Xray fingerprint names are outside this client's chosen \
                     modern set; use a current name such as \"chrome\", \"firefox\" or \
                     \"safari\"",
                ));
            }
            _ => return Err(FingerprintNameError::Unknown),
        };
        Ok(parsed)
    }

    /// A stable diagnostic name. It is not credential material.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Chrome | Self::Chrome133 => "chrome",
            Self::Firefox | Self::Firefox148 => "firefox",
            Self::Safari | Self::Safari263 => "safari",
            Self::Ios | Self::Ios14 => "ios",
            Self::Edge | Self::Edge85 => "edge",
            Self::Qq | Self::Qq111 => "qq",
            Self::Chrome120 => "hellochrome_120",
            Self::Chrome131 => "hellochrome_131",
            Self::Firefox120 => "hellofirefox_120",
            Self::Ios13 => "helloios_13",
            Self::Edge106 => "helloedge_106",
            Self::Browser360 => "hello360_11_0",
            Self::Random => "random",
            Self::Randomized => "randomized",
            Self::RandomizedNoAlpn => "randomizednoalpn",
        }
    }

    fn concrete(self) -> Option<ConcreteProfile> {
        match self {
            Self::Chrome | Self::Chrome133 => Some(ConcreteProfile::Chrome133),
            Self::Chrome120 => Some(ConcreteProfile::Chrome120),
            Self::Chrome131 => Some(ConcreteProfile::Chrome131),
            Self::Firefox | Self::Firefox148 => Some(ConcreteProfile::Firefox148),
            Self::Firefox120 => Some(ConcreteProfile::Firefox120),
            Self::Safari | Self::Safari263 => Some(ConcreteProfile::Safari263),
            Self::Ios | Self::Ios14 => Some(ConcreteProfile::Ios14),
            Self::Ios13 => Some(ConcreteProfile::Ios13),
            Self::Edge | Self::Edge85 => Some(ConcreteProfile::Edge85),
            Self::Edge106 => Some(ConcreteProfile::Edge106),
            Self::Browser360 => Some(ConcreteProfile::Browser360),
            Self::Qq | Self::Qq111 => Some(ConcreteProfile::Qq111),
            Self::Random | Self::Randomized | Self::RandomizedNoAlpn => None,
        }
    }

    /// Resolves this name to the process-wide profile.
    ///
    /// `random` and the randomized variants are chosen once per process, from
    /// the first seed supplied. That stability matters: a new capability set
    /// per connection would churn the server's bounded ClientHello-class cache.
    #[must_use]
    pub fn resolve(self, seed: [u8; 32]) -> &'static Profile {
        if let Some(concrete) = self.concrete() {
            let table: &'static ConcreteTable = &CONCRETE;
            return table.profile(concrete);
        }
        match self {
            Self::Random => {
                static CHOICE: OnceLock<Fingerprint> = OnceLock::new();
                let chosen = *CHOICE.get_or_init(|| {
                    let mut rng = Rng::new(seed);
                    data::MODERN[rng.below(data::MODERN.len())]
                });
                chosen.resolve(seed)
            }
            Self::Randomized => {
                static PROFILE: OnceLock<Profile> = OnceLock::new();
                PROFILE.get_or_init(|| randomized::build(seed, true))
            }
            Self::RandomizedNoAlpn => {
                static PROFILE: OnceLock<Profile> = OnceLock::new();
                PROFILE.get_or_init(|| randomized::build(seed, false))
            }
            _ => unreachable!("concrete profiles were handled above"),
        }
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// A configuration-time rejection of a fingerprint name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FingerprintNameError {
    /// No supported profile has this name.
    Unknown,
    /// The name exists in Xray but cannot complete REALITY authentication here.
    Unusable(&'static str),
}

impl fmt::Display for FingerprintNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => formatter.write_str(
                "must be one of chrome, firefox, safari, ios, edge, qq, random, \
                 randomized, randomizednoalpn, or an explicit supported hello* name",
            ),
            Self::Unusable(reason) => formatter.write_str(reason),
        }
    }
}

/// One static shape in the concrete table.
#[derive(Clone, Copy)]
pub(crate) enum ConcreteProfile {
    Chrome120,
    Chrome131,
    Chrome133,
    Firefox120,
    Firefox148,
    Safari263,
    Ios13,
    Ios14,
    Edge85,
    Edge106,
    Browser360,
    Qq111,
}

struct ConcreteTable {
    chrome120: Profile,
    chrome131: Profile,
    chrome133: Profile,
    firefox120: Profile,
    firefox148: Profile,
    safari263: Profile,
    ios13: Profile,
    ios14: Profile,
    edge85: Profile,
    edge106: Profile,
    browser360: Profile,
    qq111: Profile,
}

impl ConcreteTable {
    fn profile(&self, which: ConcreteProfile) -> &Profile {
        match which {
            ConcreteProfile::Chrome120 => &self.chrome120,
            ConcreteProfile::Chrome131 => &self.chrome131,
            ConcreteProfile::Chrome133 => &self.chrome133,
            ConcreteProfile::Firefox120 => &self.firefox120,
            ConcreteProfile::Firefox148 => &self.firefox148,
            ConcreteProfile::Safari263 => &self.safari263,
            ConcreteProfile::Ios13 => &self.ios13,
            ConcreteProfile::Ios14 => &self.ios14,
            ConcreteProfile::Edge85 => &self.edge85,
            ConcreteProfile::Edge106 => &self.edge106,
            ConcreteProfile::Browser360 => &self.browser360,
            ConcreteProfile::Qq111 => &self.qq111,
        }
    }
}

static CONCRETE: LazyLock<ConcreteTable> = LazyLock::new(data::concrete);

/// One complete `ClientHello` shape.
pub struct Profile {
    pub(crate) id: Fingerprint,
    pub(crate) ciphers: Vec<u16>,
    pub(crate) compression: Vec<u8>,
    pub(crate) extensions: Vec<Ext>,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) shares: Vec<ShareGroup>,
    pub(crate) shuffle: bool,
    pub(crate) padding: bool,
}

impl Profile {
    /// Whether building this profile needs an ML-KEM key agreement.
    #[must_use]
    pub fn needs_hybrid(&self) -> bool {
        self.shares.contains(&ShareGroup::Hybrid)
    }

    /// The diagnostic name of the concrete or dynamic shape.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.id.name()
    }

    /// Whether this profile carries an ALPN extension.
    #[must_use]
    pub fn alpn(&self) -> &[Vec<u8>] {
        &self.alpn
    }

    /// Produces the per-handshake order, GREASE values and ECH grease body.
    #[must_use]
    pub fn plan_with_seed(&self, seed: [u8; 32]) -> HelloPlan {
        let mut rng = Rng::new(seed);
        let mut grease_seeds = [0_u16; 6];
        for slot in &mut grease_seeds {
            let mut bytes = [0_u8; 2];
            rng.fill(&mut bytes);
            *slot = u16::from_le_bytes(bytes);
        }
        let mut values = [0_u16; 6];
        for (value, seed) in values.iter_mut().zip(grease_seeds) {
            *value = grease_value(seed);
        }
        if values[3] == values[2] {
            values[3] = grease_value(grease_seeds[3] ^ 0x1010);
        }

        let ech = self
            .extensions
            .iter()
            .any(|ext| matches!(ext, Ext::Ech(_)))
            .then(|| EchPlan::generate(self, &mut rng));

        let mut order: Vec<usize> = (0..self.extensions.len()).collect();
        if self.shuffle {
            let positions: Vec<usize> = order
                .iter()
                .copied()
                .filter(|index| !matches!(self.extensions[*index], Ext::Grease | Ext::Padding))
                .collect();
            let mut values: Vec<usize> =
                positions.iter().map(|position| order[*position]).collect();
            rng.shuffle(&mut values);
            for (position, value) in positions.into_iter().zip(values) {
                order[position] = value;
            }
        }

        HelloPlan {
            order,
            grease_cipher: values[0],
            grease_group: values[1],
            grease_extension1: values[2],
            grease_extension2: values[3],
            grease_version: values[4],
            ech,
        }
    }
}

impl fmt::Debug for Profile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Profile")
            .field("name", &self.name())
            .finish_non_exhaustive()
    }
}

/// One concrete extension position in a profile.
#[derive(Clone, Debug)]
pub(crate) enum Ext {
    Sni,
    Groups(Vec<u16>),
    Sigalgs(Vec<u16>),
    Alpn,
    Status,
    Sct,
    Ems,
    Reneg,
    Points(Vec<u8>),
    Ticket,
    PskModes(Vec<u8>),
    Versions(Vec<u16>),
    KeyShare,
    CompressCert(Vec<u16>),
    Alps(u16),
    RecordSizeLimit(u16),
    Delegated(Vec<u16>),
    ChannelId(u16),
    Ech(EchKind),
    Grease,
    Padding,
}

/// The ECH grease flavour carried by a profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EchKind {
    Chrome,
    Firefox,
}

/// One key share a profile actually sends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShareGroup {
    Grease,
    X25519,
    Hybrid,
}

/// Public key material the serializer places into key shares.
#[derive(Debug)]
pub struct ShareMaterial {
    pub(crate) x25519: [u8; X25519_PUBLIC_LEN],
    pub(crate) hybrid: Option<Vec<u8>>,
}

/// Why a profile could not be serialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// A vector or the record would exceed its wire bound.
    TooLarge,
    /// The profile declares a hybrid share that was not generated.
    MissingHybrid,
    /// The profile declares ECH grease but no plan was made.
    MissingEch,
}

/// The per-handshake portion of a `ClientHello`.
pub struct HelloPlan {
    order: Vec<usize>,
    grease_cipher: u16,
    grease_group: u16,
    grease_extension1: u16,
    grease_extension2: u16,
    grease_version: u16,
    ech: Option<EchPlan>,
}

impl HelloPlan {
    /// Serializes every extension, including padding if the profile asks for
    /// it and the `BoringSSL` length rule applies.
    ///
    /// The result excludes the two-byte extensions length; the caller writes
    /// that once around this buffer, exactly as uTLS does.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError`] if a vector or the record would exceed its wire
    /// bound, or if the profile declares material it did not generate.
    pub fn extensions(
        &self,
        profile: &Profile,
        server_name: &str,
        shares: &ShareMaterial,
    ) -> Result<Vec<u8>, PlanError> {
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(self.order.len());
        let mut padding_at = None;
        let mut grease_seen = 0_usize;
        for index in &self.order {
            match &profile.extensions[*index] {
                Ext::Padding => padding_at = Some(encoded.len()),
                Ext::Grease => {
                    let (value, body): (u16, &[u8]) = if grease_seen == 0 {
                        (self.grease_extension1, &[])
                    } else {
                        (self.grease_extension2, &[0])
                    };
                    grease_seen += 1;
                    encoded.push(wrap(value, body)?);
                }
                ext => encoded.push(self.encode(profile, ext, server_name, shares)?),
            }
        }

        let extension_total: usize = encoded.iter().map(Vec::len).sum();
        let compression_len = profile.compression.len();
        let base = 4 + 2 + 32 + 1 + 32 + 2 + 2 * profile.ciphers.len() + 1 + compression_len;
        let unpadded = base + 2 + extension_total;
        if profile.padding {
            if let Some(padding) = boring_padding(unpadded) {
                let encoded_padding = wrap(EXT_PADDING, &vec![0_u8; padding])?;
                let at = padding_at.unwrap_or(encoded.len());
                encoded.insert(at, encoded_padding);
            }
        }

        let total: usize = encoded.iter().map(Vec::len).sum();
        let mut output = Vec::with_capacity(total);
        for extension in encoded {
            output.extend_from_slice(&extension);
        }
        Ok(output)
    }

    /// The GREASE value that replaces the cipher-suite placeholder.
    #[must_use]
    pub const fn grease_cipher(&self) -> u16 {
        self.grease_cipher
    }

    #[allow(clippy::too_many_lines)]
    fn encode(
        &self,
        profile: &Profile,
        ext: &Ext,
        server_name: &str,
        shares: &ShareMaterial,
    ) -> Result<Vec<u8>, PlanError> {
        match ext {
            Ext::Sni => {
                let mut body = Vec::with_capacity(5 + server_name.len());
                push_u16(&mut body, 3 + server_name.len())?;
                body.push(0);
                push_u16(&mut body, server_name.len())?;
                body.extend_from_slice(server_name.as_bytes());
                wrap(EXT_SERVER_NAME, &body)
            }
            Ext::Groups(groups) => {
                let mut body = Vec::with_capacity(2 + groups.len() * 2);
                push_u16(&mut body, groups.len() * 2)?;
                for group in groups {
                    push_u16(&mut body, usize::from(self.group_value(*group)))?;
                }
                wrap(EXT_SUPPORTED_GROUPS, &body)
            }
            Ext::Sigalgs(algorithms) => {
                let mut body = Vec::with_capacity(2 + algorithms.len() * 2);
                push_u16(&mut body, algorithms.len() * 2)?;
                for algorithm in algorithms {
                    push_u16(&mut body, usize::from(*algorithm))?;
                }
                wrap(EXT_SIGNATURE_ALGORITHMS, &body)
            }
            Ext::Alpn => {
                let mut body = Vec::new();
                let mut list = Vec::new();
                for protocol in &profile.alpn {
                    let length = u8::try_from(protocol.len()).map_err(|_| PlanError::TooLarge)?;
                    list.push(length);
                    list.extend_from_slice(protocol);
                }
                push_u16(&mut body, list.len())?;
                body.extend_from_slice(&list);
                wrap(EXT_ALPN, &body)
            }
            Ext::Status => wrap(EXT_STATUS_REQUEST, &[1, 0, 0, 0, 0]),
            Ext::Sct => wrap(EXT_SCT, &[]),
            Ext::Ems => wrap(EXT_EXTENDED_MASTER_SECRET, &[]),
            Ext::Reneg => wrap(EXT_RENEGOTIATION, &[0]),
            Ext::Points(points) => {
                let mut body = Vec::with_capacity(1 + points.len());
                body.push(u8::try_from(points.len()).map_err(|_| PlanError::TooLarge)?);
                body.extend_from_slice(points);
                wrap(EXT_EC_POINT_FORMATS, &body)
            }
            Ext::Ticket => wrap(EXT_SESSION_TICKET, &[]),
            Ext::PskModes(modes) => {
                let mut body = Vec::with_capacity(1 + modes.len());
                body.push(u8::try_from(modes.len()).map_err(|_| PlanError::TooLarge)?);
                body.extend_from_slice(modes);
                wrap(EXT_PSK_MODES, &body)
            }
            Ext::Versions(versions) => {
                let mut body = Vec::with_capacity(1 + versions.len() * 2);
                body.push(u8::try_from(versions.len() * 2).map_err(|_| PlanError::TooLarge)?);
                for version in versions {
                    let value = if *version == GREASE_PLACEHOLDER {
                        self.grease_version
                    } else {
                        *version
                    };
                    push_u16(&mut body, usize::from(value))?;
                }
                wrap(EXT_SUPPORTED_VERSIONS, &body)
            }
            Ext::KeyShare => {
                let mut entries = Vec::new();
                for share in &profile.shares {
                    let (group, data) = match share {
                        ShareGroup::Grease => (self.grease_group, vec![0_u8]),
                        ShareGroup::X25519 => (X25519_GROUP, shares.x25519.to_vec()),
                        ShareGroup::Hybrid => (
                            X25519_MLKEM768_GROUP,
                            shares.hybrid.clone().ok_or(PlanError::MissingHybrid)?,
                        ),
                    };
                    push_u16(&mut entries, usize::from(group))?;
                    push_u16(&mut entries, data.len())?;
                    entries.extend_from_slice(&data);
                }
                let mut body = Vec::with_capacity(2 + entries.len());
                push_u16(&mut body, entries.len())?;
                body.extend_from_slice(&entries);
                wrap(EXT_KEY_SHARE, &body)
            }
            Ext::CompressCert(algorithms) => {
                let mut body = Vec::with_capacity(1 + algorithms.len() * 2);
                body.push(u8::try_from(algorithms.len() * 2).map_err(|_| PlanError::TooLarge)?);
                for algorithm in algorithms {
                    push_u16(&mut body, usize::from(*algorithm))?;
                }
                wrap(EXT_COMPRESS_CERTIFICATE, &body)
            }
            Ext::Alps(code) => {
                let protocol = profile
                    .alpn
                    .iter()
                    .find(|protocol| protocol.as_slice() == b"h2")
                    .or_else(|| profile.alpn.first());
                let mut body = Vec::new();
                if let Some(protocol) = protocol {
                    let mut list = Vec::with_capacity(1 + protocol.len());
                    list.push(u8::try_from(protocol.len()).map_err(|_| PlanError::TooLarge)?);
                    list.extend_from_slice(protocol);
                    push_u16(&mut body, list.len())?;
                    body.extend_from_slice(&list);
                }
                wrap(*code, &body)
            }
            Ext::RecordSizeLimit(limit) => wrap(EXT_RECORD_SIZE_LIMIT, &limit.to_be_bytes()),
            Ext::Delegated(algorithms) => {
                let mut body = Vec::with_capacity(2 + algorithms.len() * 2);
                push_u16(&mut body, algorithms.len() * 2)?;
                for algorithm in algorithms {
                    push_u16(&mut body, usize::from(*algorithm))?;
                }
                wrap(EXT_DELEGATED_CREDENTIALS, &body)
            }
            Ext::ChannelId(code) => wrap(*code, &[]),
            Ext::Ech(_kind) => {
                let plan = self.ech.as_ref().ok_or(PlanError::MissingEch)?;
                let mut body = Vec::new();
                body.push(0); // OuterClientHello
                push_u16(&mut body, usize::from(plan.kdf))?;
                push_u16(&mut body, usize::from(plan.aead))?;
                body.push(plan.config_id);
                push_u16(&mut body, plan.encapsulated_key.len())?;
                body.extend_from_slice(&plan.encapsulated_key);
                push_u16(&mut body, plan.payload.len())?;
                body.extend_from_slice(&plan.payload);
                wrap(EXT_ECH, &body)
            }
            Ext::Grease | Ext::Padding => unreachable!("handled by extensions()"),
        }
    }

    fn group_value(&self, group: u16) -> u16 {
        if group == GREASE_PLACEHOLDER {
            self.grease_group
        } else {
            group
        }
    }
}

impl fmt::Debug for HelloPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelloPlan")
            .field("extensions", &self.order.len())
            .finish_non_exhaustive()
    }
}

struct EchPlan {
    kdf: u16,
    aead: u16,
    config_id: u8,
    encapsulated_key: [u8; 32],
    payload: Vec<u8>,
}

impl EchPlan {
    fn generate(profile: &Profile, rng: &mut Rng) -> Self {
        let kind = profile
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Ext::Ech(kind) => Some(*kind),
                _ => None,
            })
            .unwrap_or(EchKind::Chrome);
        let (kdf, aead, lengths): (u16, u16, &[u16]) = match kind {
            EchKind::Chrome => (0x0001, 0x0001, &[128, 160, 192, 224]),
            EchKind::Firefox => {
                let candidates = [(0x0001_u16, 0x0001_u16), (0x0001, 0x0003)];
                let (kdf, aead) = candidates[rng.below(candidates.len())];
                (kdf, aead, &[223])
            }
        };
        let mut config_id = [0_u8; 1];
        rng.fill(&mut config_id);
        let mut encapsulated_key = [0_u8; 32];
        rng.fill(&mut encapsulated_key);
        let chosen = lengths[rng.below(lengths.len())];
        let mut payload = vec![0_u8; usize::from(chosen) + 16];
        rng.fill(&mut payload);
        Self {
            kdf,
            aead,
            config_id: config_id[0],
            encapsulated_key,
            payload,
        }
    }
}

fn grease_value(seed: u16) -> u16 {
    let low = (seed & 0xf0) | 0x0a;
    low | (low << 8)
}

fn boring_padding(unpadded: usize) -> Option<usize> {
    if unpadded > 0xff && unpadded < 0x200 {
        let padding = 0x200 - unpadded;
        Some(if padding >= 5 { padding - 4 } else { 1 })
    } else {
        None
    }
}

fn wrap(extension: u16, body: &[u8]) -> Result<Vec<u8>, PlanError> {
    let mut output = Vec::with_capacity(4 + body.len());
    push_u16(&mut output, usize::from(extension))?;
    push_u16(&mut output, body.len())?;
    output.extend_from_slice(body);
    Ok(output)
}

fn push_u16(output: &mut Vec<u8>, value: usize) -> Result<(), PlanError> {
    let value = u16::try_from(value).map_err(|_| PlanError::TooLarge)?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// A small deterministic PRNG. Fingerprint planning needs unbiased choices,
/// not cryptographic secrecy: every value it emits is public wire data.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        let mut state = 0xcbf2_9ce4_8422_2325_u64;
        for byte in seed {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x1000_0000_01b3);
        }
        Self(state | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    pub(crate) fn below(&mut self, upper: usize) -> usize {
        debug_assert!(upper > 0);
        let upper = upper as u64;
        let zone = u64::MAX - (u64::MAX % upper);
        loop {
            let value = self.next();
            if value < zone {
                return usize::try_from(value % upper).unwrap_or(0);
            }
        }
    }

    /// A fixed-point coin: `basis_points` out of 10,000.
    pub(crate) fn coin(&mut self, basis_points: u32) -> bool {
        debug_assert!(basis_points <= 10_000);
        self.below(10_000) < basis_points as usize
    }

    pub(crate) fn fill(&mut self, output: &mut [u8]) {
        for chunk in output.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    pub(crate) fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let other = self.below(index + 1);
            values.swap(index, other);
        }
    }
}

#[cfg(test)]
mod tests;
