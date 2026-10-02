//! Configuration: what the operator declares, checked before a byte is sent.
//!
//! Two rules shape this module, and both come from how REALITY fails.
//!
//! The first is that a bad value must be *named*. REALITY answers an
//! unparseable, unauthenticated or replayed `ClientHello` by proxying the
//! connection to the cover, so a client with a mistyped key, an IP address in
//! `serverName` or a short ID the node does not own sees no error at all — only
//! a server that never works. Validation is the only place that can say which
//! field is wrong, so it collects **every** problem in the file rather than
//! stopping at the first.
//!
//! The second is that the field names carry the migration. v2.0.1 has no client
//! role and therefore no client schema to copy, so its names are reused where
//! the meaning is the same (`publicKey`, `shortId`, camelCase, unknown keys
//! rejected) and an unknown key's message names the Xray link parameter it came
//! from. A paste of `pbk`/`sni`/`sid` is a typo with a documented answer, not a
//! mystery.

mod grammar;

use std::fmt;
use std::net::SocketAddr;

/// Default SOCKS5 listen address, loopback.
pub const DEFAULT_SOCKS5: &str = "127.0.0.1:10808";
/// Default HTTP CONNECT listen address, loopback.
pub const DEFAULT_HTTP: &str = "127.0.0.1:10809";

/// Errors found while reading a configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigError {
    problems: Vec<Problem>,
}

/// One thing wrong with a configuration, and where.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Problem {
    /// Dotted position in the file, such as `node[0].reality.publicKey`.
    pub path: String,
    /// What is wrong, phrased so it can be quoted to an operator.
    pub message: String,
}

impl Problem {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl ConfigError {
    /// A rejection with exactly one problem.
    #[must_use]
    pub fn one(path: &str, message: &str) -> Self {
        Self {
            problems: vec![Problem::new(path, message)],
        }
    }

    /// Every problem, in the order they were found.
    #[must_use]
    pub fn problems(&self) -> &[Problem] {
        &self.problems
    }

    /// Whether nothing was wrong.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.problems.is_empty()
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, problem) in self.problems.iter().enumerate() {
            if index > 0 {
                formatter.write_str("\n")?;
            }
            write!(formatter, "{}: {}", problem.path, problem.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// What to listen on, and how.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Listen {
    /// SOCKS5 address, or `None` when that inbound is disabled.
    pub socks5: Option<SocketAddr>,
    /// HTTP CONNECT address, or `None` when that inbound is disabled.
    pub http: Option<SocketAddr>,
}

impl Listen {
    /// Every address this configuration binds.
    pub fn addresses(&self) -> impl Iterator<Item = SocketAddr> {
        self.socks5.into_iter().chain(self.http)
    }
}

/// The `[listen]` table, including the one flag that is not an address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Declared {
    listen: Listen,
    allow_remote: bool,
}

/// One server this client may use.
#[derive(Clone, Eq, PartialEq)]
pub struct Node {
    /// Operator-visible label, used in logs and in `doctor` output.
    pub name: String,
    /// Host name or IP literal of the entry listener.
    pub address: String,
    /// Entry listener port.
    pub port: u16,
    /// The REALITY half that identifies which user this connection is.
    pub reality: Reality,
    /// Raw user id, never rendered.
    user_id: [u8; 16],
}

impl Node {
    /// `address:port` as one string, for a dial target or a log line.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }

    /// The raw sixteen user id bytes the request encoder needs.
    #[must_use]
    pub const fn user_id(&self) -> &[u8; 16] {
        &self.user_id
    }
}

/// The REALITY parameters of one node.
#[derive(Clone, Eq, PartialEq)]
pub struct Reality {
    /// The server's X25519 public key. Public material, safe to print.
    pub public_key: [u8; 32],
    /// Server name sent as SNI, and matched case-insensitively by the node.
    pub server_name: String,
    /// Eight wire bytes, right-zero-padded from the configured hex.
    short_id: [u8; 8],
    /// How the short ID was spelled, kept only so `doctor` can echo the shape.
    short_id_len: usize,
}

impl Reality {
    /// The short ID as it travels on the wire.
    #[must_use]
    pub const fn short_id(&self) -> &[u8; 8] {
        &self.short_id
    }

    /// Characters in the configured short ID, which is all a diagnostic may say
    /// about it: the value selects a user, so it is credential material.
    #[must_use]
    pub const fn short_id_chars(&self) -> usize {
        self.short_id_len
    }
}

impl fmt::Debug for Node {
    /// Prints what identifies a node without printing what authenticates it.
    ///
    /// The user id is omitted entirely and the short ID appears only as a
    /// length, because both name a user on a server that may be shared.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use base64::Engine as _;
        formatter
            .debug_struct("Node")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint())
            .field("userId", &"[REDACTED]")
            .field(
                "publicKey",
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.reality.public_key),
            )
            .field("serverName", &self.reality.server_name)
            .field("shortId", &self.reality.short_id_chars())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Reality {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Reality")
            .field("serverName", &self.server_name)
            .field("shortId", &self.short_id_chars())
            .finish_non_exhaustive()
    }
}

/// A validated client configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Local listeners.
    pub listen: Listen,
    /// Usable servers, in declaration order.
    pub nodes: Vec<Node>,
}

/// Reads a configuration.
///
/// # Errors
///
/// Returns every problem found, as a [`ConfigError`].
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let document = match text.parse::<toml::Table>() {
        Ok(table) => table,
        Err(error) => {
            return Err(ConfigError::one(
                "<file>",
                &describe_syntax_error(&error, text),
            ));
        }
    };
    let mut problems = Vec::new();
    reject_unknown(&document, &["listen", "node"], "<file>", &mut problems);

    let declared = read_listen(&document, &mut problems);
    if let Some(settings) = &declared {
        guard_loopback(&settings.listen, settings.allow_remote, &mut problems);
    }
    let reported = problems.len();
    let nodes = read_nodes(&document, &mut problems);
    // An entry that was refused for its own reasons has already said so; only a
    // file with nothing wrong but emptiness needs the missing-list message.
    if nodes.is_empty() && problems.len() == reported {
        problems.push(Problem::new("node", "at least one [[node]] is required"));
    }
    duplicates(&nodes, &mut problems);

    if !problems.is_empty() {
        return Err(ConfigError { problems });
    }
    Ok(Config {
        listen: declared.map_or_else(default_listen, |settings| settings.listen),
        nodes,
    })
}

/// The bind pair a file that says nothing about listening gets: both inbounds,
/// both on loopback.
fn default_listen() -> Listen {
    Listen {
        socks5: grammar::bind_address(DEFAULT_SOCKS5),
        http: grammar::bind_address(DEFAULT_HTTP),
    }
}

/// Refuses a bind address that other machines can reach.
///
/// This proxy selects nodes, holds credentials and keeps per-node state, so an
/// open relay on a shared host is a credential leak with someone else's traffic
/// attributed to this user id. Loopback-only is the default and the escape hatch
/// is a single explicit boolean.
fn guard_loopback(listen: &Listen, allow_remote: bool, problems: &mut Vec<Problem>) {
    if allow_remote {
        return;
    }
    for (path, address) in [
        ("listen.socks5", listen.socks5),
        ("listen.http", listen.http),
    ] {
        let Some(address) = address else { continue };
        if address.ip().is_loopback() {
            continue;
        }
        problems.push(Problem::new(
            path,
            format!(
                "binds {address}, which every host on the network can reach; a proxy that \
                 selects nodes and holds credentials must stay on loopback unless \
                 listen.allowRemote = true says otherwise"
            ),
        ));
    }
}

/// Renders a TOML syntax error without repeating what it found.
///
/// The library's own rendering quotes the offending line, and in this file the
/// lines most likely to be wrong are exactly the ones that must not be
/// reproduced: a user id missing a dash, a key with a stray character. Position
/// plus a fixed explanation identifies the line for an operator while leaking
/// nothing about the value.
fn describe_syntax_error(error: &toml::de::Error, text: &str) -> String {
    let position = error.span().map_or_else(String::new, |span| {
        let offset = span.start.min(text.len());
        let line = text[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = offset - text[..offset].rfind('\n').map_or(0, |index| index + 1) + 1;
        format!(" at line {line}, column {column}")
    });
    format!(
        "is not valid TOML{position} (a value on that line is malformed, or is not the type \
         this key expects)"
    )
}

fn read_listen(document: &toml::Table, problems: &mut Vec<Problem>) -> Option<Declared> {
    // Absent means "not declared", which `parse` answers with the default pair.
    let value = document.get("listen")?;
    let Some(table) = value.as_table() else {
        problems.push(Problem::new("listen", "must be a [listen] table"));
        return None;
    };
    reject_unknown(
        table,
        &["socks5", "http", "allowRemote"],
        "listen",
        problems,
    );
    let socks5 = read_bind(table, "socks5", DEFAULT_SOCKS5, problems);
    let http = read_bind(table, "http", DEFAULT_HTTP, problems);
    let mut allow_remote = false;
    if let Some(value) = table.get("allowRemote") {
        match value.as_bool() {
            Some(flag) => allow_remote = flag,
            None => problems.push(Problem::new("listen.allowRemote", "must be true or false")),
        }
    }
    Some(Declared {
        listen: Listen { socks5, http },
        allow_remote,
    })
}

/// One listen entry: absent means default, empty means disabled.
fn read_bind(
    table: &toml::Table,
    key: &str,
    default: &str,
    problems: &mut Vec<Problem>,
) -> Option<SocketAddr> {
    let path = format!("listen.{key}");
    let Some(value) = table.get(key) else {
        return grammar::bind_address(default);
    };
    let Some(text) = value.as_str() else {
        problems.push(Problem::new(&path, "must be a \"host:port\" string"));
        return None;
    };
    if text.is_empty() {
        return None;
    }
    let Some(address) = grammar::bind_address(text) else {
        problems.push(Problem::new(
            &path,
            "must be a numeric address such as 127.0.0.1:10808, or \"\" to disable",
        ));
        return None;
    };
    Some(address)
}

const ARRAY_OF_TABLES: &str = "must be an array of tables, written [[node]]";

fn read_nodes(document: &toml::Table, problems: &mut Vec<Problem>) -> Vec<Node> {
    let Some(value) = document.get("node") else {
        return Vec::new();
    };
    let Some(entries) = value.as_array() else {
        problems.push(Problem::new("node", ARRAY_OF_TABLES));
        return Vec::new();
    };
    let mut tables = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(table) = entry.as_table() else {
            problems.push(Problem::new("node", ARRAY_OF_TABLES));
            return Vec::new();
        };
        tables.push(table);
    }
    tables
        .into_iter()
        .enumerate()
        .filter_map(|(index, table)| read_node(index, table, problems))
        .collect()
}

fn read_node(index: usize, table: &toml::Table, problems: &mut Vec<Problem>) -> Option<Node> {
    let root = format!("node[{index}]");
    reject_unknown(
        table,
        &["name", "address", "port", "userId", "reality"],
        &root,
        problems,
    );
    // Each field is checked on its own, so that one bad paste reports every
    // mistake in the entry rather than the first one and then goes quiet.
    let name = read_name(table, &root, index, problems);
    let address = read_address(table, &root, problems);
    let port = read_port(table, &root, problems);
    let user_id = read_user(table, &root, problems);
    let reality = read_reality(table, &root, problems);
    match (name, address, port, user_id, reality) {
        (Some(name), Some(address), Some(port), Some(user_id), Some(reality)) => Some(Node {
            name,
            address,
            port,
            reality,
            user_id,
        }),
        _ => None,
    }
}

/// A node always has a name, so a blank one is a problem rather than a default.
fn read_name(
    table: &toml::Table,
    root: &str,
    index: usize,
    problems: &mut Vec<Problem>,
) -> Option<String> {
    match table.get("name") {
        None => Some(format!("node-{}", index + 1)),
        Some(value) => match value.as_str() {
            Some(text) if !text.trim().is_empty() => Some(text.to_owned()),
            _ => {
                problems.push(Problem::new(
                    format!("{root}.name"),
                    "must be a non-empty string, or omitted for node-N",
                ));
                None
            }
        },
    }
}

fn read_address(table: &toml::Table, root: &str, problems: &mut Vec<Problem>) -> Option<String> {
    let path = format!("{root}.address");
    let address = text(table, "address", &path, problems)?;
    if grammar::is_hostname_or_ip(&address) {
        Some(address)
    } else {
        problems.push(Problem::new(
            path,
            "must be a DNS name or an IP literal, without a port",
        ));
        None
    }
}

fn read_port(table: &toml::Table, root: &str, problems: &mut Vec<Problem>) -> Option<u16> {
    let path = format!("{root}.port");
    let number = number(table, "port", &path, problems)?;
    let Some(port) = u16::try_from(number).ok().filter(|port| *port != 0) else {
        problems.push(Problem::new(path, "must be between 1 and 65535"));
        return None;
    };
    Some(port)
}

fn read_user(table: &toml::Table, root: &str, problems: &mut Vec<Problem>) -> Option<[u8; 16]> {
    let path = format!("{root}.userId");
    let text = text(table, "userId", &path, problems)?;
    let Some(user_id) = grammar::uuid_bytes(&text) else {
        problems.push(Problem::new(
            path,
            "must be a hyphenated UUID, 36 characters",
        ));
        return None;
    };
    Some(user_id)
}

fn read_reality(table: &toml::Table, root: &str, problems: &mut Vec<Problem>) -> Option<Reality> {
    let path = format!("{root}.reality");
    let Some(value) = table.get("reality") else {
        problems.push(Problem::new(
            &path,
            "is required: this client speaks REALITY only",
        ));
        return None;
    };
    let Some(nested) = value.as_table() else {
        problems.push(Problem::new(&path, "must be a table"));
        return None;
    };
    reject_unknown(
        nested,
        &["publicKey", "shortId", "serverName"],
        &path,
        problems,
    );
    let public_key = read_key(nested, &path, problems);
    let short_id = read_short_id(nested, &path, problems);
    let server_name = read_server_name(nested, &path, problems);
    match (public_key, short_id, server_name) {
        (Some(public_key), Some((short_id, short_id_len)), Some(server_name)) => Some(Reality {
            public_key,
            server_name,
            short_id,
            short_id_len,
        }),
        _ => None,
    }
}

fn read_key(nested: &toml::Table, path: &str, problems: &mut Vec<Problem>) -> Option<[u8; 32]> {
    let key_path = format!("{path}.publicKey");
    let encoded = text(nested, "publicKey", &key_path, problems)?;
    // The one wording for every way a key can be wrong, so that a log line
    // cannot reveal whether the value was short, padded or plain garbage.
    let Some(public_key) = grammar::decode_key(&encoded) else {
        problems.push(Problem::new(key_path, grammar::KEY_RULE));
        return None;
    };
    Some(public_key)
}

fn read_short_id(
    nested: &toml::Table,
    path: &str,
    problems: &mut Vec<Problem>,
) -> Option<([u8; 8], usize)> {
    let id_path = format!("{path}.shortId");
    let encoded = text(nested, "shortId", &id_path, problems)?;
    let Some(short_id) = grammar::short_id_bytes(&encoded) else {
        problems.push(Problem::new(
            id_path,
            "must be 2 to 16 hexadecimal characters, an even number of them",
        ));
        return None;
    };
    Some((short_id, encoded.len()))
}

fn read_server_name(
    nested: &toml::Table,
    path: &str,
    problems: &mut Vec<Problem>,
) -> Option<String> {
    let name_path = format!("{path}.serverName");
    let server_name = text(nested, "serverName", &name_path, problems)?;
    if grammar::is_concrete_server_name(&server_name) {
        Some(server_name)
    } else {
        problems.push(Problem::new(
            name_path,
            "must be one concrete ASCII DNS name: the node matches SNI case-insensitively and \
             normalises nothing else, so an IP literal, a wildcard or a non-ASCII name is \
             relayed to the cover rather than rejected",
        ));
        None
    }
}

/// Reports nodes that cannot fail apart, which is how a copy-paste hides.
fn duplicates(nodes: &[Node], problems: &mut Vec<Problem>) {
    for (index, node) in nodes.iter().enumerate() {
        for (other, earlier) in nodes.iter().enumerate().take(index) {
            let same_path = node.address == earlier.address && node.port == earlier.port;
            let same_identity = node.user_id == earlier.user_id
                && node.reality.short_id == earlier.reality.short_id
                && node.reality.public_key == earlier.reality.public_key;
            if same_path && same_identity {
                problems.push(Problem::new(
                    format!("node[{index}].address"),
                    format!(
                        "and node[{other}] are the same server and user, so a failure of one is \
                         a failure of both and the list offers no redundancy",
                    ),
                ));
            }
        }
    }
}

fn text(table: &toml::Table, key: &str, path: &str, problems: &mut Vec<Problem>) -> Option<String> {
    let Some(value) = table.get(key) else {
        problems.push(Problem::new(path, "is required"));
        return None;
    };
    let Some(text) = value.as_str() else {
        problems.push(Problem::new(path, "must be a string"));
        return None;
    };
    Some(text.to_owned())
}

fn number(table: &toml::Table, key: &str, path: &str, problems: &mut Vec<Problem>) -> Option<i64> {
    let Some(value) = table.get(key) else {
        problems.push(Problem::new(path, "is required"));
        return None;
    };
    let Some(number) = value.as_integer() else {
        problems.push(Problem::new(path, "must be an integer"));
        return None;
    };
    Some(number)
}

/// Reports keys the schema does not have.
///
/// An unknown key is refused rather than ignored because a misspelled
/// credential is otherwise silent, and because an operator arriving from Xray
/// will paste `pbk`, `sni` and `sid` before reading a manual. Each of those has
/// a one-line answer naming its equivalent here.
fn reject_unknown(table: &toml::Table, allowed: &[&str], path: &str, problems: &mut Vec<Problem>) {
    const MIGRATIONS: &[(&str, &str)] = &[
        ("pbk", "the REALITY public key goes in publicKey"),
        ("sni", "the SNI goes in serverName"),
        ("sid", "the short ID goes in shortId"),
        (
            "fp",
            "this client sends its own ClientHello shape, so there is no fingerprint field: \
                v2.0.1 never inspects one",
        ),
        (
            "flow",
            "the flow is fixed to xtls-rprx-vision, which the node requires and therefore \
                  has no field",
        ),
        ("id", "the user id goes in userId"),
        ("uuid", "the user id goes in userId"),
        ("target", "the server host goes in address"),
        ("dest", "the server host goes in address"),
        (
            "security",
            "REALITY is the only transport this client speaks",
        ),
        ("network", "only TCP is supported"),
        ("type", "REALITY is the only transport this client speaks"),
    ];
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            let hint = MIGRATIONS
                .iter()
                .find(|(name, _)| *name == key.as_str())
                .map_or_else(String::new, |(_, answer)| format!("; {answer}"));
            problems.push(Problem::new(
                if path == "<file>" {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                },
                format!(
                    "is not a key this client reads (accepted: {}){hint}",
                    allowed.join(", ")
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests;
