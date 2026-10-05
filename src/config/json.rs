//! Strict, Xray-shaped JSON projected into the same validated runtime model.
//! Never silently ignore a feature or a duplicate/ambiguous setting.
use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use base64::Engine as _;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};

use super::{Config, ConfigError, Listen, Node, Problem, default_listen, duplicates, read_node};

type Object = Map<String, Value>;

// serde_json::Value normally uses last-key-wins. Reject repeated keys at EVERY
// depth before any schema projection, even if their values happen to match.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}
struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON without repeated keys")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
        Ok(Unique(Value::Bool(v)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Unique(Value::Number(n)))
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
        Ok(Unique(Value::String(v.to_owned())))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
        Ok(Unique(Value::String(v)))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
        let mut values = Vec::new();
        while let Some(Unique(v)) = seq.next_element()? {
            values.push(v);
        }
        Ok(Unique(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut values = Object::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            let Unique(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(Unique(Value::Object(values)))
    }
}

/// Reads the primary JSON format. Unknown features and duplicate keys fail closed.
///
/// # Errors
/// Returns syntax locations or all semantic problems without credential values.
pub fn parse_json(text: &str) -> Result<Config, ConfigError> {
    let Unique(value) = serde_json::from_str::<Unique>(text).map_err(|e| ConfigError::one(
        "<file>", &format!("invalid JSON or duplicate key at line {}, column {}; comments and trailing commas are not supported", e.line(), e.column())))?;
    let mut problems = Vec::new();
    let Some(root) = object(&value, "<file>", &mut problems) else {
        return Err(ConfigError { problems });
    };
    unknown(
        root,
        &["inbounds", "outbounds", "allowRemote"],
        "<file>",
        &mut problems,
    );
    let remote = boolean(root, "allowRemote", false, "allowRemote", &mut problems);
    let listen = inbounds(root, remote, &mut problems);
    let mut nodes = Vec::new();
    let mut tags = BTreeSet::new();
    match root.get("outbounds").and_then(Value::as_array) {
        Some(entries) if !entries.is_empty() => {
            for (i, entry) in entries.iter().enumerate() {
                if let Some(node) = outbound(entry, i, &mut problems) {
                    if !tags.insert(node.name.clone()) {
                        problems.push(Problem::new(
                            format!("outbounds[{i}].tag"),
                            "must be unique",
                        ));
                    }
                    nodes.push(node);
                }
            }
        }
        _ => problems.push(Problem::new(
            "outbounds",
            "must be a non-empty array of VLESS outbounds",
        )),
    }
    let before = problems.len();
    duplicates(&nodes, &mut problems);
    for p in &mut problems[before..] {
        p.path = p
            .path
            .replace("node[", "outbounds[")
            .replace(".address", ".settings.address");
        "duplicates an earlier server and identity; it provides no independent redundancy"
            .clone_into(&mut p.message);
    }
    if problems.is_empty() {
        Ok(Config { listen, nodes })
    } else {
        Err(ConfigError { problems })
    }
}

fn object<'a>(v: &'a Value, path: &str, problems: &mut Vec<Problem>) -> Option<&'a Object> {
    let result = v.as_object();
    if result.is_none() {
        problems.push(Problem::new(path, "must be an object"));
    }
    result
}
fn unknown(o: &Object, allowed: &[&str], path: &str, problems: &mut Vec<Problem>) {
    for key in o.keys() {
        if !allowed.contains(&key.as_str()) {
            let hint = match key.as_str() {
                "vnext" => {
                    "legacy vnext/users nesting is unsupported; flatten one server/user into settings.address, port, id, encryption and flow"
                }
                "fingerprint" | "fp" => {
                    "fingerprint emulation is unsupported; the client uses its native ClientHello"
                }
                "routing" => {
                    "routing rules are unsupported; every outbound participates in automatic node selection"
                }
                "log" => "configure logging with --log-level, not an Xray log object",
                "mux" => "Mux is unsupported; every tunnel uses its own TCP connection",
                _ => "unsupported field; remove it rather than assuming Xray behavior",
            };
            // Unknown property names are also untrusted and may contain secrets.
            problems.push(Problem::new(format!("{path}.<unknown>"), hint));
        }
    }
}
fn boolean(o: &Object, key: &str, default: bool, path: &str, problems: &mut Vec<Problem>) -> bool {
    match o.get(key) {
        None => default,
        Some(Value::Bool(v)) => *v,
        _ => {
            problems.push(Problem::new(path, "must be a boolean"));
            default
        }
    }
}
fn fixed(
    o: &Object,
    key: &str,
    allowed: &[&str],
    required: bool,
    path: &str,
    problems: &mut Vec<Problem>,
) {
    match o.get(key) {
        None if !required => (),
        Some(Value::String(v)) if allowed.contains(&v.as_str()) => (),
        _ => problems.push(Problem::new(
            format!("{path}.{key}"),
            format!("must be {}", allowed.join(" or ")),
        )),
    }
}
fn inbounds(root: &Object, remote: bool, problems: &mut Vec<Problem>) -> Listen {
    let Some(v) = root.get("inbounds") else {
        return default_listen();
    };
    let mut listen = Listen {
        socks5: None,
        http: None,
    };
    let Some(entries) = v.as_array() else {
        problems.push(Problem::new("inbounds", "must be an array"));
        return listen;
    };
    if entries.is_empty() {
        problems.push(Problem::new(
            "inbounds",
            "must contain at least one listener",
        ));
    }
    let mut protocols = BTreeSet::new();
    let mut tags = BTreeSet::new();
    for (i, v) in entries.iter().enumerate() {
        let path = format!("inbounds[{i}]");
        let Some(o) = object(v, &path, problems) else {
            continue;
        };
        unknown(
            o,
            &["tag", "listen", "port", "protocol", "settings"],
            &path,
            problems,
        );
        if let Some(tag) = o.get("tag") {
            match tag.as_str().filter(|s| !s.trim().is_empty()) {
                Some(s) if tags.insert(s) => (),
                _ => problems.push(Problem::new(
                    format!("{path}.tag"),
                    "must be a unique non-empty string",
                )),
            }
        }
        let protocol = o.get("protocol").and_then(Value::as_str);
        fixed(o, "protocol", &["socks", "http"], true, &path, problems);
        if let Some(s) = protocol {
            if !protocols.insert(s) {
                problems.push(Problem::new(
                    format!("{path}.protocol"),
                    "at most one listener per protocol is supported",
                ));
            }
        }
        let ip = match o.get("listen") {
            None => Some(IpAddr::from([127, 0, 0, 1])),
            Some(Value::String(s)) => s.parse::<IpAddr>().ok(),
            _ => None,
        };
        if ip.is_none() {
            problems.push(Problem::new(
                format!("{path}.listen"),
                "must be a numeric IPv4 or IPv6 address without a port",
            ));
        }
        let port = o
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|v| u16::try_from(v).ok())
            .filter(|v| *v != 0);
        if port.is_none() {
            problems.push(Problem::new(
                format!("{path}.port"),
                "must be an integer between 1 and 65535",
            ));
        }
        inbound_settings(o, protocol, &path, problems);
        if let (Some(ip), Some(port)) = (ip, port) {
            if !remote && !ip.is_loopback() {
                problems.push(Problem::new(format!("{path}.listen"), "non-loopback requires explicit allowRemote: true; listeners have no authentication"));
            }
            let bind = Some(SocketAddr::new(ip, port));
            match protocol {
                Some("socks") => listen.socks5 = bind,
                Some("http") => listen.http = bind,
                _ => (),
            }
        }
    }
    if listen.socks5.is_some() && listen.socks5 == listen.http {
        problems.push(Problem::new(
            "inbounds",
            "SOCKS5 and HTTP listeners must not share the same address and port",
        ));
    }
    listen
}

fn outbound(v: &Value, i: usize, problems: &mut Vec<Problem>) -> Option<Node> {
    let path = format!("outbounds[{i}]");
    let o = object(v, &path, problems)?;
    unknown(
        o,
        &["tag", "protocol", "settings", "streamSettings"],
        &path,
        problems,
    );
    fixed(o, "protocol", &["vless"], true, &path, problems);
    let mut table = toml::Table::new();
    if let Some(tag) = o.get("tag") {
        copy_scalar(tag, "name", &mut table);
    }
    let empty = Value::Null;
    let settings = object(
        o.get("settings").unwrap_or(&empty),
        &format!("{path}.settings"),
        problems,
    );
    if let Some(s) = settings {
        unknown(
            s,
            &["address", "port", "id", "encryption", "flow"],
            &format!("{path}.settings"),
            problems,
        );
        fixed(
            s,
            "encryption",
            &["none"],
            false,
            &format!("{path}.settings"),
            problems,
        );
        fixed(
            s,
            "flow",
            &["xtls-rprx-vision"],
            false,
            &format!("{path}.settings"),
            problems,
        );
        for (key, dest) in [("address", "address"), ("port", "port"), ("id", "userId")] {
            if let Some(v) = s.get(key) {
                copy_scalar(v, dest, &mut table);
            }
        }
    }
    outbound_stream(o, &path, &mut table, problems);
    let before = problems.len();
    let result = read_node(i, &table, problems);
    for p in &mut problems[before..] {
        p.path = p
            .path
            .replace(
                &format!("node[{i}].reality"),
                &format!("{path}.streamSettings.realitySettings"),
            )
            .replace(&format!("node[{i}].userId"), &format!("{path}.settings.id"))
            .replace(&format!("node[{i}].name"), &format!("{path}.tag"))
            .replace(
                &format!("node[{i}].address"),
                &format!("{path}.settings.address"),
            )
            .replace(&format!("node[{i}].port"), &format!("{path}.settings.port"));
    }
    result
}

// Invalid scalar types are represented as a boolean so the shared validator
// rejects them with a path, without serializing or echoing arbitrary input.
fn copy_scalar(v: &Value, key: &str, dest: &mut toml::Table) {
    let value = match v {
        Value::String(s) => toml::Value::String(s.clone()),
        Value::Number(n) => n
            .as_i64()
            .map_or(toml::Value::Boolean(false), toml::Value::Integer),
        _ => toml::Value::Boolean(false),
    };
    dest.insert(key.to_owned(), value);
}

/// Canonical JSON for an already validated configuration (contains credentials).
/// Intended for explicit migration to a protected file, never diagnostics.
#[must_use]
pub fn to_json(config: &Config) -> String {
    let mut inbounds = Vec::new();
    for (protocol, bind) in [
        ("socks", config.listen.socks5),
        ("http", config.listen.http),
    ] {
        if let Some(bind) = bind {
            inbounds.push(json!({"tag":protocol,"listen":bind.ip().to_string(),"port":bind.port(),"protocol":protocol}));
        }
    }
    let outbounds: Vec<Value> = config.nodes.iter().map(|n| json!({
        "tag":n.name,"protocol":"vless",
        "settings":{"address":n.address,"port":n.port,"id":uuid::Uuid::from_bytes(*n.user_id()).to_string(),"encryption":"none","flow":"xtls-rprx-vision"},
        "streamSettings":{"method":"raw","security":"reality","realitySettings":{
            "publicKey":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n.reality.public_key),
            "shortId":hex_short_id(&n.reality),
            "serverName":n.reality.server_name
        }}
    })).collect();
    let result = json!({"allowRemote":config.listen.addresses().any(|a| !a.ip().is_loopback()),"inbounds":inbounds,"outbounds":outbounds});
    // Serializing Value cannot fail: no maps with non-string keys or NaN exist.
    format!("{result:#}\n")
}

fn inbound_settings(o: &Object, protocol: Option<&str>, path: &str, problems: &mut Vec<Problem>) {
    if let Some(settings) = o
        .get("settings")
        .and_then(|v| object(v, &format!("{path}.settings"), problems))
    {
        let allowed = if protocol == Some("socks") {
            &["auth", "udp"][..]
        } else {
            &[][..]
        };
        unknown(settings, allowed, &format!("{path}.settings"), problems);
        if protocol == Some("socks") {
            fixed(
                settings,
                "auth",
                &["noauth"],
                false,
                &format!("{path}.settings"),
                problems,
            );
            if boolean(
                settings,
                "udp",
                false,
                &format!("{path}.settings.udp"),
                problems,
            ) {
                problems.push(Problem::new(
                    format!("{path}.settings.udp"),
                    "must be false; UDP is unsupported",
                ));
            }
        }
    }
}

fn outbound_stream(o: &Object, path: &str, table: &mut toml::Table, problems: &mut Vec<Problem>) {
    let empty = Value::Null;
    if let Some(s) = object(
        o.get("streamSettings").unwrap_or(&empty),
        &format!("{path}.streamSettings"),
        problems,
    ) {
        unknown(
            s,
            &["method", "network", "security", "realitySettings"],
            &format!("{path}.streamSettings"),
            problems,
        );
        if s.contains_key("method") && s.contains_key("network") {
            problems.push(Problem::new(
                format!("{path}.streamSettings"),
                "use method OR network, not both",
            ));
        }
        fixed(
            s,
            "method",
            &["raw"],
            false,
            &format!("{path}.streamSettings"),
            problems,
        );
        fixed(
            s,
            "network",
            &["tcp", "raw"],
            false,
            &format!("{path}.streamSettings"),
            problems,
        );
        fixed(
            s,
            "security",
            &["reality"],
            true,
            &format!("{path}.streamSettings"),
            problems,
        );
        if let Some(r) = object(
            s.get("realitySettings").unwrap_or(&empty),
            &format!("{path}.streamSettings.realitySettings"),
            problems,
        ) {
            unknown(
                r,
                &["publicKey", "password", "shortId", "serverName"],
                &format!("{path}.streamSettings.realitySettings"),
                problems,
            );
            if r.contains_key("publicKey") && r.contains_key("password") {
                problems.push(Problem::new(
                    format!("{path}.streamSettings.realitySettings"),
                    "use publicKey OR password, not both",
                ));
            }
            let mut reality = toml::Table::new();
            for key in ["publicKey", "shortId", "serverName"] {
                let v = if key == "publicKey" {
                    r.get(key).or_else(|| r.get("password"))
                } else {
                    r.get(key)
                };
                if let Some(v) = v {
                    copy_scalar(v, key, &mut reality);
                }
            }
            table.insert("reality".to_owned(), toml::Value::Table(reality));
        }
    }
}

fn hex_short_id(reality: &super::Reality) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(16);
    for byte in reality.short_id() {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value.truncate(reality.short_id_chars());
    value
}
