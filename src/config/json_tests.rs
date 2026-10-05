use super::{parse, parse_json, parse_toml, to_json};
use serde_json::{Value, json};
fn example() -> Value {
    serde_json::from_str(include_str!("../../examples/client.json")).unwrap()
}
fn rejects(v: &Value, path: &str) {
    let e = parse_json(&v.to_string()).unwrap_err();
    assert!(e.to_string().contains(path), "{e}");
}
#[test]
fn examples_are_runtime_equivalent() {
    let json = parse_json(include_str!("../../examples/client.json")).unwrap();
    let toml = parse_toml(include_str!("../../examples/client.toml")).unwrap();
    assert_eq!(json, toml);
    assert_eq!(
        parse(include_str!("../../examples/client.json")).unwrap(),
        toml
    );
    assert_eq!(parse_json(&to_json(&toml)).unwrap(), toml);
}
#[test]
fn json_rejects_duplicate_keys_at_any_depth_and_trailing_input() {
    for s in [
        "{\"inbounds\":[],\"inbounds\":[]}",
        "{\"a\":{\"secret\":1,\"secret\":2}}",
        "{\"a\":[{\"x\":1,\"x\":1}]}",
        "{}{}",
        "{\"a\":1,}",
        "{/* comment */}",
    ] {
        let e = parse_json(s).unwrap_err().to_string();
        assert!(e.contains("line"));
        assert!(!e.contains("secret"));
    }
}
#[test]
fn json_rejects_unknown_features_without_echoing_keys_or_values() {
    for key in ["routing", "dns", "mux", "log", "secret-user-id"] {
        let mut v = example();
        v[key] = json!("never-echo-this");
        let e = parse_json(&v.to_string()).unwrap_err().to_string();
        assert!(!e.contains("never-echo-this"));
        assert!(!e.contains("secret-user-id"));
    }
}
#[test]
fn json_aliases_are_equivalent_but_never_ambiguous() {
    let original = example();
    let expected = parse_json(&original.to_string()).unwrap();
    let mut v = original.clone();
    let s = v["outbounds"][0]["streamSettings"].as_object_mut().unwrap();
    s.remove("method");
    s.insert("network".into(), json!("tcp"));
    let r = s["realitySettings"].as_object_mut().unwrap();
    let key = r.remove("publicKey").unwrap();
    r.insert("password".into(), key);
    assert_eq!(parse_json(&v.to_string()).unwrap(), expected);
    v["outbounds"][0]["streamSettings"]["method"] = json!("raw");
    rejects(&v, "use method OR network");
    let mut v = original;
    v["outbounds"][0]["streamSettings"]["realitySettings"]["password"] = json!("secret");
    rejects(&v, "use publicKey OR password");
}
#[test]
fn json_keeps_all_credential_validation_and_redaction() {
    let mut v = example();
    let o = &mut v["outbounds"][0];
    o["settings"]["id"] = json!("secret-uuid");
    o["settings"]["port"] = json!(0);
    o["streamSettings"]["realitySettings"]["shortId"] = json!("secret-short-id");
    o["streamSettings"]["realitySettings"]["publicKey"] = json!("secret-key");
    o["streamSettings"]["realitySettings"]["serverName"] = json!("127.0.0.1");
    let e = parse_json(&v.to_string()).unwrap_err();
    assert!(e.problems().len() >= 5);
    let text = e.to_string();
    assert!(text.contains("outbounds[0].settings.id"));
    assert!(!text.contains("secret-"));
}
#[test]
fn json_listener_semantics_are_explicit() {
    let mut v = example();
    v.as_object_mut().unwrap().remove("inbounds");
    let c = parse_json(&v.to_string()).unwrap();
    assert!(c.listen.socks5.is_some() && c.listen.http.is_some());
    v["inbounds"] = json!([{ "protocol":"http","port":10809 }]);
    let c = parse_json(&v.to_string()).unwrap();
    assert!(c.listen.socks5.is_none());
    assert!(c.listen.http.unwrap().ip().is_loopback());
    v["inbounds"] = json!([]);
    rejects(&v, "inbounds");
}
#[test]
fn json_never_silently_opens_remote_listeners() {
    let mut v = example();
    v["inbounds"][0]["listen"] = json!("0.0.0.0");
    rejects(&v, "allowRemote");
    v["allowRemote"] = json!(true);
    let c = parse_json(&v.to_string()).unwrap();
    assert_eq!(parse_json(&to_json(&c)).unwrap(), c);
    v["allowRemote"] = json!("true");
    rejects(&v, "allowRemote");
}
#[test]
fn json_duplicate_protocols_and_bind_collisions_fail() {
    let mut v = example();
    v["inbounds"][1]["protocol"] = json!("socks");
    rejects(&v, "at most one");
    let mut v = example();
    v["inbounds"][1]["port"] = json!(10808);
    rejects(&v, "same address");
    let mut v = example();
    v["inbounds"][1]["tag"] = json!("socks-in");
    rejects(&v, "unique");
}
#[test]
fn json_unsupported_wire_modes_are_rejected() {
    for (field, value) in [
        ("flow", ""),
        ("flow", "xtls-rprx-vision-udp443"),
        ("encryption", "aes-128-gcm"),
    ] {
        let mut v = example();
        v["outbounds"][0]["settings"][field] = json!(value);
        rejects(&v, field);
    }
    for (field, value) in [("security", "tls"), ("method", "ws"), ("method", "tcp")] {
        let mut v = example();
        v["outbounds"][0]["streamSettings"][field] = json!(value);
        rejects(&v, field);
    }
    let mut v = example();
    v["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] = json!("chrome");
    rejects(&v, "fingerprint");
    let mut v = example();
    v["inbounds"][0]["settings"]["udp"] = json!(true);
    rejects(&v, "UDP");
    let mut v = example();
    v["inbounds"][0]["settings"]["auth"] = json!("password");
    rejects(&v, "auth");
}
#[test]
fn json_typed_ports_and_objects_fail_closed() {
    for bad in [
        Value::Null,
        json!(true),
        json!("443"),
        json!(443.5),
        json!(65536),
        json!(-1),
        json!(u64::MAX),
    ] {
        let mut v = example();
        v["outbounds"][0]["settings"]["port"] = bad.clone();
        rejects(&v, "port");
        v = example();
        v["inbounds"][0]["port"] = bad;
        rejects(&v, "port");
    }
    for field in ["settings", "streamSettings"] {
        let mut v = example();
        v["outbounds"][0][field] = Value::Null;
        rejects(&v, field);
    }
}
#[test]
fn json_multi_node_roundtrip_and_duplicate_detection() {
    let mut v = example();
    let mut next = v["outbounds"][0].clone();
    next["tag"] = json!("backup");
    next["settings"]["address"] = json!("backup.example.com");
    v["outbounds"].as_array_mut().unwrap().push(next);
    let c = parse_json(&v.to_string()).unwrap();
    assert_eq!(c.nodes.len(), 2);
    assert_eq!(parse_json(&to_json(&c)).unwrap(), c);
    v["outbounds"][1]["tag"] = json!("home-entry");
    rejects(&v, "tag");
    v["outbounds"][1]["tag"] = json!("backup");
    v["outbounds"][1]["settings"]["address"] = json!("www.example.com");
    rejects(&v, "duplicates");
}
#[test]
fn json_ipv6_listen_and_endpoint_roundtrip() {
    let mut v = example();
    v["inbounds"][0]["listen"] = json!("::1");
    v["outbounds"][0]["settings"]["address"] = json!("2001:db8::1");
    let c = parse_json(&v.to_string()).unwrap();
    assert_eq!(parse_json(&to_json(&c)).unwrap(), c);
}
#[test]
fn json_deep_input_is_rejected_without_panicking() {
    let s = format!("{}0{}", "[".repeat(200), "]".repeat(200));
    assert!(parse_json(&s).is_err());
}
#[test]
fn json_explicit_null_is_not_a_default() {
    for path in [
        "/outbounds/0/tag",
        "/outbounds/0/streamSettings/method",
        "/outbounds/0/settings/flow",
        "/inbounds/0/settings",
        "/inbounds/0/listen",
    ] {
        let mut v = example();
        *v.pointer_mut(path).unwrap() = Value::Null;
        assert!(parse_json(&v.to_string()).is_err(), "{path}");
    }
}
