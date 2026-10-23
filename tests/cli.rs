//! The command line, run as a subprocess.
//!
//! These are not unit tests of formatting. Each one pins a promise an operator or
//! a script depends on: that the exit code is a real answer, that a file with
//! twenty problems reports twenty times, and that nothing any command prints
//! carries a user id.
//!
//! Everything runs the binary `cargo` just built, through
//! `CARGO_BIN_EXE_rust-reality-client`, so this suite is also the proof that the
//! thing under test is the thing that ships. Nothing here reaches outside the
//! machine: every node is `127.0.0.1:1`, which refuses TCP wherever it is tried,
//! so a probe fails at the transport and never asks a resolver or a network.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The seven words the taxonomy has, in the order `explain` lists them.
const FAMILIES: [&str; 7] = [
    "local",
    "dns",
    "connect",
    "timeout",
    "handshake",
    "rejected",
    "idle",
];

/// The template's node, swapped for one that is unreachable without a network.
fn unreachable(text: &str) -> String {
    text.replace("address = \"www.example.com\"", "address = \"127.0.0.1\"")
        .replace("port = 443", "port = 1")
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rust-reality-client"))
}

/// A scratch file inside the build directory.
///
/// Not the system temp dir: this project develops only inside its own tree, and a
/// test that cannot clean up after itself should at least leave its mess where
/// `cargo clean` finds it.
fn scratch(name: &str) -> PathBuf {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("tmp-tests");
    std::fs::create_dir_all(&directory).expect("the build directory is creatable");
    directory.join(name)
}

/// Writes a file for the next invocation and returns its path.
fn write(name: &str, text: &str) -> PathBuf {
    let path = scratch(name);
    std::fs::write(&path, text).expect("the scratch directory is writable");
    path
}

/// Runs the shipped template through `generate`, then rewrites its node so no
/// test can depend on a name resolving.
fn template(name: &str) -> PathBuf {
    let path = write(name, "");
    let output = run(&["generate", "--out", &path.display().to_string()]);
    assert_eq!(code(&output), 0, "`generate` failed: {}", said(&output));
    let text = std::fs::read_to_string(&path).expect("`generate` wrote the file it named");
    write(name, &unreachable(&text))
}

/// One string one command can be given, for the paths that appear in arguments.
fn shown(path: &Path) -> String {
    path.display().to_string()
}

/// The value of a top-level `key = "value"` line, quoted or absent.
fn quoted(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} = \"");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(|rest| rest.split('"').next().unwrap_or_default().to_owned())
}

/// Runs one invocation to completion.
fn run(arguments: &[&str]) -> Output {
    binary()
        .args(arguments)
        .output()
        .expect("the binary this build produced can be executed")
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the process exited with a code rather than a signal")
}

/// Both streams as one haystack, because a message may legitimately go to either.
fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// `generate` then `check` is the shipped example validating itself.
#[test]
fn the_generated_template_is_a_valid_configuration() {
    let path = template("template-check.toml");
    let output = run(&["check", "--config", &shown(&path)]);
    let words = said(&output);
    assert_eq!(
        code(&output),
        0,
        "`check` rejected its own template: {words}"
    );
    assert!(
        words.contains("ok: 1 node(s)"),
        "the summary line names the shape the operator gets: {words}"
    );
    assert!(
        words.contains("socks5 127.0.0.1:10808") && words.contains("http 127.0.0.1:10809"),
        "both edges are reported, on loopback: {words}"
    );
}

/// Two `generate` runs are not the same file, because the id is drawn, not typed.
#[test]
fn every_generated_file_draws_its_own_user_id() {
    let first = std::fs::read_to_string(template("draw-one.toml")).expect("written");
    let second = std::fs::read_to_string(template("draw-two.toml")).expect("written");
    let one = quoted(&first, "userId").expect("the template declares a userId");
    let two = quoted(&second, "userId").expect("the template declares a userId");
    assert_eq!(one.len(), 36, "a hyphenated UUID is 36 characters");
    assert_eq!(&one[14..15], "4", "the version nibble is set");
    assert!(
        matches!(&one[19..20], "8" | "9" | "a" | "b"),
        "the variant nibble is set, so the string is a v4 id: {one}"
    );
    assert_ne!(one, two, "`generate` is not echoing a constant");
}

/// A `check` or `doctor` run prints no credential, including the one just drawn.
#[test]
fn no_diagnostic_echoes_the_user_id_it_was_given() {
    let path = template("template-secret.toml");
    let text = std::fs::read_to_string(&path).expect("the template was just written");
    let id = quoted(&text, "userId").expect("the template declares a userId");
    let config = shown(&path);
    for command in ["check", "doctor"] {
        let output = run(&[command, "--config", &config]);
        assert!(
            !said(&output).contains(&id),
            "`{command}` printed the user id it was given"
        );
    }
}

/// The short ID is named by length, never by value.
#[test]
fn a_short_id_is_reported_as_a_length() {
    let path = template("template-shortid.toml");
    let text = std::fs::read_to_string(&path).expect("the template was just written");
    let value = quoted(&text, "shortId").expect("the template declares a shortId");
    let output = run(&["check", "--config", &shown(&path)]);
    let words = said(&output);
    assert!(
        words.contains("shortId=4 chars"),
        "the declared length is all a diagnostic may say: {words}"
    );
    assert!(
        !words.contains(&value),
        "`check` printed the short ID: {words}"
    );
}

/// The `publicKey` is the one field that may be printed, because REALITY makes it
/// public by construction.
#[test]
fn the_public_key_is_named_because_it_is_not_a_secret() {
    let path = template("template-publickey.toml");
    let text = std::fs::read_to_string(&path).expect("the template was just written");
    let key = quoted(&text, "publicKey").expect("the template declares a publicKey");
    assert_eq!(key.len(), 43, "URL-safe unpadded base64 of 32 bytes");
    let output = run(&["check", "--config", &shown(&path)]);
    assert!(
        said(&output).contains(&key),
        "`check` hides the one value an operator has to compare against the server's own output"
    );
}

/// Every problem in one file, in one pass — the reason validation exists.
#[test]
fn a_broken_file_reports_every_problem_it_has() {
    let path = write(
        "broken.toml",
        r#"[listen]
socks5 = "localhost:10808"

[[node]]
name = "broken"
address = "example.com:443"
port = 0
userId = "not-a-uuid"
"#,
    );
    let output = run(&["check", "--config", &shown(&path)]);
    let words = said(&output);
    assert_eq!(
        code(&output),
        2,
        "an invalid file is a wrong invocation: {words}"
    );
    for expected in [
        "listen.socks5",
        "node[0].address",
        "node[0].port",
        "node[0].userId",
        "node[0].reality",
    ] {
        assert!(
            words.contains(expected),
            "`{expected}` was not among the problems reported: {words}"
        );
    }
}

/// An Xray paste gets the one-line answer the schema promises it.
#[test]
fn a_pasted_share_link_parameter_names_its_equivalent() {
    let path = write(
        "xray.toml",
        r#"[[node]]
address = "example.com"
port = 443
userId = "00000000-0000-4000-8000-000000000000"

[node.reality]
pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
sni = "www.example.com"
sid = "abcd"
"#,
    );
    let output = run(&["check", "--config", &shown(&path)]);
    let words = said(&output);
    assert_eq!(code(&output), 2, "unknown keys are refused: {words}");
    for expected in ["publicKey", "serverName", "shortId"] {
        assert!(
            words.contains(expected),
            "each pasted parameter has to be pointed at the key that means it: {words}"
        );
    }
}

/// A bind address that is not numeric is refused with the shape it should have.
#[test]
fn a_named_bind_address_is_refused_and_the_numeric_shape_is_shown() {
    let path = write("named.toml", "[listen]\nsocks5 = \"localhost:10808\"\n");
    let output = run(&["check", "--config", &shown(&path)]);
    let words = said(&output);
    assert_eq!(code(&output), 2, "{words}");
    assert!(
        words.contains("127.0.0.1:10808"),
        "the message has to show the accepted shape: {words}"
    );
}

/// A file with no node is refused rather than served as an empty rotation.
#[test]
fn a_file_with_nothing_to_connect_to_is_refused() {
    let path = write("empty.toml", "[listen]\nsocks5 = \"127.0.0.1:10808\"\n");
    let output = run(&["check", "--config", &shown(&path)]);
    let words = said(&output);
    assert_eq!(code(&output), 2, "{words}");
    assert!(
        words.contains("at least one [[node]]"),
        "the emptiness has to be named: {words}"
    );
}

/// A file that is not there is a wrong invocation, not a broken node.
#[test]
fn an_unreadable_file_is_wrong_about_the_invocation() {
    let output = run(&["check", "--config", "definitely-not-here.toml"]);
    assert_eq!(code(&output), 2, "{}", said(&output));
}

/// TOML that does not parse is refused by position, without quoting the value.
///
/// The line most likely to be wrong is a user id missing a dash, so the renderer
/// gives a position and a fixed explanation instead of echoing the fragment.
#[test]
fn a_syntax_error_gives_a_position_and_no_value() {
    let path = write(
        "syntax.toml",
        "[[node]]\naddress = \"example.com\"\nport = 44=5\n",
    );
    let output = run(&["check", "--config", &shown(&path)]);
    let words = said(&output);
    assert_eq!(code(&output), 2, "{words}");
    assert!(
        words.contains("is not valid TOML"),
        "the file has to be named as unparseable: {words}"
    );
    assert!(
        !words.contains("44=5"),
        "a syntax error must not reproduce the fragment it could not read: {words}"
    );
}

/// `doctor` refuses to call a placeholder a node.
#[test]
fn doctor_fails_on_the_placeholder_key_it_shipped_with() {
    let path = template("doctor-template.toml");
    let output = run(&["doctor", "--config", &shown(&path)]);
    let words = said(&output);
    assert_eq!(
        code(&output),
        1,
        "a template that has not been filled in is a broken configuration: {words}"
    );
    assert!(
        words.contains("FAIL") && words.contains("template's placeholder"),
        "the check that failed has to be named as a failure: {words}"
    );
    assert!(
        words.contains("never reached"),
        "a node that refuses TCP is reported as unreachable, which is a fact about \
         the address and not about its REALITY settings: {words}"
    );
}

/// A name the file does not have is answered with the names it does.
#[test]
fn doctor_names_the_nodes_a_file_has_when_asked_for_one_it_does_not() {
    let path = template("doctor-node.toml");
    let output = run(&["doctor", "--config", &shown(&path), "--node", "nowhere"]);
    let words = said(&output);
    assert_eq!(
        code(&output),
        2,
        "an unknown node is a wrong invocation: {words}"
    );
    assert!(
        words.contains("home-entry"),
        "the answer has to list what was available: {words}"
    );
}

/// `explain` covers the taxonomy and nothing else, and each entry says whose
/// failure it is.
#[test]
fn explain_answers_for_every_family_and_refuses_anything_else() {
    for family in FAMILIES {
        let output = run(&["explain", family]);
        let words = said(&output);
        assert_eq!(
            code(&output),
            0,
            "`explain {family}` is a defined word: {words}"
        );
        assert!(
            words.contains("counted against"),
            "the one thing an operator needs from this command: {words}"
        );
    }
    let local = said(&run(&["explain", "local"]));
    let connect = said(&run(&["explain", "connect"]));
    assert!(
        local.contains("this client, not the node"),
        "a local limit must not be read as a node problem: {local}"
    );
    assert!(
        connect.contains("no SYN was answered"),
        "the transport families have to say what the network did: {connect}"
    );
    let handshake = said(&run(&["explain", "handshake"]));
    assert!(
        handshake.contains("cover"),
        "a wrong key and a cover-relayed connection look the same, and saying so is \
         the whole point: {handshake}"
    );
    let output = run(&["explain", "vibes"]);
    assert_eq!(code(&output), 2, "an unknown family is a wrong invocation");
    assert!(
        said(&output).contains("local, dns, connect"),
        "the refusal lists the real words: {}",
        said(&output)
    );
}

/// A bad log level stops before the filesystem is touched.
#[test]
fn an_unacceptable_log_level_is_refused_by_name() {
    let output = run(&[
        "--log-level",
        "verbose",
        "check",
        "--config",
        "definitely-not-here.toml",
    ]);
    let words = said(&output);
    assert_eq!(code(&output), 2, "{words}");
    assert!(
        words.contains("error, warn, info, debug"),
        "the accepted set is printed back: {words}"
    );
}

/// `--version` is the release artifact's own identity, so a user can paste it.
#[test]
fn the_version_is_the_package_version() {
    let output = run(&["--version"]);
    assert_eq!(code(&output), 0, "{}", said(&output));
    assert!(
        said(&output).contains(env!("CARGO_PKG_VERSION")),
        "{}",
        said(&output)
    );
}

/// A listening address must not be a name, and a free port must still be asked for.
///
/// `run` is exercised as a process here rather than as a future: the promise is
/// that a valid configuration actually opens the sockets it declared, and that it
/// does not exit the moment it has bound them.
#[test]
fn run_binds_what_the_configuration_declares_and_stays_up() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port is free");
    let socks = probe
        .local_addr()
        .expect("a bound listener knows its address")
        .port();
    drop(probe);
    let path = write(
        "run.toml",
        &format!(
            r#"[listen]
socks5 = "127.0.0.1:{socks}"
http = ""

[[node]]
address = "127.0.0.1"
port = 1
userId = "00000000-0000-4000-8000-000000000000"

[node.reality]
publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
shortId = "abcd"
serverName = "www.example.com"
"#
        ),
    );
    let mut child = binary()
        .args(["run", "--config", &shown(&path)])
        .spawn()
        .expect("the binary starts");
    let mut connected = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if std::net::TcpStream::connect(("127.0.0.1", socks)).is_ok() {
            connected = true;
            break;
        }
    }
    let _ = child.kill();
    let status = child.wait().expect("the process was started by this test");
    assert!(
        connected,
        "`run` should be accepting on 127.0.0.1:{socks}, and it exited with {status:?} \
         before anything connected"
    );
}

#[test]
fn json_is_the_stdout_template_and_roundtrips() {
    let output = run(&["generate"]);
    assert_eq!(code(&output), 0);
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = v["outbounds"][0]["settings"]["id"].as_str().unwrap();
    assert_eq!(id.len(), 36);
    assert_eq!(&id[14..15], "4");
    let p = write(
        "json-default.json",
        std::str::from_utf8(&output.stdout).unwrap(),
    );
    assert_eq!(code(&run(&["check", "-c", &shown(&p)])), 0);
    let diag = said(&run(&["check", "-c", &shown(&p)]));
    assert!(!diag.contains(id));
}
#[test]
fn explicit_formats_and_extensions_must_agree() {
    let p = scratch("format-conflict.json");
    assert_eq!(
        code(&run(&["generate", "--format", "toml", "--out", &shown(&p)])),
        2
    );
    let out = run(&["generate", "--format", "toml"]);
    assert_eq!(code(&out), 0);
    assert!(String::from_utf8(out.stdout).unwrap().contains("[[node]]"));
}
#[test]
fn migrate_preserves_identity_and_refuses_overwrite() {
    let input = template("migration-input.toml");
    let output = scratch("migration-output.json");
    let _ = std::fs::remove_file(&output);
    assert_eq!(
        code(&run(&[
            "migrate",
            "-c",
            &shown(&input),
            "--out",
            &shown(&output)
        ])),
        0
    );
    let old =
        rust_reality_client::config::parse_toml(&std::fs::read_to_string(input).unwrap()).unwrap();
    let bytes = std::fs::read_to_string(&output).unwrap();
    let new = rust_reality_client::config::parse_json(&bytes).unwrap();
    assert_eq!(old, new);
    assert_eq!(
        code(&run(&[
            "migrate",
            "-c",
            &shown(&output),
            "--out",
            &shown(&output)
        ])),
        1
    );
    assert_eq!(std::fs::read_to_string(&output).unwrap(), bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn default_prefers_json_and_only_missing_json_falls_back_to_toml() {
    let directory = scratch("default-config-dir");
    std::fs::create_dir_all(&directory).unwrap();
    let _ = std::fs::remove_file(directory.join("client.json"));
    std::fs::write(
        directory.join("client.toml"),
        include_str!("../examples/client.toml"),
    )
    .unwrap();
    assert_eq!(
        code(
            &binary()
                .arg("check")
                .current_dir(&directory)
                .output()
                .unwrap()
        ),
        0
    );
    std::fs::write(directory.join("client.json"), "{broken}").unwrap();
    let output = binary()
        .arg("check")
        .current_dir(&directory)
        .output()
        .unwrap();
    assert_eq!(code(&output), 2);
    assert!(said(&output).contains("JSON"));
    std::fs::write(
        directory.join("client.json"),
        include_str!("../examples/client.json"),
    )
    .unwrap();
    std::fs::write(directory.join("client.toml"), "invalid").unwrap();
    assert_eq!(
        code(
            &binary()
                .arg("check")
                .current_dir(&directory)
                .output()
                .unwrap()
        ),
        0
    );
    assert_eq!(
        code(
            &binary()
                .args(["check", "-c", "missing.json"])
                .current_dir(&directory)
                .output()
                .unwrap()
        ),
        2
    );
}
#[test]
fn json_syntax_errors_do_not_echo_credentials() {
    let p = write(
        "secret-bad.json",
        "{\"outbounds\":[{\"id\": secret-token}]}",
    );
    let output = run(&["check", "-c", &shown(&p)]);
    assert_eq!(code(&output), 2);
    assert!(!said(&output).contains("secret-token"));
}
#[test]
fn json_and_toml_extensions_are_not_silently_reinterpreted() {
    let p = write("wrong-format.json", include_str!("../examples/client.toml"));
    assert_eq!(code(&run(&["check", "-c", &shown(&p)])), 2);
}

#[cfg(unix)]
#[test]
fn dangling_json_symlink_does_not_fall_back_to_toml() {
    let directory = scratch("dangling-json-dir");
    std::fs::create_dir_all(&directory).unwrap();
    let _ = std::fs::remove_file(directory.join("client.json"));
    std::os::unix::fs::symlink("missing-target", directory.join("client.json")).unwrap();
    std::fs::write(
        directory.join("client.toml"),
        include_str!("../examples/client.toml"),
    )
    .unwrap();
    let output = binary()
        .arg("check")
        .current_dir(directory)
        .output()
        .unwrap();
    assert_eq!(code(&output), 2);
    assert!(said(&output).contains("client.json"));
}
