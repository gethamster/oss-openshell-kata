//! Executable guest-helper contract, including real Linux process cancellation.

use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn helper(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kata-workspace"));
    command.arg("--root").arg(root);
    command
}

#[test]
fn protocol_is_available_without_opening_the_default_workspace() {
    let output = Command::new(env!("CARGO_BIN_EXE_kata-workspace"))
        .arg("protocol")
        .output()
        .expect("protocol");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"openshell-kata-workspace/1\n");
}

#[test]
fn unmanaged_docker_request_is_structured_and_acknowledgeable() {
    let root = tempfile::tempdir().expect("workspace");
    let output = helper(root.path())
        .args(["docker", "info"])
        .env_remove("OPENSHELL_WORKSPACE_COMMAND_ID")
        .env_remove("OPENSHELL_WORKSPACE_ROOT")
        .output()
        .expect("request Docker");
    assert_eq!(output.status.code(), Some(125));
    let pending = helper(root.path())
        .arg("capabilities")
        .output()
        .expect("pending requests");
    let requests: Vec<serde_json::Value> =
        serde_json::from_slice(&pending.stdout).expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["capability"], "docker");
    let id = requests[0]["command_id"].as_str().expect("command UUID");
    assert!(uuid::Uuid::parse_str(id).is_ok());
    assert!(
        helper(root.path())
            .args(["capability-ack", id])
            .status()
            .expect("acknowledge")
            .success()
    );
    assert_eq!(
        helper(root.path())
            .arg("capabilities")
            .output()
            .expect("cleared")
            .stdout,
        b"[]\n"
    );
}

#[test]
fn cli_files_preserve_binary_bytes_missing_status_and_removal_flags() {
    let root = tempfile::tempdir().expect("workspace");
    let bytes = b"binary\0file\xff";
    let mut writer = helper(root.path())
        .args(["write", "/sandbox/tree/file"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("write helper");
    let mut input = writer.stdin.take().expect("stdin");
    input
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .expect("frame length");
    input.write_all(bytes).expect("frame bytes");
    input.write_all(&[0; 4]).expect("terminator");
    input.write_all(&Sha256::digest(bytes)).expect("digest");
    drop(input);
    let written = writer.wait_with_output().expect("writer result");
    assert!(
        written.status.success(),
        "{}",
        String::from_utf8_lossy(&written.stderr)
    );
    let output = helper(root.path())
        .args(["read", "/sandbox/tree/file"])
        .output()
        .expect("read helper");
    assert!(output.status.success());
    assert_eq!(output.stdout, bytes);
    assert!(
        helper(root.path())
            .args(["remove", "/sandbox/tree", "true", "false"])
            .status()
            .expect("remove helper")
            .success()
    );
    assert_eq!(
        helper(root.path())
            .args(["read", "/sandbox/tree/file"])
            .output()
            .expect("missing helper")
            .status
            .code(),
        Some(66)
    );
    assert!(
        helper(root.path())
            .args(["remove", "/sandbox/missing", "false", "true"])
            .status()
            .expect("force helper")
            .success()
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs,
        process::Child,
        thread,
        time::{Duration, Instant},
    };
    use uuid::Uuid;

    fn wait_for(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.exists() {
            assert!(Instant::now() < deadline, "waiting for {}", path.display());
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn spawn(root: &Path, id: &str, args: &[&str]) -> Child {
        helper(root)
            .args([
                "run",
                id,
                &serde_json::to_string(args).expect("encode argv"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run helper")
    }

    #[test]
    fn run_preserves_stdin_stdout_stderr_and_nonzero_exit() {
        let root = tempfile::tempdir().expect("workspace");
        let id = Uuid::new_v4().to_string();
        let mut child = spawn(
            root.path(),
            &id,
            &["sh", "-c", "cat; printf 'diagnostic' >&2; exit 23"],
        );
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"input\0bytes")
            .expect("send stdin");
        let output = child.wait_with_output().expect("result");
        assert_eq!(
            output.status.code(),
            Some(23),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"input\0bytes");
        assert_eq!(output.stderr, b"diagnostic");
        assert!(
            !root
                .path()
                .join(format!(".system-processes/{id}.json"))
                .exists()
        );
    }

    #[test]
    fn run_restarts_after_abrupt_controller_exit() {
        let root = tempfile::tempdir().expect("workspace");
        let id = Uuid::new_v4().to_string();
        let record_path = root.path().join(format!(".system-processes/{id}.json"));
        let mut child = spawn(root.path(), &id, &["sleep", "60"]);
        wait_for(&record_path);
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(&record_path).expect("record")).expect("JSON");
        let pid = record["pid"].as_u64().expect("controller PID");
        child.kill().expect("stop launch parent without cleanup");
        child.wait().expect("reap launch parent");
        let controller = rustix::process::Pid::from_raw(i32::try_from(pid).expect("PID range"))
            .expect("controller PID");
        rustix::process::kill_process_group(controller, rustix::process::Signal::KILL)
            .expect("stop owned controller session");
        let deadline = Instant::now() + Duration::from_secs(10);
        while Path::new(&format!("/proc/{pid}")).exists() {
            assert!(Instant::now() < deadline, "controller was not reaped");
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            record_path.exists(),
            "abrupt exit must retain the old record"
        );
        let output = spawn(root.path(), &id, &["printf", "restarted"])
            .wait_with_output()
            .expect("restart same command UUID");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"restarted");
        assert!(
            !record_path.exists(),
            "completed restart cleans its own record"
        );
    }

    #[test]
    fn cancellation_rejects_modified_identity_then_kills_the_exact_session() {
        let root = tempfile::tempdir().expect("workspace");
        let marker = root.path().join("descendant-pid");
        let id = Uuid::new_v4().to_string();
        let child = spawn(
            root.path(),
            &id,
            &[
                "sh",
                "-c",
                "sleep 60 & printf '%s' \"$!\" > \"$1\"; wait",
                "sh",
                marker.to_str().expect("path"),
            ],
        );
        let record_path = root.path().join(format!(".system-processes/{id}.json"));
        wait_for(&marker);
        wait_for(&record_path);
        let original = fs::read(&record_path).expect("record");
        let mut forged: serde_json::Value = serde_json::from_slice(&original).expect("record JSON");
        forged["start"] = (forged["start"].as_u64().expect("start") + 1).into();
        fs::write(
            &record_path,
            serde_json::to_vec(&forged).expect("forged record"),
        )
        .expect("tamper");
        assert!(
            !helper(root.path())
                .args(["kill", &id])
                .output()
                .expect("reject forged identity")
                .status
                .success()
        );
        fs::write(&record_path, original).expect("restore record");
        let killed = helper(root.path())
            .args(["kill", &id])
            .output()
            .expect("kill exact session");
        assert!(
            killed.status.success(),
            "{}",
            String::from_utf8_lossy(&killed.stderr)
        );
        let output = child.wait_with_output().expect("cancelled command");
        assert_eq!(
            output.status.code(),
            Some(137),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!record_path.exists());
        let descendant = fs::read_to_string(marker).expect("descendant PID");
        let stat = fs::read_to_string(format!("/proc/{descendant}/stat"));
        if let Ok(stat) = stat {
            assert_eq!(
                stat.rsplit_once(')')
                    .expect("stat")
                    .1
                    .split_whitespace()
                    .next(),
                Some("Z"),
                "descendant still executing: {stat}"
            );
        }
        assert!(
            helper(root.path())
                .args(["kill", &id])
                .output()
                .expect("idempotent kill")
                .status
                .success()
        );
    }

    #[test]
    fn cancellation_drains_detached_double_fork_descendants() {
        let root = tempfile::tempdir().expect("workspace");
        let marker = root.path().join("detached-pid");
        let id = Uuid::new_v4().to_string();
        let child = spawn(
            root.path(),
            &id,
            &[
                "sh",
                "-c",
                r#"setsid sh -c 'sleep 60 & echo $! > "$1"' sh "$1"; sleep 60"#,
                "sh",
                marker.to_str().expect("path"),
            ],
        );
        wait_for(&marker);
        let descendant = fs::read_to_string(&marker).expect("detached PID");
        let output = helper(root.path())
            .args(["kill", &id])
            .output()
            .expect("cancel");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = child.wait_with_output().expect("drained controller");
        assert_eq!(
            output.status.code(),
            Some(137),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !std::path::Path::new(&format!("/proc/{}", descendant.trim())).exists(),
            "detached descendant must be reaped before cancellation succeeds"
        );
    }

    #[test]
    fn forged_cancel_request_never_acknowledges_or_becomes_quiescent() {
        let root = tempfile::tempdir().expect("workspace");
        let marker = root.path().join("ready");
        let id = Uuid::new_v4().to_string();
        let child = spawn(
            root.path(),
            &id,
            &[
                "sh",
                "-c",
                "touch \"$1\"; sleep 0.3",
                "sh",
                marker.to_str().expect("path"),
            ],
        );
        wait_for(&marker);
        let directory = root.path().join(".system-processes");
        let mut record: serde_json::Value = serde_json::from_slice(
            &fs::read(directory.join(format!("{id}.json"))).expect("record"),
        )
        .expect("record JSON");
        record["start"] = (record["start"].as_u64().expect("start") + 1).into();
        fs::write(
            directory.join(format!("{id}.cancel.json")),
            serde_json::to_vec(&record).expect("request"),
        )
        .expect("forged request");
        let output = child
            .wait_with_output()
            .expect("controller rejected request");
        assert!(!output.status.success());
        assert!(!directory.join(format!("{id}.cancel-ack.json")).exists());
        assert!(directory.join(format!("{id}.drain-failed")).exists());
        assert!(
            !helper(root.path())
                .arg("quiesce")
                .output()
                .expect("quiescence check")
                .status
                .success()
        );
    }

    #[test]
    fn holder_exits_only_for_its_retained_identity() {
        for forged in [false, true] {
            let root = tempfile::tempdir().expect("workspace");
            let id = Uuid::new_v4().to_string();
            let child = helper(root.path())
                .args(["hold", &id])
                .spawn()
                .expect("holder");
            let directory = root.path().join(".system-processes");
            let path = directory.join(format!("{id}.hold.json"));
            wait_for(&path);
            let mut record: serde_json::Value =
                serde_json::from_slice(&fs::read(path).expect("holder identity")).expect("JSON");
            if forged {
                record["start"] = (record["start"].as_u64().expect("start") + 1).into();
            }
            fs::write(
                directory.join(format!("{id}.hold-exit.json")),
                serde_json::to_vec(&record).expect("request"),
            )
            .expect("stop request");
            let output = child.wait_with_output().expect("stopped holder");
            assert_eq!(output.status.success(), !forged);
            if !forged {
                assert!(!directory.join(format!("{id}.hold.json")).exists());
                assert!(!directory.join(format!("{id}.hold-exit.json")).exists());
            }
        }
    }

    #[test]
    fn a_forged_holder_record_cannot_exempt_a_live_writer_from_export() {
        let root = tempfile::tempdir().expect("workspace");
        let directory = root.path().join(".system-processes");
        fs::create_dir(&directory).expect("control directory");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("private control directory");
        let mut writer = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("unmanaged process");
        let stat =
            fs::read_to_string(format!("/proc/{}/stat", writer.id())).expect("kernel identity");
        let start = stat
            .rsplit_once(')')
            .expect("stat")
            .1
            .split_whitespace()
            .nth(19)
            .expect("start")
            .parse::<u64>()
            .expect("numeric start");
        let id = Uuid::new_v4().to_string();
        fs::write(
            directory.join(format!("{id}.hold.json")),
            serde_json::to_vec(&serde_json::json!({"version":1,"pid":writer.id(),"start":start}))
                .expect("record"),
        )
        .expect("forged holder record");
        let output = helper(root.path())
            .arg("quiesce-export")
            .output()
            .expect("export attempt");
        let still_live = writer.try_wait().expect("process status").is_none();
        writer.kill().expect("clean up owned process");
        writer.wait().expect("reap owned process");
        assert!(
            still_live,
            "helper must never signal a record-selected unrelated process"
        );
        assert!(!output.status.success());
        assert!(output.stdout.is_empty(), "no archive before quiescence");
        assert!(String::from_utf8_lossy(&output.stderr).contains("holder executable changed"));
    }

    #[test]
    fn holder_identity_uuid_and_workspace_root_are_verified_before_export() {
        for changed in ["start", "uuid", "root"] {
            let source = tempfile::tempdir().expect("source");
            let other = tempfile::tempdir().expect("other workspace");
            let actual = if changed == "root" {
                other.path()
            } else {
                source.path()
            };
            let id = Uuid::new_v4().to_string();
            let mut child = helper(actual).args(["hold", &id]).spawn().expect("holder");
            let record_path = actual.join(format!(".system-processes/{id}.hold.json"));
            wait_for(&record_path);
            let original = fs::read(&record_path).expect("holder identity");
            let mut record: serde_json::Value = serde_json::from_slice(&original).expect("JSON");
            if changed == "start" {
                record["start"] = (record["start"].as_u64().expect("start") + 1).into();
            }
            let claimed = if changed == "uuid" {
                Uuid::new_v4().to_string()
            } else {
                id.clone()
            };
            let directory = source.path().join(".system-processes");
            fs::create_dir_all(&directory).expect("record directory");
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("private directory");
            fs::write(
                directory.join(format!("{claimed}.hold.json")),
                serde_json::to_vec(&record).expect("encode record"),
            )
            .expect("claimed identity");
            let output = helper(source.path())
                .arg("quiesce-export")
                .output()
                .expect("export");
            assert!(
                child.try_wait().expect("holder status").is_none(),
                "{changed}"
            );
            fs::write(&record_path, &original).expect("restore owned record");
            fs::write(
                actual.join(format!(".system-processes/{id}.hold-exit.json")),
                &original,
            )
            .expect("stop owned holder");
            assert!(child.wait().expect("holder exit").success());
            assert!(!output.status.success(), "{changed}");
            assert!(output.stdout.is_empty(), "{changed}");
            let expected = if changed == "start" {
                "holder identity changed"
            } else {
                "holder invocation changed"
            };
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "{changed}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// Run inside an isolated PID namespace, as in the normal gateway guest.
    #[test]
    #[ignore = "requires isolated PID namespace; run in a test container or normal gateway guest"]
    fn quiescent_export_keeps_the_canonical_holder_alive() {
        let root = tempfile::tempdir().expect("workspace");
        fs::write(root.path().join("retained"), b"workspace bytes").expect("content");
        let id = Uuid::new_v4().to_string();
        let mut child = Command::new("sh")
            .args(["-c", "\"$1\" --root \"$2\" run \"$3\" '[\"true\"]'; exec \"$1\" --root \"$2\" hold \"$3\"", "sh"])
            .arg(env!("CARGO_BIN_EXE_kata-workspace"))
            .arg(root.path())
            .arg(&id)
            .spawn()
            .expect("canonical workload wrapper");
        let record_path = root
            .path()
            .join(format!(".system-processes/{id}.hold.json"));
        wait_for(&record_path);
        let record = fs::read(&record_path).expect("holder identity");
        let writer_id = Uuid::new_v4().to_string();
        let marker = root.path().join("writer-ready");
        let writer = spawn(
            root.path(),
            &writer_id,
            &[
                "sh",
                "-c",
                "touch \"$1\"; while :; do sleep 1; done",
                "sh",
                marker.to_str().expect("marker path"),
            ],
        );
        wait_for(&marker);
        let first = helper(root.path())
            .arg("quiesce-export")
            .output()
            .expect("first export");
        let stopped_writer = writer.wait_with_output().expect("managed writer stopped");
        assert_eq!(stopped_writer.status.code(), Some(137));
        let alive = child.try_wait().expect("holder status").is_none();
        let second = helper(root.path())
            .arg("export")
            .output()
            .expect("repeated export");
        fs::write(
            root.path()
                .join(format!(".system-processes/{id}.hold-exit.json")),
            record,
        )
        .expect("stop owned holder");
        assert!(child.wait().expect("holder exit").success());
        assert!(alive, "quiescence must preserve the sandbox main holder");
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert!(
            second.status.success(),
            "{}",
            String::from_utf8_lossy(&second.stderr)
        );
        assert!(!first.stdout.is_empty());
        assert_eq!(first.stdout, second.stdout);
        assert_eq!(
            fs::read(root.path().join("retained")).expect("retained content"),
            b"workspace bytes"
        );
    }

    #[test]
    fn cancellation_before_record_publication_prevents_later_execution() {
        let root = tempfile::tempdir().expect("workspace");
        let id = Uuid::new_v4().to_string();
        let cancelled = helper(root.path())
            .args(["kill", &id])
            .output()
            .expect("early cancellation");
        assert!(
            cancelled.status.success(),
            "{}",
            String::from_utf8_lossy(&cancelled.stderr)
        );
        let child = spawn(root.path(), &id, &["sh", "-c", "printf 'must not execute'"]);
        let output = child.wait_with_output().expect("cancelled before start");
        assert_eq!(
            output.status.code(),
            Some(137),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "command ran after cancellation");
    }

    #[test]
    fn nested_docker_request_interrupts_without_replaying_or_running_later_commands() {
        let root = tempfile::tempdir().expect("workspace");
        let id = Uuid::new_v4().to_string();
        let child = spawn(
            root.path(),
            &id,
            &[
                "sh",
                "-c",
                "printf before; \"$1\" docker info; printf after",
                "sh",
                env!("CARGO_BIN_EXE_kata-workspace"),
            ],
        );
        let output = child.wait_with_output().expect("Docker request");
        assert_eq!(
            output.status.code(),
            Some(125),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"before");
        let request = helper(root.path())
            .args(["capability", &id])
            .output()
            .expect("capability query");
        assert!(request.status.success());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.stdout).expect("request JSON"),
            serde_json::json!({"version":1,"capability":"docker","command_id":id})
        );
        let pending = helper(root.path())
            .arg("capabilities")
            .output()
            .expect("pending requests");
        assert_eq!(
            serde_json::from_slice::<Vec<serde_json::Value>>(&pending.stdout)
                .expect("requests")
                .len(),
            1
        );
        let replay = spawn(root.path(), &id, &["sh", "-c", "printf replayed"])
            .wait_with_output()
            .expect("same operation");
        assert_eq!(replay.status.code(), Some(125));
        assert!(replay.stdout.is_empty(), "interrupted command was replayed");
        assert!(
            helper(root.path())
                .args(["capability-ack", &id])
                .status()
                .expect("acknowledge")
                .success()
        );
        assert_eq!(
            helper(root.path())
                .args(["capability", &id])
                .output()
                .expect("query acknowledged")
                .stdout,
            b"null\n"
        );
    }
}
