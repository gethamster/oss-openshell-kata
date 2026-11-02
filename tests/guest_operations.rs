use openshell_kata::{
    config::{Config, RuntimeProfile, SandboxId},
    guest::{self, Guest},
    proto::openshell::{compute::v1 as c, sandbox::v1 as s},
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

const INSTANCE: &str = "82b0e809-1dc7-437b-814d-38010b2ffbdd";
const IMAGE: &str = "registry.example/guest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn script(path: &Path, body: &str) -> anyhow::Result<()> {
    fs::write(path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn config(root: &Path, profile: RuntimeProfile) -> Config {
    Config {
        socket: root.join("socket"),
        gateway: "https://localhost:1".into(),
        gateway_ca: root.join("ca"),
        lifecycle: root.join("lifecycle"),
        lifecycle_arg: vec![],
        ssh: root.join("ssh"),
        prototype_policy_mode: false,
        vm_policy: None,
        runtime_profile: profile,
        guest_image: Some(IMAGE.into()),
        guest_network_cidr: Some("10.176.0.0/16".into()),
        additional_guest_images: Vec::new(),
        recovery_dir: None,
        hosted_network_config: None,
        max_sandboxes: None,
    }
}
fn route(root: &Path) -> serde_json::Value {
    serde_json::json!({"sandbox_id":"fixture","host":"10.176.0.3","port":22,"username":"sandbox","private_key_path":root.join("private"),"known_hosts_path":root.join("hosts"),"runtime_identity":INSTANCE})
}
fn sandbox() -> c::DriverSandbox {
    c::DriverSandbox {
        id: "fixture".into(),
        workspace: "tenant-a".into(),
        spec: Some(c::DriverSandboxSpec {
            template: Some(c::DriverSandboxTemplate {
                image: IMAGE.into(),
                ..Default::default()
            }),
            policy: Some(s::SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn default_local_lifecycle_does_not_export_an_empty_image_override() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let mut cfg = config(root.path(), RuntimeProfile::Local);
    cfg.guest_image = None;
    cfg.guest_network_cidr = None;
    script(
        &cfg.lifecycle,
        "[ \"$#\" -eq 2 ] || exit 30; [ \"${OPENSHELL_KATA_GUEST_IMAGE+x}\" != x ] || exit 29; printf '{}'",
    )?;
    guest::lifecycle(&cfg, "delete", &SandboxId::parse("fixture")?).await?;
    Ok(())
}

#[tokio::test]
async fn lifecycle_binds_workspace_and_rejects_forged_guest_routes() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let cfg = config(root.path(), RuntimeProfile::Kubernetes);
    let id = SandboxId::parse("fixture")?;
    let good = route(root.path());
    script(
        &cfg.lifecycle,
        &format!(
            "printf '%s\\n' \"$OPENSHELL_KATA_WORKSPACE\" \"$OPENSHELL_KATA_GUEST_IMAGE\" > '{}'; cat '{}'",
            root.path().join("environment").display(),
            root.path().join("route.json").display()
        ),
    )?;
    fs::write(root.path().join("route.json"), serde_json::to_vec(&good)?)?;
    let observed = guest::lifecycle_for(&cfg, "create", &id, Some("tenant-a"))
        .await?
        .expect("valid route");
    assert_eq!(observed.runtime_identity.as_deref(), Some(INSTANCE));
    assert_eq!(
        fs::read_to_string(root.path().join("environment"))?,
        format!("tenant-a\n{IMAGE}\n")
    );
    for (field, value) in [
        ("sandbox_id", serde_json::json!("other")),
        ("host", serde_json::json!("169.254.169.254")),
        ("port", serde_json::json!(2222)),
        ("username", serde_json::json!("root")),
        ("runtime_identity", serde_json::json!("bad")),
        ("private_key_path", serde_json::json!("relative")),
        ("known_hosts_path", serde_json::json!("relative")),
    ] {
        let mut forged = good.clone();
        forged[field] = value;
        fs::write(root.path().join("route.json"), serde_json::to_vec(&forged)?)?;
        assert!(
            guest::lifecycle_for(&cfg, "start", &id, Some("tenant-a"))
                .await
                .is_err(),
            "forged {field} must be rejected"
        );
    }
    script(&cfg.lifecycle, "echo invalid-output")?;
    assert!(
        guest::lifecycle_for(&cfg, "create", &id, None)
            .await
            .is_err()
    );
    script(&cfg.lifecycle, "exit 12")?;
    assert!(guest::lifecycle(&cfg, "delete", &id).await.is_err());
    Ok(())
}

#[tokio::test]
async fn verification_rejects_changed_external_fences_and_process_failure() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let cfg = config(root.path(), RuntimeProfile::Kubernetes);
    let good = serde_json::json!({"version":1,"sandbox_id":"fixture","workspace":"tenant-a","namespace":"sandbox-tenant-a","runtime_identity":INSTANCE,"runtime_class":"kata-qemu-runtime-rs","image":IMAGE,"network":"deny-all-egress","cpu":"2","memory":"4Gi","policy_sha256":"a".repeat(64),"expires_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs()+3600,"deadline_enforcement":"kubelet-active-deadline"});
    script(
        &cfg.lifecycle,
        &format!("cat '{}'", root.path().join("proof").display()),
    )?;
    fs::write(root.path().join("proof"), serde_json::to_vec(&good)?)?;
    guest::verify_runtime(&cfg, &sandbox(), INSTANCE).await?;
    for (field, value) in [
        ("namespace", "sandbox-other"),
        ("runtime_class", "runc"),
        ("image", "other:latest"),
        ("network", "allow-all"),
        ("cpu", "4"),
        ("memory", "8Gi"),
        ("policy_sha256", "missing"),
    ] {
        let mut forged = good.clone();
        forged[field] = serde_json::json!(value);
        fs::write(root.path().join("proof"), serde_json::to_vec(&forged)?)?;
        assert!(
            guest::verify_runtime(&cfg, &sandbox(), INSTANCE)
                .await
                .is_err(),
            "changed {field} must fail live verification"
        );
    }
    script(&cfg.lifecycle, "exit 1")?;
    assert!(
        guest::verify_runtime(&cfg, &sandbox(), INSTANCE)
            .await
            .is_err()
    );
    script(&cfg.lifecycle, "echo invalid-json")?;
    assert!(
        guest::verify_runtime(&cfg, &sandbox(), INSTANCE)
            .await
            .is_err()
    );
    guest::verify_runtime(
        &config(root.path(), RuntimeProfile::Local),
        &sandbox(),
        INSTANCE,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn ssh_subprocesses_pin_identity_and_confine_preview_destinations() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let cfg = config(root.path(), RuntimeProfile::Local);
    script(&cfg.ssh, "printf '%s\\n' \"$@\"")?;
    let guest: Guest = serde_json::from_value(route(root.path()))?;
    let output = guest.exec(&cfg, "printf hello")?.wait_with_output().await?;
    let args = String::from_utf8(output.stdout)?;
    assert!(args.contains("-oStrictHostKeyChecking=yes\n"));
    assert!(args.contains("-oForwardAgent=no\n"));
    assert!(args.contains("-F\n/dev/null\n"));
    assert!(args.ends_with("sandbox@10.176.0.3\nprintf hello\n"));
    let output = guest.sftp(&cfg)?.wait_with_output().await?;
    assert!(String::from_utf8(output.stdout)?.contains("-s\n--\nsandbox@10.176.0.3\nsftp\n"));
    let output = guest.tcp(&cfg, "::1", 8080)?.wait_with_output().await?;
    assert!(String::from_utf8(output.stdout)?.contains("-W\n[::1]:8080\n"));
    let output = guest.tcp(&cfg, "localhost", 80)?.wait_with_output().await?;
    assert!(String::from_utf8(output.stdout)?.contains("-W\nlocalhost:80\n"));
    for host in ["169.254.169.254", "other.internal", "10.0.0.1"] {
        assert!(guest.tcp(&cfg, host, 80).is_err());
    }
    for port in [0, 65536, u32::MAX] {
        assert!(guest.tcp(&cfg, "localhost", port).is_err());
    }
    let mut missing = cfg;
    missing.ssh = root.path().join("missing");
    assert!(guest.exec(&missing, "anything").is_err());
    assert!(guest.sftp(&missing).is_err());
    assert!(guest.tcp(&missing, "localhost", 80).is_err());
    Ok(())
}

#[tokio::test]
async fn protected_lifecycle_requires_a_challenge_before_backend_effects() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let cfg = config(root.path(), RuntimeProfile::Local);
    let marker = root.path().join("backend-entered");
    script(
        &cfg.lifecycle,
        &format!("touch '{}'; printf '{{}}'", marker.display()),
    )?;
    let policy: openshell_kata::profile::VmPolicy =
        serde_json::from_str(include_str!("../examples/docker-vm.json"))?;
    let invalid_nonce = uuid::Uuid::new_v4()
        .to_string()
        .chars()
        .take(8)
        .collect::<String>();
    for nonce in [None, Some(invalid_nonce.as_str())] {
        assert!(
            guest::lifecycle_with_policy(
                &cfg,
                "verify",
                &SandboxId::parse("fixture")?,
                Some(&policy),
                nonce
            )
            .await
            .is_err()
        );
    }
    assert!(
        !marker.exists(),
        "missing proof challenge must fail before launching the backend"
    );
    Ok(())
}

#[tokio::test]
async fn protected_lifecycle_preserves_the_exact_fresh_challenge() -> anyhow::Result<()> {
    use openshell_kata::profile::{EnforcementEvidence, VmPolicy};
    let root = tempfile::tempdir()?;
    let cfg = config(root.path(), RuntimeProfile::Local);
    let id = SandboxId::parse("fixture")?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let wrong_nonce = uuid::Uuid::new_v4().to_string();
    let policy: VmPolicy = serde_json::from_str(include_str!("../examples/docker-vm.json"))?;
    let evidence = EnforcementEvidence {
        sandbox_id: id.to_string(),
        policy_sha256: policy.digest()?,
        nonce: nonce.clone(),
        runtime: "kata-runtime-rs".into(),
        hypervisor_pid: 1,
        resources: policy.resources,
        storage_id: "private-block".into(),
        network_fence: "checked-rules".into(),
        watchdog_pid: 2,
        expires_at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            + 1800,
    };
    let mut output = serde_json::json!({"sandbox_id":id.to_string(),"host":"127.0.0.1","port":2222,"username":"sandbox","private_key_path":root.path().join("key"),"known_hosts_path":root.path().join("known"),"enforcement":evidence});
    let route = root.path().join("route.json");
    let arguments = root.path().join("arguments");
    fs::write(&route, serde_json::to_vec(&output)?)?;
    script(
        &cfg.lifecycle,
        &format!(
            "printf '%s\\n' \"$@\" > '{}'; cat '{}'",
            arguments.display(),
            route.display()
        ),
    )?;
    guest::lifecycle_with_policy(&cfg, "verify", &id, Some(&policy), Some(&nonce))
        .await?
        .expect("fresh route");
    let arguments = fs::read_to_string(arguments)?;
    assert!(
        arguments
            .lines()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair == ["--proof-nonce", nonce.as_str()]),
        "backend must receive the generated challenge unchanged"
    );
    output["enforcement"]["nonce"] = serde_json::json!(wrong_nonce);
    fs::write(&route, serde_json::to_vec(&output)?)?;
    assert!(
        guest::lifecycle_with_policy(&cfg, "verify", &id, Some(&policy), Some(&nonce))
            .await
            .is_err(),
        "a different proof challenge cannot satisfy this request"
    );
    Ok(())
}

#[tokio::test]
async fn a_burst_of_lifecycle_operations_is_bounded_parallel_and_never_times_out()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let cfg = config(root.path(), RuntimeProfile::Local);
    let active = root.path().join("active");
    fs::create_dir(&active)?;
    // A slow node: every operation takes a while and records the concurrency it saw.
    script(
        &cfg.lifecycle,
        &format!(
            "mkdir '{dir}/'\"$$\"\nls '{dir}' | wc -l >> '{dir}.log'\nsleep 0.3\nrmdir '{dir}/'\"$$\"",
            dir = active.display()
        ),
    )?;
    let burst = guest::PROVISIONING_SLOTS * 2 + 4;
    let started = std::time::Instant::now();
    let tasks: Vec<_> = (0..burst)
        .map(|index| {
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let id = SandboxId::parse(&format!("burst-{index}"))?;
                guest::lifecycle(&cfg, "stop", &id).await
            })
        })
        .collect();
    for task in tasks {
        task.await??;
    }
    let peak = fs::read_to_string(root.path().join("active.log"))?
        .lines()
        .filter_map(|line| line.trim().parse::<usize>().ok())
        .max()
        .unwrap_or_default();
    assert!(peak > 1, "distinct sandboxes run in parallel");
    assert!(
        peak <= guest::PROVISIONING_SLOTS,
        "peak {peak} exceeds the slot budget"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "slot waiting is not charged to the execution deadline"
    );
    Ok(())
}

#[tokio::test]
async fn revalidation_defers_missed_deadlines_but_never_a_verified_violation() {
    use openshell_kata::supervisor::{REVALIDATION_GRACE, revalidation_deferrable};
    use std::time::Duration;
    let elapsed = tokio::time::timeout(Duration::from_millis(1), std::future::pending::<()>())
        .await
        .expect_err("deadline");
    let missed = anyhow::Error::from(elapsed).context("guest lifecycle timed out");
    assert!(guest::is_deadline(&missed));
    assert!(revalidation_deferrable(&missed, Duration::from_secs(10)));
    assert!(
        !revalidation_deferrable(&missed, REVALIDATION_GRACE),
        "a guest cannot run unproven past the grace"
    );
    let gateway = anyhow::Error::from(tonic::Status::deadline_exceeded("busy"));
    assert!(revalidation_deferrable(&gateway, Duration::ZERO));
    for verified in [
        anyhow::anyhow!("runtime route changed during verification"),
        anyhow::Error::from(tonic::Status::permission_denied("revoked")),
    ] {
        assert!(!revalidation_deferrable(&verified, Duration::ZERO));
    }
}
