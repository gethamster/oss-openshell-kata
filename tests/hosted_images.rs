use c::compute_driver_server::ComputeDriver;
use clap::Parser;
use openshell_kata::{
    config::Config,
    driver::Driver,
    guest, hosted,
    proto::openshell::{compute::v1 as c, sandbox::v1 as s},
    recovery::{Retained, Store},
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};
use tonic::Request;

fn image(name: &str, digit: char) -> String {
    format!(
        "registry.example/{name}@sha256:{}",
        digit.to_string().repeat(64)
    )
}

fn config(root: &Path) -> Config {
    let mut config = Config::parse_from([
        "openshell-kata",
        "--socket",
        "/tmp/driver.sock",
        "--gateway-ca",
        "/tmp/ca",
        "--lifecycle",
        "/tmp/lifecycle",
        "--runtime-profile",
        "kubernetes",
        "--guest-network-cidr",
        "10.176.0.0/16",
        "--recovery-dir",
        "/tmp/registry",
    ]);
    config.guest_image = Some(image("guest", 'a'));
    config.additional_guest_images =
        vec![image("thread-minion", 'b'), image("team-workspace", 'c')];
    config.recovery_dir = Some(root.join("registry"));
    config.lifecycle = root.join("lifecycle");
    config
}

fn sandbox(image: &str) -> c::DriverSandbox {
    c::DriverSandbox {
        id: "fixture".into(),
        workspace: "tenant-a".into(),
        spec: Some(c::DriverSandboxSpec {
            policy: Some(s::SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            template: Some(c::DriverSandboxTemplate {
                image: image.into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn hosted_owner_images_use_the_existing_resource_and_policy_ceiling() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = config(root.path());
    config.validate()?;
    for image in config.admitted_images() {
        let mut request = sandbox(image);
        config.validate_request(&request)?;
        assert_eq!(
            config.for_sandbox(&request).guest_image.as_deref(),
            Some(image)
        );
        request
            .spec
            .as_mut()
            .expect("spec")
            .template
            .as_mut()
            .expect("template")
            .resources = Some(c::DriverResourceRequirements {
            cpu_request: "2".into(),
            cpu_limit: "2".into(),
            memory_request: "4Gi".into(),
            memory_limit: "4Gi".into(),
        });
        config.validate_request(&request)?;
        request
            .spec
            .as_mut()
            .expect("spec")
            .template
            .as_mut()
            .expect("template")
            .resources
            .as_mut()
            .expect("resources")
            .cpu_limit = "4".into();
        assert!(
            config.validate_request(&request).is_err(),
            "owner cannot expand CPU"
        );
        request = sandbox(image);
        request
            .spec
            .as_mut()
            .expect("spec")
            .environment
            .insert("BYPASS".into(), "1".into());
        assert!(
            config.validate_request(&request).is_err(),
            "owner cannot override environment"
        );
        request = sandbox(image);
        request
            .spec
            .as_mut()
            .expect("spec")
            .policy
            .as_mut()
            .expect("policy")
            .filesystem = Some(s::FilesystemPolicy {
            read_write: vec!["/sandbox".into()],
            ..Default::default()
        });
        assert!(
            config.validate_request(&request).is_err(),
            "owner cannot claim native isolation"
        );
    }
    for image in [
        image("unknown", 'd'),
        "registry.example/team-workspace:latest".into(),
    ] {
        assert!(config.validate_request(&sandbox(&image)).is_err());
    }
    let mut invalid = config.clone();
    invalid
        .additional_guest_images
        .push("registry.example/owner:latest".into());
    assert!(invalid.validate().is_err());
    invalid = config.clone();
    invalid.prototype_policy_mode = true;
    assert!(invalid.validate().is_err());
    invalid = config;
    invalid.guest_image = None;
    assert!(invalid.validate().is_err());
    Ok(())
}

#[tokio::test]
async fn hosted_recovery_and_restart_keep_the_admitted_original_image() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let original = config(root.path());
    let owner_image = image("team-workspace", 'c');
    let retained = Retained::new(
        sandbox(&owner_image),
        "703852d9-6f8a-4feb-8ee6-b4e859856d84".into(),
        "generation".into(),
    );
    Store::for_config(&original)?.save(&retained)?;
    let mut changed = original;
    changed.guest_image = Some(image("new-default", 'd'));
    changed.additional_guest_images.reverse();
    changed.validate()?;
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$1:$OPENSHELL_KATA_GUEST_IMAGE\" >> '{}'\ncase \"$1\" in\nstart) printf '%s' '{}' ;;\nesac\n",
        root.path().join("calls").display(),
        serde_json::json!({"sandbox_id":"fixture","host":"10.176.0.3","port":22,"username":"sandbox","private_key_path":root.path().join("key"),"known_hosts_path":root.path().join("hosts"),"runtime_identity":retained.runtime_identity})
    );
    fs::write(&changed.lifecycle, script)?;
    fs::set_permissions(&changed.lifecycle, fs::Permissions::from_mode(0o700))?;
    let driver = Driver::new(Arc::new(changed.clone()))?;
    driver.recover().await?;
    let recovered = driver
        .get_sandbox(Request::new(c::GetSandboxRequest {
            sandbox_id: "fixture".into(),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .sandbox
        .expect("retained sandbox");
    assert_eq!(
        recovered
            .spec
            .as_ref()
            .expect("spec")
            .template
            .as_ref()
            .expect("template")
            .image,
        owner_image
    );
    let selected = changed.for_sandbox(&recovered);
    guest::lifecycle_for(
        &selected,
        "start",
        &openshell_kata::config::SandboxId::parse("fixture")?,
        Some("tenant-a"),
    )
    .await?;
    assert_eq!(
        fs::read_to_string(root.path().join("calls"))?,
        format!("stop:{owner_image}\nstart:{owner_image}\n")
    );
    let proof: hosted::RuntimeProof = serde_json::from_value(
        serde_json::json!({"version":1,"sandbox_id":"fixture","workspace":"tenant-a","namespace":"sandbox-tenant-a","runtime_identity":retained.runtime_identity,"runtime_class":"kata-qemu-runtime-rs","image":owner_image,"network":"deny-all-egress","cpu":"2","memory":"4Gi","policy_sha256":"a".repeat(64),"expires_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()+3600,"deadline_enforcement":"kubelet-active-deadline"}),
    )?;
    proof.validate(
        &recovered,
        selected.guest_image.as_deref().expect("selected"),
        &retained.runtime_identity,
    )?;
    assert!(
        proof
            .validate(
                &recovered,
                changed.guest_image.as_deref().expect("default"),
                &retained.runtime_identity
            )
            .is_err()
    );
    changed
        .additional_guest_images
        .retain(|image| image != &owner_image);
    let removed = Store::for_config(&changed)?.load(&changed)?;
    assert!(removed.admitted.is_empty());
    assert_eq!(
        removed.retired.len(),
        1,
        "unlisted owner must retire, never rebind"
    );
    Ok(())
}
