use clap::Parser;
use openshell_kata::{
    config::{Config, RuntimeProfile},
    proto::openshell::{compute::v1 as c, sandbox::v1 as s},
    recovery::{Retained, Store},
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

const IMAGE: &str = "registry.example/guest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn config(root: &Path) -> Config {
    Config {
        socket: root.join("socket"),
        gateway: "https://localhost:1".into(),
        gateway_ca: root.join("ca"),
        lifecycle: root.join("lifecycle"),
        lifecycle_arg: vec![],
        ssh: root.join("ssh"),
        prototype_policy_mode: false,
        vm_policy: None,
        runtime_profile: RuntimeProfile::Kubernetes,
        guest_image: Some(IMAGE.into()),
        guest_network_cidr: Some("10.176.0.0/16".into()),
        additional_guest_images: Vec::new(),
        recovery_dir: Some(root.join("registry")),
        hosted_network_config: None,
        max_sandboxes: None,
    }
}
fn intent() -> Retained {
    Retained::new(
        c::DriverSandbox {
            id: "fixture".into(),
            workspace: "tenant-a".into(),
            name: "sandbox".into(),
            spec: Some(c::DriverSandboxSpec {
                launch_authentication: b"must-not-persist-credentials".to_vec(),
                policy: Some(s::SandboxPolicy {
                    version: 1,
                    ..Default::default()
                }),
                template: Some(c::DriverSandboxTemplate {
                    image: IMAGE.into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        "703852d9-6f8a-4feb-8ee6-b4e859856d84".into(),
        "generation".into(),
    )
}
fn snapshot(root: &Path) -> anyhow::Result<std::path::PathBuf> {
    Ok(fs::read_dir(root)?.next().expect("snapshot")?.path())
}

#[test]
fn atomic_snapshots_are_private_scrubbed_and_profile_bound() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = config(root.path());
    let path = config.recovery_dir.clone().expect("registry");
    let store = Store::new(path.clone());
    let mut retained = intent();
    retained
        .sandbox
        .spec
        .as_mut()
        .expect("spec")
        .launch_authentication = b"injected-after-construction".to_vec();
    store.save(&retained)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o700);
    let file = snapshot(&path)?;
    assert_eq!(fs::metadata(&file)?.permissions().mode() & 0o777, 0o600);
    let loaded = store.load(&config)?.admitted;
    assert_eq!(loaded.len(), 1);
    assert!(
        loaded[0]
            .sandbox
            .spec
            .as_ref()
            .expect("spec")
            .launch_authentication
            .is_empty()
    );
    assert_eq!(loaded[0].runtime_identity, retained.runtime_identity);
    let changed = Config {
        guest_image: Some(IMAGE.replace("aaaa", "bbbb")),
        ..config.clone()
    };
    let rebound = store.load(&changed)?;
    assert!(
        rebound.admitted.is_empty() && rebound.retired.len() == 1,
        "operator image change retires retained storage instead of rebinding it"
    );
    store.save(&Retained::new(
        loaded[0].sandbox.clone(),
        String::new(),
        "retry".into(),
    ))?;
    assert_eq!(
        fs::read_dir(&path)?.count(),
        1,
        "atomic replacement leaves no parallel record"
    );
    store.remove("fixture")?;
    store.remove("fixture")?;
    assert_eq!(fs::read_dir(path)?.count(), 0);
    Ok(())
}

#[test]
fn corrupt_or_substituted_snapshots_fail_closed() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = config(root.path());
    let path = config.recovery_dir.clone().expect("registry");
    let store = Store::new(path.clone());
    store.save(&intent())?;
    let file = snapshot(&path)?;
    let good = fs::read(&file)?;
    fs::write(&file, b"corrupt")?;
    assert!(store.load(&config).is_err());
    fs::write(&file, &good)?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;
    assert!(store.load(&config).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
    let mut data: serde_json::Value = serde_json::from_slice(&good)?;
    data["version"] = serde_json::json!(2);
    fs::write(&file, serde_json::to_vec(&data)?)?;
    assert!(store.load(&config).is_err());
    fs::write(&file, &good)?;
    fs::rename(&file, path.join("wrong.json"))?;
    assert!(store.load(&config).is_err());
    fs::remove_file(path.join("wrong.json"))?;
    symlink(root.path().join("outside"), &file)?;
    assert!(store.load(&config).is_err());
    Ok(())
}

#[test]
fn symlinked_registry_and_invalid_paths_are_rejected() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("directory");
    fs::create_dir(&directory)?;
    let link = root.path().join("link");
    symlink(&directory, &link)?;
    assert!(Store::new(link).save(&intent()).is_err());
    assert!(Store::new("relative".into()).save(&intent()).is_err());
    let store = Store::new(directory);
    let mut invalid = intent();
    invalid.sandbox.id = "../escape".into();
    assert!(store.save(&invalid).is_err());
    let mut config = config(root.path());
    config.recovery_dir = None;
    assert!(config.validate().is_err());
    Ok(())
}

#[test]
fn oversized_intent_and_third_workspace_reservation_are_rejected_before_commit()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = config(root.path());
    let path = config.recovery_dir.clone().expect("registry");
    let store = Store::new(path.clone());
    store.save(&intent())?;
    let mut oversized = intent();
    oversized.sandbox.spec.as_mut().expect("spec").command = vec!["x".repeat(1_500_000)];
    assert!(
        store.save(&oversized).is_err(),
        "serialized JSON must fit the same limit as restart loading"
    );
    assert!(
        store.load(&config)?.admitted[0]
            .sandbox
            .spec
            .as_ref()
            .expect("spec")
            .command
            .is_empty(),
        "failed replacement retains the last loadable record"
    );
    let mut second = intent();
    second.sandbox.id = "second".into();
    store.save(&second)?;
    let mut third = intent();
    third.sandbox.id = "third".into();
    assert!(
        store.save(&third).is_err(),
        "failed creates cannot bypass the two-sandbox pilot reservation cap"
    );
    store.save(&Retained {
        generation: "update".into(),
        ..second.clone()
    })?;
    store.remove("second")?;
    store.save(&third)?;
    assert_eq!(store.load(&config)?.admitted.len(), 2);
    Ok(())
}

#[test]
fn recovery_inventory_has_bounded_record_count_and_total_bytes() -> anyhow::Result<()> {
    for large in [false, true] {
        let root = tempfile::tempdir()?;
        let config = config(root.path());
        let directory = config.recovery_dir.clone().expect("registry");
        fs::create_dir(&directory)?;
        let count = if large { 5 } else { 129 };
        for index in 0..count {
            let file = fs::File::create(directory.join(format!("{index}.json")))?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            if large {
                file.set_len(4 * 1024 * 1024)?;
            }
        }
        let store = Store::new(directory);
        let loaded = store.load(&config).map(|recovered| recovered.admitted);
        assert!(loaded.is_err(), "inventory must be bounded before decoding");
        assert!(
            loaded
                .err()
                .expect("inventory failure")
                .to_string()
                .contains("inventory")
        );
        assert!(store.save(&intent()).is_err());
    }
    Ok(())
}

#[test]
fn concurrent_reservations_cannot_exceed_workspace_inventory() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let configuration = config(root.path());
    let store = Store::new(configuration.recovery_dir.clone().expect("registry"));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let workers: Vec<_> = (0..3)
        .map(|index| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut record = intent();
                record.sandbox.id = format!("concurrent-{index}");
                barrier.wait();
                store.save(&record).is_ok()
            })
        })
        .collect();
    barrier.wait();
    let saved = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .filter(|saved| *saved)
        .count();
    assert_eq!(saved, 2);
    assert_eq!(store.load(&configuration)?.admitted.len(), 2);
    Ok(())
}

fn native_config(root: &Path) -> anyhow::Result<Config> {
    let policy = root.join("vm-policy.json");
    fs::write(
        &policy,
        serde_json::to_vec(
            &serde_json::json!({"version":1,"profile":"docker-vm","resources":{"vcpus":32,"memory_mib":131072,"disk_mib":262144,"lifetime_secs":3600},"filesystem":{"host_mounts":"deny","transfer_max_bytes":268435456,"transfer_max_entries":4096},"network":{"tcp_allow":[]}}),
        )?,
    )?;
    fs::write(root.join("ca"), b"public-test-ca")?;
    Ok(Config {
        runtime_profile: RuntimeProfile::Local,
        vm_policy: Some(policy),
        guest_network_cidr: None,
        additional_guest_images: Vec::new(),
        max_sandboxes: Some(4),
        ..config(root)
    })
}

fn save_native(store: &Store, index: usize) -> anyhow::Result<()> {
    let mut retained = intent();
    retained.sandbox.id = format!("native-{index}");
    retained.sandbox.workspace = format!("workspace-{index}");
    store.save(&retained)
}

#[test]
fn native_capacity_follows_the_operator_setting() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = Config {
        max_sandboxes: Some(48),
        ..native_config(root.path())?
    };
    let store = Store::for_config(&config)?;
    for index in 0..47 {
        save_native(&store, index)?;
    }
    save_native(&store, 47).expect("the sandbox at capacity minus one is admitted");
    let refused = save_native(&store, 48).expect_err("a sandbox beyond capacity is refused");
    assert!(refused.to_string().contains("capacity of 48"), "{refused}");
    save_native(&store, 0).expect("an existing reservation can be rewritten at capacity");
    assert_eq!(store.load(&config)?.admitted.len(), 48);

    let lowered = Config {
        max_sandboxes: Some(8),
        ..config.clone()
    };
    assert!(
        Store::for_config(&lowered)?.load(&lowered).is_err(),
        "retained inventory above a lowered capacity fails closed"
    );
    let raised = Config {
        max_sandboxes: Some(64),
        ..config
    };
    let raised_store = Store::for_config(&raised)?;
    assert_eq!(
        raised_store.load(&raised)?.admitted.len(),
        48,
        "raising capacity keeps retained intent bound"
    );
    save_native(&raised_store, 48)?;
    Ok(())
}

#[test]
fn native_capacity_is_required_bounded_and_native_only() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let native = native_config(root.path())?;
    for capacity in [1, 64] {
        Config {
            max_sandboxes: Some(capacity),
            ..native.clone()
        }
        .validate()?;
    }
    for invalid in [
        Config {
            max_sandboxes: None,
            ..native.clone()
        },
        Config {
            max_sandboxes: Some(0),
            ..native.clone()
        },
        Config {
            max_sandboxes: Some(65),
            ..native.clone()
        },
    ] {
        assert!(invalid.validate().is_err(), "{:?}", invalid.max_sandboxes);
        assert!(Store::for_config(&invalid).is_err());
    }
    let hosted = Config {
        max_sandboxes: Some(4),
        ..config(root.path())
    };
    assert!(
        hosted.validate().is_err(),
        "the hosted pilot keeps its per-workspace rule"
    );
    for (argument, accepted) in [("0", false), ("1", true), ("64", true), ("65", false)] {
        let parsed = Config::try_parse_from([
            "openshell-kata",
            "--socket=/s",
            "--gateway-ca=/ca",
            "--lifecycle=/l",
            "--max-sandboxes",
            argument,
        ]);
        assert_eq!(parsed.is_ok(), accepted, "--max-sandboxes {argument}");
    }
    Ok(())
}

#[test]
fn native_recovery_is_bound_scrubbed_and_caps_all_workspaces() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = native_config(root.path())?;
    let store = Store::for_config(&config)?;
    for index in 0..4 {
        let mut retained = intent();
        retained.sandbox.id = format!("native-{index}");
        retained.sandbox.workspace = format!("workspace-{index}");
        store.save(&retained)?;
    }
    let loaded = store.load(&config)?.admitted;
    assert_eq!(loaded.len(), 4);
    assert!(loaded.iter().all(|r| {
        r.sandbox
            .spec
            .as_ref()
            .expect("spec")
            .launch_authentication
            .is_empty()
    }));
    let mut fifth = intent();
    fifth.sandbox.id = "fifth".into();
    fifth.sandbox.workspace = "unrelated-workspace".into();
    assert!(
        store.save(&fifth).is_err(),
        "native disk cap is global, not per workspace"
    );
    let changed = Config {
        gateway: "https://localhost:2".into(),
        ..config.clone()
    };
    assert!(
        Store::for_config(&changed)?.load(&changed).is_err(),
        "gateway authority cannot rebind retained intent"
    );
    let changed = Config {
        lifecycle_arg: vec!["--resource-profile=local".into()],
        ..config.clone()
    };
    assert!(
        Store::for_config(&changed)?.load(&changed).is_err(),
        "operator lifecycle selection must match"
    );
    fs::write(
        config.vm_policy.as_ref().expect("policy"),
        fs::read_to_string(config.vm_policy.as_ref().expect("policy"))?.replace("3600", "3601"),
    )?;
    assert!(
        Store::for_config(&config)?.load(&config).is_err(),
        "policy changes need explicit migration"
    );
    Ok(())
}

#[test]
fn native_recovery_rejects_legacy_unbound_records_and_unsafe_configuration() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = native_config(root.path())?;
    Store::new(config.recovery_dir.clone().expect("registry")).save(&intent())?;
    assert!(Store::for_config(&config)?.load(&config).is_err());
    for invalid in [
        Config {
            vm_policy: None,
            ..config.clone()
        },
        Config {
            guest_image: None,
            ..config.clone()
        },
        Config {
            prototype_policy_mode: true,
            ..config.clone()
        },
        Config {
            recovery_dir: Some("relative".into()),
            ..config.clone()
        },
    ] {
        assert!(invalid.validate().is_err());
        assert!(Store::for_config(&invalid).is_err());
    }
    Ok(())
}

#[test]
fn native_concurrent_reservations_cannot_exceed_capacity() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let configuration = native_config(root.path())?;
    let store = Store::for_config(&configuration)?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(7));
    let workers: Vec<_> = (0..6)
        .map(|index| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut record = intent();
                record.sandbox.id = format!("native-concurrent-{index}");
                record.sandbox.workspace = format!("workspace-{index}");
                barrier.wait();
                store.save(&record).is_ok()
            })
        })
        .collect();
    barrier.wait();
    let saved = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .filter(|saved| *saved)
        .count();
    assert_eq!(saved, 4);
    assert_eq!(store.load(&configuration)?.admitted.len(), 4);
    Ok(())
}

#[test]
fn native_recovery_rejects_changed_public_ca_and_invalid_retained_shape() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let config = native_config(root.path())?;
    let store = Store::for_config(&config)?;
    let mut invalid = intent();
    invalid
        .sandbox
        .spec
        .as_mut()
        .expect("spec")
        .template
        .as_mut()
        .expect("template")
        .image = IMAGE.replace("aaaa", "bbbb");
    store.save(&invalid)?;
    let recovered = store.load(&config)?;
    assert!(
        recovered.admitted.is_empty(),
        "a retained image outside the operator profile is never restarted"
    );
    assert_eq!(recovered.retired.len(), 1);
    assert!(
        recovered.retired[0]
            .reason
            .contains("guest image differs from operator profile"),
        "{}",
        recovered.retired[0].reason
    );
    store.save(&intent())?;
    fs::write(&config.gateway_ca, b"replacement-public-ca")?;
    assert!(
        Store::for_config(&config)?.load(&config).is_err(),
        "CA authority replacement cannot rebind retained disks"
    );
    fs::write(&config.gateway_ca, b"")?;
    assert!(Store::for_config(&config).is_err());
    Ok(())
}

fn with_template(id: &str, edit: impl FnOnce(&mut c::DriverSandboxTemplate)) -> Retained {
    let mut retained = intent();
    retained.sandbox.id = id.into();
    retained.sandbox.workspace = format!("workspace-{id}");
    edit(
        retained
            .sandbox
            .spec
            .as_mut()
            .expect("spec")
            .template
            .as_mut()
            .expect("template"),
    );
    retained
}

#[test]
fn records_the_operator_profile_no_longer_admits_are_retired_not_fatal() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let previous_image = IMAGE.replace("aaaa", "cccc");
    let previous = Config {
        additional_guest_images: vec![previous_image.clone()],
        ..native_config(root.path())?
    };
    let store = Store::for_config(&previous)?;
    store.save(&with_template("kept", |_| {}))?;
    store.save(&with_template("old-image", |template| {
        template.image = previous_image.clone();
    }))?;
    store.save(&with_template("old-size", |template| {
        template.resources = Some(c::DriverResourceRequirements {
            cpu_request: "16".into(),
            ..Default::default()
        });
    }))?;
    // The next release drops the previous image from the allowlist.
    let current = Config {
        additional_guest_images: Vec::new(),
        ..previous
    };
    let recovered = Store::for_config(&current)?.load(&current)?;
    let admitted: Vec<_> = recovered
        .admitted
        .iter()
        .map(|r| r.sandbox.id.as_str())
        .collect();
    let mut retired: Vec<_> = recovered
        .retired
        .iter()
        .map(|r| r.retained.sandbox.id.as_str())
        .collect();
    retired.sort_unstable();
    assert_eq!(admitted, vec!["kept"]);
    assert_eq!(retired, vec!["old-image", "old-size"]);
    assert!(recovered.retired.iter().all(|r| {
        r.retained
            .sandbox
            .spec
            .as_ref()
            .is_some_and(|spec| spec.launch_authentication.is_empty())
    }));
    Ok(())
}
