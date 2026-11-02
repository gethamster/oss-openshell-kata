use openshell_kata::{
    config::{Config, SandboxId},
    guest::Guest,
    upload::UploadPlan,
};

#[test]
fn local_prototype_mode_cannot_be_redirected_by_url_userinfo() {
    let mut config = Config {
        socket: "/tmp/adapter.sock".into(),
        gateway: "https://127.0.0.1:29670".into(),
        gateway_ca: "/tmp/ca".into(),
        lifecycle: "/tmp/lifecycle".into(),
        lifecycle_arg: Vec::new(),
        ssh: "/usr/bin/ssh".into(),
        prototype_policy_mode: true,
        vm_policy: None,
        runtime_profile: openshell_kata::config::RuntimeProfile::Local,
        guest_image: None,
        guest_network_cidr: None,
        additional_guest_images: Vec::new(),
        recovery_dir: None,
        max_sandboxes: None,
    };
    assert!(config.validate().is_ok());
    for endpoint in [
        "https://localhost:443@remote.example:443",
        "https://remote.example",
        "http://127.0.0.1:29670",
    ] {
        config.gateway = endpoint.into();
        assert!(config.validate().is_err(), "accepted {endpoint}");
    }
}

#[test]
fn sandbox_identifiers_cannot_change_runner_targets() {
    for value in ["", "../bad", "bad;id", "bad name", "a/b", "-bad", "_bad"] {
        assert!(SandboxId::parse(value).is_err(), "accepted {value:?}");
    }
    assert_eq!(
        SandboxId::parse("sandbox-123").expect("valid id").as_str(),
        "sandbox-123"
    );
}

#[test]
fn guest_metadata_requires_loopback_and_safe_identity() {
    let metadata = r#"{"sandbox_id":"sandbox-123","host":"127.0.0.1","port":2200,"username":"sandbox","private_key_path":"/tmp/key","known_hosts_path":"/tmp/known_hosts"}"#;
    let guest: Guest = serde_json::from_str(metadata).expect("metadata JSON");
    assert!(
        guest
            .validate(&SandboxId::parse("sandbox-123").expect("id"))
            .is_ok()
    );
    let evil: Guest =
        serde_json::from_str(&metadata.replace("127.0.0.1", "example.com")).expect("metadata JSON");
    assert!(
        evil.validate(&SandboxId::parse("sandbox-123").expect("id"))
            .is_err()
    );
}

#[test]
fn uploads_confine_destination_to_workspace() {
    for path in ["/sandbox", "/sandbox/project"] {
        assert!(
            UploadPlan::parse(format!(r#"{{"destination_directory":"{path}"}}"#).as_bytes())
                .is_ok()
        );
    }
    for path in [
        "/sandbox-evil",
        "/sandbox/../escape",
        "/tmp",
        "sandbox/project",
    ] {
        assert!(
            UploadPlan::parse(format!(r#"{{"destination_directory":"{path}"}}"#).as_bytes())
                .is_err()
        );
    }
}

#[test]
fn upload_plan_rejects_unknown_fields_control_characters_and_unknown_kinds() {
    for plan in [
        r#"{"destination_directory":"/sandbox","extra":true}"#,
        r#"{"destination_directory":"/sandbox/\u0000"}"#,
        r#"{"destination_directory":"/sandbox","expected_destination":{"path":"/sandbox","kind":"device"}}"#,
        r#"{"destination_directory":"/sandbox","expected_destination":{"path":"/sandbox\n","kind":"file"}}"#,
    ] {
        assert!(UploadPlan::parse(plan.as_bytes()).is_err());
    }
}

#[test]
fn hosted_operator_requires_an_explicit_private_guest_network() {
    let mut config = Config {
        socket: "/private/adapter.sock".into(),
        gateway: "https://gateway.example:443".into(),
        gateway_ca: "/private/ca".into(),
        lifecycle: "/usr/local/bin/kata-kubernetes".into(),
        lifecycle_arg: Vec::new(),
        ssh: "/usr/bin/ssh".into(),
        prototype_policy_mode: false,
        vm_policy: None,
        runtime_profile: openshell_kata::config::RuntimeProfile::Kubernetes,
        guest_image: Some(format!("registry.example/guest@sha256:{}", "a".repeat(64))),
        guest_network_cidr: None,
        additional_guest_images: Vec::new(),
        recovery_dir: Some("/private/registry".into()),
        max_sandboxes: None,
    };
    assert!(config.validate().is_err(), "network cannot be implicit");
    config.guest_network_cidr = Some("172.20.0.0/16".into());
    assert!(
        config.validate().is_ok(),
        "operator range is not cloud-specific"
    );
    config.guest_network_cidr = Some("0.0.0.0/0".into());
    assert!(
        config.validate().is_err(),
        "all-network route is not a guest range"
    );
}
