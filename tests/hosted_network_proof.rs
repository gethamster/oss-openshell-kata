use openshell_kata::{
    hosted::RuntimeProof,
    network::{
        BrokerBinding, Endpoint, HostedBrokerConfig, NetworkPolicy, hosted_fence::HostedFenceIntent,
    },
    proto::openshell::{compute::v1 as c, sandbox::v1 as s},
    resource_shape::ResourceShape,
};
use serde_json::{Value, json};

const POD: &str = "9eab8e3a-4b95-4cc0-9b86-9cbd97433d32";
const NS: &str = "0dd39c8f-5a6d-461c-84c8-c3e3ff987aec";
const BROKER: &str = "7a1b6d63-dc7d-46c1-8a40-d6ae7ed9cf51";
const IMAGE: &str = "registry.example/guest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fixture() -> anyhow::Result<(tempfile::TempDir, c::DriverSandbox, NetworkPolicy, Value)> {
    let root = tempfile::tempdir()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let policy = NetworkPolicy {
        tcp_allow: vec![Endpoint {
            host: "registry.npmjs.org".into(),
            port: 443,
        }],
        ..Default::default()
    };
    let mut native = s::SandboxPolicy {
        version: 1,
        ..Default::default()
    };
    native.network_policies.insert(
        "npm".into(),
        s::NetworkPolicyRule {
            binaries: vec![s::NetworkBinary { path: "/**".into() }],
            endpoints: vec![s::NetworkEndpoint {
                host: "registry.npmjs.org".into(),
                port: 443,
                tls: 1,
                protocol: "tcp".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let sandbox = c::DriverSandbox {
        id: "sandbox-proof".into(),
        workspace: "tenant-proof".into(),
        spec: Some(c::DriverSandboxSpec {
            policy: Some(native),
            template: Some(c::DriverSandboxTemplate {
                image: IMAGE.into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let binding = BrokerBinding {
        workspace: sandbox.workspace.clone(),
        namespace_uid: NS.into(),
        sandbox_id: sandbox.id.clone(),
        launch_nonce: nonce().into(),
        expires_at_unix: now + 3600,
    };
    let config = HostedBrokerConfig {
        version: 1,
        operator_ceiling: policy.clone(),
        initial_ceiling: policy.clone(),
        binding: binding.clone(),
        protected_hostname_suffixes: vec!["internal.example".into()],
        baseline_denied_cidrs: vec!["8.8.8.8/32".into()],
        authorization_lease_secs: 30,
    };
    std::fs::write(
        root.path().join("operator.json"),
        serde_json::to_vec(
            &json!({"version":1,"broker_namespace":"openshell-network","broker_namespace_uid":BROKER,"guard_namespace":"kata-system","guard_namespace_uid":"fb7d9e07-2d92-4fb0-a91a-64fe9be8c8b9","guard_client_tls_config_file":"/operator/guard-client.json","operator_ceiling":policy,"baseline_denied_cidrs":config.baseline_denied_cidrs,"protected_hostname_suffixes":config.protected_hostname_suffixes,"authorization_lease_secs":30,"resolver_nameservers":["10.193.0.10"],"resolver_namespace_labels":{"kubernetes.io/metadata.name":"kube-system"},"resolver_pod_labels":{"k8s-app":"kube-dns"},"inventory_file":root.path().join("inventory.json")}),
        )?,
    )?;
    let fence = HostedFenceIntent {
        version: 1,
        workspace: sandbox.workspace.clone(),
        namespace_uid: NS.into(),
        sandbox_id: sandbox.id.clone(),
        pod_uid: POD.into(),
        launch_nonce: nonce().into(),
        expires_at_unix: binding.expires_at_unix,
        broker_pod_uid: BROKER.into(),
        broker_ip: "10.1.2.3".parse()?,
        broker_port: 3128,
        broker_config_sha256: config.digest()?,
        controller_cidrs: vec!["10.2.3.4/32".into()],
        guest_ip: "10.3.4.5".parse()?,
        guest_mac: "02:00:00:00:00:01".into(),
        gateway_ip: "169.254.1.1".parse()?,
        gateway_mac: "02:00:00:00:00:02".into(),
        interface: "eth0".into(),
        node_uid: "6aff11e4-6309-46f9-9fc1-7ff7368a5b5b".into(),
        boot_id: "79bd5c89-d496-419d-893d-75fdce8acbb5".into(),
    };
    let value = json!({"version":2,"sandbox_id":sandbox.id,"workspace":sandbox.workspace,"namespace":"sandbox-tenant-proof","runtime_identity":POD,"runtime_class":"kata-qemu-runtime-rs-guarded","image":IMAGE,"network":"brokered-public-tcp-v1","cpu":"2","memory":"4Gi","policy_sha256":"a".repeat(64),"expires_at_unix":binding.expires_at_unix,"deadline_enforcement":"kubelet-active-deadline","proof_nonce":nonce(),"source_namespace_uid":NS,"broker_pod_uid":BROKER,"broker_ip":"10.1.2.3",
        "broker":{"nonce":nonce(),"binding":binding,"startup_epoch":"abf8756b-d208-43f7-9ffd-e2fe82c57532","generation":2,"policy":policy,"policy_sha256":policy.digest()?,"config_sha256":config.digest()?,"inventory_generation":1,"inventory_sha256":"b".repeat(64),"effective_denied_sha256":"c".repeat(64),"authorization_expires_at_unix":now+20,"active_connections":0,"stopping":false},
        "fence":{"version":1,"binding":fence,"netns_device":1,"netns_inode":2,"ifindex":3,"ingress_link_id":4,"egress_link_id":5,"ingress_program_id":6,"egress_program_id":7,"object_sha256":"d".repeat(64),"intent_sha256":fence.sha256()?,"installed_at_unix":now}});
    Ok((root, sandbox, policy, value))
}

#[test]
fn brokered_proofs_pin_policy_launch_process_and_external_fence() -> anyhow::Result<()> {
    let (root, sandbox, policy, value) = fixture()?;
    let path = root.path().join("operator.json");
    let verify = |value: Value| -> anyhow::Result<()> {
        serde_json::from_value::<RuntimeProof>(value)?.validate_for_profile(
            &sandbox,
            IMAGE,
            &ResourceShape::default(),
            POD,
            Some(&path),
            nonce(),
            Some(&policy),
        )
    };
    verify(value.clone())?;
    assert!(
        serde_json::from_value::<RuntimeProof>(value.clone())?
            .validate(&sandbox, IMAGE, &ResourceShape::default(), POD)
            .is_err(),
        "legacy profile rejects new authority"
    );
    for (field, replacement) in [
        ("proof_nonce", json!(POD)),
        ("source_namespace_uid", json!(BROKER)),
        ("broker_pod_uid", json!(POD)),
        ("broker_ip", json!("10.9.9.9")),
        ("network", json!("deny-all-egress")),
        ("version", json!(1)),
        ("fence", Value::Null),
        ("broker", Value::Null),
    ] {
        let mut wrong = value.clone();
        wrong[field] = replacement;
        assert!(verify(wrong).is_err(), "unbound top-level field {field}");
    }
    for (field, replacement) in [
        ("nonce", json!(POD)),
        ("generation", json!(0)),
        ("startup_epoch", json!("bad")),
        ("authorization_expires_at_unix", json!(0)),
        ("policy_sha256", json!("e".repeat(64))),
        ("config_sha256", json!("f".repeat(64))),
        ("stopping", json!(true)),
        ("inventory_generation", json!(0)),
        ("inventory_sha256", json!("bad")),
    ] {
        let mut wrong = value.clone();
        wrong["broker"][field] = replacement;
        assert!(verify(wrong).is_err(), "unbound broker field {field}");
    }
    for field in [
        "pod_uid",
        "namespace_uid",
        "launch_nonce",
        "broker_pod_uid",
        "broker_config_sha256",
    ] {
        let mut wrong = value.clone();
        wrong["fence"]["binding"][field] = json!("2c7203c0-8580-4b6a-9f44-0953d26bb548");
        assert!(verify(wrong).is_err(), "unbound host fence field {field}");
    }
    Ok(())
}

#[test]
fn startup_deny_all_is_not_a_successful_authorization() -> anyhow::Result<()> {
    let (root, sandbox, policy, mut value) = fixture()?;
    value["broker"]["generation"] = json!(1);
    value["broker"]["policy"] = json!(NetworkPolicy::default());
    value["broker"]["policy_sha256"] = json!(NetworkPolicy::default().digest()?);
    value["broker"]["authorization_expires_at_unix"] = json!(0);
    let proof: RuntimeProof = serde_json::from_value(value)?;
    let path = root.path().join("operator.json");
    proof.validate_for_profile(
        &sandbox,
        IMAGE,
        &ResourceShape::default(),
        POD,
        Some(&path),
        nonce(),
        None,
    )?;
    assert!(
        proof
            .validate_for_profile(
                &sandbox,
                IMAGE,
                &ResourceShape::default(),
                POD,
                Some(&path),
                nonce(),
                Some(&policy)
            )
            .is_err()
    );
    Ok(())
}

fn nonce() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE
        .get_or_init(|| uuid::Uuid::new_v4().to_string())
        .as_str()
}
