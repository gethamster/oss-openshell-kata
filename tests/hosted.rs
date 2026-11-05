use openshell_kata::{
    hosted,
    proto::openshell::{compute::v1 as c, sandbox::v1 as s},
    resource_shape::ResourceShape,
};

fn default_shape() -> ResourceShape {
    ResourceShape::default()
}

fn request() -> c::DriverSandbox {
    c::DriverSandbox {
        id: "6d62883f-fcb5-4b5e-a250-aaea50eeaf41".into(),
        workspace: "1h31c".into(),
        spec: Some(c::DriverSandboxSpec {
            policy: Some(s::SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            template: Some(c::DriverSandboxTemplate {
                image: format!("registry.example/guest@sha256:{}", "a".repeat(64)),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn only_explicit_vm_policy_and_pinned_image_are_admitted() {
    let input = request();
    let image = input
        .spec
        .as_ref()
        .expect("valid hosted fixture")
        .template
        .as_ref()
        .expect("valid hosted fixture")
        .image
        .clone();
    hosted::validate_request(&input, &image, &default_shape()).expect("valid hosted fixture");
    let mut other = input.clone();
    other.workspace = "default".into();
    assert!(hosted::validate_request(&other, &image, &default_shape()).is_err());
    other = input.clone();
    other
        .spec
        .as_mut()
        .expect("valid hosted fixture")
        .policy
        .as_mut()
        .expect("valid hosted fixture")
        .filesystem = Some(s::FilesystemPolicy {
        read_write: vec!["/sandbox".into()],
        ..Default::default()
    });
    assert!(hosted::validate_request(&other, &image, &default_shape()).is_err());
    assert!(hosted::validate_request(&input, "docker:latest", &default_shape()).is_err());
}

#[test]
fn proof_is_bound_to_workspace_image_and_runtime_generation() {
    let input = request();
    let image = input
        .spec
        .as_ref()
        .expect("valid hosted fixture")
        .template
        .as_ref()
        .expect("valid hosted fixture")
        .image
        .clone();
    let value = serde_json::json!({"version":1,"sandbox_id":input.id,"workspace":"1h31c",
        "namespace":"sandbox-1h31c","runtime_identity":"5da94e07-4af3-4ee9-b74e-f233091a404f",
        "runtime_class":"kata-qemu-runtime-rs","image":image,"network":"deny-all-egress",
        "cpu":"2","memory":"4Gi","policy_sha256":"a".repeat(64),"expires_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs()+3600,"deadline_enforcement":"kubelet-active-deadline"});
    let proof: hosted::RuntimeProof =
        serde_json::from_value(value.clone()).expect("valid hosted fixture");
    proof
        .validate(
            &input,
            &image,
            &default_shape(),
            "5da94e07-4af3-4ee9-b74e-f233091a404f",
        )
        .expect("valid hosted fixture");
    assert!(
        proof
            .validate(&input, &image, &default_shape(), "other-generation")
            .is_err()
    );
    for (field, changed) in [
        ("expires_at_unix", serde_json::json!(0)),
        ("deadline_enforcement", serde_json::json!("guest-timer")),
    ] {
        let mut wrong = value.clone();
        wrong[field] = changed;
        let wrong: hosted::RuntimeProof =
            serde_json::from_value(wrong).expect("malformed proof fixture");
        assert!(
            wrong
                .validate(
                    &input,
                    &image,
                    &default_shape(),
                    "5da94e07-4af3-4ee9-b74e-f233091a404f"
                )
                .is_err(),
            "invalid lease field {field}"
        );
    }
    let mut wrong = value;
    wrong["workspace"] = "another".into();
    let proof: hosted::RuntimeProof = serde_json::from_value(wrong).expect("valid hosted fixture");
    assert!(
        proof
            .validate(
                &input,
                &image,
                &default_shape(),
                "5da94e07-4af3-4ee9-b74e-f233091a404f"
            )
            .is_err()
    );
}

#[test]
fn operator_network_is_private_and_cloud_independent() -> anyhow::Result<()> {
    for cidr in [
        "10.48.0.0/16",
        "172.20.0.0/16",
        "192.168.8.0/24",
        "fd12:3456::/48",
    ] {
        let network = hosted::validate_network(cidr)?;
        assert!(network.contains(&network.network()));
    }
    for cidr in [
        "0.0.0.0/0",
        "10.0.0.0/7",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "2001:db8::/32",
        "::/0",
        "bad",
    ] {
        assert!(
            hosted::validate_network(cidr).is_err(),
            "accepted unqualified range {cidr}"
        );
    }
    Ok(())
}

#[test]
fn hosted_network_is_explicit_and_cannot_expand_initial_authority() -> anyhow::Result<()> {
    use openshell_kata::network::{Endpoint, NetworkPolicy};
    let mut input = request();
    let image = input
        .spec
        .as_ref()
        .expect("spec")
        .template
        .as_ref()
        .expect("template")
        .image
        .clone();
    let ceiling = NetworkPolicy {
        tcp_allow: vec![Endpoint {
            host: "registry.npmjs.org".into(),
            port: 443,
        }],
        ..Default::default()
    };
    assert_eq!(
        hosted::validate_brokered_request(&input, &image, &default_shape(), &ceiling)?,
        NetworkPolicy::default()
    );
    let native = input
        .spec
        .as_mut()
        .expect("spec")
        .policy
        .as_mut()
        .expect("policy");
    native.network_policies.insert(
        "npm".into(),
        s::NetworkPolicyRule {
            binaries: vec![s::NetworkBinary { path: "/**".into() }],
            endpoints: vec![s::NetworkEndpoint {
                host: "registry.npmjs.org".into(),
                port: 443,
                protocol: "tcp".into(),
                tls: 1,
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    assert!(
        hosted::validate_request(&input, &image, &default_shape()).is_err(),
        "legacy isolated cannot gain networking"
    );
    assert_eq!(
        hosted::validate_brokered_request(&input, &image, &default_shape(), &ceiling)?,
        ceiling
    );
    assert!(
        hosted::validate_brokered_request(
            &input,
            &image,
            &default_shape(),
            &NetworkPolicy::default()
        )
        .is_err(),
        "empty original capability cannot widen"
    );
    Ok(())
}

fn with_resources(cpu: &str, memory: &str) -> c::DriverSandbox {
    let mut input = request();
    input
        .spec
        .as_mut()
        .expect("spec")
        .template
        .as_mut()
        .expect("template")
        .resources = Some(c::DriverResourceRequirements {
        cpu_request: cpu.into(),
        cpu_limit: cpu.into(),
        memory_request: memory.into(),
        memory_limit: memory.into(),
    });
    input
}

#[test]
fn only_a_declared_shape_admits_larger_template_resources() {
    let build = ResourceShape::parse("build=4,8Gi,100Gi").expect("build shape");
    let input = with_resources("4", "8Gi");
    let image = input
        .spec
        .as_ref()
        .expect("spec")
        .template
        .as_ref()
        .expect("template")
        .image
        .clone();
    // Unknown shape: without a declaration, the default shape refuses 4 vCPU / 8 GiB.
    assert!(hosted::validate_request(&input, &image, &default_shape()).is_err());
    assert_eq!(
        ResourceShape::select(
            &[],
            input
                .spec
                .as_ref()
                .and_then(|s| s.template.as_ref())
                .and_then(|t| t.resources.as_ref())
        ),
        default_shape()
    );
    hosted::validate_request(&input, &image, &build).expect("declared shape");
    // A declared shape never admits the default request or another size.
    assert!(hosted::validate_request(&request(), &image, &build).is_err());
    assert!(hosted::validate_request(&with_resources("6", "12Gi"), &image, &build).is_err());
    hosted::validate_request(&with_resources("2", "4Gi"), &image, &default_shape())
        .expect("explicit default");
}

#[test]
fn proof_binds_the_admitted_resource_shape() {
    let build = ResourceShape::parse("build=4,8Gi,100Gi").expect("build shape");
    let input = with_resources("4", "8Gi");
    let image = input
        .spec
        .as_ref()
        .expect("spec")
        .template
        .as_ref()
        .expect("template")
        .image
        .clone();
    let identity = "5da94e07-4af3-4ee9-b74e-f233091a404f";
    let value = serde_json::json!({"version":1,"sandbox_id":input.id,"workspace":"1h31c",
        "namespace":"sandbox-1h31c","runtime_identity":identity,
        "runtime_class":"kata-qemu-runtime-rs","image":image,"network":"deny-all-egress",
        "cpu":"4","memory":"8Gi","resource_shape":build,"policy_sha256":"a".repeat(64),"expires_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs()+3600,"deadline_enforcement":"kubelet-active-deadline"});
    let proof: hosted::RuntimeProof = serde_json::from_value(value.clone()).expect("proof");
    proof
        .validate(&input, &image, &build, identity)
        .expect("shaped proof");
    for (field, changed) in [
        ("cpu", serde_json::json!("2")),
        ("memory", serde_json::json!("4Gi")),
        ("resource_shape", serde_json::Value::Null),
        (
            "resource_shape",
            serde_json::json!(ResourceShape::parse("build=4,8Gi,19Gi").expect("small")),
        ),
    ] {
        let mut wrong = value.clone();
        wrong[field] = changed;
        let wrong: hosted::RuntimeProof = serde_json::from_value(wrong).expect("proof");
        assert!(
            wrong.validate(&input, &image, &build, identity).is_err(),
            "{field}"
        );
    }
}
