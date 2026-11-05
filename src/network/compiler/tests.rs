use super::*;
use crate::proto::openshell::sandbox::v1::{
    NetworkBinary, NetworkCredentialBinding, NetworkPolicyRule,
};

fn ceiling() -> NetworkPolicy {
    NetworkPolicy {
        tcp_allow: [
            "api.anthropic.com",
            "github.com",
            "api.github.com",
            "chatgpt.com",
        ]
        .into_iter()
        .map(|host| Endpoint {
            host: host.into(),
            port: 443,
        })
        .collect(),
        ..Default::default()
    }
}

/// The credential-bearing endpoint shape a Kata placement policy emits.
fn rest(host: &str, access: i32) -> NetworkEndpoint {
    NetworkEndpoint {
        host: host.into(),
        port: 443,
        protocol: "rest".into(),
        enforcement: 1,
        access,
        // Stamped by the gateway when an attached provider binds this host.
        provider_credentialed: true,
        ..Default::default()
    }
}

fn skip(host: &str) -> NetworkEndpoint {
    NetworkEndpoint {
        host: host.into(),
        port: 443,
        tls: 1,
        ..Default::default()
    }
}

fn rule(binary: &str, endpoints: Vec<NetworkEndpoint>) -> NetworkPolicyRule {
    NetworkPolicyRule {
        binaries: vec![NetworkBinary {
            path: binary.into(),
        }],
        endpoints,
        ..Default::default()
    }
}

fn policy(rules: Vec<(&str, NetworkPolicyRule)>) -> SandboxPolicy {
    SandboxPolicy {
        version: 1,
        network_policies: rules
            .into_iter()
            .map(|(name, rule)| (name.to_owned(), rule))
            .collect(),
        ..Default::default()
    }
}

#[test]
fn credentialed_rest_endpoints_compile_to_inspected_destinations() -> Result<()> {
    let native = policy(vec![(
        "model_and_subscriptions",
        rule(
            "/**",
            vec![
                rest("api.anthropic.com", 2),
                rest("GitHub.com.", 2),
                rest("api.github.com", 3),
                skip("chatgpt.com"),
            ],
        ),
    )]);
    let compiled = compile_native_with_inspection(&native, &ceiling())?;
    assert_eq!(compiled.tcp_allow.len(), 4);
    let inspected: Vec<_> = compiled
        .tls_inspect
        .iter()
        .map(|endpoint| (endpoint.host.as_str(), endpoint.access))
        .collect();
    assert_eq!(
        inspected,
        [
            ("api.anthropic.com", RestAccess::ReadWrite),
            ("api.github.com", RestAccess::Full),
            ("github.com", RestAccess::ReadWrite),
        ]
    );
    let validated = compiled.validate()?;
    assert_eq!(validated.inspection("chatgpt.com", 443), None);
    assert!(validated.allows("chatgpt.com", 443));
    Ok(())
}

#[test]
fn hosted_and_strict_compilation_never_inspect() {
    let native = policy(vec![(
        "subscriptions",
        rule("/**", vec![rest("api.anthropic.com", 2)]),
    )]);
    assert!(compile_native(&native, &ceiling()).is_err());
}

#[test]
fn credentialed_endpoints_outside_the_supported_shape_fail_closed() {
    let cases: Vec<(&str, NetworkEndpoint)> = vec![
        (
            "uninspected credentials",
            NetworkEndpoint {
                allow_uninspected_credentials: true,
                ..rest("api.anthropic.com", 2)
            },
        ),
        (
            "credentialed L4",
            NetworkEndpoint {
                provider_credentialed: true,
                ..skip("api.anthropic.com")
            },
        ),
        (
            "credentialed tcp without tls mode",
            NetworkEndpoint {
                protocol: "tcp".into(),
                provider_credentialed: true,
                ..Default::default()
            },
        ),
        (
            "rest with tls skip",
            NetworkEndpoint {
                tls: 1,
                ..rest("api.anthropic.com", 2)
            },
        ),
        (
            "deprecated terminate",
            NetworkEndpoint {
                tls: 2,
                ..rest("api.anthropic.com", 2)
            },
        ),
        (
            "audit mode",
            NetworkEndpoint {
                enforcement: 2,
                ..rest("api.anthropic.com", 2)
            },
        ),
        ("no access preset", rest("api.anthropic.com", 0)),
        (
            "explicit L7 rules",
            NetworkEndpoint {
                rules: vec![Default::default()],
                ..rest("api.anthropic.com", 2)
            },
        ),
        (
            "path scope",
            NetworkEndpoint {
                path: "/v1/**".into(),
                ..rest("api.anthropic.com", 2)
            },
        ),
        (
            "credential binding",
            NetworkEndpoint {
                credential_binding: Some(NetworkCredentialBinding::default()),
                ..rest("api.anthropic.com", 2)
            },
        ),
        (
            "body rewriting",
            NetworkEndpoint {
                request_body_credential_rewrite: true,
                ..rest("api.anthropic.com", 2)
            },
        ),
        ("outside the operator ceiling", rest("api.openai.com", 2)),
        (
            "IP literal",
            NetworkEndpoint {
                host: "93.184.216.34".into(),
                ..rest("api.anthropic.com", 2)
            },
        ),
    ];
    let mut wide = ceiling();
    wide.tcp_allow.push(Endpoint {
        host: "93.184.216.34".into(),
        port: 443,
    });
    for (name, endpoint) in cases {
        let endpoint = NetworkEndpoint {
            host: if endpoint.host.is_empty() {
                "api.anthropic.com".into()
            } else {
                endpoint.host.clone()
            },
            port: 443,
            ..endpoint
        };
        let native = policy(vec![("rule", rule("/**", vec![endpoint]))]);
        assert!(
            compile_native_with_inspection(&native, &wide).is_err(),
            "accepted {name}"
        );
    }
}

#[test]
fn one_destination_cannot_be_both_opaque_and_inspected() {
    let native = policy(vec![
        ("inspected", rule("/**", vec![rest("api.github.com", 1)])),
        ("opaque", rule("/**", vec![skip("api.github.com")])),
    ]);
    assert!(compile_native_with_inspection(&native, &ceiling()).is_err());
}

#[test]
fn matching_rest_rules_union_their_presets() -> Result<()> {
    let native = policy(vec![
        ("read", rule("/**", vec![rest("api.github.com", 1)])),
        ("write", rule("/**", vec![rest("api.github.com", 2)])),
    ]);
    let compiled = compile_native_with_inspection(&native, &ceiling())?;
    assert_eq!(compiled.tls_inspect[0].access, RestAccess::ReadWrite);
    Ok(())
}

#[test]
fn provider_composed_rules_grant_nothing_in_a_vm() -> Result<()> {
    // The gateway composes one `_provider_*` rule per attached provider from
    // its profile, naming that profile's executables and L7 rules.
    let provider = NetworkPolicyRule {
        binaries: vec![
            NetworkBinary {
                path: "/usr/bin/git".into(),
            },
            NetworkBinary {
                path: "/usr/local/bin/system-agent".into(),
            },
        ],
        endpoints: vec![NetworkEndpoint {
            rules: vec![Default::default()],
            ..rest("github.com", 0)
        }],
        ..Default::default()
    };
    let only_provider = policy(vec![(
        "_provider_github_repo_0123456789ab",
        provider.clone(),
    )]);
    let compiled = compile_native_with_inspection(&only_provider, &ceiling())?;
    assert!(compiled.tcp_allow.is_empty() && compiled.tls_inspect.is_empty());
    let with_sandbox_rule = policy(vec![
        ("_provider_github_repo_0123456789ab", provider.clone()),
        (
            "model_and_subscriptions",
            rule("/**", vec![rest("github.com", 2)]),
        ),
    ]);
    let compiled = compile_native_with_inspection(&with_sandbox_rule, &ceiling())?;
    assert_eq!(compiled.tls_inspect[0].access, RestAccess::ReadWrite);
    // Without the reserved provider prefix a narrow executable rule is a
    // sandbox claim the VM cannot enforce.
    let authored = policy(vec![("github", provider)]);
    assert!(compile_native_with_inspection(&authored, &ceiling()).is_err());
    Ok(())
}

#[test]
fn inspected_destinations_must_be_allowed_dns_names() {
    let policy = NetworkPolicy {
        tcp_allow: vec![],
        tls_inspect: vec![InspectedEndpoint {
            host: "api.anthropic.com".into(),
            port: 443,
            access: RestAccess::Full,
        }],
        ..Default::default()
    };
    assert!(policy.validate().is_err());
    let unchanged = serde_json::to_string(&NetworkPolicy::default()).expect("serialize");
    assert_eq!(
        unchanged, r#"{"tcp_allow":[]}"#,
        "existing policy encodings and digests are unchanged"
    );
}

#[test]
fn access_presets_match_openshell_rest_expansion() {
    for method in ["GET", "HEAD", "OPTIONS"] {
        assert!(RestAccess::ReadOnly.allows(method));
    }
    for method in ["POST", "PUT", "PATCH"] {
        assert!(!RestAccess::ReadOnly.allows(method));
        assert!(RestAccess::ReadWrite.allows(method));
    }
    assert!(!RestAccess::ReadWrite.allows("DELETE"));
    assert!(RestAccess::Full.allows("DELETE"));
}

fn public_ceiling(ports: Vec<u16>) -> NetworkPolicy {
    NetworkPolicy {
        tcp_allow_public_ports: ports,
        ..ceiling()
    }
}

fn skip_on(host: &str, ports: Vec<u32>) -> NetworkEndpoint {
    NetworkEndpoint {
        ports,
        port: 0,
        ..skip(host)
    }
}

#[test]
fn public_host_rules_compile_only_within_ceiling_public_ports() -> Result<()> {
    let native = policy(vec![(
        "build",
        rule(
            "/**",
            vec![skip_on("**", vec![443, 80]), skip("github.com")],
        ),
    )]);
    let compiled = compile_native(&native, &public_ceiling(vec![80, 443]))?;
    assert_eq!(compiled.tcp_allow_public_ports, vec![80, 443]);
    assert_eq!(
        compiled.tcp_allow,
        vec![Endpoint {
            host: "github.com".into(),
            port: 443
        }]
    );
    assert!(compiled.is_subset_of(&public_ceiling(vec![80, 443]))?);
    // The ceiling grants 443 only: port 80 must be refused, not dropped.
    let error = compile_native(&native, &public_ceiling(vec![443]))
        .expect_err("public port outside ceiling");
    assert!(error.to_string().contains("public port"));
    // No public ports in the ceiling: the exact-only behaviour is unchanged.
    assert!(compile_native(&native, &ceiling()).is_err());
    // An empty host without allowed_ips selects public hosts too.
    let empty = policy(vec![("build", rule("/**", vec![skip("")]))]);
    assert_eq!(
        compile_native(&empty, &public_ceiling(vec![443]))?.tcp_allow_public_ports,
        vec![443]
    );
    Ok(())
}

#[test]
fn public_host_rules_keep_every_other_restriction() {
    let ceiling = public_ceiling(vec![443]);
    let with_ips = NetworkEndpoint {
        allowed_ips: vec!["10.0.0.0/8".into()],
        ..skip("")
    };
    for native in [
        // allowed_ips replaces the private-range check in OpenShell; never here.
        policy(vec![("ips", rule("/**", vec![with_ips]))]),
        // Public traffic is TLS passthrough only: no inspection or credentials.
        policy(vec![("rest", rule("/**", vec![rest("**", 2)]))]),
        // Executable identity is still unsupported.
        policy(vec![("git", rule("/usr/bin/git", vec![skip("**")]))]),
        // Only `**` is "every name"; other globs stay rejected.
        policy(vec![("glob", rule("/**", vec![skip("*.example.com")]))]),
        policy(vec![("star", rule("/**", vec![skip("*")]))]),
    ] {
        assert!(compile_native_with_inspection(&native, &ceiling).is_err());
        assert!(compile_native(&native, &ceiling).is_err());
    }
}
