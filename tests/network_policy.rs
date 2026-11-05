use openshell_kata::network::{Endpoint, NetworkPolicy, globally_routable};
use std::net::IpAddr;

#[test]
fn exact_endpoints_are_normalized_and_wildcards_rejected() {
    let policy = NetworkPolicy {
        tcp_allow: vec![Endpoint {
            host: "Registry.NPMJS.org.".into(),
            port: 443,
        }],
        ..Default::default()
    }
    .validate()
    .expect("valid policy");
    assert!(policy.allows("registry.npmjs.org", 443));
    assert!(!policy.allows("registry.npmjs.org.evil.test", 443));
    assert!(!policy.allows("registry.npmjs.org", 80));
    for host in [
        "*.example.com",
        "user@example.com",
        "example.com/path",
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
        "168.63.129.16",
    ] {
        assert!(
            NetworkPolicy {
                tcp_allow: vec![Endpoint {
                    host: host.into(),
                    port: 443
                }],
                ..Default::default()
            }
            .validate()
            .is_err(),
            "accepted {host}"
        );
    }
}

#[test]
fn non_global_and_transition_addresses_cannot_reach_metadata_or_siblings() {
    for address in [
        "0.0.0.0",
        "10.1.2.3",
        "100.100.100.200",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.2",
        "192.168.0.2",
        "198.18.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "168.63.129.16",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::",
        "2001:db8::1",
        "fd00:ec2::254",
        "fe80::1",
        "ff02::1",
    ] {
        assert!(
            !globally_routable(address.parse::<IpAddr>().expect("address")),
            "accepted {address}"
        );
    }
    for address in [
        "1.1.1.1",
        "8.8.8.8",
        "93.184.216.34",
        "2606:4700:4700::1111",
    ] {
        assert!(
            globally_routable(address.parse().expect("address")),
            "rejected {address}"
        );
    }
}

fn public(ports: Vec<u16>) -> NetworkPolicy {
    NetworkPolicy {
        tcp_allow_public_ports: ports,
        ..Default::default()
    }
}

#[test]
fn public_ports_are_optional_and_old_policies_are_unchanged() {
    let old = r#"{"tcp_allow":[{"host":"example.com","port":443}]}"#;
    let parsed: NetworkPolicy = serde_json::from_str(old).expect("old policy parses");
    assert!(parsed.tcp_allow_public_ports.is_empty());
    let text = serde_json::to_string(&parsed.normalized().expect("valid")).expect("json");
    assert_eq!(text, old);
    let new: NetworkPolicy =
        serde_json::from_str(r#"{"tcp_allow":[],"tcp_allow_public_ports":[443,80,443]}"#)
            .expect("new policy parses");
    assert_eq!(
        new.normalized().expect("valid").tcp_allow_public_ports,
        vec![80, 443]
    );
    assert!(!new.is_deny_all());
    assert!(NetworkPolicy::default().is_deny_all());
    assert!(public(vec![0]).validate().is_err());
    assert!(public((1..=17).collect()).validate().is_err());
}

#[test]
fn public_port_admits_public_names_only_on_that_port() {
    let policy = public(vec![443]).validate().expect("valid");
    for host in [
        "example.com",
        "Registry.NPMJS.org.",
        "xn--bcher-kva.example",
    ] {
        assert!(policy.allows(host, 443), "refused {host}");
        // A public port is never an exact grant.
        assert!(!policy.allows_exact(host, 443), "exact {host}");
    }
    assert!(!policy.allows("example.com", 80));
    for host in [
        // Global IP literals bypass name-based protected suffixes.
        "1.1.1.1",
        "2606:4700::1111",
        "1.1.1.1.",
        // inet_aton forms that a system resolver reads as IPv4 addresses.
        "8.8.1028",
        "0x8.0x8.0x8.0x8",
        "010.8.8.8",
        "example.123",
        "localhost",
        "10.0.0.5",
        "169.254.169.254",
        "127.0.0.1",
        "::1",
        "*.example.com",
        "user@example.com",
        "",
    ] {
        assert!(!policy.allows(host, 443), "accepted {host}");
    }
}

#[test]
fn public_ports_are_contained_by_the_ceiling() {
    let exact = NetworkPolicy {
        tcp_allow: vec![Endpoint {
            host: "example.com".into(),
            port: 443,
        }],
        ..Default::default()
    };
    assert!(
        public(vec![443])
            .is_subset_of(&public(vec![443, 80]))
            .expect("valid")
    );
    assert!(!public(vec![443]).is_subset_of(&exact).expect("valid"));
    assert!(
        !public(vec![80])
            .is_subset_of(&public(vec![443]))
            .expect("valid")
    );
    // A public ceiling port covers exact destinations on that port.
    assert!(exact.is_subset_of(&public(vec![443])).expect("valid"));
    assert!(
        !public(vec![443])
            .is_subset_of(&NetworkPolicy::default())
            .expect("valid")
    );
}
