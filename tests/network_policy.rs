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
