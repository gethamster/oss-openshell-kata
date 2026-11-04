use super::*;
use crate::network::{BrokerBinding, HostedBrokerConfig, NetworkPolicy};
use serde_json::json;

const UID: &str = "11111111-1111-4111-8111-111111111111";
const NS: &str = "22222222-2222-4222-8222-222222222222";
const BROKER: &str = "33333333-3333-4333-8333-333333333333";
const NONCE: &str = "44444444-4444-4444-8444-444444444444";
const NODE: &str = "55555555-5555-4555-8555-555555555555";
const BOOT: &str = "66666666-6666-4666-8666-666666666666";
const CONTROLLER: &str = "77777777-7777-4777-8777-777777777777";
const IMAGE: &str = "registry.example/guest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub(super) fn fixture() -> Result<(config::Config, Value, admission::Launch)> {
    use sha2::{Digest, Sha256};
    let mut config: config::Config = serde_json::from_value(
        json!({"version":1,"node_name":"node-a","node_uid":NODE,"boot_id":BOOT,"kubectl_path":"/usr/bin/kubectl","kubectl_sha256":"a".repeat(64),"kubeconfig_path":"/etc/kubeconfig","bundle_root":"/run/containerd/bundles","nsenter_path":"/usr/bin/nsenter","ip_path":"/usr/sbin/ip","broker_namespace":"openshell-network","broker_namespace_uid":BROKER,"broker_image":IMAGE,"guest_image":IMAGE,"operator_network_config_path":"/etc/operator.json","controller_namespace":"openshell-system","controller_namespace_uid":CONTROLLER,"controller_labels":{"role":"sandbox-control"},"controller_container_images":{"gateway":IMAGE},"controller_init_container_images":{"trust":IMAGE,"kata-adapter":IMAGE},"controller_restartable_init_containers":["kata-adapter"]}),
    )?;
    let operator: crate::kubernetes::HostedNetworkConfig = serde_json::from_value(
        json!({"version":1,"broker_namespace":"openshell-network","broker_namespace_uid":BROKER,"guard_namespace":"kata-system","guard_namespace_uid":"fb7d9e07-2d92-4fb0-a91a-64fe9be8c8b9","guard_client_tls_config_file":"/operator/guard-client.json","operator_ceiling":{"tcp_allow":[]},"baseline_denied_cidrs":[],"protected_hostname_suffixes":[],"authorization_lease_secs":30,"resolver_nameservers":["10.0.0.10"],"resolver_namespace_labels":{"name":"dns"},"resolver_pod_labels":{"app":"dns"},"inventory_file":"/etc/inventory.json"}),
    )?;
    config.operator = Some(operator);
    let expiry = host::now()? + 3600;
    let binding = BrokerBinding {
        workspace: "tenant-a".into(),
        namespace_uid: NS.into(),
        sandbox_id: "sandbox-test".into(),
        launch_nonce: NONCE.into(),
        expires_at_unix: expiry,
    };
    let broker_config = HostedBrokerConfig {
        version: 1,
        operator_ceiling: NetworkPolicy::default(),
        initial_ceiling: NetworkPolicy::default(),
        binding,
        protected_hostname_suffixes: vec![],
        baseline_denied_cidrs: vec![],
        authorization_lease_secs: 30,
    };
    let digest = broker_config.digest()?;
    let name = format!(
        "kata-{}",
        &format!("{:x}", Sha256::digest(b"sandbox-test"))[..24]
    );
    let guest = json!({"metadata":{"name":name,"namespace":"sandbox-tenant-a","uid":UID,"labels":{"app.kubernetes.io/managed-by":"openshell-kata","sandbox-id":name,"openshell-kata.io/namespace-uid":NS,"platform.tryhamster.dev/network-profile":admission::PROFILE,"openshell-kata.io/launch-nonce":NONCE},"annotations":{"openshell-kata.io/sandbox-id":"sandbox-test","openshell-kata.io/launch-nonce":NONCE,"openshell-kata.io/expires-at":expiry.to_string(),"openshell-kata.io/source-namespace-uid":NS,"openshell-kata.io/broker-pod-uid":BROKER,"openshell-kata.io/broker-ip":"10.2.3.4","openshell-kata.io/broker-port":"3128","openshell-kata.io/broker-config-sha256":digest}},"spec":{"nodeName":"node-a","runtimeClassName":"kata-qemu-runtime-rs-guarded","automountServiceAccountToken":false,"containers":[{"name":"guest","image":IMAGE}],"initContainers":[{"name":"storage","image":IMAGE}]},"status":{}});
    let broker_name = format!("broker-{}", NONCE.replace('-', ""));
    let metadata = json!({"name":broker_name,"namespace":"openshell-network","uid":BROKER,"labels":{"app.kubernetes.io/managed-by":"openshell-kata","openshell-kata.io/component":"network-broker","openshell-kata.io/namespace-uid":NS,"openshell-kata.io/launch-nonce":NONCE},"ownerReferences":[{"apiVersion":"v1","kind":"Namespace","name":"sandbox-tenant-a","uid":NS,"controller":false,"blockOwnerDeletion":false}]});
    let mut broker = crate::kubernetes::node_broker_manifest(
        IMAGE,
        BROKER,
        &broker_config,
        config.operator.as_ref().expect("fixture operator"),
    )?;
    broker["metadata"]["uid"] = json!(BROKER);
    broker["status"] = json!({"phase":"Running","podIP":"10.2.3.4","containerStatuses":[{"name":"broker","ready":true,"restartCount":0}]});
    let configmap = json!({"metadata":metadata,"immutable":true,"data":{"config.json":serde_json::to_string(&broker_config)?}});
    let controllers = json!({"items":[{"metadata":{"namespace":"openshell-system","uid":CONTROLLER,"labels":{"role":"sandbox-control"}},"spec":{"containers":[{"name":"gateway","image":IMAGE}],"initContainers":[{"name":"trust","image":IMAGE},{"name":"kata-adapter","image":IMAGE,"restartPolicy":"Always"}]},"status":{"phase":"Running","podIP":"10.3.4.5","containerStatuses":[{"name":"gateway","ready":true,"state":{"running":{}}}],"initContainerStatuses":[{"name":"trust","state":{"terminated":{"exitCode":0,"reason":"Completed"}}},{"name":"kata-adapter","ready":true,"started":true,"state":{"running":{}}}]}}]});
    let namespace = |name, uid| json!({"metadata":{"name":name,"uid":uid,"labels":{"openshell-kata.io/namespace-uid":uid}}});
    Ok((
        config,
        guest,
        admission::Launch {
            source_namespace: namespace("sandbox-tenant-a", NS),
            node: json!({"metadata":{"name":"node-a","uid":NODE,"labels":{"openshell-kata.io/guarded-runtime":"true"}},"status":{"nodeInfo":{"bootID":BOOT}}}),
            broker_namespace: namespace("openshell-network", BROKER),
            controller_namespace: namespace("openshell-system", CONTROLLER),
            controllers,
            broker,
            configmap,
        },
    ))
}

#[test]
fn api_identity_and_restartable_controller_sidecars_are_bound_before_network_observation()
-> Result<()> {
    let (config, guest, launch) = fixture()?;
    config.validate()?;
    let intent = admission::derive(&config, &guest, &launch)?;
    assert_eq!(intent.controller_cidrs, vec!["10.3.4.5/32"]);
    assert_eq!(intent.pod_uid, UID);
    assert_eq!(intent.namespace_uid, NS);
    assert!(
        guest["status"].get("podIP").is_none(),
        "preboot PodIP is intentionally unknown"
    );
    for field in ["uid", "namespace"] {
        let mut changed = guest.clone();
        changed["metadata"][field] = json!("bad");
        assert!(
            admission::derive(&config, &changed, &launch).is_err(),
            "unbound guest {field}"
        );
    }
    for key in [
        "sandbox-id",
        "launch-nonce",
        "expires-at",
        "source-namespace-uid",
        "broker-pod-uid",
        "broker-ip",
        "broker-port",
        "broker-config-sha256",
    ] {
        let mut changed = guest.clone();
        changed["metadata"]["annotations"][format!("openshell-kata.io/{key}")] = json!("bad");
        assert!(
            admission::derive(&config, &changed, &launch).is_err(),
            "unbound annotation {key}"
        );
    }
    Ok(())
}

#[test]
fn owner_guest_images_are_pinned_and_match_the_storage_initializer() -> Result<()> {
    let (mut config, guest, launch) = fixture()?;
    assert!(
        config.additional_guest_images.is_empty(),
        "omitted list preserves the default"
    );
    let owner = format!("registry.example/team-workspace@sha256:{}", "b".repeat(64));
    let thread = format!("registry.example/thread-minion@sha256:{}", "c".repeat(64));
    config.additional_guest_images = vec![owner.clone(), thread.clone()];
    config.validate()?;
    for image in [IMAGE, owner.as_str(), thread.as_str()] {
        let mut selected = guest.clone();
        selected["spec"]["containers"][0]["image"] = json!(image);
        selected["spec"]["initContainers"][0]["image"] = json!(image);
        let intent = admission::derive(&config, &selected, &launch)?;
        assert_eq!(intent.pod_uid, UID);
        assert_eq!(intent.namespace_uid, NS);
        assert_eq!(intent.launch_nonce, NONCE);
        // Even two admitted images may not be mixed within one guest generation.
        selected["spec"]["initContainers"][0]["image"] =
            json!(if image == IMAGE { &owner } else { IMAGE });
        assert!(admission::derive(&config, &selected, &launch).is_err());
    }
    for image in [
        "registry.example/owner:latest".to_owned(),
        format!("registry.example/foreign@sha256:{}", "d".repeat(64)),
    ] {
        let mut selected = guest.clone();
        selected["spec"]["containers"][0]["image"] = json!(image);
        selected["spec"]["initContainers"][0]["image"] = json!(image);
        assert!(admission::derive(&config, &selected, &launch).is_err());
    }
    config
        .additional_guest_images
        .push("registry.example/owner:latest".into());
    assert!(
        config.validate().is_err(),
        "operator additions must also be digest pinned"
    );
    Ok(())
}

#[test]
fn namespace_mirrors_are_optional_but_guest_generation_is_required() -> Result<()> {
    let (config, mut guest, mut launch) = fixture()?;
    for namespace in [
        &mut launch.source_namespace,
        &mut launch.broker_namespace,
        &mut launch.controller_namespace,
    ] {
        namespace["metadata"]
            .as_object_mut()
            .expect("metadata")
            .remove("labels");
    }
    admission::derive(&config, &guest, &launch)?;
    guest["metadata"]["labels"]["openshell-kata.io/namespace-uid"] = json!(UID);
    assert!(admission::derive(&config, &guest, &launch).is_err());
    Ok(())
}

#[test]
fn controller_namespace_images_ready_state_and_native_init_sidecars_cannot_drift() -> Result<()> {
    for field in [
        "namespace",
        "image",
        "restart",
        "ready",
        "completed",
        "extra",
        "host",
        "ephemeral",
    ] {
        let (config, guest, mut launch) = fixture()?;
        let pod = &mut launch.controllers["items"][0];
        match field {
            "namespace" => pod["metadata"]["namespace"] = json!("another"),
            "image" => pod["spec"]["containers"][0]["image"] = json!("untrusted:latest"),
            "restart" => pod["spec"]["initContainers"][1]["restartPolicy"] = Value::Null,
            "ready" => pod["status"]["initContainerStatuses"][1]["ready"] = json!(false),
            "completed" => {
                pod["status"]["initContainerStatuses"][0]["state"]["terminated"]["exitCode"] =
                    json!(1)
            }
            "extra" => pod["spec"]["containers"]
                .as_array_mut()
                .expect("fixture containers")
                .push(json!({"name":"extra","image":IMAGE})),
            "host" => pod["spec"]["hostNetwork"] = json!(true),
            "ephemeral" => pod["spec"]["ephemeralContainers"] = json!([{"name":"debug"}]),
            _ => unreachable!("bounded fixture mutation"),
        }
        assert!(
            admission::derive(&config, &guest, &launch).is_err(),
            "unbound controller {field}"
        );
    }
    Ok(())
}

#[test]
fn gateway_mac_must_be_known_before_guest_boot() -> Result<()> {
    let address = json!([{"ifname":"eth0","ifindex":2,"address":"02:00:00:00:00:01","addr_info":[{"family":"inet","local":"10.4.5.6"}]}]);
    let routes = json!([{"dst":"default","gateway":"169.254.1.1","dev":"eth0"}]);
    let neighbor = json!([{"dst":"169.254.1.1","dev":"eth0","lladdr":"02:00:00:00:00:02","state":["PERMANENT"]}]);
    assert_eq!(
        host::parse_network(&address, &routes, &neighbor)?.0,
        "10.4.5.6".parse::<std::net::Ipv4Addr>()?
    );
    assert!(host::parse_network(&address, &routes, &json!([])).is_err());
    let mut invalid = neighbor.clone();
    invalid[0]["state"] = json!(["INCOMPLETE"]);
    assert!(host::parse_network(&address, &routes, &invalid).is_err());
    let mut invalid = address.clone();
    invalid[0]["addr_info"][0]["local"] = json!("8.8.8.8");
    assert!(host::parse_network(&invalid, &routes, &neighbor).is_err());
    Ok(())
}

#[test]
fn intent_is_private_atomic_and_cannot_be_rebound() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let (config, guest, launch) = fixture()?;
    let intent = admission::derive(&config, &guest, &launch)?;
    let root = tempfile::tempdir()?;
    host::publish_at(root.path(), &intent)?;
    host::publish_at(root.path(), &intent)?;
    let path = root.path().join(format!("{UID}.json"));
    assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    let mut wrong = intent.clone();
    wrong.broker_port = 1;
    assert!(host::publish_at(root.path(), &wrong).is_err());
    Ok(())
}

#[tokio::test]
async fn observation_commands_are_bounded_and_fail_closed() -> Result<()> {
    let mut command = tokio::process::Command::new("/bin/sh");
    command.args(["-c", "exit 2"]);
    assert!(client::bounded(command).await.is_err());
    let mut command = tokio::process::Command::new("/bin/echo");
    command.arg("observed");
    assert_eq!(client::bounded(command).await?, b"observed\n");
    let mut command = tokio::process::Command::new("/bin/sleep");
    command.arg("2");
    assert!(
        client::bounded_for(command, Duration::from_millis(20))
            .await
            .is_err()
    );
    let mut command = tokio::process::Command::new("/bin/sh");
    command.args(["-c", "head -c 2097153 /dev/zero"]);
    assert!(client::bounded(command).await.is_err());
    Ok(())
}

#[test]
fn broker_process_owner_and_operator_ceiling_are_independent_of_tenant_annotations() -> Result<()> {
    for field in [
        "uid",
        "namespace",
        "owner",
        "sourceuid",
        "configmutable",
        "configunknown",
        "configceiling",
        "node",
        "boot",
        "brokerimage",
        "brokercommand",
        "brokerhostmount",
        "brokercap",
        "restart",
    ] {
        let (config, guest, mut launch) = fixture()?;
        match field {
            "uid" => launch.broker["metadata"]["uid"] = json!("bad"),
            "namespace" => launch.broker_namespace["metadata"]["uid"] = json!(UID),
            "owner" => launch.configmap["metadata"]["ownerReferences"][0]["uid"] = json!(UID),
            "sourceuid" => launch.source_namespace["metadata"]["uid"] = json!(UID),
            "configmutable" => launch.configmap["immutable"] = json!(false),
            "configunknown" => {
                let mut value: Value = serde_json::from_str(
                    launch.configmap["data"]["config.json"]
                        .as_str()
                        .expect("fixture config"),
                )?;
                value["unknown"] = json!(true);
                launch.configmap["data"]["config.json"] = json!(serde_json::to_string(&value)?);
            }
            "configceiling" => {
                let mut value: Value = serde_json::from_str(
                    launch.configmap["data"]["config.json"]
                        .as_str()
                        .expect("fixture config"),
                )?;
                value["operator_ceiling"]["tcp_allow"] =
                    json!([{"host":"registry.npmjs.org","port":443}]);
                launch.configmap["data"]["config.json"] = json!(serde_json::to_string(&value)?);
            }
            "node" => launch.node["metadata"]["uid"] = json!(UID),
            "boot" => launch.node["status"]["nodeInfo"]["bootID"] = json!(UID),
            "brokerimage" => launch.broker["spec"]["containers"][0]["image"] = json!("latest"),
            "brokercommand" => launch.broker["spec"]["containers"][0]["command"] = json!(["sh"]),
            "brokerhostmount" => {
                launch.broker["spec"]["volumes"][0]["hostPath"] = json!({"path":"/"})
            }
            "brokercap" => {
                launch.broker["spec"]["containers"][0]["securityContext"]["capabilities"]["add"] =
                    json!(["NET_ADMIN"])
            }
            "restart" => launch.broker["status"]["containerStatuses"][0]["restartCount"] = json!(1),
            _ => unreachable!("bounded mutation"),
        }
        assert!(
            admission::derive(&config, &guest, &launch).is_err(),
            "accepted changed {field}"
        );
    }
    Ok(())
}

#[test]
fn input_and_resource_replacement_checks_are_closed() -> Result<()> {
    let (config, guest, launch) = fixture()?;
    assert!(admission::stable_guest(&guest, &guest));
    assert!(admission::stable_broker(&launch.broker, &launch.broker));
    let mut changed = guest.clone();
    changed["metadata"]["uid"] = json!(NS);
    assert!(!admission::stable_guest(&guest, &changed));
    let mut changed = launch.broker.clone();
    changed["status"]["podIP"] = json!("10.0.0.1");
    assert!(!admission::stable_broker(&launch.broker, &changed));
    for value in ["", "../bad", "x,y=z", "-bad", "NAME"] {
        assert!(config::dns_label(value).is_err());
    }
    for value in [
        "bad",
        "00000000-0000-0000-0000-000000000000",
        "ABCDEFAB-1111-4111-8111-111111111111",
    ] {
        assert!(config::canonical_uuid(value).is_err());
    }
    let mut changed = config.clone();
    changed
        .controller_restartable_init_containers
        .insert("unknown".into());
    assert!(changed.validate().is_err());
    let mut changed = config.clone();
    changed.kubeconfig_path = "relative".into();
    assert!(changed.validate().is_err());
    let mut changed = config;
    changed.controller_labels.clear();
    assert!(changed.validate().is_err());
    Ok(())
}

#[test]
fn kubernetes_observation_requires_verified_tls_and_projected_service_account_auth() -> Result<()> {
    let config = json!({"clusters":[{"name":"cluster","cluster":{"server":"https://kubernetes.default.svc","certificate-authority":"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"}}],"users":[{"name":"watcher","user":{"tokenFile":"/var/run/secrets/kubernetes.io/serviceaccount/token"}}],"contexts":[{"name":"watcher","context":{"cluster":"cluster","user":"watcher"}}],"current-context":"watcher"});
    config::validate_kubeconfig(&config)?;
    for field in [
        "plaintext",
        "skipverify",
        "exec",
        "inline-token",
        "multiple",
        "wrong-context",
    ] {
        let mut wrong = config.clone();
        match field {
            "plaintext" => {
                wrong["clusters"][0]["cluster"]["server"] = json!("http://kubernetes.default.svc")
            }
            "skipverify" => {
                wrong["clusters"][0]["cluster"]["insecure-skip-tls-verify"] = json!(true)
            }
            "exec" => wrong["users"][0]["user"]["exec"] = json!({"command":"malicious"}),
            "inline-token" => wrong["users"][0]["user"] = json!({"token":"inline"}),
            "multiple" => wrong["contexts"]
                .as_array_mut()
                .expect("fixture contexts")
                .push(json!({"name":"other"})),
            "wrong-context" => wrong["current-context"] = json!("other"),
            _ => unreachable!("bounded mutation"),
        }
        assert!(
            config::validate_kubeconfig(&wrong).is_err(),
            "accepted unsafe {field}"
        );
    }
    Ok(())
}

#[test]
fn unrendered_broker_pod_fields_cannot_acquire_preboot_authority() -> Result<()> {
    for field in [
        "lifecycle",
        "envFrom",
        "startupProbe",
        "livenessProbe",
        "readinessProbe",
        "init-image",
        "init-command",
        "env",
        "mount-source",
        "config-source",
        "inventory-source",
        "volume-items",
        "extra-pod-field",
        "extra-container-field",
    ] {
        let (config, guest, mut launch) = fixture()?;
        match field {
            "lifecycle" => {
                launch.broker["spec"]["containers"][0]["lifecycle"] =
                    json!({"postStart":{"exec":{"command":["sh","-c","malicious"]}}})
            }
            "envFrom" => {
                launch.broker["spec"]["containers"][0]["envFrom"] =
                    json!([{"configMapRef":{"name":"untrusted"}}])
            }
            "startupProbe" | "livenessProbe" | "readinessProbe" => {
                launch.broker["spec"]["containers"][0][field] =
                    json!({"exec":{"command":["sh","-c","malicious"]}})
            }
            "init-image" => {
                launch.broker["spec"]["initContainers"] =
                    json!([{"name":"control-permissions","image":"untrusted:latest"}])
            }
            "init-command" => {
                launch.broker["spec"]["initContainers"] = json!([{"name":"control-permissions","image":IMAGE,"command":["sh","-c","malicious"]}])
            }
            "env" => {
                launch.broker["spec"]["containers"][0]["env"] =
                    json!([{"name":"UNTRUSTED","value":"injected"}])
            }
            "mount-source" => {
                launch.broker["spec"]["containers"][0]["volumeMounts"] =
                    json!([{"name":"inventory","mountPath":"/broker-config"}])
            }
            "config-source" => {
                launch.broker["spec"]["volumes"][1]["configMap"] = json!({"name":"untrusted"})
            }
            "inventory-source" => {
                launch.broker["spec"]["volumes"][2]["configMap"] = json!({"name":"untrusted"})
            }
            "volume-items" => {
                launch.broker["spec"]["volumes"][1]["configMap"]["items"] =
                    json!([{"key":"another","path":"config.json"}])
            }
            "extra-pod-field" => launch.broker["spec"]["arbitraryFutureAuthority"] = json!(true),
            "extra-container-field" => {
                launch.broker["spec"]["containers"][0]["arbitraryFutureAuthority"] = json!(true)
            }
            _ => unreachable!("bounded adversarial projection"),
        }
        assert!(
            admission::derive(&config, &guest, &launch).is_err(),
            "preboot authority accepted unrendered {field}"
        );
    }
    Ok(())
}

#[test]
fn neighbor_initialization_requires_a_guest_that_has_never_started() -> Result<()> {
    let (_, mut guest, _) = fixture()?;
    admission::require_preboot(&guest)?;
    guest["status"]["phase"] = json!("Pending");
    admission::require_preboot(&guest)?;
    for phase in ["Running", "Succeeded", "Failed"] {
        guest["status"]["phase"] = json!(phase);
        assert!(admission::require_preboot(&guest).is_err());
    }
    guest["status"]["phase"] = json!("Pending");
    for group in ["containerStatuses", "initContainerStatuses"] {
        for state in [json!({"running":{}}), json!({"terminated":{"exitCode":0}})] {
            guest["status"][group] = json!([{"state":state}]);
            assert!(admission::require_preboot(&guest).is_err());
        }
        guest["status"][group] = Value::Null;
    }
    Ok(())
}

#[tokio::test]
async fn optional_arp_initialization_is_bounded_and_rereads_exact_network_identity() -> Result<()> {
    use std::{fs, os::unix::fs::PermissionsExt};
    let root = tempfile::tempdir()?;
    let (mut config, _, _) = fixture()?;
    config.nsenter_path = root.path().join("nsenter");
    config.ip_path = root.path().join("ip");
    let arp = root.path().join("arping");
    let address = json!([{"ifname":"eth0","ifindex":2,"address":"02:00:00:00:00:01","addr_info":[{"family":"inet","local":"10.4.5.6"}]}]);
    let route = json!([{"dst":"default","gateway":"169.254.4.6","dev":"eth0"}]);
    let neighbor = json!([{"dst":"169.254.4.6","dev":"eth0","lladdr":"02:00:00:00:00:02","state":["REACHABLE"]}]);
    for (name, value) in [
        ("address", &address),
        ("route", &route),
        ("neighbor", &neighbor),
        ("after-address", &address),
        ("after-route", &route),
    ] {
        fs::write(root.path().join(name), serde_json::to_vec(value)?)?;
    }
    let quoted = crate::config::shell_quote(root.path().to_str().expect("temp path"));
    fs::write(
        &config.nsenter_path,
        format!(
            r#"#!/bin/sh
root={quoted}
case "$3" in
*/arping)
    printf '%s\n' "$@" > "$root/calls"
    [ ! -f "$root/fail" ] || exit 1
    touch "$root/resolved" ;;
*/ip)
    case "$*" in
    *'address show dev eth0') if [ -f "$root/resolved" ]; then cat "$root/after-address"; else cat "$root/address"; fi ;;
    *'route show default') if [ -f "$root/resolved" ]; then cat "$root/after-route"; else cat "$root/route"; fi ;;
    *'neigh show') if [ -f "$root/resolved" ]; then cat "$root/neighbor"; else printf '[]'; fi ;;
    *) exit 4 ;;
    esac ;;
*) exit 3 ;;
esac
"#
        ),
    )?;
    fs::set_permissions(&config.nsenter_path, fs::Permissions::from_mode(0o700))?;
    let namespace = std::path::Path::new("/proc/123/fd/4");
    assert!(host::observe_network(&config, namespace).await.is_err());
    assert!(
        !root.path().join("calls").exists(),
        "default performs no ARP action"
    );
    config.arping_path = Some(arp.clone());
    let observed = host::observe_network(&config, namespace).await?;
    assert_eq!(observed.2, "169.254.4.6".parse::<std::net::Ipv4Addr>()?);
    assert_eq!(observed.3, "02:00:00:00:00:02");
    assert_eq!(
        fs::read_to_string(root.path().join("calls"))?,
        format!(
            "--net=/proc/123/fd/4\n--\n{}\n-I\neth0\n-c\n1\n-w\n2\n169.254.4.6\n",
            arp.display()
        )
    );
    fs::remove_file(root.path().join("calls"))?;
    host::observe_network(&config, namespace).await?;
    assert!(
        !root.path().join("calls").exists(),
        "resolved neighbors need no initialization"
    );
    fs::remove_file(root.path().join("resolved"))?;
    fs::write(root.path().join("fail"), b"")?;
    assert!(host::observe_network(&config, namespace).await.is_err());
    fs::remove_file(root.path().join("fail"))?;
    let mut changed = address.clone();
    changed[0]["ifindex"] = json!(3);
    fs::write(
        root.path().join("after-address"),
        serde_json::to_vec(&changed)?,
    )?;
    assert!(
        host::observe_network(&config, namespace).await.is_err(),
        "replacement interface rejected"
    );
    fs::remove_file(root.path().join("resolved"))?;
    fs::write(
        root.path().join("after-address"),
        serde_json::to_vec(&address)?,
    )?;
    let mut changed = route.clone();
    changed[0]["gateway"] = json!("169.254.4.7");
    fs::write(
        root.path().join("after-route"),
        serde_json::to_vec(&changed)?,
    )?;
    assert!(
        host::observe_network(&config, namespace).await.is_err(),
        "changed default gateway rejected"
    );
    Ok(())
}
