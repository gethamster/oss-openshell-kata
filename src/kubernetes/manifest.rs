//! Operator-owned Kubernetes resources for one isolated sandbox.

use crate::resource_shape::ResourceShape;
use serde_json::{Value, json};

pub(super) const RUNTIME: &str = "kata-qemu-runtime-rs";
pub(super) const GUARDED_RUNTIME: &str = "kata-qemu-runtime-rs-guarded";
pub(super) const GUARDED_NODE_LABEL: &str = "openshell-kata.io/guarded-runtime";
pub(super) fn runtime(state: &super::model::State) -> &'static str {
    if state.broker.is_some() {
        GUARDED_RUNTIME
    } else {
        RUNTIME
    }
}
pub(super) const OWNER: &str = "openshell-kata";

pub(super) fn labels(name: &str) -> Value {
    json!({"app.kubernetes.io/managed-by":OWNER,"sandbox-id":name,
        "platform.tryhamster.dev/network-profile":"isolated"})
}

pub(super) fn metadata(name: &str, namespace: &str) -> Value {
    json!({"name":name,"namespace":namespace,"labels":labels(name)})
}

pub(super) fn limits(shape: &ResourceShape) -> Value {
    json!({"cpu":shape.cpu(),"memory":shape.memory(),"ephemeral-storage":"1Gi"})
}

pub(super) fn network_policy(name: &str, namespace: &str, control_namespace: &str) -> Value {
    json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
        "metadata":metadata(name,namespace),"spec":{
        "podSelector":{"matchLabels":{"sandbox-id":name}},"policyTypes":["Ingress","Egress"],"egress":[],
        "ingress":[{"from":[{"namespaceSelector":{"matchLabels":{
            "kubernetes.io/metadata.name":control_namespace}},
            "podSelector":{"matchLabels":{"platform.tryhamster.dev/role":"sandbox-control"}}}],
            "ports":[{"port":22,"protocol":"TCP"}]}]}})
}

pub(super) fn pvc(
    name: &str,
    namespace: &str,
    storage_class: &str,
    shape: &ResourceShape,
) -> Value {
    json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":metadata(name,namespace),
        "spec":{"accessModes":["ReadWriteOnce"],"storageClassName":storage_class,
        "resources":{"requests":{"storage":shape.storage()}}}})
}

/// Guest path of the raw Docker disk. A block volume reaches the Kata VM as a
/// virtio disk, so the guest formats it and Docker uses overlay2 instead of VFS.
pub(super) const DOCKER_DEVICE: &str = "/dev/openshell-docker";

pub(super) fn docker_pvc_name(name: &str) -> String {
    format!("{name}-docker")
}

/// The private raw disk for the guest Docker data root. It has the shape's size.
pub(super) fn docker_pvc(
    name: &str,
    namespace: &str,
    storage_class: &str,
    shape: &ResourceShape,
) -> Value {
    let mut volume = pvc(name, namespace, storage_class, shape);
    volume["metadata"]["name"] = json!(docker_pvc_name(name));
    volume["spec"]["volumeMode"] = json!("Block");
    volume
}

/// `docker_disk` selects the raw Docker disk. Without it, Docker data stays on
/// the shared `data` volume with VFS, as for guests launched before the disk.
pub(super) fn pod(
    name: &str,
    namespace: &str,
    image: &str,
    shape: &ResourceShape,
    docker_disk: bool,
) -> Value {
    let resources = json!({"requests":limits(shape),"limits":limits(shape)});
    let mut pod = json!({"apiVersion":"v1","kind":"Pod","metadata":metadata(name,namespace),"spec":{
        "runtimeClassName":RUNTIME,"serviceAccountName":"openshell-sandbox",
        "automountServiceAccountToken":false,"enableServiceLinks":false,"restartPolicy":"Never",
        "terminationGracePeriodSeconds":15,"nodeSelector":{"pool":"kata-workers"},
        "tolerations":[{"key":"sandbox-runtime","operator":"Equal","value":"kata","effect":"NoSchedule"}],
        "initContainers":[{"name":"storage","image":image,"command":["sh","-ec",
            "mkdir -p /data/workspace /data/docker; chown 1000:1000 /data/workspace"],
            "resources":resources,"securityContext":{"runAsUser":0,"allowPrivilegeEscalation":false,
                "capabilities":{"drop":["ALL"],"add":["CHOWN"]}},
            "volumeMounts":[{"name":"data","mountPath":"/data"}]}],
        "containers":[{"name":"guest","image":image,"securityContext":{"privileged":true},
            "resources":resources,"env":[{"name":"DOCKER_TLS_CERTDIR"},
                {"name":"KATA_DOCKER_STORAGE_DRIVER","value":"vfs"}],
            "command":["/usr/local/sbin/openshell-kata-init"],
            "readinessProbe":{"exec":{"command":["sh","-ec",r#"test -n "$(ss -H -lnt 'sport = :22')""#]},"initialDelaySeconds":2,"periodSeconds":2},
            "startupProbe":{"exec":{"command":["docker","info"]},
                "periodSeconds":2,"timeoutSeconds":3,"failureThreshold":90},
            "volumeMounts":[{"name":"data","mountPath":"/sandbox","subPath":"workspace"},
                {"name":"data","mountPath":"/var/lib/docker","subPath":"docker"},
                {"name":"ssh","mountPath":"/run/guest-ssh","readOnly":true}]}],
        "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":name}},
            {"name":"ssh","secret":{"secretName":name,"defaultMode":384}}]}});
    if docker_disk {
        let guest = &mut pod["spec"]["containers"][0];
        guest["env"][1]["value"] = json!("overlay2");
        guest["volumeMounts"]
            .as_array_mut()
            .expect("static guest mounts")
            .retain(|mount| mount["subPath"] != "docker");
        guest["volumeDevices"] = json!([{"name":"docker","devicePath":DOCKER_DEVICE}]);
        pod["spec"]["volumes"]
            .as_array_mut()
            .expect("static guest volumes")
            .push(json!({"name":"docker","persistentVolumeClaim":{"claimName":docker_pvc_name(name)}}));
    }
    pod
}
