//! Operator-owned Kubernetes resources for one isolated sandbox.

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

pub(super) fn limits() -> Value {
    json!({"cpu":"2","memory":"4Gi","ephemeral-storage":"1Gi"})
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

pub(super) fn pvc(name: &str, namespace: &str, storage_class: &str) -> Value {
    json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":metadata(name,namespace),
        "spec":{"accessModes":["ReadWriteOnce"],"storageClassName":storage_class,
        "resources":{"requests":{"storage":"19Gi"}}}})
}

pub(super) fn pod(name: &str, namespace: &str, image: &str) -> Value {
    let resources = json!({"requests":limits(),"limits":limits()});
    json!({"apiVersion":"v1","kind":"Pod","metadata":metadata(name,namespace),"spec":{
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
            "resources":resources,"env":[{"name":"DOCKER_TLS_CERTDIR","value":""},
                {"name":"KATA_DOCKER_STORAGE_DRIVER","value":"vfs"}],
            "command":["/usr/local/sbin/openshell-kata-init"],
            "readinessProbe":{"exec":{"command":["sh","-ec",r#"test -n "$(ss -H -lnt 'sport = :22')""#]},"initialDelaySeconds":2,"periodSeconds":2},
            "startupProbe":{"exec":{"command":["docker","info"]},
                "periodSeconds":2,"timeoutSeconds":3,"failureThreshold":90},
            "volumeMounts":[{"name":"data","mountPath":"/sandbox","subPath":"workspace"},
                {"name":"data","mountPath":"/var/lib/docker","subPath":"docker"},
                {"name":"ssh","mountPath":"/run/guest-ssh","readOnly":true}]}],
        "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":name}},
            {"name":"ssh","secret":{"secretName":name,"defaultMode":384}}]}})
}
