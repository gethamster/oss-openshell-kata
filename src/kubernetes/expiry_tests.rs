use super::{client::Client, lifecycle, manifest, model::State, policy, reaper};
use serde_json::{Value, json};

struct Fixture {
    _temporary: tempfile::TempDir,
    root: std::path::PathBuf,
    client: Client,
    state: State,
    pod: Value,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("fixture");
        let root = temporary.path().canonicalize().expect("canonical fixture");
        let sandbox = uuid::Uuid::new_v4().to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let identity = uuid::Uuid::new_v4().to_string();
        let name = policy::resource_id(&sandbox).expect("resource name");
        let state = State {
            sandbox_id: sandbox.clone(),
            workspace: "tenant".into(),
            namespace: "sandbox-tenant".into(),
            name: name.clone(),
            image: format!("registry.example/guest@sha256:{}", "a".repeat(64)),
            host: String::new(),
            port: 22,
            username: "sandbox".into(),
            runtime_identity: identity.clone(),
            broker: None,
            launch_nonce: Some(nonce.clone()),
            owns_volume_for_launch: true,
            expires_at: Some(1100),
            private_key_path: root.join("key"),
            known_hosts_path: root.join("known"),
        };
        let pod = json!({"metadata":{"name":name,"namespace":state.namespace,
            "uid":identity,"resourceVersion":"123","creationTimestamp":"1970-01-01T00:16:40Z",
            "labels":manifest::labels(&name),"annotations":{
                "openshell-kata.io/sandbox-id":sandbox,"openshell-kata.io/launch-nonce":nonce,
                "openshell-kata.io/expires-at":"1100"}},
            "spec":{"activeDeadlineSeconds":100},"status":{"phase":"Pending"}});
        let program = root.join("kubectl");
        let script = format!(
            r#"#!/bin/sh
set -eu
root='{}'
printf '%s\n' "$*" >> "$root/calls.txt"
case "$*" in
*"get namespace "*) printf '%s' '{{"metadata":{{"labels":{{"platform.tryhamster.dev/tenant":"tenant","platform.tryhamster.dev/role":"sandbox"}}}}}}';;
*"get pods "*) cat "$root/pods.json";;
*"get pod "*) if test -f "$root/pod.json"; then cat "$root/pod.json"; fi;;
*"patch pod "*) previous=''; for argument do if test "$previous" = '-p'; then printf '%s' "$argument" > "$root/patch.json"; fi; previous=$argument; done;;
*"delete --raw "*) cat > "$root/delete.json"; if test -f "$root/conflict"; then exit 1; fi; rm -f "$root/pod.json";;
*) exit 1;;
esac
"#,
            root.display()
        );
        super::test_program::write(&program, &script);
        std::fs::write(
            root.join("pod.json"),
            serde_json::to_vec(&pod).expect("pod"),
        )
        .expect("pending pod");
        std::fs::write(
            root.join("pods.json"),
            serde_json::to_vec(&json!({"items":[pod]})).expect("pods"),
        )
        .expect("pod inventory");
        Self {
            _temporary: temporary,
            root,
            client: Client {
                context: None,
                program,
            },
            state,
            pod,
        }
    }
}

#[tokio::test]
async fn delayed_pending_start_tightens_deadline_before_running_or_ready() {
    let mut fixture = Fixture::new();
    fixture.pod["status"]["startTime"] = json!("1970-01-01T00:18:10Z");
    lifecycle::enforce_lease_at(&fixture.client, &fixture.state, &fixture.pod, 1091)
        .await
        .expect("reconcile pending started pod");
    let patch: Value = serde_json::from_slice(
        &std::fs::read(fixture.root.join("patch.json"))
            .expect("Pending pod must be tightened before Ready"),
    )
    .expect("patch");
    assert_eq!(patch[3]["value"], 10);
}

#[tokio::test]
async fn pending_expiry_without_start_time_requests_generation_bound_deletion() {
    let fixture = Fixture::new();
    let error = lifecycle::enforce_lease_at(&fixture.client, &fixture.state, &fixture.pod, 1100)
        .await
        .expect_err("expired Pending pod must fail launch");
    assert!(error.to_string().contains("lease expired"), "{error:#}");
    let request: Value = serde_json::from_slice(
        &std::fs::read(fixture.root.join("delete.json"))
            .expect("expired pending pod deletion request"),
    )
    .expect("request");
    assert_eq!(
        request["preconditions"]["uid"],
        fixture.pod["metadata"]["uid"]
    );
    assert_eq!(request["preconditions"]["resourceVersion"], "123");
    assert!(request.get("gracePeriodSeconds").is_none());
    assert!(!fixture.root.join("pod.json").exists());
}

#[tokio::test]
async fn independent_reaper_requests_pending_expiry_after_adapter_exit() {
    let fixture = Fixture::new();
    let summary = reaper::reconcile(&fixture.client, "tenant", 1100, 0)
        .await
        .expect("independent reconciliation");
    assert_eq!(summary.requested, 1);
    assert_eq!(summary.errors, 0);
    assert!(!fixture.root.join("pod.json").exists());
    let request: Value = serde_json::from_slice(
        &std::fs::read(fixture.root.join("delete.json")).expect("deletion request"),
    )
    .expect("request");
    assert_eq!(
        request["preconditions"]["uid"],
        fixture.pod["metadata"]["uid"]
    );
    assert_eq!(request["preconditions"]["resourceVersion"], "123");
    assert!(request.get("gracePeriodSeconds").is_none());
}

#[tokio::test]
async fn unexpired_pending_pod_remains_untouched() {
    let fixture = Fixture::new();
    let summary = reaper::reconcile(&fixture.client, "tenant", 1099, 0)
        .await
        .expect("before expiry");
    assert_eq!(summary.unexpired, 1);
    assert_eq!(summary.requested, 0);
    assert!(!fixture.root.join("delete.json").exists());
}

#[tokio::test]
async fn independent_reaper_tightens_a_delayed_pending_start_without_adapter_help() {
    let mut fixture = Fixture::new();
    fixture.pod["status"]["startTime"] = json!("1970-01-01T00:18:10Z");
    std::fs::write(
        fixture.root.join("pods.json"),
        serde_json::to_vec(&json!({"items":[fixture.pod]})).expect("inventory"),
    )
    .expect("write inventory");
    let summary = reaper::reconcile(&fixture.client, "tenant", 1091, 0)
        .await
        .expect("controller tightens before Ready");
    assert_eq!(summary.tightened, 1);
    assert_eq!(summary.requested, 0);
    let patch: Value = serde_json::from_slice(
        &std::fs::read(fixture.root.join("patch.json")).expect("deadline patch"),
    )
    .expect("patch");
    assert_eq!(patch[0]["value"], fixture.pod["metadata"]["uid"]);
    assert_eq!(patch[1]["value"], "123");
    assert_eq!(patch[3]["value"], 10);
}

#[tokio::test]
async fn rotating_batches_do_not_starve_other_expired_pods_after_persistent_conflicts() {
    let fixture = Fixture::new();
    let pods: Vec<_> = (0..17)
        .map(|_| {
            let sandbox = uuid::Uuid::new_v4().to_string();
            let name = policy::resource_id(&sandbox).expect("name");
            let mut pod = fixture.pod.clone();
            pod["metadata"]["name"] = json!(name);
            pod["metadata"]["labels"] = manifest::labels(&name);
            pod["metadata"]["uid"] = json!(uuid::Uuid::new_v4().to_string());
            pod["metadata"]["annotations"]["openshell-kata.io/sandbox-id"] = json!(sandbox);
            pod
        })
        .collect();
    std::fs::write(
        fixture.root.join("pods.json"),
        serde_json::to_vec(&json!({"items":pods})).expect("inventory"),
    )
    .expect("write inventory");
    std::fs::write(fixture.root.join("conflict"), b"conflict").expect("conflicts");
    for cursor in [0, 16] {
        let summary = reaper::reconcile(&fixture.client, "tenant", 1100, cursor)
            .await
            .expect("bounded round robin pass");
        assert_eq!(summary.errors, 16);
    }
    let calls = std::fs::read_to_string(fixture.root.join("calls.txt")).expect("calls");
    let names: std::collections::BTreeSet<_> = calls
        .lines()
        .filter(|line| line.contains("delete --raw"))
        .filter_map(|line| {
            line.split_whitespace()
                .find(|arg| arg.starts_with("/api/v1/"))
        })
        .collect();
    assert_eq!(
        names.len(),
        17,
        "a persistent conflict must not starve later pods"
    );
}

#[tokio::test]
async fn foreign_namespace_stops_reconciliation_before_inventory_or_delete() {
    let fixture = Fixture::new();
    assert!(
        reaper::reconcile(&fixture.client, "another-tenant", 1100, 0)
            .await
            .is_err()
    );
    let calls = std::fs::read_to_string(fixture.root.join("calls.txt")).expect("calls");
    assert_eq!(calls.lines().count(), 1);
    assert!(!calls.contains("get pods"));
    assert!(!calls.contains("delete"));
}

#[test]
fn live_lease_binding_rejects_expiry_extension_or_identity_substitution() {
    let fixture = Fixture::new();
    for (key, value) in [
        ("openshell-kata.io/expires-at", "1200".to_owned()),
        (
            "openshell-kata.io/launch-nonce",
            uuid::Uuid::new_v4().to_string(),
        ),
        (
            "openshell-kata.io/sandbox-id",
            uuid::Uuid::new_v4().to_string(),
        ),
    ] {
        let mut changed = fixture.pod.clone();
        changed["metadata"]["annotations"][key] = json!(value);
        assert!(
            super::lease::validate_binding(&changed, &fixture.state).is_err(),
            "accepted changed {key}"
        );
    }
}

#[tokio::test]
async fn malformed_and_foreign_pods_do_not_prevent_valid_expired_cleanup() {
    let fixture = Fixture::new();
    let mut foreign = fixture.pod.clone();
    foreign["metadata"]["labels"]["app.kubernetes.io/managed-by"] = json!("another-controller");
    let mut invalid = fixture.pod.clone();
    invalid["metadata"]["annotations"]["openshell-kata.io/expires-at"] = json!("01100");
    std::fs::write(
        fixture.root.join("pods.json"),
        serde_json::to_vec(&json!({"items":[foreign,invalid,fixture.pod]})).expect("inventory"),
    )
    .expect("write inventory");
    let summary = reaper::reconcile(&fixture.client, "tenant", 1100, 0)
        .await
        .expect("reconciliation continues");
    assert_eq!(summary.foreign, 1);
    assert_eq!(summary.invalid, 1);
    assert_eq!(summary.requested, 1);
}

#[tokio::test]
async fn uid_or_revision_conflict_has_no_force_or_name_only_fallback() {
    let fixture = Fixture::new();
    std::fs::write(fixture.root.join("conflict"), b"changed generation").expect("conflict");
    let summary = reaper::reconcile(&fixture.client, "tenant", 1100, 0)
        .await
        .expect("resource error is reported");
    assert_eq!(summary.errors, 1);
    assert_eq!(summary.requested, 0);
    assert!(fixture.root.join("pod.json").exists());
    let calls = std::fs::read_to_string(fixture.root.join("calls.txt")).expect("calls");
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.contains("delete "))
            .count(),
        1
    );
    assert!(!calls.contains("--force"));
    assert!(!calls.contains("delete pod "));
}

#[tokio::test]
async fn once_reports_a_failed_conditional_delete_as_unsuccessful() {
    let fixture = Fixture::new();
    std::fs::write(fixture.root.join("conflict"), b"changed generation").expect("conflict");
    let error = reaper::run(&fixture.client, "tenant", true)
        .await
        .expect_err("qualification must not report success for failed deletes");
    assert!(error.to_string().contains("failed requests"), "{error:#}");
    assert!(fixture.root.join("pod.json").exists());
}

#[tokio::test]
async fn reaper_rejects_missing_lease_and_identity_fields_without_deletion() {
    for pointer in [
        "/metadata/annotations/openshell-kata.io~1expires-at",
        "/metadata/annotations/openshell-kata.io~1launch-nonce",
        "/metadata/annotations/openshell-kata.io~1sandbox-id",
        "/metadata/uid",
        "/metadata/resourceVersion",
        "/metadata/namespace",
    ] {
        let fixture = Fixture::new();
        let mut pod = fixture.pod.clone();
        *pod.pointer_mut(pointer).expect("field") = json!(null);
        std::fs::write(
            fixture.root.join("pods.json"),
            serde_json::to_vec(&json!({"items":[pod]})).expect("inventory"),
        )
        .expect("write inventory");
        let summary = reaper::reconcile(&fixture.client, "tenant", 1100, 0)
            .await
            .expect("invalid lease reported");
        assert_eq!(summary.invalid, 1, "accepted {pointer}");
        assert_eq!(summary.requested, 0, "deleted {pointer}");
    }
}
