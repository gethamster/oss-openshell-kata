use super::{Action, client::Client, manifest, workspace};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt as _;

struct Fixture {
    root: tempfile::TempDir,
    client: Client,
}

impl Fixture {
    fn new(namespace: Option<Value>, pods: Value) -> Self {
        let root = tempfile::tempdir().expect("fixture");
        let program = root.path().join("kubectl");
        if let Some(namespace) = namespace {
            std::fs::write(root.path().join("namespace.json"), namespace.to_string())
                .expect("namespace");
        }
        std::fs::write(root.path().join("pods.json"), pods.to_string()).expect("pods");
        std::fs::write(
            &program,
            format!(
                r#"#!/bin/sh
cd '{}'
printf '%s\n' "$*" >> calls
[ ! -f fail ] || exit 1
case "$*" in
  *"get namespace sandbox-tenant "*) [ ! -f namespace.json ] || cat namespace.json ;;
  *"get pods -n sandbox-tenant "*)
    case "$*" in *"--ignore-not-found"*) exit 0 ;; esac
    cat pods.json ;;
  *) exit 2 ;;
esac
"#,
                root.path().display()
            ),
        )
        .expect("client");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
            .expect("executable");
        Self {
            root,
            client: Client {
                context: Some("operator-context".into()),
                program,
            },
        }
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(self.root.path().join("calls")).expect("calls")
    }
}

fn namespace() -> Value {
    json!({"metadata":{"labels":{
        "platform.tryhamster.dev/tenant":"tenant",
        "platform.tryhamster.dev/role":"sandbox"
    }}})
}

#[tokio::test]
async fn deleting_absent_workspace_is_idempotent_but_ensure_requires_namespace() {
    let fixture = Fixture::new(None, json!({"items":[]}));
    for _ in 0..2 {
        workspace(&fixture.client, "tenant", Action::DeleteWorkspace)
            .await
            .expect("already removed namespace");
    }
    assert!(
        workspace(&fixture.client, "tenant", Action::EnsureWorkspace)
            .await
            .is_err()
    );
    let calls = fixture.calls();
    assert_eq!(calls.lines().count(), 3);
    assert!(calls.lines().all(|call| {
        call == "--request-timeout=10s --context=operator-context get namespace sandbox-tenant -o json --ignore-not-found"
    }));
}

#[tokio::test]
async fn deleting_present_workspace_still_requires_owner_and_no_managed_guests() {
    let fixture = Fixture::new(Some(namespace()), json!({"items":[]}));
    workspace(&fixture.client, "tenant", Action::DeleteWorkspace)
        .await
        .expect("empty owned namespace");
    assert_eq!(fixture.calls().lines().count(), 2);
    assert!(fixture.calls().lines().any(|call| {
        call == "--request-timeout=10s --context=operator-context get pods -n sandbox-tenant -o json"
    }));

    let fixture = Fixture::new(
        Some(namespace()),
        json!({"items":[{"metadata":{"labels":{"app.kubernetes.io/managed-by":manifest::OWNER}}}]}),
    );
    assert!(
        workspace(&fixture.client, "tenant", Action::DeleteWorkspace)
            .await
            .expect_err("active guest must block deletion")
            .to_string()
            .contains("active guests")
    );
    let mut foreign = namespace();
    foreign["metadata"]["labels"]["platform.tryhamster.dev/tenant"] = json!("other");
    let fixture = Fixture::new(Some(foreign), json!({"items":[]}));
    assert!(
        workspace(&fixture.client, "tenant", Action::DeleteWorkspace)
            .await
            .is_err()
    );
    assert_eq!(fixture.calls().lines().count(), 1);
}

#[tokio::test]
async fn deleting_workspace_never_treats_failed_observation_as_absence() {
    let fixture = Fixture::new(None, json!({"items":[]}));
    std::fs::write(fixture.root.path().join("fail"), "forbidden").expect("failure");
    assert!(
        workspace(&fixture.client, "tenant", Action::DeleteWorkspace)
            .await
            .expect_err("failed authenticated read must hold")
            .to_string()
            .contains("kubectl operation failed")
    );
    assert_eq!(fixture.calls().lines().count(), 1);
}
