//! Filesystem state contracts for the local runtime.

#[path = "../src/runtime/state.rs"]
mod state;

use serde::{Deserialize, Serialize};
use state::{StateDirectory, validate_id};
use std::fs;
use std::os::unix::{fs::PermissionsExt, fs::symlink};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Record {
    sandbox_id: String,
    counter: u32,
}

fn root() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::Builder::new()
        .prefix("oks-")
        .tempdir_in("/tmp")
        .expect("create test root");
    let canonical = temporary.path().canonicalize().expect("canonical root");
    (temporary, canonical)
}

#[test]
fn rejects_path_and_shell_identifiers() {
    for value in ["", "../other", "-option", "a/b", "a;whoami", "é"] {
        assert!(validate_id(value).is_err(), "accepted invalid ID {value:?}");
    }
    assert!(validate_id(&"a".repeat(97)).is_err());
    assert!(validate_id(&"a".repeat(96)).is_ok());
    assert!(validate_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    assert!(validate_id("tenant.task_2").is_ok());
}

#[test]
fn creates_private_root_and_refuses_relative_roots() {
    let (_temporary, parent) = root();
    assert!(StateDirectory::new("relative/state").is_err());
    let directory = StateDirectory::new(parent.join("nested/state")).expect("create private root");
    assert!(directory.root().is_absolute());
    assert_eq!(
        fs::metadata(directory.root())
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn rejects_parent_components_before_creating_any_directory() {
    let (_temporary, parent) = root();
    assert!(StateDirectory::new(parent.join("new/../other")).is_err());
    assert!(!parent.join("new").exists());
}

#[test]
fn rejects_symlink_root_and_ancestors() {
    let (_temporary, parent) = root();
    let real = parent.join("real");
    fs::create_dir(&real).expect("real directory");
    symlink(&real, parent.join("link")).expect("root symlink");
    assert!(StateDirectory::new(parent.join("link")).is_err());
    assert!(StateDirectory::new(parent.join("link/nested")).is_err());
}

#[test]
fn creates_once_and_round_trips_private_metadata() {
    let (_temporary, parent) = root();
    let directory = StateDirectory::new(parent.join("state")).expect("state");
    let path = directory.create("one").expect("create one");
    assert_eq!(directory.path("one").expect("path"), path);
    assert!(directory.create("one").is_err());
    assert_eq!(
        fs::metadata(&path)
            .expect("state metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let first = Record {
        sandbox_id: "one".into(),
        counter: 1,
    };
    directory.write("one", &first).expect("initial write");
    assert_eq!(directory.read::<Record>("one").expect("read"), first);
    directory
        .write(
            "one",
            &Record {
                counter: 2,
                ..first
            },
        )
        .expect("replace write");
    assert_eq!(
        directory
            .read::<Record>("one")
            .expect("replacement")
            .counter,
        2
    );
    assert_eq!(
        fs::metadata(path.join("metadata.json"))
            .expect("metadata file")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_dir(path).expect("list state").count(),
        1,
        "temporary file leaked"
    );
}

#[test]
fn metadata_publication_sync_uses_the_retained_root_capability_after_rename() {
    let (_temporary, parent) = root();
    let original = parent.join("state");
    let renamed = parent.join("renamed");
    let directory = StateDirectory::new(&original).expect("state");
    directory.create("one").expect("sandbox state");
    fs::rename(&original, &renamed).expect("rename retained root");
    fs::create_dir(&original).expect("unrelated replacement root");
    let record = Record {
        sandbox_id: "one".into(),
        counter: 1,
    };

    directory
        .write("one", &record)
        .expect("publish and sync metadata through the retained capability");

    assert_eq!(directory.read::<Record>("one").expect("read"), record);
    assert!(renamed.join("one/metadata.json").is_file());
    assert_eq!(fs::read_dir(&original).expect("replacement").count(), 0);
}

#[test]
fn rejects_unknown_state_and_state_symlinks() {
    let (_temporary, parent) = root();
    let directory = StateDirectory::new(parent.join("state")).expect("state");
    assert!(directory.read::<Record>("unknown").is_err());
    assert!(directory.remove("unknown").is_err());
    directory.create("one").expect("one");
    symlink(
        directory.path("one").expect("one path"),
        directory.root().join("two"),
    )
    .expect("state symlink");
    assert!(directory.read::<Record>("two").is_err());
    assert!(
        directory
            .write(
                "two",
                &Record {
                    sandbox_id: "two".into(),
                    counter: 0
                }
            )
            .is_err()
    );
    assert!(directory.remove("two").is_err());
    assert!(directory.path("../one").is_err());
}

#[test]
fn refuses_metadata_symlink_without_touching_target() {
    let (_temporary, parent) = root();
    let directory = StateDirectory::new(parent.join("state")).expect("state");
    let path = directory.create("one").expect("one");
    let target = parent.join("outside");
    fs::write(&target, b"keep").expect("outside file");
    symlink(&target, path.join("metadata.json")).expect("metadata symlink");
    assert!(directory.read::<Record>("one").is_err());
    assert!(
        directory
            .write(
                "one",
                &Record {
                    sandbox_id: "one".into(),
                    counter: 0
                }
            )
            .is_err()
    );
    assert_eq!(fs::read(&target).expect("outside unchanged"), b"keep");
}

#[test]
fn removal_is_scoped_and_does_not_follow_child_symlinks() {
    let (_temporary, parent) = root();
    let directory = StateDirectory::new(parent.join("state")).expect("state");
    let one = directory.create("one").expect("one");
    let two = directory.create("two").expect("two");
    fs::write(two.join("retain"), b"keep").expect("retained file");
    symlink(&two, one.join("other")).expect("child symlink");
    directory.remove("one").expect("remove one");
    assert!(!one.exists());
    assert_eq!(
        fs::read(two.join("retain")).expect("other state retained"),
        b"keep"
    );
}

#[test]
fn socket_paths_are_short_and_bound_to_complete_identifiers() {
    let (_temporary, parent) = root();
    let directory = StateDirectory::new(parent.join("s")).expect("state");
    let first = directory
        .control_path("11111111-1111-4111-8111-111111111111")
        .expect("first socket");
    let second = directory
        .control_path("11111111-1111-4111-8111-111111111112")
        .expect("second socket");
    assert_ne!(first, second);
    assert!(first.as_os_str().len() <= 80);
    assert_eq!(first.file_name().expect("socket name").len(), 20);
    assert_eq!(
        fs::metadata(first.parent().expect("socket directory"))
            .expect("socket directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let long = StateDirectory::new(parent.join("x".repeat(90))).expect("long state root");
    assert!(long.control_path("one").is_err());
}

#[test]
fn retained_inventory_counts_private_guests_and_rejects_unknown_entries() {
    let (_temporary, parent) = root();
    let state = StateDirectory::new(parent.join("state")).expect("state");
    state.create("one").expect("first guest");
    state.create("two").expect("second guest");
    state
        .control_path("one")
        .expect("internal socket directory");
    assert_eq!(state.retained_count().expect("count"), 2);
    fs::write(state.root().join("unknown"), b"not guest state").expect("unexpected entry");
    assert!(state.retained_count().is_err());
}
