//! Workspace migration preserves data while rejecting archive escapes.
use openshell_kata::workspace::{self, Workspace};
use std::{
    fs,
    io::Cursor,
    os::unix::fs::{PermissionsExt, symlink},
};

#[test]
fn deterministic_archives_round_trip_files_modes_links_and_ignore_control_state() {
    let source = tempfile::tempdir().expect("source");
    fs::create_dir_all(source.path().join(".git/objects")).expect("git");
    fs::create_dir(source.path().join(".system-processes")).expect("processes");
    fs::write(source.path().join(".system-processes/private"), b"control").expect("control");
    fs::write(
        source.path().join(".git/config"),
        b"uncommitted\0configuration",
    )
    .expect("config");
    fs::write(source.path().join("run"), b"#!/bin/sh\nexit 0\n").expect("script");
    fs::set_permissions(source.path().join("run"), fs::Permissions::from_mode(0o751))
        .expect("mode");
    symlink("../run", source.path().join(".git/run")).expect("relative link");
    let source = Workspace::open(source.path()).expect("source capability");
    let mut archive = Vec::new();
    workspace::export(&source, &mut archive).expect("export");
    let mut repeated = Vec::new();
    workspace::export(&source, &mut repeated).expect("repeat export");
    assert_eq!(archive, repeated);
    let target = tempfile::tempdir().expect("target");
    fs::write(target.path().join("stale"), b"old").expect("stale target");
    let target_workspace = Workspace::open(target.path()).expect("target capability");
    workspace::import(&target_workspace, Cursor::new(&archive)).expect("import");
    workspace::import(&target_workspace, Cursor::new(&archive)).expect("idempotent replay");
    let mut actual = Vec::new();
    workspace::export(&target_workspace, &mut actual).expect("re-export");
    assert_eq!(archive, actual);
    assert!(!target.path().join("stale").exists());
    assert!(!target.path().join(".system-processes").exists());
    assert_eq!(
        fs::read_link(target.path().join(".git/run")).expect("link"),
        std::path::Path::new("../run")
    );
    assert_eq!(
        fs::metadata(target.path().join("run"))
            .expect("mode")
            .permissions()
            .mode()
            & 0o777,
        0o751
    );
}

#[test]
fn invalid_archive_leaves_destination_intact_and_removes_staging() {
    let target = tempfile::tempdir().expect("target");
    fs::write(target.path().join("keep"), b"original").expect("original");
    let workspace = Workspace::open(target.path()).expect("workspace");
    for link in ["/etc/passwd", "../outside"] {
        let mut bytes = Vec::new();
        let mut archive = tar::Builder::new(&mut bytes);
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name(link).expect("link target");
        archive
            .append_data(&mut header, "escape", std::io::empty())
            .expect("archive");
        archive.finish().expect("finish");
        drop(archive);
        assert!(workspace::import(&workspace, Cursor::new(bytes)).is_err());
        assert_eq!(
            fs::read(target.path().join("keep")).expect("kept"),
            b"original"
        );
        assert_eq!(fs::read_dir(target.path()).expect("entries").count(), 1);
    }
}

#[test]
fn symlink_parent_and_special_file_are_rejected() {
    let source = tempfile::tempdir().expect("source");
    let outside = tempfile::tempdir().expect("outside");
    symlink(outside.path(), source.path().join("escape")).expect("outside link");
    let workspace = Workspace::open(source.path()).expect("workspace");
    assert!(workspace::export(&workspace, Vec::new()).is_err());
    fs::remove_file(source.path().join("escape")).expect("remove link");
    let _socket =
        std::os::unix::net::UnixListener::bind(source.path().join("socket")).expect("socket");
    assert!(workspace::export(&workspace, Vec::new()).is_err());
}
