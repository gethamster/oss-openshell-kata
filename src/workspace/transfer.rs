//! Deterministic, bounded workspace archives for a quiescent runtime move.
use super::Workspace;
use anyhow::{Context, Result, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions, Permissions, PermissionsExt};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::{Component, Path},
};

const MAX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_WIRE: u64 = MAX_BYTES + 128 * 1024 * 1024;

fn reserved(name: &str) -> bool {
    name == ".system-processes" || name == ".system-quiesced" || name.starts_with(".system-import-")
}

fn path(value: &Path) -> Result<String> {
    let value = value
        .to_str()
        .context("workspace archive path must be UTF-8")?;
    ensure!(
        !value.is_empty() && value.len() <= 255,
        "workspace archive path limit exceeded"
    );
    ensure!(
        Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_))),
        "invalid workspace archive path"
    );
    ensure!(
        !reserved(value.split('/').next().context("archive path")?),
        "reserved workspace path"
    );
    Ok(value.into())
}

fn link_target(name: &str, target: &Path) -> Result<()> {
    ensure!(
        !target.as_os_str().is_empty() && !target.is_absolute(),
        "workspace symlink must be relative"
    );
    let mut depth = Path::new(name)
        .parent()
        .map_or(0, |parent| parent.components().count());
    for part in target.components() {
        match part {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            _ => anyhow::bail!("workspace symlink escapes its root"),
        }
    }
    Ok(())
}

/// Export files, directories and confined relative symlinks in canonical order.
pub fn export(workspace: &Workspace, output: impl Write) -> Result<()> {
    super::process::verify_frozen_export(workspace)?;
    let mut archive = tar::Builder::new(output);
    let mut entries = 0;
    let mut bytes = 0;
    export_dir(
        &workspace.directory,
        Path::new(""),
        &mut archive,
        &mut entries,
        &mut bytes,
    )?;
    archive.finish()?;
    Ok(())
}

fn export_dir<W: Write>(
    directory: &Dir,
    prefix: &Path,
    archive: &mut tar::Builder<W>,
    entries: &mut usize,
    bytes: &mut u64,
) -> Result<()> {
    let mut names = directory
        .entries()?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    for name in names {
        if prefix.as_os_str().is_empty() && name.to_str().is_some_and(reserved) {
            continue;
        }
        let full = prefix.join(&name);
        let full = path(&full)?;
        *entries += 1;
        ensure!(
            *entries <= MAX_ENTRIES,
            "workspace archive entry limit exceeded"
        );
        let metadata = directory.symlink_metadata(&name)?;
        let mut header = tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_mode(metadata.permissions().mode() & 0o777);
        if metadata.is_dir() {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            archive.append_data(&mut header, &full, std::io::empty())?;
            export_dir(
                &directory.open_dir_nofollow(&name)?,
                Path::new(&full),
                archive,
                entries,
                bytes,
            )?;
        } else if metadata.file_type().is_symlink() {
            let target = directory.read_link(&name)?;
            link_target(&full, &target)?;
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_link_name(target)?;
            archive.append_data(&mut header, &full, std::io::empty())?;
        } else {
            ensure!(metadata.is_file(), "workspace contains a special file");
            *bytes = bytes
                .checked_add(metadata.len())
                .context("workspace archive size overflow")?;
            ensure!(*bytes <= MAX_BYTES, "workspace archive byte limit exceeded");
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            let file = directory.open_with(&name, &options)?;
            let actual = file.metadata()?;
            ensure!(
                actual.is_file() && actual.len() == metadata.len(),
                "workspace file changed during export"
            );
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(actual.len());
            archive.append_data(&mut header, &full, file)?;
        }
    }
    Ok(())
}

/// Validate an entire archive in a private staging tree before replacing data.
/// Replaying the same archive is idempotent; helper process state is preserved.
pub fn import(workspace: &Workspace, input: impl Read) -> Result<()> {
    let name = format!(".system-import-{}", uuid::Uuid::new_v4());
    super::files::create_private_directory(&workspace.directory, &name)?;
    let staging = Workspace {
        directory: workspace.directory.open_dir_nofollow(&name)?,
        root: workspace.root.join(&name),
    };
    let result = import_staged(&staging, input).and_then(|directories| {
        let names = workspace
            .directory
            .entries()?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        for existing in names {
            if existing.to_str().is_some_and(reserved) {
                continue;
            }
            remove_tree(&workspace.directory, &existing)?;
        }
        for entry in staging.directory.entries()? {
            let entry = entry?;
            staging
                .directory
                .rename(entry.file_name(), &workspace.directory, entry.file_name())?;
        }
        restore_directory_modes(workspace, directories)?;
        super::files::sync_directory(&workspace.directory)
    });
    remove_tree(&workspace.directory, Path::new(&name).as_os_str())?;
    result
}

fn remove_tree(parent: &Dir, name: &std::ffi::OsStr) -> Result<()> {
    if parent.symlink_metadata(name)?.is_dir() {
        let directory = parent.open_dir_nofollow(name)?;
        let mode = directory.dir_metadata()?.permissions().mode();
        directory.set_permissions(".", Permissions::from_mode(mode | 0o700))?;
        for entry in directory.entries()? {
            remove_tree(&directory, &entry?.file_name())?;
        }
        parent.remove_dir(name)?;
    } else {
        parent.remove_file(name)?;
    }
    Ok(())
}

fn import_staged(workspace: &Workspace, input: impl Read) -> Result<Vec<(String, u32)>> {
    let mut archive = tar::Archive::new(input.take(MAX_WIRE + 1));
    let mut names = BTreeSet::new();
    let mut directories = Vec::new();
    let mut bytes = 0_u64;
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        ensure!(
            entry.header().as_ustar().is_some(),
            "workspace archive must use USTAR headers"
        );
        let name = path(&entry.path()?)?;
        ensure!(
            names.insert(name.clone()) && names.len() <= MAX_ENTRIES,
            "duplicate or excessive workspace entries"
        );
        let kind = entry.header().entry_type();
        let mode = entry.header().mode()? & 0o777;
        let size = entry.header().size()?;
        bytes = bytes
            .checked_add(size)
            .context("workspace archive size overflow")?;
        ensure!(bytes <= MAX_BYTES, "workspace archive byte limit exceeded");
        let (parent, leaf) = workspace.parent(&format!("/sandbox/{name}"), true)?;
        if kind.is_dir() {
            ensure!(size == 0, "invalid directory entry");
            super::files::create_private_directory(&parent, &leaf)?;
            directories.push((name, mode));
        } else if kind.is_file() {
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            let mut file = parent.open_with(&leaf, &options)?;
            ensure!(
                std::io::copy(&mut entry, &mut file)? == size,
                "truncated workspace file"
            );
            file.set_permissions(Permissions::from_mode(mode))?;
            file.sync_all()?;
        } else if kind.is_symlink() {
            ensure!(size == 0, "invalid symlink entry");
            let target = entry
                .link_name()?
                .context("missing workspace symlink target")?;
            link_target(&name, &target)?;
            parent.symlink(&target, &leaf)?;
        } else {
            anyhow::bail!("unsupported workspace archive entry");
        }
    }
    let mut remaining = archive.into_inner();
    let mut padding = [0; 65536];
    loop {
        let read = remaining.read(&mut padding)?;
        if read == 0 {
            break;
        }
        ensure!(
            padding[..read].iter().all(|byte| *byte == 0),
            "trailing workspace archive data"
        );
    }
    ensure!(
        remaining.limit() > 0,
        "workspace archive wire limit exceeded"
    );
    Ok(directories)
}

fn restore_directory_modes(
    workspace: &Workspace,
    mut directories: Vec<(String, u32)>,
) -> Result<()> {
    directories.sort_by_key(|(name, _)| std::cmp::Reverse(name.len()));
    for (name, mode) in directories {
        let (parent, leaf) = workspace.parent(&format!("/sandbox/{name}"), false)?;
        parent
            .open_dir_nofollow(leaf)?
            .set_permissions(".", Permissions::from_mode(mode))?;
    }
    Ok(())
}
