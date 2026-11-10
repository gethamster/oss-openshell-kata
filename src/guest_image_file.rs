//! Operator-managed list of additional admitted guest images, re-read on every use.
//!
//! The adapter loads its VM policy once, but a release that only adds or drops a
//! thread image must not restart the driver and stop every running guest. The
//! operator therefore writes those images to a root-owned file that is read at
//! admission time. The file only ever widens the CLI-admitted set; a missing or
//! untrusted file leaves the images it lists unadmitted and everything named on
//! the command line working.
use anyhow::{Context, Result, ensure};
use std::{
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    sync::Mutex,
};

const MAX_BYTES: u64 = 64 * 1024;
const MAX_IMAGES: usize = 64;

/// The image references listed by the trusted root-owned file at `path`.
pub fn load(path: &Path) -> Result<Vec<String>> {
    load_owned_by(path, 0)
}

fn load_owned_by(path: &Path, owner: u32) -> Result<Vec<String>> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|part| !matches!(part, Component::CurDir | Component::ParentDir)),
        "additional guest images file must be an absolute path without traversal"
    );
    let metadata =
        std::fs::symlink_metadata(path).context("inspect additional guest images file")?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.mode() & 0o022 == 0
            && metadata.len() <= MAX_BYTES,
        "additional guest images file must be a small regular file owned by root and not group or world writable"
    );
    let mut file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    ensure!(
        opened.dev() == metadata.dev()
            && opened.ino() == metadata.ino()
            && opened.uid() == metadata.uid()
            && opened.mode() == metadata.mode(),
        "additional guest images file changed while opening"
    );
    let mut bytes = Vec::new();
    (&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "additional guest images file is oversized"
    );
    let images: Vec<String> = serde_json::from_slice(&bytes)
        .context("additional guest images must be a JSON array of strings")?;
    ensure!(
        images.len() <= MAX_IMAGES,
        "additional guest images file lists too many images"
    );
    for image in &images {
        crate::hosted::validate_image(image)?;
    }
    Ok(images)
}

/// Images the file lists, or none when it is unusable; an unusable file is
/// logged once per distinct failure so a bad file does not flood the log.
pub fn load_or_fail_closed(path: &Path) -> Vec<String> {
    static LAST_FAILURE: Mutex<Option<String>> = Mutex::new(None);
    let result = load(path);
    let mut last = LAST_FAILURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match result {
        Ok(images) => {
            *last = None;
            images
        }
        Err(error) => {
            let message = format!("{error:#}");
            if last.as_deref() != Some(message.as_str()) {
                tracing::error!(path=%path.display(), error=%message, "additional guest images file unusable; admitting only command-line images");
                *last = Some(message);
            }
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn image(c: char) -> String {
        format!(
            "registry.example/thread@sha256:{}",
            c.to_string().repeat(64)
        )
    }
    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }
    fn write(dir: &Path, body: &str, mode: u32) -> std::path::PathBuf {
        let path = dir.join("images.json");
        std::fs::write(&path, body).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[test]
    fn reads_a_trusted_file_afresh_each_time() {
        let dir = tempfile::tempdir().expect("dir");
        let path = write(
            dir.path(),
            &serde_json::to_string(&[image('a')]).expect("json"),
            0o644,
        );
        assert_eq!(load_owned_by(&path, me()).expect("load"), vec![image('a')]);
        write(dir.path(), "[]", 0o644);
        assert!(load_owned_by(&path, me()).expect("reload").is_empty());
    }

    #[test]
    fn refuses_untrusted_or_invalid_files() {
        let dir = tempfile::tempdir().expect("dir");
        let good = serde_json::to_string(&[image('a')]).expect("json");
        let path = write(dir.path(), &good, 0o664);
        assert!(load_owned_by(&path, me()).is_err(), "group writable");
        write(dir.path(), &good, 0o646);
        assert!(load_owned_by(&path, me()).is_err(), "world writable");
        write(dir.path(), &good, 0o644);
        assert!(
            load_owned_by(&path, me().wrapping_add(1)).is_err(),
            "wrong owner"
        );
        assert!(load(&path).is_err() || me() == 0, "not root-owned");
        assert!(load_owned_by(Path::new("relative.json"), me()).is_err());
        assert!(load_owned_by(&dir.path().join("missing.json"), me()).is_err());
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(load_owned_by(&link, me()).is_err(), "symlink");
        for body in ["{}", "[1]", "[\"registry.example/t:latest\"]", "not json"] {
            let path = write(dir.path(), body, 0o644);
            assert!(load_owned_by(&path, me()).is_err(), "{body}");
        }
    }

    #[test]
    fn unusable_file_admits_nothing() {
        let dir = tempfile::tempdir().expect("dir");
        assert!(load_or_fail_closed(&dir.path().join("missing.json")).is_empty());
    }
}
