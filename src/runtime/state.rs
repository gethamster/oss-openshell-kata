//! Private, capability-scoped state for local runtime sandboxes.

use anyhow::{Context, Result, bail};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, Metadata, MetadataExt, OpenOptions, OpenOptionsExt,
    Permissions, PermissionsExt,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt as StdMetadataExt;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_SOCKET_PATH_BYTES: usize = 80;
const METADATA_NAME: &str = "metadata.json";

/// Validate the original lifecycle's bounded, non-path sandbox identifiers.
///
/// # Errors
/// Returns an error for empty, non-ASCII, path-like, or overlong identifiers.
pub fn validate_id(value: &str) -> Result<()> {
    let valid_first = value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric);
    if !valid_first
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("invalid sandbox identifier");
    }
    Ok(())
}

/// An owned private directory anchoring all per-sandbox filesystem operations.
#[derive(Debug)]
pub struct StateDirectory {
    root: PathBuf,
    directory: Dir,
    owner_uid: u32,
}

impl StateDirectory {
    /// Create or open an absolute private state directory without following symlinks.
    ///
    /// # Errors
    /// Rejects relative paths, symlink components, non-directories, and foreign owners.
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let directory = open_absolute_directory(root)?;
        // A newly created file is owned by the effective user without requiring unsafe getuid.
        let probe =
            tempfile::NamedTempFile::new_in(root).context("checking state directory ownership")?;
        let owner_uid = StdMetadataExt::uid(&probe.as_file().metadata()?);
        if directory.dir_metadata()?.uid() != owner_uid {
            bail!("state directory belongs to another user");
        }
        directory.set_permissions(".", Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
        let root = fs::canonicalize(root).context("canonicalizing state directory")?;
        Ok(Self {
            root,
            directory,
            owner_uid,
        })
    }

    /// Return the canonical absolute root used by operator-facing key paths.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a validated identifier without requiring the sandbox to exist yet.
    ///
    /// # Errors
    /// Rejects identifiers that could escape or alias the state directory.
    pub fn path(&self, id: &str) -> Result<PathBuf> {
        validate_id(id)?;
        Ok(self.root.join(id))
    }

    /// Count retained guest directories under the held private root capability.
    ///
    /// # Errors
    /// Rejects unexpected entries, links and directories with unsafe ownership or modes.
    pub fn retained_count(&self) -> Result<usize> {
        Ok(self.retained_ids()?.len())
    }

    /// List retained guest identifiers under the held private root capability.
    ///
    /// # Errors
    /// Rejects unexpected entries, links and directories with unsafe ownership or modes.
    pub fn retained_ids(&self) -> Result<Vec<String>> {
        self.check_root()?;
        let mut ids = Vec::new();
        for entry in self.directory.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("non-UTF8 runtime state entry")?;
            // Node and per-sandbox lifecycle locks are regular files, never retained guests.
            if name == ".t" || name.starts_with(".lock") {
                continue;
            }
            self.open_state(name)?;
            ids.push(name.to_owned());
        }
        Ok(ids)
    }

    /// Exclusively create one private sandbox directory.
    ///
    /// # Errors
    /// Rejects existing entries, invalid identifiers, or inaccessible state roots.
    pub fn create(&self, id: &str) -> Result<PathBuf> {
        validate_id(id)?;
        self.check_root()?;
        let mut builder = DirBuilder::new();
        builder.mode(PRIVATE_DIRECTORY_MODE);
        self.directory
            .create_dir_with(id, &builder)
            .context("creating sandbox state")?;
        self.open_state(id)?;
        self.path(id)
    }

    /// Read typed metadata from a private, regular, single-link file.
    ///
    /// # Errors
    /// Rejects missing state, links, foreign owners, non-private files, and invalid JSON.
    pub fn read<T: DeserializeOwned>(&self, id: &str) -> Result<T> {
        let directory = self.open_state(id)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = directory
            .open_with(METADATA_NAME, &options)
            .context("opening sandbox metadata")?;
        check_metadata_file(&file.metadata()?, self.owner_uid)?;
        serde_json::from_reader(file).context("decoding sandbox metadata")
    }

    /// Atomically replace typed metadata using a new private file and a durable rename.
    ///
    /// # Errors
    /// Rejects unknown state or unsafe existing metadata, serialization, and I/O failures.
    pub fn write<T: Serialize>(&self, id: &str, value: &T) -> Result<()> {
        let directory = self.open_state(id)?;
        match directory.symlink_metadata(METADATA_NAME) {
            Ok(metadata) => check_metadata_file(&metadata, self.owner_uid)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("checking sandbox metadata"),
        }
        let bytes = serde_json::to_vec(value).context("encoding sandbox metadata")?;
        let temporary_name = format!(".metadata-{}.tmp", Uuid::new_v4());
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .follow(FollowSymlinks::No);
        let result = (|| -> Result<()> {
            let mut file = directory.open_with(&temporary_name, &options)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            directory.rename(&temporary_name, &directory, METADATA_NAME)?;
            // Linux capability directories can be O_PATH handles. Open a
            // readable handle through the same capability for durable sync.
            directory
                .open(".")
                .context("opening sandbox directory for sync")?
                .sync_all()
                .context("syncing sandbox directory")?;
            Ok(())
        })();
        if result.is_err() {
            let _cleanup = directory.remove_file(&temporary_name);
        }
        result.context("replacing sandbox metadata")
    }

    /// Remove only a verified sandbox directory without following nested links.
    ///
    /// # Errors
    /// Rejects unknown, non-private, foreign, or symbolic-link state directories.
    pub fn remove(&self, id: &str) -> Result<()> {
        self.open_state(id)?;
        self.directory
            .remove_dir_all(id)
            .context("removing sandbox state")
    }

    /// Compute a short control-socket path bound to the complete sandbox state path.
    ///
    /// # Errors
    /// Rejects invalid identifiers, unsafe socket directories, or paths too long for macOS.
    pub fn control_path(&self, id: &str) -> Result<PathBuf> {
        let path = self.path(id)?;
        self.check_root()?;
        let mut builder = DirBuilder::new();
        builder.mode(PRIVATE_DIRECTORY_MODE);
        match self.directory.create_dir_with(".t", &builder) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("creating control socket directory"),
        }
        let socket_directory = self.directory.open_dir_nofollow(".t")?;
        check_private_directory(&socket_directory.dir_metadata()?, self.owner_uid)?;
        let hash = format!("{:x}", Sha256::digest(path.as_os_str().as_bytes()));
        let socket = self.root.join(".t").join(&hash[..20]);
        if socket.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES {
            bail!("runtime state path is too long for an SSH control socket");
        }
        Ok(socket)
    }

    fn open_state(&self, id: &str) -> Result<Dir> {
        validate_id(id)?;
        self.check_root()?;
        let directory = self
            .directory
            .open_dir_nofollow(id)
            .context("opening sandbox state")?;
        check_private_directory(&directory.dir_metadata()?, self.owner_uid)?;
        Ok(directory)
    }

    fn check_root(&self) -> Result<()> {
        check_private_directory(&self.directory.dir_metadata()?, self.owner_uid)
    }
}

fn open_absolute_directory(path: &Path) -> Result<Dir> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        bail!("state root must be an absolute non-root path");
    }
    let mut directory = Dir::open_ambient_dir("/", ambient_authority())?;
    let mut builder = DirBuilder::new();
    builder.mode(PRIVATE_DIRECTORY_MODE);
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => match directory.open_dir_nofollow(name) {
                Ok(next) => directory = next,
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    directory.create_dir_with(name, &builder)?;
                    directory = directory.open_dir_nofollow(name)?;
                }
                Err(error) => return Err(error).context("state root contains an unsafe component"),
            },
            _ => bail!("state root must not contain relative components"),
        }
    }
    Ok(directory)
}

fn check_private_directory(metadata: &Metadata, owner_uid: u32) -> Result<()> {
    if !metadata.is_dir() || metadata.uid() != owner_uid || metadata.mode() & 0o077 != 0 {
        bail!("state directory is not private and owned by the runtime user");
    }
    Ok(())
}

fn check_metadata_file(metadata: &Metadata, owner_uid: u32) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        bail!("sandbox metadata is not a private owned regular file");
    }
    Ok(())
}
