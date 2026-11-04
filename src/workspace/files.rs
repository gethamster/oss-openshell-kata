use super::MAX_FILE_BYTES;
use anyhow::{Context, Result, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, DirBuilder, DirBuilderExt, OpenOptions, OpenOptionsExt},
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const MAX_CHUNK_BYTES: usize = 65536;

/// Removal semantics matching System's workspace API.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemoveOptions {
    pub recursive: bool,
    pub force: bool,
}

/// An opened directory anchoring guest-side workspace operations.
#[derive(Debug)]
pub struct Workspace {
    pub(super) directory: Dir,
    pub(super) root: PathBuf,
}

impl Workspace {
    /// Open the trusted workspace root; CLI callers normally use `/sandbox`.
    ///
    /// # Errors
    /// Rejects relative roots, symlinks, replacement races and non-directories.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        ensure!(root.is_absolute(), "workspace root must be absolute");
        let before = std::fs::symlink_metadata(root)?;
        ensure!(
            before.is_dir() && !before.file_type().is_symlink(),
            "workspace root must be a real directory"
        );
        let directory = Dir::open_ambient_dir(root, ambient_authority())?;
        let after = directory.dir_metadata()?;
        ensure!(
            before.dev() == after.dev() && before.ino() == after.ino(),
            "workspace root changed while opening"
        );
        Ok(Self {
            directory,
            root: root.to_owned(),
        })
    }

    /// Read a regular file without following symlinks; return false when absent.
    ///
    /// # Errors
    /// Rejects escaping paths, links, special files, oversized files and I/O failures.
    pub fn read(&self, path: &str, mut output: impl Write) -> Result<bool> {
        let (parent, name) = match self.parent(path, false) {
            Ok(value) => value,
            Err(error) if not_found(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        let descriptor = match rustix::fs::openat(
            &parent,
            name.as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ) {
            Ok(value) => value,
            Err(rustix::io::Errno::NOENT) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let mut file = std::fs::File::from(descriptor);
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "workspace read requires a regular file");
        ensure!(
            metadata.len() <= MAX_FILE_BYTES,
            "workspace file limit exceeded"
        );
        let mut buffer = [0; MAX_CHUNK_BYTES];
        let mut total = 0_u64;
        loop {
            let bytes = file.read(&mut buffer)?;
            if bytes == 0 {
                return Ok(true);
            }
            total += bytes as u64;
            ensure!(total <= MAX_FILE_BYTES, "workspace file limit exceeded");
            output.write_all(&buffer[..bytes])?;
        }
    }

    /// Atomically write System's bounded chunk-and-SHA256 stdin protocol.
    ///
    /// # Errors
    /// Rejects invalid paths, frames, digests, missing EOF and filesystem failures.
    pub fn write(&self, path: &str, mut input: impl Read) -> Result<()> {
        let (parent, name) = self.parent(path, true)?;
        let temporary = format!(".system-upload-{}", Uuid::new_v4());
        let result = (|| {
            let mut options = private_file_options();
            options.write(true).create_new(true);
            let mut file = parent.open_with(&temporary, &options)?;
            receive(&mut input, &mut file)?;
            file.sync_all()?;
            parent.rename(&temporary, &parent, name)?;
            sync_directory(&parent)
        })();
        if result.is_err() {
            match parent.remove_file(&temporary) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("remove incomplete workspace upload"),
            }
        }
        result
    }

    /// Remove a file, symlink or directory without traversing symlink parents.
    ///
    /// # Errors
    /// Rejects invalid paths, nonempty directories without recursive, and missing
    /// entries without force, or returns an underlying filesystem failure.
    pub fn remove(&self, path: &str, options: RemoveOptions) -> Result<()> {
        let result = (|| {
            let (parent, name) = self.parent(path, false)?;
            let metadata = parent.symlink_metadata(&name)?;
            if metadata.is_dir() {
                if options.recursive {
                    parent.remove_dir_all(&name)?;
                } else {
                    parent.remove_dir(&name)?;
                }
            } else {
                parent.remove_file(&name)?;
            }
            sync_directory(&parent)
        })();
        match result {
            Err(error) if options.force && not_found(&error) => Ok(()),
            value => value,
        }
    }

    pub(super) fn parent(&self, path: &str, create: bool) -> Result<(Dir, String)> {
        ensure!(
            path.len() <= 4096 && !path.chars().any(char::is_control),
            "invalid workspace path"
        );
        let relative = path
            .strip_prefix("/sandbox/")
            .context("workspace path required")?;
        let parts = relative.split('/').collect::<Vec<_>>();
        ensure!(
            parts.iter().all(|part| !matches!(*part, "" | "." | "..")),
            "invalid workspace path component"
        );
        let (name, ancestors) = parts.split_last().context("workspace filename required")?;
        let mut directory = self.directory.try_clone()?;
        for part in ancestors {
            if create {
                create_private_directory(&directory, part)?;
            }
            directory = directory.open_dir_nofollow(part)?;
        }
        Ok((directory, (*name).to_owned()))
    }
}

pub(super) fn private_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.mode(0o600).follow(FollowSymlinks::No);
    options
}

pub(super) fn create_private_directory(parent: &Dir, name: &str) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    match parent.create_dir_with(name, &builder) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn sync_directory(directory: &Dir) -> Result<()> {
    directory.open(".")?.sync_all()?;
    Ok(())
}

fn not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn receive(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let mut total = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0; MAX_CHUNK_BYTES];
    loop {
        let mut header = [0; 4];
        input
            .read_exact(&mut header)
            .context("incomplete workspace upload header")?;
        let size = u32::from_be_bytes(header) as usize;
        if size == 0 {
            break;
        }
        total += size as u64;
        ensure!(
            size <= MAX_CHUNK_BYTES && total <= MAX_FILE_BYTES,
            "workspace file limit exceeded"
        );
        input
            .read_exact(&mut buffer[..size])
            .context("incomplete workspace upload chunk")?;
        digest.update(&buffer[..size]);
        output.write_all(&buffer[..size])?;
    }
    let mut expected = [0; 32];
    input
        .read_exact(&mut expected)
        .context("incomplete workspace upload digest")?;
    ensure!(
        digest.finalize()[..] == expected,
        "workspace upload digest mismatch"
    );
    ensure!(
        input.read(&mut [0])? == 0,
        "unexpected workspace upload data"
    );
    Ok(())
}
