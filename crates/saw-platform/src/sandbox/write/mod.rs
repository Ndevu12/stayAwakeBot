//! Writes saw's own files in one step, where they were named and nowhere else.

mod moves;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::fmt;
use std::fs::File;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub use moves::{move_into, new_folder, rename_beside, rename_in, set_mode};
#[cfg(unix)]
pub use unix::{Folder, open_folder, open_parent};
#[cfg(windows)]
pub use windows::{Folder, open_folder, open_parent};

/// What to do when the written file's name is a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtALink {
    Refuse,
    FollowTrusted,
    Replace,
}

/// The mode a written file gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The mode the file has, or the one a new file gets by default.
    AsAPlainWrite,
    Set(u32),
}

/// Why a write did not happen.
#[derive(Debug)]
pub enum WriteError {
    /// The path reaches somewhere else through a link the writer does not trust.
    Redirected(String),
    /// The file read back differently from what was written.
    NotAsWritten,
    Io(io::Error),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::Redirected(why) => write!(f, "{why}"),
            WriteError::NotAsWritten => write!(f, "the file did not read back as written"),
            WriteError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for WriteError {}

impl From<io::Error> for WriteError {
    fn from(error: io::Error) -> Self {
        WriteError::Io(error)
    }
}

fn staging_name(target: &Path) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    let suffix = target.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    format!(".saw-{:016x}{suffix}", hasher.finish())
}

/// Write a file's new contents beside it and put them in place in one step. Takes the file, its
/// mode, what to do at a link at its name, and the writing. Returns nothing, or why it was not
/// written.
pub fn write_with<F>(where_: &Path, mode: Mode, at_a_link: AtALink, write: F) -> Result<(), WriteError>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let (folder, name) = open_target(where_, at_a_link, true)?;
    folder.write_staged(&name, &staging_name(where_), mode, write)
}

/// Write bytes to a file in one step and read them back. Takes the file, the bytes, its mode and
/// what to do at a link at its name. Returns nothing, or why it was not written.
pub fn replace(where_: &Path, bytes: &[u8], mode: Mode, at_a_link: AtALink) -> Result<(), WriteError> {
    write_with(where_, mode, at_a_link, |file| file.write_all(bytes))?;
    match read_back(where_, bytes.len() as u64, at_a_link) {
        Some(read) if read == bytes => Ok(()),
        _ => Err(WriteError::NotAsWritten),
    }
}

/// Read a file saw wrote, through the folders it was written through. Takes the file, the most
/// bytes to read and how its name was written. Returns the bytes, or none when it is not a regular
/// file there.
pub fn read_back(where_: &Path, limit: u64, at_a_link: AtALink) -> Option<Vec<u8>> {
    let (folder, name) = open_target(where_, at_a_link, false).ok()?;
    folder.read_regular(&name, limit)
}

/// Make a folder and every missing folder above it. Takes the folder and its mode, or none.
/// Returns nothing, or why it was not made.
pub fn make_folder(where_: &Path, mode: Option<u32>) -> Result<(), WriteError> {
    let folder = open_folder(where_, true, 0o777)?;
    if let Some(mode) = mode {
        folder.set_own_mode(mode)?;
    }
    Ok(())
}

fn open_target(where_: &Path, at_a_link: AtALink, create: bool) -> Result<(Folder, std::ffi::OsString), WriteError> {
    if at_a_link == AtALink::FollowTrusted {
        return open_parent(where_, create, 0o777);
    }
    let parent = where_.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = where_.file_name().ok_or_else(|| WriteError::Redirected(format!("{} names no file", where_.display())))?;
    let folder = open_folder(parent, create, 0o777)?;
    if at_a_link == AtALink::Refuse && folder.is_link(name)? {
        return Err(WriteError::Redirected(format!("{} is a link", where_.display())));
    }
    Ok((folder, name.to_os_string()))
}
