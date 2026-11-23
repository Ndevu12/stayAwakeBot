//! Opens folders and writes files within held folders, on Windows.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::write::{Mode, WriteError};

const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_SHARE_READ: u32 = 0x0001;
const FILE_SHARE_WRITE: u32 = 0x0002;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// An open folder, with every folder on the way to it held open.
#[derive(Debug)]
pub struct Folder {
    path: PathBuf,
    _held: Vec<File>,
}

fn hold(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn is_reparse_point(found: &fs::Metadata) -> bool {
    found.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn checked_folder(path: &Path, original: &Path) -> Result<File, WriteError> {
    let held = hold(path)?;
    let found = held.metadata()?;
    if is_reparse_point(&found) {
        return Err(WriteError::Redirected(format!("{} reaches elsewhere through a link at {}", original.display(), path.display())));
    }
    if !found.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotADirectory, path.display().to_string()).into());
    }
    Ok(held)
}

/// Open a folder for writing in, holding every folder on the way. Takes the folder, whether to make missing parts, and their mode. Returns the
/// open folder, or why it was not opened.
pub fn open_folder(path: &Path, create: bool, _mode: u32) -> Result<Folder, WriteError> {
    let absolute = std::path::absolute(path)?;
    let mut current = PathBuf::new();
    let mut held: Vec<File> = Vec::new();
    for part in absolute.components() {
        match part {
            Component::Prefix(_) | Component::RootDir => {
                current.push(part.as_os_str());
                if matches!(part, Component::RootDir) {
                    held.push(checked_folder(&current, path)?);
                }
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if current.pop() {
                    held.pop();
                }
            }
            Component::Normal(name) => {
                current.push(name);
                match checked_folder(&current, path) {
                    Ok(folder) => held.push(folder),
                    Err(WriteError::Io(error)) if error.kind() == io::ErrorKind::NotFound && create => {
                        match fs::create_dir(&current) {
                            Err(error) if error.kind() != io::ErrorKind::AlreadyExists => return Err(error.into()),
                            _ => {}
                        }
                        held.push(checked_folder(&current, path)?);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(Folder { path: current, _held: held })
}

/// Open the folder a file is named in, refusing a link at the file's own name. Takes the file,
/// whether to make missing folders and their mode. Returns the open folder and the name in it, or
/// why they were not opened.
pub fn open_parent(where_: &Path, create: bool, mode: u32) -> Result<(Folder, OsString), WriteError> {
    let parent = where_.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let folder = open_folder(parent, create, mode)?;
    let name = where_.file_name().map(OsStr::to_os_string).ok_or_else(|| WriteError::Redirected(format!("{} names no file", where_.display())))?;
    if folder.is_link(&name)? {
        return Err(WriteError::Redirected(format!("{} is a link", where_.display())));
    }
    Ok((folder, name))
}

impl Folder {
    /// Tell whether a name in this folder is a link. Takes the name. Returns the answer.
    pub fn is_link(&self, name: &OsStr) -> io::Result<bool> {
        match fs::symlink_metadata(self.path.join(name)) {
            Ok(found) => Ok(is_reparse_point(&found)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn write_staged<F>(&self, name: &OsStr, staging: &str, _mode: Mode, write: F) -> Result<(), WriteError>
    where
        F: FnOnce(&mut File) -> io::Result<()>,
    {
        let staged = self.path.join(staging);
        let outcome = (|| -> io::Result<()> {
            let mut file = OpenOptions::new().write(true).create_new(true).share_mode(0).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&staged)?;
            write(&mut file)?;
            file.flush()?;
            drop(file);
            fs::rename(&staged, self.path.join(name))
        })();
        if outcome.is_err() {
            let _ = fs::remove_file(&staged);
        }
        outcome.map_err(WriteError::Io)
    }

    pub(crate) fn read_regular(&self, name: &OsStr, limit: u64) -> Option<Vec<u8>> {
        let file = OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(self.path.join(name)).ok()?;
        let found = file.metadata().ok()?;
        if is_reparse_point(&found) || !found.is_file() {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes).ok()?;
        Some(bytes)
    }

    pub(crate) fn set_own_mode(&self, _mode: u32) -> io::Result<()> {
        Ok(())
    }
}

impl Folder {
    /// Open a folder under this one, refusing any link. Takes the path. Returns the open folder,
    /// or why it was not opened.
    pub fn open_under(&self, path: &Path) -> Result<Folder, WriteError> {
        open_folder(&self.path.join(path), false, 0o777)
    }

    /// Check a file in this folder is a file of its own. Takes its name and the mode. Returns
    /// nothing, or why it is not.
    pub fn set_mode_of(&self, name: &OsStr, _mode: u32) -> Result<(), WriteError> {
        let found = fs::symlink_metadata(self.path.join(name))?;
        if is_reparse_point(&found) || !found.is_file() {
            return Err(WriteError::Redirected(format!("{} is not a file of its own", name.to_string_lossy())));
        }
        Ok(())
    }

    /// Make a folder in this one. Takes its name and mode. Returns nothing, or why it was not made.
    pub fn make_dir(&self, name: &OsStr, _mode: u32) -> io::Result<()> {
        fs::create_dir(self.path.join(name))
    }

    /// Move an entry of this folder into another folder under a name, replacing what is there.
    /// Takes the entry, the folder and the name. Returns nothing, or why it was not moved.
    pub fn rename_to(&self, entry: &OsStr, folder: &Folder, name: &OsStr) -> io::Result<()> {
        fs::rename(self.path.join(entry), folder.path.join(name))
    }

    /// Rename an entry of this folder without replacing what has the new name. Takes the entry and
    /// the new name. Returns nothing, or why it was not renamed.
    #[allow(unsafe_code)]
    pub fn rename_no_replace(&self, entry: &OsStr, name: &OsStr) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        let wide = |path: PathBuf| path.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let (from, to) = (wide(self.path.join(entry)), wide(self.path.join(name)));
        // SAFETY: both strings are NUL-terminated locals that outlive the call.
        let moved = unsafe { windows_sys::Win32::Storage::FileSystem::MoveFileExW(from.as_ptr(), to.as_ptr(), 0) };
        if moved == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Copy an entry of this folder into another folder under a name, keeping times. Takes the
    /// entry, the folder and the name. Returns whether it was a folder, or why it was not copied.
    pub fn copy_into(&self, entry: &OsStr, folder: &Folder, name: &OsStr) -> io::Result<bool> {
        copy_path(&self.path.join(entry), &folder.path.join(name))
    }

    /// Remove an entry of this folder, and everything under it when it is a folder. Takes the
    /// entry. Returns nothing, or why it was not removed.
    pub fn remove(&self, entry: &OsStr) -> io::Result<()> {
        let path = self.path.join(entry);
        if fs::symlink_metadata(&path)?.is_dir() { fs::remove_dir_all(path) } else { fs::remove_file(path) }
    }
}

fn copy_path(from: &Path, to: &Path) -> io::Result<bool> {
    let found = fs::symlink_metadata(from)?;
    if is_reparse_point(&found) {
        return Err(io::Error::other(format!("{} is a link", from.display())));
    }
    let times = fs::FileTimes::new().set_accessed(found.accessed()?).set_modified(found.modified()?);
    if found.is_dir() {
        fs::create_dir(to)?;
        for child in fs::read_dir(from)? {
            let child = child?;
            copy_path(&child.path(), &to.join(child.file_name()))?;
        }
        hold(to)?.set_times(times)?;
        return Ok(true);
    }
    fs::copy(from, to)?;
    OpenOptions::new().write(true).open(to)?.set_times(times)?;
    Ok(false)
}
