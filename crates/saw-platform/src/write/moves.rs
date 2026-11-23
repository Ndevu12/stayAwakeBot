//! Sets modes, makes folders, and renames and moves entries, without being redirected.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use crate::write::{WriteError, open_folder, open_parent};

fn one_entry(name: &str) -> Result<(), WriteError> {
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    if matches!(name, "" | "." | "..") || name.contains(separators) {
        return Err(WriteError::Redirected(format!("'{name}' is not one entry of a folder")));
    }
    Ok(())
}

fn named(path: &Path) -> Result<(&Path, &OsStr), WriteError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| WriteError::Redirected(format!("{} names no entry", path.display())))?;
    Ok((parent, name))
}

/// Give a file a mode. Takes the file and the mode. Returns nothing, or why it was not given.
pub fn set_mode(where_: &Path, mode: u32) -> Result<(), WriteError> {
    let (folder, name) = open_parent(where_, false, 0o777)?;
    folder.set_mode_of(&name, mode).map_err(|error| match error {
        WriteError::Redirected(_) => WriteError::Redirected(format!("{} is not a file of its own", where_.display())),
        other => other,
    })
}

/// Make a folder no one else made, named `stem` or `stem-<n>`. Takes the parent, the name, the
/// mode and how many names to try. Returns its path, or why none was made.
pub fn new_folder(parent: &Path, stem: &str, mode: u32, tries: usize) -> Result<PathBuf, WriteError> {
    one_entry(stem)?;
    let folder = open_folder(parent, true, 0o777)?;
    for n in 0..tries {
        let name = if n == 0 { stem.to_string() } else { format!("{stem}-{n}") };
        match folder.make_dir(OsStr::new(&name), mode) {
            Ok(()) => return Ok(parent.join(name)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("no free name for {stem} in {}", parent.display())).into())
}

/// Rename an entry of a folder. Takes the folder, the entry and its new name. Returns nothing, or
/// why it was not renamed.
pub fn rename_in(folder: &Path, old: &str, new: &str) -> Result<(), WriteError> {
    one_entry(old)?;
    one_entry(new)?;
    let opened = open_folder(folder, false, 0o777)?;
    opened.rename_to(OsStr::new(old), &opened, OsStr::new(new))?;
    Ok(())
}

/// Move a file, link or folder, whole, into a folder under a new name. Takes the source, the
/// folder and the name. Returns nothing, or why it was not moved.
pub fn move_into(source: &Path, folder: &Path, name: &str) -> Result<(), WriteError> {
    one_entry(name)?;
    let (origin_path, entry) = named(source)?;
    let origin = open_folder(origin_path, false, 0o777)?;
    let destination = open_folder(folder, false, 0o777)?;
    match origin.rename_to(entry, &destination, OsStr::new(name)) {
        Ok(()) => Ok(()),
        Err(error) if is_another_disk(&error) => {
            origin.copy_into(entry, &destination, OsStr::new(name))?;
            origin.remove(entry)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Rename an entry to another name in the same folder, never replacing what is there. Takes the
/// folder, the entry and its new name. Returns nothing, or why it was not renamed.
pub fn rename_beside(folder: &Path, name: &str, new_name: &str) -> Result<(), WriteError> {
    one_entry(name)?;
    one_entry(new_name)?;
    let opened = open_folder(folder, false, 0o777)?;
    opened.rename_no_replace(OsStr::new(name), OsStr::new(new_name))?;
    Ok(())
}

#[cfg(unix)]
fn is_another_disk(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EXDEV)
}

#[cfg(windows)]
fn is_another_disk(error: &io::Error) -> bool {
    error.raw_os_error() == Some(17)
}
