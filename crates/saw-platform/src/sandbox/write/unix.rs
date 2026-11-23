//! Opens folders and writes files relative to open folders, on Unix.

use std::collections::VecDeque;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::sandbox::write::{Mode, WriteError};

const MAX_LINKS: usize = 40;

/// An open folder.
#[derive(Debug)]
pub struct Folder(OwnedFd);

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name holds a NUL"))
}

fn checked(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
}

#[allow(unsafe_code)]
fn stat_at(folder: libc::c_int, name: &CString) -> io::Result<libc::stat> {
    // SAFETY: an all-zero stat is a valid value of that plain struct.
    let mut found: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `name` is NUL-terminated and `found` is a local the call fills.
    checked(unsafe { libc::fstatat(folder, name.as_ptr(), &mut found, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(found)
}

#[allow(unsafe_code)]
fn stat_of(fd: libc::c_int) -> io::Result<libc::stat> {
    // SAFETY: an all-zero stat is a valid value of that plain struct.
    let mut found: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open and `found` is a local the call fills.
    checked(unsafe { libc::fstat(fd, &mut found) })?;
    Ok(found)
}

fn is_kind(found: &libc::stat, kind: libc::mode_t) -> bool {
    found.st_mode & libc::S_IFMT == kind
}

#[allow(unsafe_code)]
fn open_at(folder: libc::c_int, name: &CString, flags: libc::c_int, mode: libc::c_uint) -> io::Result<OwnedFd> {
    // SAFETY: `name` is NUL-terminated; the returned descriptor is owned only by the OwnedFd.
    let fd = checked(unsafe { libc::openat(folder, name.as_ptr(), flags | libc::O_CLOEXEC, mode) })?;
    // SAFETY: `fd` was just opened and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
const SEARCH_ONLY: libc::c_int = libc::O_PATH;
#[cfg(target_os = "macos")]
const SEARCH_ONLY: libc::c_int = libc::O_SEARCH;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const SEARCH_ONLY: libc::c_int = 0;

fn open_dir(folder: libc::c_int, name: &CString, extra: libc::c_int) -> io::Result<OwnedFd> {
    match open_at(folder, name, libc::O_RDONLY | libc::O_DIRECTORY | extra, 0) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied && SEARCH_ONLY != 0 => {
            open_at(folder, name, SEARCH_ONLY | libc::O_DIRECTORY | extra, 0)
        }
        other => other,
    }
}

fn root() -> io::Result<OwnedFd> {
    open_dir(libc::AT_FDCWD, &CString::new("/").expect("no NUL"), 0)
}

#[allow(unsafe_code)]
fn trusted_owners() -> Vec<libc::uid_t> {
    // SAFETY: geteuid has no arguments and cannot fail.
    let me = unsafe { libc::geteuid() };
    if me == 0 { vec![0] } else { vec![0, me] }
}

fn placed_by_trusted(link: &libc::stat, holder: &libc::stat) -> bool {
    let owners = trusted_owners();
    let writable_by_others: libc::mode_t = 0o002 | if owners == [0] { 0o020 } else { 0 };
    owners.contains(&link.st_uid) && owners.contains(&holder.st_uid) && holder.st_mode & writable_by_others == 0
}

#[allow(unsafe_code)]
fn read_link_at(folder: libc::c_int, name: &CString) -> io::Result<PathBuf> {
    let mut buffer = vec![0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: the buffer is a local of the given length that outlives the call.
    let length = unsafe { libc::readlinkat(folder, name.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from(OsStr::from_bytes(&buffer))))
}

fn parts_of(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect()
}

fn walk(path: &Path, create: bool, mode: u32, start: Option<&Folder>) -> Result<Folder, WriteError> {
    let mut fd = match start {
        Some(folder) if path.is_relative() => folder.0.try_clone()?,
        _ => root()?,
    };
    let absolute = if path.is_relative() && start.is_none() { std::env::current_dir()?.join(path) } else { path.to_path_buf() };
    let mut parts: VecDeque<(OsString, bool)> = parts_of(&absolute).into_iter().map(|p| (p, false)).collect();
    let mut links = 0;
    while let Some((part, inside_a_link)) = parts.pop_front() {
        let name = c_name(&part)?;
        let found = match stat_at(fd.as_raw_fd(), &name) {
            Ok(found) => found,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create && !inside_a_link && part != ".." => {
                make_dir_at(fd.as_raw_fd(), &name, mode)?;
                stat_at(fd.as_raw_fd(), &name)?
            }
            Err(error) => return Err(error.into()),
        };
        if is_kind(&found, libc::S_IFLNK) {
            links += 1;
            if !placed_by_trusted(&found, &stat_of(fd.as_raw_fd())?) || links > MAX_LINKS {
                return Err(WriteError::Redirected(format!("{} reaches elsewhere through a link at {}", path.display(), part.to_string_lossy())));
            }
            let target = read_link_at(fd.as_raw_fd(), &name)?;
            if target.is_absolute() {
                fd = root()?;
            }
            for (index, inner) in parts_of(&target).into_iter().enumerate() {
                parts.insert(index, (inner, true));
            }
            continue;
        }
        let entered = open_dir(fd.as_raw_fd(), &name, libc::O_NOFOLLOW)?;
        let opened = stat_of(entered.as_raw_fd())?;
        if !is_kind(&opened, libc::S_IFDIR) || (opened.st_dev, opened.st_ino) != (found.st_dev, found.st_ino) {
            return Err(WriteError::Redirected(format!("{} changed while it was opened", part.to_string_lossy())));
        }
        fd = entered;
    }
    Ok(Folder(fd))
}

#[allow(unsafe_code)]
fn make_dir_at(folder: libc::c_int, name: &CString, mode: u32) -> io::Result<()> {
    // SAFETY: `name` is NUL-terminated.
    match checked(unsafe { libc::mkdirat(folder, name.as_ptr(), mode as libc::mode_t) }) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other.map(|_| ()),
    }
}

/// Open a folder for writing in, one step at a time, without being redirected. Takes the folder,
/// whether to make missing parts, and their mode. Returns the open folder, or why it was not opened.
pub fn open_folder(path: &Path, create: bool, mode: u32) -> Result<Folder, WriteError> {
    walk(path, create, mode, None)
}

/// Open the folder a file is named in, following a trusted link at the file's own name. Takes the
/// file, whether to make missing folders and their mode. Returns the open folder and the name in
/// it, or why they were not opened.
pub fn open_parent(where_: &Path, create: bool, mode: u32) -> Result<(Folder, OsString), WriteError> {
    let parent = where_.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut folder = open_folder(parent, create, mode)?;
    let mut name = where_.file_name().map(OsStr::to_os_string).ok_or_else(|| WriteError::Redirected(format!("{} names no file", where_.display())))?;
    for _ in 0..MAX_LINKS {
        let c = c_name(&name)?;
        let found = match stat_at(folder.0.as_raw_fd(), &c) {
            Ok(found) => found,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((folder, name)),
            Err(error) => return Err(error.into()),
        };
        if !is_kind(&found, libc::S_IFLNK) {
            return Ok((folder, name));
        }
        if !placed_by_trusted(&found, &stat_of(folder.0.as_raw_fd())?) {
            return Err(WriteError::Redirected(format!("{} is a link", where_.display())));
        }
        let target = read_link_at(folder.0.as_raw_fd(), &c)?;
        let last = target.file_name().map(OsStr::to_os_string);
        let Some(last) = last.filter(|n| n != "." && n != "..") else {
            return Err(WriteError::Redirected(format!("{} is a link to a folder", where_.display())));
        };
        let within = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        folder = walk(within, false, mode, Some(&folder))?;
        name = last;
    }
    Err(WriteError::Redirected(format!("{} reaches elsewhere through too many links", where_.display())))
}

impl Folder {
    /// Tell whether a name in this folder is a link. Takes the name. Returns the answer.
    pub fn is_link(&self, name: &OsStr) -> io::Result<bool> {
        match stat_at(self.0.as_raw_fd(), &c_name(name)?) {
            Ok(found) => Ok(is_kind(&found, libc::S_IFLNK)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn mode_of(&self, name: &CString) -> io::Result<Option<u32>> {
        match stat_at(self.0.as_raw_fd(), name) {
            Ok(found) if is_kind(&found, libc::S_IFREG) => Ok(Some(u32::from(found.st_mode) & 0o7777)),
            Ok(_) => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn write_staged<F>(&self, name: &OsStr, staging: &str, mode: Mode, write: F) -> Result<(), WriteError>
    where
        F: FnOnce(&mut File) -> io::Result<()>,
    {
        let target = c_name(name)?;
        let staged = c_name(OsStr::new(staging))?;
        let kept = match mode {
            Mode::AsAPlainWrite => self.mode_of(&target)?,
            Mode::Set(set) => Some(set),
        };
        let initial = if mode == Mode::AsAPlainWrite { 0o666 } else { 0o600 };
        let fd = open_at(self.0.as_raw_fd(), &staged, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, initial)?;
        let outcome = (|| -> io::Result<()> {
            let mut file = File::from(fd);
            write(&mut file)?;
            file.flush()?;
            if let Some(kept) = kept {
                // SAFETY: the file's descriptor is open for this call.
                checked(unsafe { libc::fchmod(file.as_raw_fd(), kept as libc::mode_t) })?;
            }
            drop(file);
            // SAFETY: both names are NUL-terminated and the folder is open.
            checked(unsafe { libc::renameat(self.0.as_raw_fd(), staged.as_ptr(), self.0.as_raw_fd(), target.as_ptr()) })?;
            Ok(())
        })();
        if outcome.is_err() {
            // SAFETY: the name is NUL-terminated and the folder is open.
            unsafe { libc::unlinkat(self.0.as_raw_fd(), staged.as_ptr(), 0) };
        }
        outcome.map_err(WriteError::Io)
    }

    pub(crate) fn read_regular(&self, name: &OsStr, limit: u64) -> Option<Vec<u8>> {
        let fd = open_at(self.0.as_raw_fd(), &c_name(name).ok()?, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0).ok()?;
        if !is_kind(&stat_of(fd.as_raw_fd()).ok()?, libc::S_IFREG) {
            return None;
        }
        let mut bytes = Vec::new();
        File::from(fd).take(limit + 1).read_to_end(&mut bytes).ok()?;
        Some(bytes)
    }

    #[allow(unsafe_code)]
    pub(crate) fn set_own_mode(&self, mode: u32) -> io::Result<()> {
        // SAFETY: the folder's descriptor is open for this call.
        checked(unsafe { libc::fchmod(self.0.as_raw_fd(), mode as libc::mode_t) }).map(|_| ())
    }
}

#[allow(unsafe_code)]
fn entries_of(folder: libc::c_int) -> io::Result<Vec<OsString>> {
    // SAFETY: dup returns a new descriptor that fdopendir takes over and closedir releases.
    let copy = checked(unsafe { libc::dup(folder) })?;
    // SAFETY: `copy` is an open folder descriptor this function owns.
    let listing = unsafe { libc::fdopendir(copy) };
    if listing.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: `copy` is an open descriptor this function still owns.
        unsafe { libc::close(copy) };
        return Err(error);
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: `listing` is an open directory stream.
        let entry = unsafe { libc::readdir(listing) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `d_name` is a NUL-terminated name inside the entry readdir returned.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = OsStr::from_bytes(name.to_bytes());
        if name != "." && name != ".." {
            names.push(name.to_os_string());
        }
    }
    // SAFETY: `listing` is open and is closed once.
    unsafe { libc::closedir(listing) };
    Ok(names)
}

fn times_of(found: &libc::stat) -> std::fs::FileTimes {
    let at = |seconds: i64, nanos: i64| {
        let since = std::time::Duration::new(seconds.max(0) as u64, nanos.clamp(0, 999_999_999) as u32);
        std::time::UNIX_EPOCH + since
    };
    std::fs::FileTimes::new()
        .set_accessed(at(found.st_atime as i64, found.st_atime_nsec as i64))
        .set_modified(at(found.st_mtime as i64, found.st_mtime_nsec as i64))
}

impl Folder {
    /// Open a folder under this one, one step at a time, without being redirected. Takes the path.
    /// Returns the open folder, or why it was not opened.
    pub fn open_under(&self, path: &Path) -> Result<Folder, WriteError> {
        walk(path, false, 0o777, Some(self))
    }

    /// Give a file in this folder a mode. Takes its name and the mode. Returns nothing, or why it
    /// was not given.
    #[allow(unsafe_code)]
    pub fn set_mode_of(&self, name: &OsStr, mode: u32) -> Result<(), WriteError> {
        let fd = open_at(self.0.as_raw_fd(), &c_name(name)?, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0)?;
        let found = stat_of(fd.as_raw_fd())?;
        if !is_kind(&found, libc::S_IFREG) || found.st_nlink != 1 {
            return Err(WriteError::Redirected(format!("{} is not a file of its own", name.to_string_lossy())));
        }
        // SAFETY: the file's descriptor is open for this call.
        checked(unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) })?;
        Ok(())
    }

    /// Make a folder in this one. Takes its name and mode. Returns nothing, or why it was not made.
    #[allow(unsafe_code)]
    pub fn make_dir(&self, name: &OsStr, mode: u32) -> io::Result<()> {
        // SAFETY: the name is NUL-terminated and the folder is open.
        checked(unsafe { libc::mkdirat(self.0.as_raw_fd(), c_name(name)?.as_ptr(), mode as libc::mode_t) }).map(|_| ())
    }

    /// Move an entry of this folder into another folder under a name, replacing what is there.
    /// Takes the entry, the folder and the name. Returns nothing, or why it was not moved.
    #[allow(unsafe_code)]
    pub fn rename_to(&self, entry: &OsStr, folder: &Folder, name: &OsStr) -> io::Result<()> {
        let (from, to) = (c_name(entry)?, c_name(name)?);
        // SAFETY: both names are NUL-terminated and both folders are open.
        checked(unsafe { libc::renameat(self.0.as_raw_fd(), from.as_ptr(), folder.0.as_raw_fd(), to.as_ptr()) }).map(|_| ())
    }

    /// Rename an entry of this folder without replacing what has the new name. Takes the entry and
    /// the new name. Returns nothing, or why it was not renamed.
    pub fn rename_no_replace(&self, entry: &OsStr, name: &OsStr) -> io::Result<()> {
        let (from, to) = (c_name(entry)?, c_name(name)?);
        match kernel_rename_no_replace(self.0.as_raw_fd(), &from, &to) {
            Some(answer) => answer,
            None => match stat_at(self.0.as_raw_fd(), &to) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => self.rename_to(entry, self, name),
                Err(error) => Err(error),
                Ok(_) => Err(io::Error::from_raw_os_error(libc::EEXIST)),
            },
        }
    }

    /// Copy an entry of this folder, a file, link or folder, into another folder under a name,
    /// keeping modes and times. Takes the entry, the folder and the name. Returns whether it was a
    /// folder, or why it was not copied.
    #[allow(unsafe_code)]
    pub fn copy_into(&self, entry: &OsStr, folder: &Folder, name: &OsStr) -> io::Result<bool> {
        let (from, to) = (c_name(entry)?, c_name(name)?);
        let found = stat_at(self.0.as_raw_fd(), &from)?;
        if is_kind(&found, libc::S_IFLNK) {
            let target = c_name(read_link_at(self.0.as_raw_fd(), &from)?.as_os_str())?;
            // SAFETY: both strings are NUL-terminated and the folder is open.
            checked(unsafe { libc::symlinkat(target.as_ptr(), folder.0.as_raw_fd(), to.as_ptr()) })?;
            return Ok(false);
        }
        let mode = u32::from(found.st_mode) & 0o7777;
        if is_kind(&found, libc::S_IFDIR) {
            let given = Folder(open_dir(self.0.as_raw_fd(), &from, libc::O_NOFOLLOW)?);
            folder.make_dir(name, mode | 0o700)?;
            let inner = Folder(open_dir(folder.0.as_raw_fd(), &to, libc::O_NOFOLLOW)?);
            for child in entries_of(given.0.as_raw_fd())? {
                given.copy_into(&child, &inner, &child)?;
            }
            // SAFETY: the folder's descriptor is open for this call.
            checked(unsafe { libc::fchmod(inner.0.as_raw_fd(), mode as libc::mode_t) })?;
            File::from(inner.0).set_times(times_of(&found))?;
            return Ok(true);
        }
        if !is_kind(&found, libc::S_IFREG) {
            return Err(io::Error::other(format!("{} is not a file, link or folder", entry.to_string_lossy())));
        }
        let reading = open_at(self.0.as_raw_fd(), &from, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0)?;
        if !is_kind(&stat_of(reading.as_raw_fd())?, libc::S_IFREG) {
            return Err(io::Error::other(format!("{} is not a file", entry.to_string_lossy())));
        }
        let writing = open_at(folder.0.as_raw_fd(), &to, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, 0o600)?;
        let (mut source, mut out) = (File::from(reading), File::from(writing));
        io::copy(&mut source, &mut out)?;
        out.flush()?;
        // SAFETY: the file's descriptor is open for this call.
        checked(unsafe { libc::fchmod(out.as_raw_fd(), mode as libc::mode_t) })?;
        out.set_times(times_of(&found))?;
        Ok(false)
    }

    /// Remove an entry of this folder, and everything under it when it is a folder. Takes the
    /// entry. Returns nothing, or why it was not removed.
    #[allow(unsafe_code)]
    pub fn remove(&self, entry: &OsStr) -> io::Result<()> {
        let name = c_name(entry)?;
        let found = stat_at(self.0.as_raw_fd(), &name)?;
        if is_kind(&found, libc::S_IFDIR) {
            let inner = Folder(open_dir(self.0.as_raw_fd(), &name, libc::O_NOFOLLOW)?);
            for child in entries_of(inner.0.as_raw_fd())? {
                inner.remove(&child)?;
            }
            // SAFETY: the name is NUL-terminated and the folder is open.
            return checked(unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }).map(|_| ());
        }
        // SAFETY: the name is NUL-terminated and the folder is open.
        checked(unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) }).map(|_| ())
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn kernel_rename_no_replace(folder: libc::c_int, from: &CString, to: &CString) -> Option<io::Result<()>> {
    // SAFETY: both names are NUL-terminated and the folder is open.
    let result = unsafe { libc::renameat2(folder, from.as_ptr(), folder, to.as_ptr(), libc::RENAME_NOREPLACE) };
    unsupported_or(result)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn kernel_rename_no_replace(folder: libc::c_int, from: &CString, to: &CString) -> Option<io::Result<()>> {
    // SAFETY: both names are NUL-terminated and the folder is open.
    let result = unsafe { libc::renameatx_np(folder, from.as_ptr(), folder, to.as_ptr(), libc::RENAME_EXCL) };
    unsupported_or(result)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn kernel_rename_no_replace(_folder: libc::c_int, _from: &CString, _to: &CString) -> Option<io::Result<()>> {
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unsupported_or(result: libc::c_int) -> Option<io::Result<()>> {
    if result == 0 {
        return Some(Ok(()));
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP) => None,
        #[cfg(target_os = "linux")]
        Some(code) if code == libc::EOPNOTSUPP => None,
        _ => Some(Err(error)),
    }
}
