//! Tells whether a process runs a program that is no longer a file on this disk.

use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

const DELETED: &str = " (deleted)";
const WRITABLE_BY_OTHERS: u32 = 0o022;
const MEMORY_FILESYSTEMS: [u64; 2] = [0x0102_1994, 0x8584_58F6];

/// The parts of a file's status this check reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStatus {
    pub mode: u32,
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
}

impl FileStatus {
    #[cfg(unix)]
    fn of(found: &std::fs::Metadata) -> FileStatus {
        use std::os::unix::fs::MetadataExt;
        FileStatus { mode: found.mode(), uid: found.uid(), dev: found.dev(), ino: found.ino() }
    }

    #[cfg(not(unix))]
    fn of(_found: &std::fs::Metadata) -> FileStatus {
        FileStatus { mode: 0, uid: u32::MAX, dev: 0, ino: 0 }
    }

    fn is_regular(&self) -> bool {
        self.mode & 0o170000 == 0o100000
    }

    fn is_folder(&self) -> bool {
        self.mode & 0o170000 == 0o040000
    }

    fn same_file(&self, other: &FileStatus) -> bool {
        (self.dev, self.ino) == (other.dev, other.ino)
    }

    fn installed_by_root(&self) -> bool {
        self.is_regular() && self.uid == 0 && self.mode & WRITABLE_BY_OTHERS == 0
    }
}

/// Return a file's status, following links. Takes the path.
pub fn status(path: &Path) -> io::Result<FileStatus> {
    std::fs::metadata(path).map(|found| FileStatus::of(&found))
}

fn link_status(path: &Path) -> io::Result<FileStatus> {
    std::fs::symlink_metadata(path).map(|found| FileStatus::of(&found))
}

/// What the check reads about a process.
pub trait Readers {
    /// Return the path of the file a process runs, or none. Takes the process id.
    fn path(&self, pid: u32) -> Option<PathBuf>;
    /// Return the status of the file a process runs. Takes the process id.
    fn running(&self, pid: u32) -> io::Result<FileStatus>;
    /// Return the kernel's number for the filesystem that file lives on. Takes the process id.
    fn filesystem(&self, pid: u32) -> io::Result<u64>;
    /// Return the account a process runs as, or none. Takes the process id.
    fn account(&self, pid: u32) -> Option<i64>;
    /// Tell whether this run is root's.
    fn as_root(&self) -> bool;
}

/// The machine saw runs on.
pub struct System;

impl Readers for System {
    fn path(&self, pid: u32) -> Option<PathBuf> {
        super::listing::program_path(pid)
    }

    fn running(&self, pid: u32) -> io::Result<FileStatus> {
        status(Path::new(&format!("/proc/{pid}/exe")))
    }

    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    fn filesystem(&self, pid: u32) -> io::Result<u64> {
        let name = std::ffi::CString::new(format!("/proc/{pid}/exe")).map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
        // SAFETY: an all-zero statfs is a valid value of that plain struct.
        let mut found: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `name` is NUL-terminated and `found` is a local; both outlive the call.
        if unsafe { libc::statfs(name.as_ptr(), &mut found) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(found.f_type as u64 & 0xFFFF_FFFF)
    }

    #[cfg(not(target_os = "linux"))]
    fn filesystem(&self, _pid: u32) -> io::Result<u64> {
        Err(io::Error::from(ErrorKind::Unsupported))
    }

    fn account(&self, pid: u32) -> Option<i64> {
        super::identity::identify(pid).0.map(|who| who.uid)
    }

    fn as_root(&self) -> bool {
        #[cfg(unix)]
        return crate::account::effective_user_id() == 0;
        #[cfg(not(unix))]
        return false;
    }
}

/// Tell whether a process runs something that is no longer a file on this disk. Takes the process
/// id.
pub fn program_is_gone(pid: u32) -> bool {
    program_is_gone_with(pid, &System)
}

fn text_of(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    #[cfg(unix)]
    return std::borrow::Cow::Borrowed(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()));
    #[cfg(not(unix))]
    return std::borrow::Cow::Owned(path.to_string_lossy().into_owned().into_bytes());
}

fn path_from(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    return PathBuf::from(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(bytes));
    #[cfg(not(unix))]
    return PathBuf::from(String::from_utf8_lossy(bytes).into_owned());
}

/// Tell whether a process runs something that is no longer a file on this disk. Takes the process
/// id and the readers. Returns the answer.
pub fn program_is_gone_with(pid: u32, readers: &dyn Readers) -> bool {
    let Some(place) = readers.path(pid) else { return false };
    let bytes = text_of(&place);
    if bytes.starts_with(b"/memfd:") {
        return true;
    }
    let deleted = bytes.ends_with(DELETED.as_bytes());
    let info = match readers.running(pid) {
        Ok(info) => info,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return if readers.as_root() { false } else { deleted || !exists(&place) },
        Err(_) => return deleted || !exists(&place),
    };
    if deleted {
        let gone_from = path_from(&bytes[..bytes.len() - DELETED.len()]);
        return !administrators_program(&gone_from, &info, &view_of(pid), readers.account(pid));
    }
    match status(&place) {
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => on_memory(pid, readers),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => !readers.as_root() || on_memory(pid, readers),
        Err(_) => true,
        Ok(here) if here.same_file(&info) => false,
        Ok(_) => on_memory(pid, readers),
    }
}

fn exists(place: &Path) -> bool {
    std::fs::metadata(place).is_ok()
}

fn joined(view: &Path, path: &Path) -> PathBuf {
    if view.as_os_str().is_empty() {
        return path.to_path_buf();
    }
    let mut bytes = text_of(view).into_owned();
    bytes.extend_from_slice(&text_of(path));
    path_from(&bytes)
}

fn administrators_program(gone_from: &Path, info: &FileStatus, view: &Path, runs_as: Option<i64>) -> bool {
    if !(info.installed_by_root() && only_root_changes(&dirname(gone_from), view)) {
        return false;
    }
    if runs_as.is_some_and(|uid| uid > 0) {
        return true;
    }
    match status(&joined(view, gone_from)) {
        Ok(now) => now.installed_by_root() && !now.same_file(info),
        Err(_) => false,
    }
}

fn on_memory(pid: u32, readers: &dyn Readers) -> bool {
    match readers.filesystem(pid) {
        Ok(kind) => MEMORY_FILESYSTEMS.contains(&kind),
        Err(_) => true,
    }
}

fn dirname(path: &Path) -> PathBuf {
    let bytes = text_of(path);
    let cut = bytes.iter().rposition(|b| *b == b'/').map_or(0, |i| i + 1);
    let mut head = &bytes[..cut];
    if !head.is_empty() && head.iter().any(|b| *b != b'/') {
        while head.last() == Some(&b'/') {
            head = &head[..head.len() - 1];
        }
    }
    path_from(head)
}

/// Return the root that turns a path another process sees into one this run can open, or an empty
/// path. Takes the process id.
pub fn view_of(pid: u32) -> PathBuf {
    if !cfg!(target_os = "linux") {
        return PathBuf::new();
    }
    let ours = std::fs::read_link("/proc/self/ns/mnt");
    match std::fs::read_link(format!("/proc/{pid}/ns/mnt")) {
        Ok(theirs) if ours.is_ok_and(|ours| ours == theirs) => PathBuf::new(),
        Ok(_) if std::fs::metadata(format!("/proc/{pid}/root/")).is_ok() => PathBuf::from(format!("/proc/{pid}/root")),
        _ => PathBuf::new(),
    }
}

/// Tell whether only an administrator can change what a folder holds. Takes the folder and the
/// root it is read through.
pub fn only_root_changes(folder: &Path, view: &Path) -> bool {
    let mut path = if folder.as_os_str().is_empty() { PathBuf::new() } else { crate::sandbox::paths::normalized(folder) };
    if !text_of(&path).starts_with(b"/") {
        return false;
    }
    loop {
        let Ok(info) = link_status(&joined(view, &path)) else { return false };
        if !info.is_folder() || info.uid != 0 || info.mode & WRITABLE_BY_OTHERS != 0 {
            return false;
        }
        let parent = dirname(&path);
        if text_of(&path).as_ref() == b"/" || parent == path {
            return true;
        }
        path = parent;
    }
}

/// Tell whether this run sees the machine's administrator as root.
pub fn maps_the_hosts_root() -> bool {
    if !cfg!(target_os = "linux") {
        return true;
    }
    match std::fs::read("/proc/self/uid_map") {
        Err(error) if error.kind() == ErrorKind::NotFound => true,
        Err(_) => false,
        Ok(table) => String::from_utf8_lossy(&table).lines().any(|line| super::words(line).get(..2) == Some(&["0", "0"][..])),
    }
}
