//! Reads files and walks folders.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Whether a read follows a link at the path's own name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Follow {
    Links,
    NoLinks,
}

/// The identity of a file on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub device: u64,
    pub inode: u64,
}

/// Why a file was not read.
#[derive(Debug)]
pub enum ReadError {
    /// The path names something other than a regular file.
    NotRegular,
    /// The file is larger than the limit.
    TooLarge(u64),
    /// The file is not the one first found there.
    Replaced,
    /// The file could not be opened or read.
    Unreadable(io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::NotRegular => write!(f, "not a regular file"),
            ReadError::TooLarge(size) => write!(f, "{size} bytes, over the limit"),
            ReadError::Replaced => write!(f, "replaced since it was found"),
            ReadError::Unreadable(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ReadError {}

/// Return the identity of the file at a path. Takes the path and whether to follow a link there.
/// Returns the identity, or why it could not be read.
#[cfg(unix)]
pub fn identity(path: &Path, follow: Follow) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let found = match follow {
        Follow::Links => fs::metadata(path)?,
        Follow::NoLinks => fs::symlink_metadata(path)?,
    };
    Ok(FileId { device: found.dev(), inode: found.ino() })
}

/// Return the identity of the file at a path. Takes the path and whether to follow a link there.
/// Returns the identity, or why it could not be read.
#[cfg(windows)]
pub fn identity(path: &Path, follow: Follow) -> io::Result<FileId> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
    if follow == Follow::NoLinks {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    let file = OpenOptions::new().access_mode(0).custom_flags(flags).open(path)?;
    id_of_file(&file)
}

#[cfg(unix)]
fn id_of_file(file: &File) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let found = file.metadata()?;
    Ok(FileId { device: found.dev(), inode: found.ino() })
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn id_of_file(file: &File) -> io::Result<FileId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
    // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid value of that plain struct.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open for the whole call and `info` is a local the call fills.
    let filled = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if filled == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok(FileId { device: u64::from(info.dwVolumeSerialNumber), inode: index })
}

/// Open a regular file for reading without waiting on anything that is not one. Takes the path,
/// whether to follow a link at its name, and the file it must be, when given. Returns the open
/// file and its size, or why it was not opened.
pub fn open_regular(path: &Path, follow: Follow, same_as: Option<FileId>) -> Result<(File, u64), ReadError> {
    let mut options = OpenOptions::new();
    options.read(true);
    set_open_flags(&mut options, follow);
    let file = options.open(path).map_err(|error| if follow == Follow::NoLinks && is_link_refused(&error) { ReadError::NotRegular } else { ReadError::Unreadable(error) })?;
    let found = file.metadata().map_err(ReadError::Unreadable)?;
    if !found.is_file() {
        return Err(ReadError::NotRegular);
    }
    if let Some(expected) = same_as {
        if id_of_file(&file).map_err(ReadError::Unreadable)? != expected {
            return Err(ReadError::Replaced);
        }
    }
    Ok((file, found.len()))
}

#[cfg(unix)]
fn set_open_flags(options: &mut OpenOptions, follow: Follow) {
    use std::os::unix::fs::OpenOptionsExt;
    let no_follow = if follow == Follow::NoLinks { libc::O_NOFOLLOW } else { 0 };
    options.custom_flags(libc::O_NONBLOCK | no_follow);
}

#[cfg(windows)]
fn set_open_flags(options: &mut OpenOptions, follow: Follow) {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    if follow == Follow::NoLinks {
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

#[cfg(not(any(unix, windows)))]
fn set_open_flags(_options: &mut OpenOptions, _follow: Follow) {}

#[cfg(unix)]
fn is_link_refused(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_link_refused(_error: &io::Error) -> bool {
    false
}

/// Read a regular file without waiting on anything that is not one. Takes the path, the most
/// bytes to accept, whether to follow a link at its name, and the file it must be, when given.
/// Returns the bytes, or why they were not read.
pub fn read_regular(path: &Path, limit: u64, follow: Follow, same_as: Option<FileId>) -> Result<Vec<u8>, ReadError> {
    let (file, size) = open_regular(path, follow, same_as)?;
    if size > limit {
        return Err(ReadError::TooLarge(size));
    }
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes).map_err(ReadError::Unreadable)?;
    Ok(bytes)
}

/// Read the start and the end of a regular file. Takes the path, how many bytes of each, and
/// whether to follow a link at its name. Returns the head and the tail, or why they were not read.
pub fn head_and_tail(path: &Path, half: u64, follow: Follow) -> Result<(Vec<u8>, Vec<u8>), ReadError> {
    let (mut file, _) = open_regular(path, follow, None)?;
    let mut head = Vec::new();
    (&mut file).take(half).read_to_end(&mut head).map_err(ReadError::Unreadable)?;
    let offset = i64::try_from(half).map_err(|_| ReadError::TooLarge(half))?;
    if file.seek(SeekFrom::End(-offset)).is_err() {
        file.seek(SeekFrom::Start(0)).map_err(ReadError::Unreadable)?;
    }
    let mut tail = Vec::new();
    file.take(half).read_to_end(&mut tail).map_err(ReadError::Unreadable)?;
    Ok((head, tail))
}

/// One overlapping window of a byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// How many lines come before the window.
    pub lines_before: usize,
    pub bytes: Vec<u8>,
}

/// Walk a byte stream in overlapping windows, the last one ending at the end of the stream. Takes
/// a reader, the stream's size, the window size and the overlap. Returns the windows, or why the
/// stream could not be read.
pub fn windows<R: Read>(reader: &mut R, size: u64, window: usize, overlap: usize) -> io::Result<Vec<Window>> {
    let window = window.max(1);
    let step = window.saturating_sub(overlap.min(window / 2)).max(1);
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    let (mut buffer, mut position, mut lines_before, mut ended) = (Vec::new(), 0usize, 0usize, false);
    let mut out = Vec::new();
    loop {
        while buffer.len() < window && !ended {
            let mut chunk = vec![0u8; window - buffer.len()];
            let read = reader.read(&mut chunk)?;
            ended = read == 0;
            buffer.extend_from_slice(&chunk[..read]);
        }
        if buffer.is_empty() {
            return Ok(out);
        }
        out.push(Window { lines_before, bytes: buffer.clone() });
        if ended || position + buffer.len() >= size {
            return Ok(out);
        }
        let advance = step.min(size.saturating_sub(window).saturating_sub(position));
        lines_before += buffer[..advance.min(buffer.len())].iter().filter(|b| **b == b'\n').count();
        buffer.drain(..advance.min(buffer.len()));
        position += advance;
    }
}

/// What walking a folder found.
#[derive(Debug, Default)]
pub struct Walk {
    /// Every file, relative to the root, in walk order.
    pub files: Vec<PathBuf>,
    /// The folder names left out.
    pub pruned: BTreeSet<String>,
    /// The folders that could not be listed, relative to the root, and why.
    pub unwalkable: Vec<(PathBuf, io::Error)>,
}

/// Walk a folder top-down without entering a linked folder. Takes the root, the folder to walk
/// under it, and whether a folder name is left out. Returns what the walk found.
pub fn walk(root: &Path, start: &Path, leave_out: &dyn Fn(&str) -> bool) -> Walk {
    let mut found = Walk::default();
    walk_folder(root, start, leave_out, &mut found);
    found
}

fn walk_folder(root: &Path, folder: &Path, leave_out: &dyn Fn(&str) -> bool, found: &mut Walk) {
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(error) => {
            found.unwalkable.push((relative(root, folder), error));
            return;
        }
    };
    let mut folders = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let path = entry.path();
        let is_folder = fs::metadata(&path).is_ok_and(|m| m.is_dir());
        if !is_folder {
            found.files.push(relative(root, &path));
            continue;
        }
        let shown = name.to_string_lossy().into_owned();
        if leave_out(&shown) {
            found.pruned.insert(shown);
            continue;
        }
        let is_link = entry.file_type().is_ok_and(|t| t.is_symlink());
        folders.push((path, is_link));
    }
    for (path, is_link) in folders {
        if !is_link {
            walk_folder(root, &path, leave_out, found);
        }
    }
}

fn relative(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).map(Path::to_path_buf).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[allow(unsafe_code)]
    fn make_pipe(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    }

    fn folder(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("saw-files-{unique}-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn a_pipe_is_refused_without_waiting() {
        let root = folder("pipe");
        let pipe = root.join("named.js");
        make_pipe(&pipe);
        let started = Instant::now();
        assert!(matches!(read_regular(&pipe, 1 << 20, Follow::Links, None), Err(ReadError::NotRegular)));
        assert!(started.elapsed() < Duration::from_secs(2));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_link_is_read_only_when_links_are_followed() {
        let root = folder("link");
        fs::write(root.join("real.txt"), b"content").unwrap();
        std::os::unix::fs::symlink(root.join("real.txt"), root.join("link.txt")).unwrap();
        assert!(matches!(read_regular(&root.join("link.txt"), 100, Follow::NoLinks, None), Err(ReadError::NotRegular)));
        assert_eq!(read_regular(&root.join("link.txt"), 100, Follow::Links, None).unwrap(), b"content");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_over_the_limit_or_replaced_is_not_read() {
        let root = folder("limits");
        fs::write(root.join("big.txt"), vec![b'a'; 100]).unwrap();
        fs::write(root.join("other.txt"), b"x").unwrap();
        assert!(matches!(read_regular(&root.join("big.txt"), 10, Follow::NoLinks, None), Err(ReadError::TooLarge(100))));
        let other = identity(&root.join("other.txt"), Follow::NoLinks).unwrap();
        assert!(matches!(read_regular(&root.join("big.txt"), 1000, Follow::NoLinks, Some(other)), Err(ReadError::Replaced)));
        let own = identity(&root.join("big.txt"), Follow::NoLinks).unwrap();
        assert_eq!(read_regular(&root.join("big.txt"), 1000, Follow::NoLinks, Some(own)).unwrap().len(), 100);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_head_and_the_tail_are_read() {
        let root = folder("head-tail");
        fs::write(root.join("long.txt"), b"0123456789").unwrap();
        assert_eq!(head_and_tail(&root.join("long.txt"), 3, Follow::NoLinks).unwrap(), (b"012".to_vec(), b"789".to_vec()));
        assert_eq!(head_and_tail(&root.join("long.txt"), 20, Follow::NoLinks).unwrap().1, b"0123456789".to_vec());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_folder_that_cannot_be_listed_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let root = folder("unwalkable");
        fs::create_dir_all(root.join("shut")).unwrap();
        fs::set_permissions(root.join("shut"), fs::Permissions::from_mode(0o000)).unwrap();
        let found = walk(&root, &root, &|_| false);
        fs::set_permissions(root.join("shut"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(found.unwalkable.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(), vec![PathBuf::from("shut")]);
        let _ = fs::remove_dir_all(&root);
    }
}
