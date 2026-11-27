//! Paths read the way saw's Python reads them: `~` expanded, joined and normalized, resolved by the
//! file system. Only regular files are read.

use std::fs;
use std::path::{is_separator, Component, Path, PathBuf};

use crate::platform;

use super::Environment;

const NO_HOOKS_FOLDER: [&str; 2] = ["saw", "git-runs-no-hooks"];

/// Expand a leading `~` to the home folder. Takes the text and the environment. Returns the text,
/// unchanged when it names no home folder this can find.
pub fn expand_user(value: &str, environ: &Environment) -> String {
    let home = platform::home_folder(environ);
    let names_home = value.strip_prefix('~').is_some_and(|rest| rest.is_empty() || rest.starts_with(is_separator));
    match home.filter(|_| names_home) {
        Some(home) if value == "~" => home,
        Some(home) => format!("{}{}", home.trim_end_matches(is_separator), &value[1..]),
        None => value.to_string(),
    }
}

/// Collapse `.`, `..` and repeated separators in a path without reading the file system.
pub fn normalize(path: &Path) -> PathBuf {
    let mut parts: Vec<Component> = Vec::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => match parts.last() {
                Some(Component::Normal(_)) => {
                    parts.pop();
                }
                Some(Component::RootDir) => {}
                _ => parts.push(part),
            },
            other => parts.push(other),
        }
    }
    let joined: PathBuf = parts.iter().collect();
    if joined.as_os_str().is_empty() { PathBuf::from(".") } else { joined }
}

/// Resolve a path git reads from configuration. Takes the directory it is relative to, the value
/// and the environment. Returns the path, `~` expanded.
pub fn resolve(base: &Path, value: &str, environ: &Environment) -> PathBuf {
    let expanded = PathBuf::from(expand_user(value, environ));
    normalize(&if expanded.is_absolute() { expanded } else { base.join(expanded) })
}

/// Resolve every link in a path the file system can, keeping what does not exist as written.
pub fn real_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    if let Ok(found) = fs::canonicalize(&absolute) {
        return found;
    }
    let absolute = normalize(&absolute);
    match (absolute.parent(), absolute.file_name()) {
        (Some(parent), Some(name)) if parent != absolute => real_path(parent).join(name),
        _ => absolute,
    }
}

/// Whether a path exists, a link counting whether or not what it names does.
pub fn lexists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Whether a path is a regular file, links followed.
pub fn is_regular_file(path: &Path) -> bool {
    fs::metadata(path).map(|found| found.is_file()).unwrap_or(false)
}

/// Whether a path is a link.
pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).map(|found| found.file_type().is_symlink()).unwrap_or(false)
}

/// The text of a regular file, read leniently, or None for one absent, not regular or unreadable.
pub fn read_regular_text(path: &Path) -> Option<String> {
    if !is_regular_file(path) {
        return None;
    }
    fs::read(path).ok().map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// What names the same file for every spelling of a path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identity {
    /// The device and file number of a file that exists: its inode, or its file index on Windows.
    File(u64, u64),
    /// The real path of one that does not.
    Path(PathBuf),
}

/// Name the file or directory a path reaches. Takes the path.
pub fn file_identity(path: &Path) -> Identity {
    match platform::file_id(path) {
        Ok((device, number)) => Identity::File(device, number),
        Err(_) => Identity::Path(real_path(path)),
    }
}

/// The name of the kind of error the file system gave, as saw's Python names it.
pub fn error_name(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => "PermissionError",
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        std::io::ErrorKind::NotADirectory => "NotADirectoryError",
        _ => "OSError",
    }
}

/// The empty folder saw keeps for git to run hooks from, made when missing: the one saw's Python
/// uses. Takes the environment. Returns it, or why it cannot be used.
pub fn no_hooks_folder(environ: &Environment) -> Result<PathBuf, String> {
    let state = match environ.get("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        Some(state) => PathBuf::from(state),
        None => PathBuf::from(expand_user("~", environ)).join(".local").join("state"),
    };
    let folder = NO_HOOKS_FOLDER.iter().fold(state, |path, part| path.join(part));
    let shown = folder.display();
    if let Err(error) = platform::create_private_folder(&folder) {
        return Err(format!("saw's empty hooks folder {shown} could not be used: {error}"));
    }
    let found = fs::symlink_metadata(&folder).map_err(|error| format!("saw's empty hooks folder {shown} could not be used: {error}"))?;
    if !found.is_dir() {
        return Err(format!("saw's empty hooks folder {shown} is not a folder"));
    }
    if !platform::belongs_to_this_user(&folder, &found) {
        return Err(format!("saw's empty hooks folder {shown} belongs to someone else"));
    }
    let mut entries = fs::read_dir(&folder).map_err(|error| format!("saw's empty hooks folder {shown} could not be used: {error}"))?;
    if entries.next().is_some() {
        return Err(format!("saw's empty hooks folder {shown} holds files; remove them"));
    }
    Ok(folder)
}
