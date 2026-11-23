//! Resolves and names the paths saw keeps its own things at.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

/// Drop `.` parts and doubled separators from a path. Takes the path. Returns it.
pub fn tidy(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        if part != Component::CurDir || out.as_os_str().is_empty() && path.components().count() == 1 {
            out.push(part.as_os_str());
        }
    }
    out
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

/// Name a path by the first half of its SHA-256. Takes the path. Returns the name.
pub fn key_of(path: &Path) -> String {
    let digest = Sha256::digest(path_bytes(path));
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// Resolve a path as Python's `os.path.realpath` does without `strict`. Takes the path. Returns it
/// with every link that exists followed and the rest kept as written.
pub fn real_path(path: &Path) -> PathBuf {
    let mut seen: HashMap<PathBuf, Option<PathBuf>> = HashMap::new();
    let (resolved, _) = join_real(PathBuf::new(), path, &mut seen);
    let absolute = if resolved.is_absolute() {
        resolved
    } else {
        std::env::current_dir().map(|cwd| cwd.join(&resolved)).unwrap_or(resolved)
    };
    normalized(&absolute)
}

pub(crate) fn normalized(path: &Path) -> PathBuf {
    let mut out: Vec<OsString> = Vec::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name.to_os_string()),
            _ => {}
        }
    }
    let mut result = PathBuf::from("/");
    for part in out {
        result.push(part);
    }
    result
}

fn join_real(mut path: PathBuf, rest: &Path, seen: &mut HashMap<PathBuf, Option<PathBuf>>) -> (PathBuf, bool) {
    if rest.is_absolute() {
        path = PathBuf::from("/");
    }
    let parts: Vec<Component> = rest.components().filter(|c| !matches!(c, Component::RootDir | Component::CurDir)).collect();
    for (index, part) in parts.iter().enumerate() {
        let name = part.as_os_str();
        if *part == Component::ParentDir {
            if path.as_os_str().is_empty() {
                path = PathBuf::from("..");
            } else if path.file_name().is_none() || path.ends_with("..") {
                path.push("..");
            } else {
                path.pop();
                if path.as_os_str().is_empty() {
                    path = PathBuf::new();
                }
            }
            continue;
        }
        let candidate = path.join(name);
        let is_link = std::fs::symlink_metadata(&candidate).is_ok_and(|m| m.file_type().is_symlink());
        if !is_link {
            path = candidate;
            continue;
        }
        let remaining: PathBuf = parts[index + 1..].iter().map(|c| c.as_os_str()).collect();
        if let Some(known) = seen.get(&candidate) {
            match known {
                Some(resolved) => {
                    path = resolved.clone();
                    continue;
                }
                None => return (candidate.join(remaining), false),
            }
        }
        seen.insert(candidate.clone(), None);
        let target = std::fs::read_link(&candidate).unwrap_or_default();
        let (resolved, ok) = join_real(path.clone(), &target, seen);
        if !ok {
            return (resolved.join(remaining), false);
        }
        seen.insert(candidate, Some(resolved.clone()));
        path = resolved;
    }
    (path, true)
}

/// Expand a leading `~` or `~user` as Python's `expanduser` does. Takes the path and the home to
/// use for a bare `~`. Returns the path.
pub fn expand_user(given: &str, home: &Path) -> PathBuf {
    let Some(rest) = given.strip_prefix('~') else { return PathBuf::from(given) };
    let (user, tail) = rest.split_once('/').unwrap_or((rest, ""));
    let found = if user.is_empty() { Some(home.to_path_buf()) } else { crate::account::home_of_user(user) };
    match found {
        Some(found) if tail.is_empty() => found,
        Some(found) => found.join(tail),
        None => PathBuf::from(given),
    }
}
