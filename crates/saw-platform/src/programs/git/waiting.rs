//! Tells whether git would wait on a repository's configuration.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::programs::git::{Context, Git, Request, records};

pub const MAX_WAIT_FILES: usize = 256;
pub const MAX_INCLUDE_DEPTH: usize = 10;
pub const MAX_CONFIG_BYTES: u64 = 4 << 20;

/// Tell whether every git command in a repository would wait on its configuration. Takes the git
/// handle and the repository. Returns the answer, false when it cannot be said.
pub fn config_waits(git: &Git, start: &Path) -> bool {
    let Some(git_dir) = plain_git_dir(start) else { return false };
    let common = if fs::symlink_metadata(git_dir.join("commondir")).is_ok() {
        match followed(&git_dir.join("commondir"), "") {
            Some(common) => common,
            None => return false,
        }
    } else {
        git_dir
    };
    let mut budget = MAX_WAIT_FILES;
    waits_on(git, &common.join("config"), &mut HashSet::new(), &mut budget, 0) == Some(true)
}

fn plain_git_dir(start: &Path) -> Option<PathBuf> {
    let top = fs::canonicalize(start).ok()?;
    let dot_git = top.join(".git");
    let git_dir = match fs::symlink_metadata(&dot_git) {
        Ok(found) if found.is_dir() => dot_git,
        Ok(_) => followed(&dot_git, "gitdir:")?,
        Err(_) => top,
    };
    (is_git_directory(&git_dir) && owned_by_this_user(&git_dir)).then_some(git_dir)
}

#[cfg(unix)]
fn owned_by_this_user(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).is_ok_and(|found| found.uid() == crate::account::user_id())
}

#[cfg(not(unix))]
fn owned_by_this_user(_path: &Path) -> bool {
    false
}

fn regular_text(path: &Path) -> Option<String> {
    if !fs::metadata(path).ok()?.is_file() {
        return None;
    }
    fs::read(path).ok().map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn followed(pointer: &Path, prefix: &str) -> Option<PathBuf> {
    let text = regular_text(pointer)?;
    let value = text.strip_prefix(prefix)?.trim();
    if value.is_empty() {
        return None;
    }
    fs::canonicalize(pointer.parent()?.join(value)).ok()
}

/// Tell whether a path is a git directory. Takes the path. Returns the answer.
pub fn is_git_directory(path: &Path) -> bool {
    let common = if fs::symlink_metadata(path.join("commondir")).is_ok() {
        followed(&path.join("commondir"), "")
    } else {
        Some(path.to_path_buf())
    };
    common.is_some_and(|common| valid_head(&path.join("HEAD")) && common.join("objects").is_dir() && common.join("refs").is_dir())
}

fn valid_head(head: &Path) -> bool {
    if fs::symlink_metadata(head).is_ok_and(|found| found.file_type().is_symlink()) {
        return fs::read_link(head).is_ok_and(|target| target.starts_with("refs/"));
    }
    let Some(text) = regular_text(head) else { return false };
    if let Some(named) = text.strip_prefix("ref:") {
        return named.trim_start().starts_with("refs/");
    }
    let word = text.split_whitespace().next().unwrap_or("");
    matches!(word.len(), 40 | 64) && word.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(unix)]
fn is_pipe(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::metadata(path).is_ok_and(|found| found.file_type().is_fifo())
}

#[cfg(not(unix))]
fn is_pipe(_path: &Path) -> bool {
    false
}

fn waits_on(git: &Git, path: &Path, examined: &mut HashSet<PathBuf>, budget: &mut usize, depth: usize) -> Option<bool> {
    if depth > MAX_INCLUDE_DEPTH {
        return None;
    }
    if is_pipe(path) {
        return Some(true);
    }
    let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if examined.contains(&key) {
        return Some(false);
    }
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    examined.insert(key);
    let Some(pairs) = config_file_pairs(git, path) else { return Some(false) };
    let mut unsure = false;
    for (name, value) in pairs {
        let Some(value) = value.filter(|v| !v.is_empty()) else { continue };
        if !name.eq_ignore_ascii_case("include.path") {
            continue;
        }
        let Some(target) = include_target(path, &value) else {
            unsure = true;
            continue;
        };
        match waits_on(git, &target, examined, budget, depth + 1) {
            Some(true) => return Some(true),
            None => unsure = true,
            Some(false) => {}
        }
    }
    if unsure { None } else { Some(false) }
}

/// Read one configuration file without its includes. Takes the git handle and the file. Returns its
/// key and value pairs in order, or none when it could not be read.
pub fn config_file_pairs(git: &Git, path: &Path) -> Option<Vec<(String, Option<String>)>> {
    if fs::symlink_metadata(path).is_err() {
        return Some(Vec::new());
    }
    let found = fs::metadata(path).ok()?;
    if !found.is_file() || found.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let shown = path.display().to_string();
    let request = Request::new(Context::Untrusted, None, &["config", "--file", &shown, "--no-includes", "--list", "-z"]);
    let listed = git.output(&request).ok()?;
    Some(
        records(&listed)
            .into_iter()
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| {
                let text = String::from_utf8_lossy(chunk);
                match text.split_once('\n') {
                    Some((key, value)) => (key.to_string(), Some(value.to_string())),
                    None => (text.into_owned(), None),
                }
            })
            .collect(),
    )
}

fn include_target(including: &Path, value: &str) -> Option<PathBuf> {
    if value.starts_with("%(") {
        return None;
    }
    if let Some(rest) = value.strip_prefix('~') {
        let (user, rest) = rest.split_once('/').unwrap_or((rest, ""));
        let home = if user.is_empty() { std::env::var_os("HOME").map(PathBuf::from)? } else { crate::account::home_of_user(user)? };
        return Some(if rest.is_empty() { home } else { home.join(rest) });
    }
    let named = Path::new(value);
    if named.is_absolute() {
        return Some(named.to_path_buf());
    }
    Some(including.parent()?.join(named))
}
