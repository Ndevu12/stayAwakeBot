//! Keeps one folder per run for everything it creates outside a repository, and releases it.

use std::fs::{self, DirBuilder, OpenOptions};
use std::hash::{BuildHasher, Hasher, RandomState};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::env::Environment;

pub const ROOT_PREFIX: &str = "saw-run-";
pub const RECORD: &str = "run.json";
pub const KEPT: &str = "reports";

type Teardown = Box<dyn Fn(&Path) -> String + Send + Sync>;

struct Area {
    path: PathBuf,
    purpose: String,
    teardown: Option<Teardown>,
    kept: bool,
}

/// One run's folder and the areas it made in it.
pub struct Scratch {
    temp: PathBuf,
    root: Mutex<Option<PathBuf>>,
    areas: Mutex<Vec<Area>>,
}

/// Name a folder for a purpose. Takes the purpose. Returns the name.
pub fn slug(purpose: &str) -> String {
    let named: String = purpose.to_lowercase().chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    let trimmed = named.trim_matches('-');
    if trimmed.is_empty() { "scratch".to_string() } else { trimmed.to_string() }
}

/// Return the system's temporary folder, as Python's `tempfile` finds it. Takes the environment.
pub fn temp_folder(env: &Environment) -> PathBuf {
    ["TMPDIR", "TEMP", "TMP"]
        .iter()
        .find_map(|name| env.variables().get(*name).filter(|v| !v.is_empty()).map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir)
}

fn random_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut bits = hasher.finish();
    let letters = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    (0..8).map(|_| {
        let c = letters[(bits % letters.len() as u64) as usize] as char;
        bits /= letters.len() as u64;
        c
    }).collect()
}

#[cfg(unix)]
fn private_folder() -> DirBuilder {
    let mut builder = DirBuilder::new();
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
}

#[cfg(not(unix))]
fn private_folder() -> DirBuilder {
    DirBuilder::new()
}

/// Make a folder of its own under a base, named with a prefix and random letters. Takes the base
/// and the prefix. Returns the folder, or why none was made.
pub fn make_unique_folder(base: &Path, prefix: &str) -> io::Result<PathBuf> {
    for _ in 0..100 {
        let candidate = base.join(format!("{prefix}{}", random_name()));
        match private_folder().create(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free name"))
}

impl Scratch {
    /// Make an empty run. Takes the system's temporary folder. Returns the run.
    pub fn new(temp: PathBuf) -> Scratch {
        Scratch { temp, root: Mutex::new(None), areas: Mutex::new(Vec::new()) }
    }

    /// Return the folder this run puts everything under, making it on first use.
    pub fn root(&self) -> io::Result<PathBuf> {
        let mut root = self.root.lock().expect("the root is never poisoned");
        if let Some(made) = root.as_ref() {
            return Ok(made.clone());
        }
        let made = make_unique_folder(&self.temp, ROOT_PREFIX)?;
        self.write_record(&made);
        *root = Some(made.clone());
        Ok(made)
    }

    fn write_record(&self, root: &Path) {
        use saw_model::document::Document;
        let uid = user_id().map(|id| Document::Number(u64::from(id).into())).unwrap_or(Document::Null);
        let record = Document::Object(saw_model::ordered::Ordered(vec![
            ("version".to_string(), Document::Number(1u64.into())),
            ("pid".to_string(), Document::Number(u64::from(crate::programs::process_id()).into())),
            ("uid".to_string(), uid),
            ("tmp_root".to_string(), Document::String(self.temp.display().to_string())),
        ]));
        if let Ok(text) = saw_model::json::to_string(&record, saw_model::json::Style::INDENTED) {
            let _ = fs::write(root.join(RECORD), text + "\n");
        }
    }

    fn base(&self, parts: &[&str]) -> io::Result<PathBuf> {
        let mut base = self.root()?;
        for part in parts {
            base.push(part);
        }
        fs::create_dir_all(&base)?;
        Ok(base)
    }

    fn hold(&self, area: Area) {
        self.areas.lock().expect("the areas are never poisoned").push(area);
    }

    /// Make a folder under this run's root. Takes what it is for and how to tear it down. Returns
    /// the path.
    pub fn new_dir(&self, purpose: &str, teardown: Option<Teardown>) -> io::Result<PathBuf> {
        let made = make_unique_folder(&self.base(&[&slug(purpose)])?, "tmp")?;
        self.hold(Area { path: made.clone(), purpose: purpose.to_string(), teardown, kept: false });
        Ok(made)
    }

    /// Make a folder the operator is given, which the run does not remove. Takes what it is for.
    /// Returns the path.
    pub fn kept_dir(&self, purpose: &str) -> io::Result<PathBuf> {
        let made = make_unique_folder(&self.base(&[KEPT, &slug(purpose)])?, &local_stamp())?;
        self.hold(Area { path: made.clone(), purpose: purpose.to_string(), teardown: None, kept: true });
        Ok(made)
    }

    /// Make a file under this run's root. Takes what it is for, a suffix and the mode. Returns the
    /// path.
    pub fn new_file(&self, purpose: &str, suffix: &str, mode: u32) -> io::Result<PathBuf> {
        let base = self.base(&[&slug(purpose)])?;
        #[cfg(not(unix))]
        let _ = mode;
        for _ in 0..100 {
            let candidate = base.join(format!("tmp{}{suffix}", random_name()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
            match options.open(&candidate) {
                Ok(_) => {
                    #[cfg(unix)]
                    fs::set_permissions(&candidate, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
                    self.hold(Area { path: candidate.clone(), purpose: purpose.to_string(), teardown: None, kept: false });
                    return Ok(candidate);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free name"))
    }

    /// Release one area before the run ends. Takes its path. Returns an empty string when it is
    /// gone, else why it is not.
    pub fn release_path(&self, path: &Path) -> String {
        let found = {
            let mut areas = self.areas.lock().expect("the areas are never poisoned");
            areas.iter().position(|a| a.path == path).map(|i| areas.remove(i))
        };
        found.map(|area| remove_area(&area)).unwrap_or_default()
    }

    /// Return the paths and purposes this run made and still holds, newest first.
    pub fn held(&self) -> Vec<(PathBuf, String)> {
        self.areas.lock().expect("the areas are never poisoned").iter().rev().map(|a| (a.path.clone(), a.purpose.clone())).collect()
    }

    /// Remove what this run made, newest first, keeping what the operator was given. Returns a
    /// reason for each one that could not be removed.
    pub fn release(&self) -> Vec<String> {
        let areas: Vec<Area> = std::mem::take(&mut *self.areas.lock().expect("the areas are never poisoned"));
        let mut reasons = Vec::new();
        for area in areas.iter().rev().filter(|a| !a.kept) {
            let why = remove_area(area);
            if !why.is_empty() {
                reasons.push(format!("{} at {}: {why}", area.purpose, area.path.display()));
            }
        }
        if let Some(root) = self.root.lock().expect("the root is never poisoned").take() {
            reasons.extend(drop_root(&root));
        }
        reasons
    }
}

fn remove_area(area: &Area) -> String {
    if let Some(teardown) = &area.teardown {
        let why = teardown(&area.path);
        if !why.is_empty() {
            return why;
        }
    }
    if fs::symlink_metadata(&area.path).is_err() {
        return String::new();
    }
    remove_tree(&area.path)
}

fn drop_root(root: &Path) -> Vec<String> {
    let kept = root.join(KEPT);
    if fs::read_dir(&kept).is_ok_and(|mut entries| entries.next().is_some()) {
        return Vec::new();
    }
    let record = root.join(RECORD);
    if record.exists() {
        if let Err(error) = fs::remove_file(&record) {
            return vec![format!("the run record at {}: {error}", record.display())];
        }
    }
    let why = remove_tree(root);
    if why.is_empty() { Vec::new() } else { vec![format!("the run directory at {}: {why}", root.display())] }
}

/// Remove a tree, reopening a folder that denies it once. Takes the path. Returns an empty string
/// when it is gone, else why it is not.
pub fn remove_tree(path: &Path) -> String {
    let mut problems = Vec::new();
    remove_reopening(path, &mut problems);
    if fs::symlink_metadata(path).is_ok() {
        return problems.into_iter().next().unwrap_or_else(|| "still present".to_string());
    }
    String::new()
}

fn reopen(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = path.parent() {
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn remove_reopening(path: &Path, problems: &mut Vec<String>) {
    let Ok(found) = fs::symlink_metadata(path) else { return };
    if found.is_dir() {
        let listed = fs::read_dir(path).or_else(|_| {
            reopen(path);
            fs::read_dir(path)
        });
        match listed {
            Ok(entries) => {
                for entry in entries.flatten() {
                    remove_reopening(&entry.path(), problems);
                }
            }
            Err(error) => problems.push(format!("{}: {error}", path.display())),
        }
        if let Err(error) = fs::remove_dir(path).or_else(|_| {
            reopen(path);
            fs::remove_dir(path)
        }) {
            problems.push(format!("{}: {error}", path.display()));
        }
    } else if let Err(error) = fs::remove_file(path).or_else(|_| {
        reopen(path);
        fs::remove_file(path)
    }) {
        problems.push(format!("{}: {error}", path.display()));
    }
}

#[cfg(unix)]
fn user_id() -> Option<u32> {
    Some(crate::account::user_id())
}

#[cfg(not(unix))]
fn user_id() -> Option<u32> {
    None
}

/// Return the local time as `YYYY-MM-DD-HHMMSS-`.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn local_stamp() -> String {
    // SAFETY: time with a null pointer only returns the current time.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    // SAFETY: an all-zero tm is a valid value of that plain struct.
    let mut parts: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are to locals that outlive the call.
    unsafe { libc::localtime_r(&now, &mut parts) };
    format!("{:04}-{:02}-{:02}-{:02}{:02}{:02}-", parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday, parts.tm_hour, parts.tm_min, parts.tm_sec)
}

/// Return the local time as `YYYY-MM-DD-HHMMSS-`.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn local_stamp() -> String {
    // SAFETY: an all-zero SYSTEMTIME is a valid value of that plain struct.
    let mut now: windows_sys::Win32::Foundation::SYSTEMTIME = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a local the call fills.
    unsafe { windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut now) };
    format!("{:04}-{:02}-{:02}-{:02}{:02}{:02}-", now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond)
}
