//! The fingerprint of the programs a repository's own git settings start: every setting in its own
//! configuration that `lib/data/git_exec_keys.json` lists as running a program, every file under the
//! hooks folder git runs hooks from when that folder is the repository's own, except a hook whose
//! bytes match the one saw installs, every file under the working tree's top folder that holds that
//! hooks folder, and the hook managers' own files (`lib/data/git_hook_managers.json`). saw's Python
//! `lib/git/settings_fingerprint.py` reads the same fingerprint. Nothing in the folder is run.

use std::cell::Cell;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;

use sha2::{Digest, Sha256};

use super::exec_keys::{rule_for, ExecKey, Runs};
use super::locate::Found;
use super::paths;
use super::Environment;
use crate::git_tables::table;

const OWN_SCOPES: [&str; 2] = ["local", "worktree"];
const HOOKS_KEY: &str = "core.hookspath";
const NEVER_RUN_SUFFIX: &str = ".sample";
const BOOLEAN_WORDS: [&str; 9] = ["true", "false", "yes", "no", "on", "off", "1", "0", ""];
const EXT_PREFIX: &str = "ext::";
const SETTING: &str = "setting";
const HOOKS_FOLDER: &str = "hooks";
const HOOK: &str = "hook";
const HOOK_LINK: &str = "hook-link";
const TREE: &str = "tree";
const TREE_LINK: &str = "tree-link";
const MANAGER: &str = "manager";
const MANAGER_LINK: &str = "manager-link";
const ABSENT: &str = "absent";
const PACKAGE: &str = "package.json";
const MOST_FILES: usize = 2000;
const NOT_A_FILE: &str = "not-a-file";
const RUN: [&str; 3] = [SETTING, HOOK, HOOK_LINK];
const MANAGERS_FILE: &str = include_str!("../../../../../lib/data/git_hook_managers.json");

/// What hook managers run or read: file patterns, and the package.json keys they read.
#[derive(Deserialize)]
struct HookManagers {
    files: Vec<String>,
    package_keys: Vec<String>,
}

fn hook_managers() -> &'static HookManagers {
    static READ: OnceLock<HookManagers> = OnceLock::new();
    READ.get_or_init(|| serde_json::from_str(MANAGERS_FILE).expect("saw's hook manager files"))
}

/// One file the fingerprint covers: its path relative to where the reading started, whether it is
/// a link, and the sha256 of a file or a link's target and the sha256 of what it points to.
type Read = (String, bool, String);

/// The programs one repository's own settings start, as sorted entries: `["setting", scope, key,
/// value]`, `["hooks", folder]` and `["hook", name, sha256]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// The repository's common git directory, every link resolved: the key it is kept under.
    pub repository: PathBuf,
    /// The folder to name it by: the top of its working tree, or its git directory without one.
    pub folder: PathBuf,
    pub entries: Vec<Vec<String>>,
}

impl Fingerprint {
    /// Whether the repository's own settings start no program at all: no setting and no hook.
    pub fn is_empty(&self) -> bool {
        !self.entries.iter().any(|entry| entry.first().is_some_and(|tag| RUN.contains(&tag.as_str())))
    }

    /// The sha256 of the entries written as compact JSON, in hex.
    pub fn digest(&self) -> String {
        let written = serde_json::to_string(&self.entries).unwrap_or_default();
        hex(&Sha256::digest(written.as_bytes()))
    }

    /// Name what the settings start, the way a person reads them: each setting's key and each hook
    /// by name. Returns the names in order.
    pub fn named(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for entry in &self.entries {
            let name = match entry.first().map(String::as_str) {
                Some(SETTING) => entry.get(2).cloned(),
                Some(HOOK) => entry.get(1).map(|name| format!("the {name} hook")),
                _ => None,
            };
            if let Some(name) = name.filter(|name| !names.contains(name)) {
                names.push(name);
            }
        }
        names
    }
}

/// Read the fingerprint from git's listing of every setting with its scope (`git config --list
/// --show-scope -z`) and where the repository lies. Takes the listing, where the repository lies
/// and the environment. Returns the fingerprint, or why a hook file could not be read.
pub fn from_listing(listing: &[u8], found: &Found, environ: &Environment) -> Result<Fingerprint, String> {
    let listed = String::from_utf8_lossy(listing);
    let fields: Vec<&str> = listed.split('\0').collect();
    let mut entries: Vec<Vec<String>> = Vec::new();
    let mut hooks_setting: Option<(String, String)> = None;
    for pair in fields.chunks_exact(2) {
        let (scope, entry) = (pair[0], pair[1]);
        let Some((key, value)) = entry.split_once('\n') else { continue };
        if key.to_lowercase() == HOOKS_KEY && !value.is_empty() {
            hooks_setting = Some((scope.to_string(), value.to_string()));
        }
        let runs = rule_for(key).is_some_and(|rule| runs_a_program(rule, key, value, environ));
        if OWN_SCOPES.contains(&scope) && runs {
            entries.push(vec![SETTING.into(), scope.into(), key.into(), value.into()]);
        }
    }
    let named_by_a_setting = hooks_setting.is_some();
    let folder = own_hooks_folder(hooks_setting, found, environ);
    let budget = Cell::new(0);
    if let Some(folder) = &folder {
        let hooks = hook_files(folder, &budget, environ)?;
        if !hooks.is_empty() {
            entries.push(vec![HOOKS_FOLDER.into(), paths::real_path(folder).display().to_string()]);
            entries.extend(hooks);
        }
    }
    if let Some(top) = &found.top {
        let named = folder.as_deref().filter(|_| named_by_a_setting);
        entries.extend(tree_holding_the_hooks(named, top, &found.common_dir, &budget)?);
        entries.extend(manager_files(top, &budget)?);
    }
    entries.sort();
    entries.dedup();
    let folder = found.top.clone().unwrap_or_else(|| found.git_dir.clone());
    Ok(Fingerprint { repository: paths::real_path(&found.common_dir), folder, entries })
}

/// Whether a setting's value starts a program. Takes its rule, its key, its value and the
/// environment.
pub(super) fn runs_a_program(rule: &ExecKey, key: &str, value: &str, environ: &Environment) -> bool {
    let text = value.trim();
    let lowered = text.to_lowercase();
    match rule.runs {
        Runs::HooksDirectory => !text.is_empty(),
        Runs::EnablesTransport => !text.is_empty() && lowered != "never",
        Runs::UnlessBoolean => !BOOLEAN_WORDS.contains(&lowered.as_str()),
        Runs::AfterBang => text.starts_with('!'),
        Runs::ExtTransport => super::exec_keys::subsection(key).is_some_and(|sub| sub.to_lowercase().starts_with(EXT_PREFIX)),
        Runs::ExtAddress => lowered.starts_with(EXT_PREFIX),
        Runs::AbsolutePath => !text.is_empty() && Path::new(&paths::expand_user(text, environ)).is_absolute(),
        Runs::Command => !text.is_empty(),
    }
}

/// The hooks folder git runs hooks from when it is the repository's own: the folder its own
/// settings name, a relative folder the operator's settings name, or the default under the common
/// directory. Takes the last `core.hooksPath` with its scope, where the repository lies and the
/// environment. Returns it, or None when the operator's own folder is in force.
fn own_hooks_folder(setting: Option<(String, String)>, found: &Found, environ: &Environment) -> Option<PathBuf> {
    let Some((scope, value)) = setting else { return Some(found.common_dir.join("hooks")) };
    let expanded = PathBuf::from(paths::expand_user(&value, environ));
    if expanded.is_absolute() {
        return OWN_SCOPES.contains(&scope.as_str()).then_some(expanded);
    }
    let base = found.top.clone().unwrap_or_else(|| found.git_dir.clone());
    Some(paths::normalize(&base.join(expanded)))
}

/// List every file under a folder, links under it recorded as links and never followed. Takes the
/// folder and the count of files read. Returns what was read, or why a file could not be read.
fn walk(folder: &Path, budget: &Cell<usize>) -> Result<Vec<Read>, String> {
    let listing = match fs::read_dir(folder) {
        Ok(listing) => listing,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => return Ok(Vec::new()),
        Err(error) => return Err(format!("{} could not be read: {error}", folder.display())),
    };
    let mut names = Vec::new();
    for child in listing {
        names.push(child.map_err(|error| format!("{} could not be read: {error}", folder.display()))?.file_name());
    }
    names.sort_by(|one, other| one.as_bytes().cmp(other.as_bytes()));
    let mut found = Vec::new();
    for name in names {
        found.extend(read_path(&folder.join(&name), &name.to_string_lossy(), budget)?);
    }
    Ok(found)
}

/// Read one path: a link by its target and the sha256 of the file it points to, joined by a NUL, a
/// folder by every file under it, a file by its sha256.
/// Takes the path, its name relative to where the reading started and the count of files read.
/// Returns what was read, none for anything else, or why it could not be read.
fn read_path(path: &Path, rel: &str, budget: &Cell<usize>) -> Result<Vec<Read>, String> {
    let unreadable = |error: std::io::Error| format!("{} could not be read: {error}", path.display());
    let found = match fs::symlink_metadata(path) {
        Ok(found) => found,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(unreadable(error)),
    };
    if found.file_type().is_symlink() {
        count_one(budget, path)?;
        let target = fs::read_link(path).map_err(unreadable)?;
        let contents = match fs::metadata(path) {
            Ok(pointed) if pointed.is_file() => hex(&Sha256::digest(&fs::read(path).map_err(unreadable)?)),
            _ => NOT_A_FILE.to_string(),
        };
        return Ok(vec![(rel.to_string(), true, format!("{}\0{contents}", target.to_string_lossy()))]);
    }
    if found.is_dir() {
        return Ok(walk(path, budget)?.into_iter().map(|(inner, link, value)| (format!("{rel}/{inner}"), link, value)).collect());
    }
    if !found.is_file() {
        return Ok(Vec::new());
    }
    count_one(budget, path)?;
    let bytes = fs::read(path).map_err(unreadable)?;
    Ok(vec![(rel.to_string(), false, hex(&Sha256::digest(&bytes)))])
}

fn count_one(budget: &Cell<usize>, path: &Path) -> Result<(), String> {
    budget.set(budget.get() + 1);
    if budget.get() > MOST_FILES {
        return Err(format!("more than {MOST_FILES} files lie around {}", path.display()));
    }
    Ok(())
}

/// List every file under a hooks folder: each path with the sha256 of its contents or a link's
/// target, the example files git writes and the hooks saw installs left out. Takes the folder, the
/// count of files read and the environment. Returns the entries, or why a file could not be read.
fn hook_files(folder: &Path, budget: &Cell<usize>, environ: &Environment) -> Result<Vec<Vec<String>>, String> {
    let mut found = Vec::new();
    for (rel, link, value) in walk(folder, budget)? {
        if !rel.contains('/') && rel.ends_with(NEVER_RUN_SUFFIX) {
            continue;
        }
        if !link && saws_own_hook(Path::new(&rel), environ).is_some_and(|own| hex(&Sha256::digest(&own)) == value) {
            continue;
        }
        found.push(vec![if link { HOOK_LINK } else { HOOK }.into(), rel, value]);
    }
    Ok(found)
}

/// List every file under the working tree's top folder that holds the hooks folder `core.hooksPath`
/// names, when it lies inside the working tree and outside the git directory. Takes that hooks
/// folder (None when no setting names one), the top of the working tree, the common directory and
/// the count of files read. Returns the entries, or why they could not be read.
fn tree_holding_the_hooks(folder: Option<&Path>, top: &Path, common_dir: &Path, budget: &Cell<usize>) -> Result<Vec<Vec<String>>, String> {
    let Some(folder) = folder.filter(|folder| !paths::real_path(folder).starts_with(paths::real_path(common_dir))) else {
        return Ok(Vec::new());
    };
    let Ok(inside) = paths::real_path(folder).strip_prefix(paths::real_path(top)).map(Path::to_path_buf) else { return Ok(Vec::new()) };
    let Some(first) = inside.components().next() else {
        return Err(format!("the hooks folder is the whole working tree of {}", top.display()));
    };
    let first = first.as_os_str().to_string_lossy().into_owned();
    Ok(walk(&top.join(&first), budget)?
        .into_iter()
        .map(|(rel, link, value)| vec![if link { TREE_LINK } else { TREE }.into(), format!("{first}/{rel}"), value])
        .collect())
}

/// List the hook managers' own files in a working tree, each pattern no file matches recorded as
/// absent, and package.json when it holds a key a hook manager reads. Takes the top of the working
/// tree and the count of files read. Returns the entries, or why a file could not be read.
fn manager_files(top: &Path, budget: &Cell<usize>) -> Result<Vec<Vec<String>>, String> {
    let managers = hook_managers();
    let mut found = Vec::new();
    for pattern in &managers.files {
        let matched = matching(top, pattern, budget)?;
        if matched.is_empty() {
            found.push(vec![ABSENT.into(), pattern.clone()]);
        }
        found.extend(matched.into_iter().map(|(rel, link, value)| vec![if link { MANAGER_LINK } else { MANAGER }.into(), rel, value]));
    }
    let package = top.join(PACKAGE);
    let contents = match fs::read(&package) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            found.push(vec![ABSENT.into(), PACKAGE.into()]);
            return Ok(found);
        }
        Err(error) => return Err(format!("{} could not be read: {error}", package.display())),
    };
    let keys: Option<serde_json::Value> = serde_json::from_slice(&contents).ok();
    let without_keys = keys.as_ref().and_then(serde_json::Value::as_object)
        .is_some_and(|object| !managers.package_keys.iter().any(|key| object.contains_key(key)));
    found.push(match without_keys {
        true => vec![ABSENT.into(), PACKAGE.into()],
        false => vec![MANAGER.into(), PACKAGE.into(), hex(&Sha256::digest(&contents))],
    });
    Ok(found)
}

/// List the files a hook manager pattern matches in a working tree, a matched folder by every file
/// under it. Takes the top of the working tree, the pattern and the count of files read. Returns
/// what was read, each path relative to the top, or why a file could not be read.
fn matching(top: &Path, pattern: &str, budget: &Cell<usize>) -> Result<Vec<Read>, String> {
    let named_up_to = pattern.find('*').map_or(pattern, |star| &pattern[..star]);
    let base = named_up_to.rfind('/').map_or("", |slash| &named_up_to[..slash]);
    let wanted = if base.is_empty() { pattern } else { &pattern[base.len() + 1..] };
    let folder = if base.is_empty() { top.to_path_buf() } else { top.join(base) };
    let listing = match fs::read_dir(&folder) {
        Ok(listing) => listing,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => return Ok(Vec::new()),
        Err(error) => return Err(format!("{} could not be read: {error}", folder.display())),
    };
    let mut names = Vec::new();
    for child in listing {
        names.push(child.map_err(|error| format!("{} could not be read: {error}", folder.display()))?.file_name());
    }
    names.sort_by(|one, other| one.as_bytes().cmp(other.as_bytes()));
    let mut found = Vec::new();
    for name in names {
        let shown = name.to_string_lossy().into_owned();
        if glob_matches(wanted, &shown) {
            let rel = if base.is_empty() { shown } else { format!("{base}/{shown}") };
            found.extend(read_path(&folder.join(&name), &rel, budget)?);
        }
    }
    Ok(found)
}

/// Whether a name matches a pattern whose only wildcard is `*`, letters compared without regard to
/// ASCII case. Takes the pattern and the name.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.to_ascii_lowercase(), name.to_ascii_lowercase());
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !name.starts_with(first) || !name.ends_with(last) || name.len() < first.len() + last.len() {
        return false;
    }
    let end = name.len() - last.len();
    let mut at = first.len();
    for middle in &parts[1..parts.len() - 1] {
        match name.get(at..end).and_then(|rest| rest.find(middle)) {
            Some(found) => at += found + middle.len(),
            None => return false,
        }
    }
    true
}

/// Read the hook saw installs at a path in its own template. Takes the path relative to the hooks
/// folder and the environment. Returns its bytes, or None.
pub fn saws_own_hook(rel: &Path, environ: &Environment) -> Option<Vec<u8>> {
    let config = match environ.get("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        Some(config) => PathBuf::from(config),
        None => Path::new(environ.get("HOME")?).join(".config"),
    };
    let folder = table("saws_own_hooks_folder").iter().fold(config, |path, part| path.join(part));
    let path = folder.join(rel);
    fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_file()).then(|| fs::read(&path).ok()).flatten()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
