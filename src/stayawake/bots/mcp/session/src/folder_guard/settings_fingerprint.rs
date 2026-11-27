//! The fingerprint of the programs a repository's own git settings start: every setting in its own
//! configuration that `lib/data/git_exec_keys.json` lists as running a program, and every hook file
//! in the hooks folder git runs hooks from when that folder is the repository's own. saw's Python
//! `lib/git/settings_fingerprint.py` reads the same fingerprint. Nothing in the folder is run.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::exec_keys::{rule_for, ExecKey, Runs};
use super::locate::Found;
use super::paths;
use super::Environment;

const OWN_SCOPES: [&str; 2] = ["local", "worktree"];
const HOOKS_KEY: &str = "core.hookspath";
const NEVER_RUN_SUFFIX: &str = ".sample";
const BOOLEAN_WORDS: [&str; 9] = ["true", "false", "yes", "no", "on", "off", "1", "0", ""];
const EXT_PREFIX: &str = "ext::";
const SETTING: &str = "setting";
const HOOKS_FOLDER: &str = "hooks";
const HOOK: &str = "hook";

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
    /// Whether the repository's own settings start no program at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
    if let Some(folder) = own_hooks_folder(hooks_setting, found, environ) {
        let hooks = hook_files(&folder)?;
        if !hooks.is_empty() {
            entries.push(vec![HOOKS_FOLDER.into(), paths::real_path(&folder).display().to_string()]);
            entries.extend(hooks);
        }
    }
    entries.sort();
    let folder = found.top.clone().unwrap_or_else(|| found.git_dir.clone());
    Ok(Fingerprint { repository: paths::real_path(&found.common_dir), folder, entries })
}

/// Whether a setting's value starts a program. Takes its rule, its key, its value and the
/// environment.
fn runs_a_program(rule: &ExecKey, key: &str, value: &str, environ: &Environment) -> bool {
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

/// List every file in a hooks folder git may run or a hook may read: each name with the sha256 of
/// its contents, links followed, the example files git writes left out. Takes the folder. Returns
/// the entries, or why a file could not be read.
fn hook_files(folder: &Path) -> Result<Vec<Vec<String>>, String> {
    let listing = match fs::read_dir(folder) {
        Ok(listing) => listing,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => return Ok(Vec::new()),
        Err(error) => return Err(format!("the hooks folder {} could not be read: {error}", folder.display())),
    };
    let mut found = Vec::new();
    for child in listing {
        let child = child.map_err(|error| format!("the hooks folder {} could not be read: {error}", folder.display()))?;
        let name = child.file_name().to_string_lossy().into_owned();
        let path: PathBuf = child.path();
        if name.ends_with(NEVER_RUN_SUFFIX) || !fs::metadata(&path).is_ok_and(|meta| meta.is_file()) {
            continue;
        }
        let bytes = fs::read(&path).map_err(|error| format!("the hook {} could not be read: {error}", path.display()))?;
        found.push(vec![HOOK.into(), name, hex(&Sha256::digest(&bytes))]);
    }
    Ok(found)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
