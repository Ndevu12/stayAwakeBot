//! Whether a git command's repository plainly starts no program of its own, read from its files
//! without running git: a `.git` folder at or above the folder, its own settings file naming no
//! program and no other settings file, no hook file but the examples git writes and the hooks saw
//! installs, and settings of the operator's that name no hooks folder and no other settings file.
//! Anything it cannot read plainly is not vouched for.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::exec_keys::rule_for;
use super::settings_fingerprint::{runs_a_program, saws_own_hook};
use super::{command_line, paths, surface, typed_command, Environment};

const HOOKS_KEY: &str = "core.hookspath";
const NEVER_RUN_SUFFIX: &str = ".sample";
const SETTINGS_LIMIT: u64 = 1 << 16;
const NAMES_A_REPOSITORY: [&str; 9] = ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS"];
const GIVES_SETTINGS_PREFIXES: [&str; 3] = ["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"];
const OPERATOR_WORDS: [&str; 2] = ["hookspath", "include"];

/// Say whether a git command's repository plainly starts no program of its own. Takes the
/// operator's git, the folder the command runs in, the arguments without the program name and the
/// environment. Returns the answer, read from its files.
pub fn starts_no_program(git: &Path, folder: &Path, args: &[String], environ: &Environment) -> bool {
    if environ.keys().any(|name| NAMES_A_REPOSITORY.contains(&name.as_str()) || GIVES_SETTINGS_PREFIXES.iter().any(|prefix| name.starts_with(prefix))) {
        return false;
    }
    let located = command_line::read(args, folder, &|_, _| None);
    let Ok(command) = typed_command::read(args, environ) else { return false };
    if !located.readable || command.names_its_repository() || !command.settings.is_empty() {
        return false;
    }
    let place = located.folder.clone().unwrap_or_else(|| folder.to_path_buf());
    operator_names_nothing(git, environ) && match git_folder(&paths::real_path(&place)) {
        Some(Some(git_dir)) => own_settings_name_nothing(&git_dir, environ) && only_known_hooks(&git_dir.join("hooks"), environ),
        Some(None) => true,
        None => false,
    }
}

/// Find the `.git` folder of the repository at or above a folder. Takes the folder, every link
/// resolved. Returns it, Some(None) with no repository, or None for a repository it cannot read
/// plainly.
fn git_folder(start: &Path) -> Option<Option<PathBuf>> {
    for at in start.ancestors() {
        let dot_git = at.join(".git");
        if paths::lexists(&dot_git) {
            let plain = fs::symlink_metadata(&dot_git).is_ok_and(|found| found.is_dir());
            let shared = paths::lexists(&dot_git.join("commondir")) || paths::lexists(&dot_git.join("config.worktree"));
            return (plain && !shared).then_some(Some(dot_git));
        }
        if surface::is_git_directory(at) {
            return None;
        }
    }
    Some(None)
}

/// Whether the operator's own settings files name no hooks folder and no other settings file.
/// Takes the operator's git and the environment.
fn operator_names_nothing(git: &Path, environ: &Environment) -> bool {
    let home = environ.get("HOME").map(PathBuf::from);
    let config_home = environ.get("XDG_CONFIG_HOME").filter(|value| !value.is_empty()).map(PathBuf::from)
        .or_else(|| home.as_ref().map(|home| home.join(".config")));
    let mut files: Vec<PathBuf> = Vec::new();
    match environ.get("GIT_CONFIG_GLOBAL") {
        Some(global) => files.push(PathBuf::from(global)),
        None => files.extend(home.map(|home| home.join(".gitconfig")).into_iter().chain(config_home.map(|config| config.join("git").join("config")))),
    }
    let no_system = environ.get("GIT_CONFIG_NOSYSTEM").is_some_and(|value| !matches!(value.to_lowercase().as_str(), "" | "0" | "false" | "no" | "off"));
    match environ.get("GIT_CONFIG_SYSTEM") {
        Some(system) => files.push(PathBuf::from(system)),
        None if !no_system => {
            files.push(PathBuf::from("/etc/gitconfig"));
            if let Some(prefix) = paths::real_path(git).parent().and_then(Path::parent) {
                files.push(prefix.join("etc").join("gitconfig"));
            }
        }
        None => {}
    }
    files.iter().all(|file| match settings_text(file) {
        Ok(text) => text.is_none_or(|text| !OPERATOR_WORDS.iter().any(|word| text.to_lowercase().contains(word))),
        Err(()) => false,
    })
}

/// Whether a repository's own settings file plainly names no program and no other settings file.
/// Takes its `.git` folder and the environment.
fn own_settings_name_nothing(git_dir: &Path, environ: &Environment) -> bool {
    let Ok(Some(text)) = settings_text(&git_dir.join("config")) else { return false };
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.ends_with('\\') {
            return false;
        }
        if let Some(header) = line.strip_prefix('[') {
            match section_named(header) {
                Some(named) => section = named,
                None => return false,
            }
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((key, value)) => (key.trim(), Some(value.trim())),
            None => (line, None),
        };
        let plain_key = !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if section.is_empty() || !plain_key || value.is_some_and(|value| value.contains(['"', '#', ';', '\\'])) {
            return false;
        }
        let listed = format!("{section}.{}", key.to_ascii_lowercase());
        if listed == HOOKS_KEY {
            return false;
        }
        if let (Some(rule), Some(value)) = (rule_for(&listed), value) {
            if runs_a_program(rule, &listed, value, environ) {
                return false;
            }
        }
    }
    true
}

/// Read a section header the way git lists its section: `[name]` or `[name "subsection"]`. Takes
/// the header after its `[`. Returns the section, or None for one naming another settings file or
/// one it cannot read plainly.
fn section_named(header: &str) -> Option<String> {
    let header = header.strip_suffix(']')?;
    let (name, subsection) = match header.split_once(' ') {
        None => (header, None),
        Some((name, rest)) => {
            let inner = rest.trim().strip_prefix('"')?.strip_suffix('"')?;
            if inner.contains(['"', '\\']) {
                return None;
            }
            (name, Some(inner))
        }
    };
    let lowered = name.to_ascii_lowercase();
    let plain = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !plain || lowered == "include" || lowered == "includeif" {
        return None;
    }
    Some(match subsection {
        Some(subsection) => format!("{lowered}.{subsection}"),
        None => lowered,
    })
}

/// Whether a hooks folder holds nothing but the examples git writes and the hooks saw installs.
/// Takes the folder and the environment.
fn only_known_hooks(folder: &Path, environ: &Environment) -> bool {
    let listing = match fs::read_dir(folder) {
        Ok(listing) => listing,
        Err(error) => return error.kind() == ErrorKind::NotFound,
    };
    listing.into_iter().all(|child| {
        let Ok(child) = child else { return false };
        let name = child.file_name();
        if name.to_string_lossy().ends_with(NEVER_RUN_SUFFIX) {
            return true;
        }
        let path = child.path();
        fs::metadata(&path).is_ok_and(|found| found.is_file())
            && saws_own_hook(&name, environ).is_some_and(|own| fs::read(&path).is_ok_and(|bytes| bytes == own))
    })
}

/// Read a settings file of a plain size. Takes its path. Returns its text, None for a missing file,
/// or an error.
fn settings_text(file: &Path) -> Result<Option<String>, ()> {
    match fs::metadata(file) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Ok(found) if found.is_file() && found.len() <= SETTINGS_LIMIT => fs::read_to_string(file).map(Some).map_err(|_| ()),
        _ => Err(()),
    }
}
