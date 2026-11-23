//! Locates saw's own stores.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::env::{Environment, SAW_ADVISORY_CACHE_DIR, XDG_CACHE_HOME};

const LAUNCHD_LABEL: &str = "com.ndevu.saw.watch";
const SYSTEMD_UNIT: &str = "saw-watch.service";
const WINDOWS_TASK: &str = "saw-watch";

/// Where each of saw's stores is, for one environment.
#[derive(Debug, Clone, Copy)]
pub struct Stores<'a> {
    env: &'a Environment,
}

fn tidy(path: PathBuf) -> PathBuf {
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

fn key_of(path: &Path) -> String {
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

fn normalized(path: &Path) -> PathBuf {
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

impl<'a> Stores<'a> {
    /// Make the registry for an environment. Takes the environment. Returns the registry.
    pub fn new(env: &'a Environment) -> Self {
        Stores { env }
    }

    fn config(&self, name: &str) -> PathBuf {
        tidy(self.env.xdg_config_home().join("saw").join(name))
    }

    fn cache(&self, name: &str) -> PathBuf {
        tidy(self.env.xdg_cache_home().join("saw").join(name))
    }

    fn state(&self, name: &str) -> PathBuf {
        tidy(self.env.xdg_state_home().join("saw").join(name))
    }

    /// Return the folder git copies new repositories' hooks from.
    pub fn git_template(&self) -> PathBuf {
        self.config("git-template")
    }

    /// Return the folder of the hooks saw installs.
    pub fn hooks(&self) -> PathBuf {
        self.git_template().join("hooks")
    }

    /// Return the record of how saw's hooks were installed.
    pub fn hook_install(&self) -> PathBuf {
        self.config("hook-install.json")
    }

    /// Return the record of histories the hooks checked.
    pub fn hook_history_checked(&self) -> PathBuf {
        self.cache("hook-history-checked.json")
    }

    /// Return the record of settings the hooks scanned.
    pub fn hook_settings_scans(&self) -> PathBuf {
        self.cache("hook-settings-scans.json")
    }

    /// Return the record of warnings the hooks showed.
    pub fn hook_warnings_shown(&self) -> PathBuf {
        self.cache("hook-warnings-shown.json")
    }

    /// Return the record of checks the hooks made.
    pub fn hook_checks_made(&self) -> PathBuf {
        self.cache("hook-checks-made.json")
    }

    /// Return the hooks' scan cache.
    pub fn hook_scan_cache(&self) -> PathBuf {
        self.cache("hook-scan-cache.json")
    }

    /// Return the record of trees `saw govern` applied.
    pub fn govern_applied(&self) -> PathBuf {
        self.cache("govern-applied.json")
    }

    /// Return the record of held trees the user let in.
    pub fn govern_accepted(&self) -> PathBuf {
        self.cache("govern-accepted.json")
    }

    /// Return the folder of working trees' clean contents.
    pub fn clean_contents_folder(&self) -> PathBuf {
        self.cache("hook-clean-contents")
    }

    /// Return the file of one working tree's clean contents. Takes the tree's root.
    pub fn clean_contents(&self, root: &Path) -> PathBuf {
        self.clean_contents_folder().join(format!("{}.json", key_of(&real_path(root))))
    }

    /// Return the push record of one repository. Takes its git folder.
    pub fn push_record(&self, git_dir: &Path) -> PathBuf {
        self.cache("push-record").join(format!("{}.json", key_of(&real_path(git_dir))))
    }

    /// Return the folder hooks are set aside in.
    pub fn set_aside_hooks(&self) -> PathBuf {
        self.state("set-aside").join("hooks")
    }

    /// Return the record of how `saw watch` was installed.
    pub fn watch_install(&self) -> PathBuf {
        self.state("watch-install.json")
    }

    /// Return the record of code seen running.
    pub fn live_code(&self) -> PathBuf {
        self.state("live-code.json")
    }

    /// Return the record of agent approvals.
    pub fn agent_approvals(&self) -> PathBuf {
        self.state("agent-approvals.json")
    }

    /// Return the record of editor changes `saw harden` made.
    pub fn editor_changes(&self) -> PathBuf {
        self.state("editor-changes.json")
    }

    /// Return the folder of captured processes.
    pub fn captured(&self) -> PathBuf {
        self.state("captured")
    }

    /// Return the folder of `saw govern`'s status records.
    pub fn govern_status(&self) -> PathBuf {
        self.state("govern").join("status")
    }

    /// Return the autorun baseline.
    pub fn autorun_baseline(&self) -> PathBuf {
        self.env.autorun_baseline_path().unwrap_or_else(|| self.state("autorun-baseline.json"))
    }

    /// Return the folder of one repository's amend runs. Takes the repository's slug.
    pub fn amend_state(&self, slug: &str) -> PathBuf {
        let safe: String = slug.chars().map(|c| if c.is_alphanumeric() || "-._".contains(c) { c } else { '-' }).collect();
        self.state("amend").join(if safe.is_empty() { "repository".to_string() } else { safe })
    }

    /// Return the folder of the advisory database.
    pub fn advisories(&self) -> PathBuf {
        if let Some(given) = self.env.get(SAW_ADVISORY_CACHE_DIR) {
            return tidy(self.expand_user(&given));
        }
        let base = self.env.get(XDG_CACHE_HOME).map(PathBuf::from).unwrap_or_else(|| self.env.home().join(".cache"));
        tidy(base.join("saw").join("advisories"))
    }

    /// Return the GitHub App sign-in file.
    pub fn github_app(&self) -> PathBuf {
        tidy(self.raw_config_home().join("saw").join("github-app.json"))
    }

    /// Return the GitHub App sign-in file's earlier place.
    pub fn github_app_earlier(&self) -> PathBuf {
        tidy(self.raw_config_home().join("stayawake").join("github-app.json"))
    }

    /// Return the file that keeps `saw watch` scheduled on this system.
    pub fn watch_schedule(&self) -> PathBuf {
        let home = self.env.home();
        if cfg!(target_os = "linux") {
            home.join(".config").join("systemd").join("user").join(SYSTEMD_UNIT)
        } else if cfg!(windows) {
            home.join("AppData").join("Local").join("saw").join(format!("{WINDOWS_TASK}.xml"))
        } else {
            home.join("Library").join("LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist"))
        }
    }

    /// Return the folder `saw watch` and the user's own commands share. Takes the home of the
    /// account saw acts for.
    pub fn watch_shared(&self, acting_home: &Path) -> PathBuf {
        acting_home.join(".local").join("state").join("saw")
    }

    fn raw_config_home(&self) -> PathBuf {
        match self.env.variables().get("XDG_CONFIG_HOME") {
            Some(raw) if !raw.is_empty() => PathBuf::from(raw),
            _ => self.env.home().join(".config"),
        }
    }

    fn expand_user(&self, given: &str) -> PathBuf {
        let Some(rest) = given.strip_prefix('~') else { return PathBuf::from(given) };
        let (user, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let home = if user.is_empty() { Some(self.env.home()) } else { crate::account::home_of_user(user) };
        match home {
            Some(home) if tail.is_empty() => home,
            Some(home) => home.join(tail),
            None => PathBuf::from(given),
        }
    }
}
