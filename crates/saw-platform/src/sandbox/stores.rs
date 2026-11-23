//! Locates saw's own stores.

use std::path::{Path, PathBuf};

use crate::env::{Environment, SAW_ADVISORY_CACHE_DIR, XDG_CACHE_HOME};
use crate::sandbox::paths::{expand_user, key_of, real_path, tidy};

const LAUNCHD_LABEL: &str = "com.ndevu.saw.watch";
const SYSTEMD_UNIT: &str = "saw-watch.service";
const WINDOWS_TASK: &str = "saw-watch";

/// Where each of saw's stores is, for one environment.
#[derive(Debug, Clone, Copy)]
pub struct Stores<'a> {
    env: &'a Environment,
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
            return tidy(expand_user(&given, &self.env.home()));
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
}
