//! Reads the environment variables saw uses.

use std::collections::BTreeMap;
use std::path::PathBuf;

pub const GH_SECURITY_TOKEN: &str = "GH_SECURITY_TOKEN";
pub const GITHUB_TOKEN: &str = "GITHUB_TOKEN";
pub const GITHUB_REPOSITORY: &str = "GITHUB_REPOSITORY";
pub const SLACK_WEBHOOK_URL: &str = "SLACK_WEBHOOK_URL";
pub const STAYAWAKE_REPORTS_DIR: &str = "STAYAWAKE_REPORTS_DIR";
pub const SAW_ADVISORY_CACHE_DIR: &str = "SAW_ADVISORY_CACHE_DIR";
pub const XDG_CACHE_HOME: &str = "XDG_CACHE_HOME";
pub const XDG_CONFIG_HOME: &str = "XDG_CONFIG_HOME";
pub const XDG_STATE_HOME: &str = "XDG_STATE_HOME";
pub const SAW_AUTORUN_BASELINE: &str = "SAW_AUTORUN_BASELINE";
pub const SAW_HOOK_DISABLED: &str = "SAW_HOOK_DISABLED";
pub const SAW_GOVERN_SYSTEM: &str = "SAW_GOVERN_SYSTEM";
pub const SAW_GOVERN_HOLDING: &str = "SAW_GOVERN_HOLDING";
pub const GOVERN_ACTIVATION: &[&str] = &[SAW_GOVERN_SYSTEM, SAW_GOVERN_HOLDING];
pub const SAW_HOOK_TIMEOUT: &str = "SAW_HOOK_TIMEOUT";
pub const NO_COLOR: &str = "NO_COLOR";
pub const CLICOLOR_FORCE: &str = "CLICOLOR_FORCE";
pub const CI: &str = "CI";
pub const GITHUB_ACTIONS: &str = "GITHUB_ACTIONS";
pub const GITLAB_CI: &str = "GITLAB_CI";
pub const CIRCLECI: &str = "CIRCLECI";
pub const BUILDKITE: &str = "BUILDKITE";
pub const RUNNER_OS: &str = "RUNNER_OS";
pub const TERM: &str = "TERM";
pub const COLORTERM: &str = "COLORTERM";
pub const PAGER: &str = "PAGER";
pub const NO_STREAM: &[&str] = &["STAYAWAKE_NO_STREAM", "NO_STREAM"];
pub const STREAM: &str = "STAYAWAKE_STREAM";

const RUNNER_MARKERS: &[&str] = &[GITHUB_ACTIONS, GITLAB_CI, CIRCLECI, BUILDKITE, RUNNER_OS];

/// The environment saw reads, held as a snapshot.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    variables: BTreeMap<String, String>,
}

fn is_python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn truthy(value: Option<&str>) -> bool {
    !matches!(value.unwrap_or("").to_lowercase().as_str(), "" | "0" | "false" | "no" | "off")
}

/// Read a whole number as Python's `int` reads one that fits an account id. Takes the text.
/// Returns the number, or none.
pub fn python_int(text: &str) -> Option<u32> {
    let trimmed = text.trim_matches(is_python_space);
    let digits = trimmed.strip_prefix('+').unwrap_or(trimmed);
    let bytes = digits.as_bytes();
    if bytes.is_empty() || bytes[0] == b'_' || bytes[bytes.len() - 1] == b'_' || digits.contains("__") {
        return None;
    }
    if !digits.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return None;
    }
    digits.replace('_', "").parse::<u32>().ok()
}

/// Read a number as Python's `float` reads it. Takes the text. Returns the number, or none.
pub fn python_float(text: &str) -> Option<f64> {
    let trimmed = text.trim_matches(is_python_space);
    let bytes = trimmed.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'_' {
            let digit_before = index > 0 && bytes[index - 1].is_ascii_digit();
            let digit_after = bytes.get(index + 1).is_some_and(u8::is_ascii_digit);
            if !(digit_before && digit_after) {
                return None;
            }
        }
    }
    trimmed.replace('_', "").parse::<f64>().ok()
}

impl Environment {
    /// Take a snapshot of this process's environment. Returns it.
    pub fn from_process() -> Environment {
        Environment { variables: std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect() }
    }

    /// Make an environment from given variables. Takes them. Returns the environment.
    pub fn from_variables(variables: BTreeMap<String, String>) -> Environment {
        Environment { variables }
    }

    /// Return every variable, as given.
    pub fn variables(&self) -> &BTreeMap<String, String> {
        &self.variables
    }

    /// Read one variable, trimmed. Takes its name. Returns the value, or none when it is unset or blank.
    pub fn get(&self, name: &str) -> Option<String> {
        let value = self.variables.get(name)?.trim_matches(is_python_space);
        (!value.is_empty()).then(|| value.to_string())
    }

    /// Tell whether any of the variables holds a value. Takes their names. Returns the answer.
    pub fn any_set(&self, names: &[&str]) -> bool {
        names.iter().any(|name| self.get(name).is_some())
    }

    /// Return the home folder as Python's `expanduser("~")` finds it.
    pub fn home(&self) -> PathBuf {
        home_of(&self.variables)
    }

    /// Tell whether this is an ephemeral CI runner. Returns the answer.
    pub fn is_ephemeral_runner(&self) -> bool {
        self.any_set(RUNNER_MARKERS) && !self.has_persistent_home()
    }

    fn has_persistent_home(&self) -> bool {
        let home = self.get("HOME").map(PathBuf::from).unwrap_or_else(|| self.home());
        let Ok(entries) = std::fs::read_dir(home.join(".ssh")) else { return false };
        entries.flatten().any(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.starts_with("id_") && !name.ends_with(".pub")
        })
    }

    /// Return the GitHub token, or none.
    pub fn github_token(&self) -> Option<String> {
        self.get(GITHUB_TOKEN)
    }

    /// Return the GitHub repository variable, or none.
    pub fn github_repository(&self) -> Option<String> {
        self.get(GITHUB_REPOSITORY)
    }

    /// Return the owner and name in the GitHub repository variable, or none when it is unset or
    /// malformed.
    pub fn github_slug(&self) -> Option<(String, String)> {
        let repository = self.github_repository()?;
        let (owner, name) = repository.split_once('/')?;
        (!owner.is_empty() && !name.is_empty()).then(|| (owner.to_string(), name.to_string()))
    }

    /// Return the Slack webhook, or none.
    pub fn slack_webhook(&self) -> Option<String> {
        self.get(SLACK_WEBHOOK_URL)
    }

    /// Tell whether colour is switched off.
    pub fn no_color(&self) -> bool {
        self.get(NO_COLOR).is_some()
    }

    /// Tell whether colour is forced on.
    pub fn clicolor_force(&self) -> bool {
        truthy(self.get(CLICOLOR_FORCE).as_deref())
    }

    /// Tell whether this runs under CI.
    pub fn is_ci(&self) -> bool {
        truthy(self.get(CI).as_deref())
    }

    /// Tell whether live output was asked off.
    pub fn stream_disabled(&self) -> bool {
        self.any_set(NO_STREAM)
    }

    /// Tell whether live output was asked for.
    pub fn stream_forced(&self) -> bool {
        truthy(self.get(STREAM).as_deref())
    }

    /// Tell whether saw's git hooks are switched off.
    pub fn hook_disabled(&self) -> bool {
        truthy(self.get(SAW_HOOK_DISABLED).as_deref())
    }

    /// Return the time a hook scan may take, in seconds. Takes the hook event. Returns zero for no
    /// limit.
    pub fn hook_timeout(&self, event: Option<&str>) -> f64 {
        let default = if event == Some("pre-push") { 20.0 } else { 60.0 };
        let Some(raw) = self.get(SAW_HOOK_TIMEOUT) else { return default };
        match python_float(&raw) {
            Some(value) if value > 0.0 => value,
            Some(_) => 0.0,
            None => default,
        }
    }

    /// Return the configuration folder base.
    pub fn xdg_config_home(&self) -> PathBuf {
        self.get(XDG_CONFIG_HOME).map(PathBuf::from).unwrap_or_else(|| self.home().join(".config"))
    }

    /// Return the cache folder base.
    pub fn xdg_cache_home(&self) -> PathBuf {
        self.get(XDG_CACHE_HOME).map(PathBuf::from).unwrap_or_else(|| self.home().join(".cache"))
    }

    /// Return the state folder base.
    pub fn xdg_state_home(&self) -> PathBuf {
        self.get(XDG_STATE_HOME).map(PathBuf::from).unwrap_or_else(|| self.home().join(".local").join("state"))
    }

    /// Return the autorun baseline file given in the environment, or none.
    pub fn autorun_baseline_path(&self) -> Option<PathBuf> {
        self.get(SAW_AUTORUN_BASELINE).map(PathBuf::from)
    }
}

#[cfg(unix)]
fn home_of(variables: &BTreeMap<String, String>) -> PathBuf {
    let home = match variables.get("HOME") {
        Some(home) => home.clone(),
        None => crate::account::home_folder().map(|p| p.display().to_string()).unwrap_or_else(|| "~".into()),
    };
    let trimmed = home.trim_end_matches('/');
    PathBuf::from(if trimmed.is_empty() { "/" } else { trimmed })
}

#[cfg(windows)]
fn home_of(variables: &BTreeMap<String, String>) -> PathBuf {
    if let Some(profile) = variables.get("USERPROFILE") {
        return PathBuf::from(profile);
    }
    match (variables.get("HOMEDRIVE"), variables.get("HOMEPATH")) {
        (drive, Some(path)) => PathBuf::from(format!("{}{}", drive.map(String::as_str).unwrap_or(""), path)),
        _ => PathBuf::from("~"),
    }
}

#[cfg(not(any(unix, windows)))]
fn home_of(_variables: &BTreeMap<String, String>) -> PathBuf {
    PathBuf::from("~")
}
