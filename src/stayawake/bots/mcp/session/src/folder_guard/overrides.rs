//! Decides every setting and environment variable a command runs with to keep each program the
//! folder's own settings name from starting, the same way saw's `folder_guard` decides them.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::exec_keys::{always_set, exec_keys, rule_for, subsection, ExecKey, Runs};
use super::paths;
use super::surface::Found;
use super::Environment;

pub const VALUE_VARIABLE_PREFIX: &str = "SAW_GUARD_VALUE_";
const ALLOWED_PROTOCOLS: &str = "GIT_ALLOW_PROTOCOL";
const UNREADABLE: char = '\u{FFFD}';

/// The settings in order and the environment variables in order.
pub type Decided = (Vec<(String, String)>, Vec<(String, String)>);

/// Decide every setting and environment variable the command runs with. Takes the folder's
/// program-running entries, the operator's own entries, saw's empty hooks folder and the
/// environment. Returns them, or the reason the command may not run.
pub fn decide(commands: &[Found], operator: &[(String, Option<String>)], hooks: &Path, environ: &Environment) -> Result<Decided, String> {
    let own: HashMap<&str, &str> = operator.iter().map(|(key, value)| (key.as_str(), value.as_deref().unwrap_or("true"))).collect();
    let mut settings: Vec<(String, String)> = Vec::new();
    let mut environment: Vec<(String, String)> = Vec::new();
    let mut cleared: HashSet<String> = HashSet::new();
    for rule in exec_keys() {
        match rule.runs {
            Runs::HooksDirectory => settings.push((rule.key.clone(), hooks_path(own.get(rule.key.as_str()).copied(), hooks, environ))),
            Runs::EnablesTransport => settings.push(instead(rule, &rule.key)),
            _ => {}
        }
    }
    settings.extend(always_set().iter().cloned());
    for Found { rule, key } in commands {
        if matches!(rule.runs, Runs::HooksDirectory | Runs::EnablesTransport) {
            continue;
        }
        if key.contains(UNREADABLE) {
            return Err("a setting in this folder has a name that is not valid text".to_string());
        }
        let replaced_by = &rule.replaced_by;
        if replaced_by.refuse {
            return Err(format!("this folder's settings name a program in {key} that cannot be kept from running"));
        }
        if let Some(variable) = &replaced_by.environment {
            if environ.contains_key(variable) {
                continue;
            }
            if operator.iter().any(|(own_key, _)| rule.matches(own_key)) {
                return Err(format!("both your settings and this folder's set {key}"));
            }
            set(&mut environment, variable, &replaced_by.value);
        } else if let Some(reset) = &replaced_by.reset {
            if cleared.insert(reset.clone()) {
                settings.push((reset.clone(), String::new()));
                for (own_key, value) in operator {
                    if let Some(value) = value.as_ref().filter(|_| same_list(own_key, reset)) {
                        settings.push((own_key.clone(), value.clone()));
                    }
                }
            }
        } else if replaced_by.setting.is_some() {
            settings.push(instead(rule, key));
        } else {
            let value = own.get(key.as_str()).map(|value| value.to_string()).unwrap_or_else(|| runs_nothing(rule).to_string());
            settings.push((key.clone(), value));
        }
    }
    if let Some((name, value)) = protocols_left(&settings, environ) {
        set(&mut environment, &name, &value);
    }
    Ok((once(settings), environment))
}

/// Set a variable in an ordered environment, keeping its place when it is already there.
pub fn set(environment: &mut Vec<(String, String)>, name: &str, value: &str) {
    match environment.iter_mut().find(|(each, _)| each == name) {
        Some(found) => found.1 = value.to_string(),
        None => environment.push((name.to_string(), value.to_string())),
    }
}

/// The folder git runs hooks from: the operator's own, when it names an absolute folder, else
/// saw's empty one.
fn hooks_path(own: Option<&str>, hooks: &Path, environ: &Environment) -> String {
    match own {
        Some(own) if !own.is_empty() && Path::new(&paths::expand_user(own, environ)).is_absolute() => own.to_string(),
        _ => hooks.display().to_string(),
    }
}

/// The setting that stands for a key whose own value cannot be set again.
fn instead(rule: &ExecKey, key: &str) -> (String, String) {
    match &rule.replaced_by.setting {
        Some(setting) => (setting.replace("{subsection}", subsection(key).unwrap_or("")), rule.replaced_by.value.clone()),
        None => (key.to_string(), rule.replaced_by.value.clone()),
    }
}

fn same_list(key: &str, reset: &str) -> bool {
    rule_for(key).is_some_and(|rule| rule.replaced_by.reset.as_deref() == Some(reset))
}

fn runs_nothing(rule: &ExecKey) -> &'static str {
    if rule.runs == Runs::UnlessBoolean { "false" } else { "" }
}

/// Take out of the environment's allowed transports every one a setting turns off. Returns the
/// variable to set, when it changes.
fn protocols_left(settings: &[(String, String)], environ: &Environment) -> Option<(String, String)> {
    let allowed = environ.get(ALLOWED_PROTOCOLS)?;
    let turned_off: HashSet<&str> = settings
        .iter()
        .filter(|(key, value)| key.starts_with("protocol.") && key.ends_with(".allow") && key.matches('.').count() == 2 && value == "never")
        .filter_map(|(key, _)| key.split('.').nth(1))
        .collect();
    let given: Vec<&str> = allowed.split(':').collect();
    let kept: Vec<&str> = given.iter().copied().filter(|name| !turned_off.contains(name)).collect();
    (kept != given).then(|| (ALLOWED_PROTOCOLS.to_string(), kept.join(":")))
}

/// Drop a setting given again with the same value, unless it clears a list.
fn once(settings: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut kept = Vec::new();
    for (key, value) in settings {
        let lowered = (key.to_lowercase(), value.clone());
        let clears_a_list = rule_for(&key).is_some_and(|rule| rule.replaced_by.reset.is_some());
        if seen.contains(&lowered) && !clears_a_list {
            continue;
        }
        seen.insert(lowered);
        kept.push((key, value));
    }
    kept
}

/// Spell the settings in git's global options. Returns the options, and the environment variables
/// holding the value of a setting whose name holds `=`.
pub fn arguments(settings: &[(String, String)]) -> (Vec<String>, Vec<(String, String)>) {
    let mut options = Vec::new();
    let mut values: Vec<(String, String)> = Vec::new();
    for (key, value) in settings {
        if key.contains('=') {
            let name = format!("{VALUE_VARIABLE_PREFIX}{}", values.len() + 1);
            options.push(format!("--config-env={key}={name}"));
            values.push((name, value.clone()));
        } else {
            options.push("-c".to_string());
            options.push(format!("{key}={value}"));
        }
    }
    (options, values)
}
