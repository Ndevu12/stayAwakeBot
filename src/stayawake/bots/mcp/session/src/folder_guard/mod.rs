//! Works out the settings and environment that keep a git command from starting a program the
//! folder's own git configuration names: the `run_with` `saw govern classify` answers, from the
//! same data, without starting saw. Nothing in the folder is run.

mod command_line;
mod exec_keys;
mod git;
pub mod kept_settings;
mod locate;
mod overrides;
mod paths;
mod settings_fingerprint;
mod starts_no_program;
mod surface;
mod typed_command;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub use command_line::shell_words;
pub use settings_fingerprint::Fingerprint;
pub use starts_no_program::starts_no_program;

/// The environment a command runs in, by variable name.
pub type Environment = HashMap<String, String>;

const SUBCOMMANDS_THAT_REPORT_SETTINGS: [&str; 2] = ["config", "var"];
const HOOKS_KEY: &str = "core.hookspath";

/// How to run one command: git's own options to put before its arguments, the settings they give
/// in order, and the environment variables to set.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunWith {
    pub arguments: Vec<String>,
    pub settings: Vec<(String, String)>,
    pub environment: Vec<(String, String)>,
}

impl RunWith {
    /// Describe it the way `saw govern classify` spells `run_with`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "arguments": self.arguments,
            "settings": self.settings.iter().map(|(key, value)| serde_json::json!({"key": key, "value": value})).collect::<Vec<_>>(),
            "environment": self.environment.iter().map(|(name, value)| (name.clone(), serde_json::Value::from(value.clone()))).collect::<serde_json::Map<_, _>>(),
        })
    }
}

/// Work out the settings and environment that keep a git command from starting anything the
/// folder's own configuration names. Takes the operator's git, the folder the command runs in, the arguments without the
/// program name and the environment the command runs in. Returns how to run it, or why saw cannot
/// vouch for running it this way.
pub fn guard(git: &Path, folder: &Path, args: &[String], environ: &Environment) -> Result<RunWith, String> {
    let runner = git::Git::new(git, environ);
    let answer = guard_with(&runner, folder, args, environ);
    match runner.stalled() {
        Some(stalled) if answer.is_ok() => Err(format!("git did not answer: {stalled}")),
        _ => answer,
    }
}

fn guard_with(git: &git::Git, folder: &Path, args: &[String], environ: &Environment) -> Result<RunWith, String> {
    let located = command_line::read(args, folder, &|_, _| None);
    if !located.readable {
        return Err(format!("this command line cannot be read: {}", located.reason));
    }
    let place: PathBuf = located.folder.clone().unwrap_or_else(|| folder.to_path_buf());
    let alias_of = |at: &Path, name: &str| {
        let found = git.answer(&git::Call::settings(Some(at), &["config", "--get", &format!("alias.{name}")])).text();
        let found = found.trim_end_matches('\n');
        (!found.is_empty()).then(|| found.to_string())
    };
    let reading = command_line::read(args, folder, &alias_of);
    if reading.readable && reports_settings(reading.subcommand.as_deref(), &reading.rest) {
        return Ok(RunWith::default());
    }
    let command = match typed_command::read(args, environ) {
        Ok(command) => command,
        Err(_) if matches!(located.subcommand.as_deref(), None | Some("version")) => return Ok(RunWith::default()),
        Err(why) => return Err(format!("this command line cannot be read: {why}")),
    };
    let hooks = paths::no_hooks_folder(environ)?;
    git.use_no_hooks_folder(&hooks);
    let mut first: Vec<git::Call> = locate::reads(&place, &command)[..1].to_vec();
    if let Some(likely) = surface::likely_git_dir(&place, environ) {
        first.extend(surface::first_reads(&likely, environ));
    }
    git.run_all(&first);
    let git_dir = locate::repository(git, &place, &command, environ)?;
    let listed_at = git_dir.clone().unwrap_or_else(|| place.clone());
    let operator = operator_entries(git, &listed_at).ok_or_else(|| format!("your own git settings did not load in {}", place.display()))?;
    let commands = match &git_dir {
        Some(git_dir) => {
            let read = surface::read(git, git_dir, environ);
            if let Some(first) = read.unexamined.first() {
                return Err(format!("part of the git settings of {} did not load: {first}", place.display()));
            }
            read.commands
        }
        None => Vec::new(),
    };
    let (mut settings, mut environment) = overrides::decide(&commands, &operator, &hooks, environ)?;
    if reading.readable && reading.subcommand.as_deref() == Some("rev-parse") && reading.rest.iter().any(|arg| arg == "--git-path") {
        settings.retain(|(key, _)| key.to_lowercase() != HOOKS_KEY);
    }
    let (arguments, values) = overrides::arguments(&settings);
    for (name, value) in values {
        overrides::set(&mut environment, &name, &value);
    }
    Ok(RunWith { arguments, settings, environment })
}

/// Read the fingerprint of the programs the own settings of the repository a git command acts on
/// start. Takes the operator's git, the folder the command runs in, the arguments without the
/// program name and the environment the command runs in. Returns it, None when the command acts on
/// no repository, or why it cannot be read.
pub fn fingerprint(git: &Path, folder: &Path, args: &[String], environ: &Environment) -> Result<Option<Fingerprint>, String> {
    let runner = git::Git::new(git, environ);
    let read = fingerprint_with(&runner, folder, args, environ);
    match runner.stalled() {
        Some(stalled) => Err(format!("git did not answer: {stalled}")),
        None => read,
    }
}

fn fingerprint_with(git: &git::Git, folder: &Path, args: &[String], environ: &Environment) -> Result<Option<Fingerprint>, String> {
    let located = command_line::read(args, folder, &|_, _| None);
    if !located.readable {
        return Err(format!("this command line cannot be read: {}", located.reason));
    }
    let place: PathBuf = located.folder.clone().unwrap_or_else(|| folder.to_path_buf());
    let command = typed_command::read(args, environ).map_err(|why| format!("this command line cannot be read: {why}"))?;
    git.use_no_hooks_folder(&paths::no_hooks_folder(environ)?);
    let Some(found) = locate::found(git, &place, &command, environ)? else { return Ok(None) };
    let listed = git.answer(&locate::reading_settings(&command, &place, &["config", "--list", "--show-scope", "-z"]));
    let listing = listed.succeeded().ok_or_else(|| format!("the git settings of {} did not load", place.display()))?;
    settings_fingerprint::from_listing(listing, &found, environ).map(Some)
}

/// Whether a command only reads or writes settings: it runs no program and reports what the
/// settings say.
fn reports_settings(subcommand: Option<&str>, rest: &[String]) -> bool {
    let Some(subcommand) = subcommand.filter(|sub| SUBCOMMANDS_THAT_REPORT_SETTINGS.contains(sub)) else { return false };
    let edits = rest.iter().any(|arg| arg == "-e" || arg == "--edit");
    let first_word = rest.iter().find(|arg| !arg.starts_with('-'));
    !(edits || (subcommand == "config" && first_word.is_some_and(|word| word == "edit")))
}

/// List every entry of the operator's own configuration, system and global scopes and what they
/// include, in the order git applies them at a place. Returns each key with its value (None for a
/// bare key), or None when git could not list them.
fn operator_entries(git: &git::Git, place: &Path) -> Option<Vec<(String, Option<String>)>> {
    let listed = git.answer(&git::Call::settings(Some(place), &["config", "--list", "--show-origin", "--show-scope", "-z"]));
    let listed = String::from_utf8_lossy(listed.succeeded()?).into_owned();
    let fields: Vec<&str> = listed.split('\0').collect();
    let mut found = Vec::new();
    for triple in fields.chunks_exact(3) {
        let (scope, entry) = (triple[0], triple[2]);
        let (key, value) = match entry.split_once('\n') {
            Some((key, value)) => (key, Some(value.to_string())),
            None => (entry, None),
        };
        if matches!(scope, "system" | "global") && !key.is_empty() {
            found.push((key.to_string(), value));
        }
    }
    Some(found)
}
