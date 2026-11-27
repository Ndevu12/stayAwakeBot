//! A git command the way the operator typed it, read the way saw's `typed_command` reads it: the
//! settings its command line and environment give and what names its repository.

use super::Environment;

pub const LOCATION_VARIABLES: [&str; 9] = ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM"];
const UNREAD_VARIABLES: [&str; 2] = ["GIT_ATTR_SOURCE", "GIT_SHALLOW_FILE"];
const OPTIONS_WITH_A_VALUE: [&str; 10] = ["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env",
    "--super-prefix", "--attr-source", "--shallow-file", "--exec-path"];
const OPTIONS_WITH_A_SEPARATE_VALUE: [&str; 5] = ["-C", "-c", "--git-dir", "--work-tree", "--namespace"];
const OPTIONS_NOT_READ: [&str; 6] = ["--super-prefix", "--attr-source", "--shallow-file", "--config-env", "--exec-path", "--list-cmds"];
const KEPT_FLAGS: [&str; 9] = ["--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks", "--no-advice",
    "--literal-pathspecs", "--no-literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs"];
const DROPPED_FLAGS: [&str; 4] = ["-p", "--paginate", "-P", "--no-pager"];
const PRINTS_AND_STOPS: [&str; 8] = ["-h", "--help", "-v", "--version", "--exec-path", "--html-path", "--man-path", "--info-path"];
pub const NOT_READ: &str = "how git would run this command cannot be checked";

/// A git command read through git's own options.
#[derive(Debug, Default)]
pub struct TypedCommand {
    /// What `--git-dir` names, unchanged.
    pub git_dir: String,
    /// What `--work-tree` names, unchanged.
    pub work_tree: String,
    /// Whether `--bare` was given.
    pub bare: bool,
    /// The settings the environment and `-c` give, in git's order. None stands for a key given
    /// without `=`.
    pub settings: Vec<(String, Option<String>)>,
    /// The variables that name the repository, with their values.
    pub locations: Vec<(String, String)>,
}

impl TypedCommand {
    /// Tell whether the command names its repository, index or objects itself.
    pub fn names_its_repository(&self) -> bool {
        let named = self.locations.iter().any(|(name, _)| {
            !matches!(name.as_str(), "GIT_NAMESPACE" | "GIT_CEILING_DIRECTORIES" | "GIT_DISCOVERY_ACROSS_FILESYSTEM")
        });
        !self.git_dir.is_empty() || !self.work_tree.is_empty() || self.bare || named
    }

    /// List the options that name the command's repository, in git's own spelling.
    pub fn location_options(&self) -> Vec<String> {
        let mut options = Vec::new();
        if !self.git_dir.is_empty() {
            options.push(format!("--git-dir={}", self.git_dir));
        }
        if !self.work_tree.is_empty() {
            options.push(format!("--work-tree={}", self.work_tree));
        }
        if self.bare {
            options.push("--bare".to_string());
        }
        options
    }
}

/// Read a git command line through git's own options and its environment. Takes the arguments
/// without the program name and the command's environment. Returns the command, or `NOT_READ` when
/// git would not reach a subcommand saw can read, or its settings cannot be read.
pub fn read(args: &[String], environment: &Environment) -> Result<TypedCommand, &'static str> {
    let mut settings = environment_settings(environment).ok_or(NOT_READ)?;
    if UNREAD_VARIABLES.iter().any(|name| environment.get(*name).is_some_and(|value| !value.is_empty())) {
        return Err(NOT_READ);
    }
    let mut command = TypedCommand::default();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if !arg.starts_with('-') {
            command.settings = settings;
            command.locations = LOCATION_VARIABLES
                .iter()
                .filter_map(|name| environment.get(*name).filter(|value| !value.is_empty()).map(|value| (name.to_string(), value.clone())))
                .collect();
            return Ok(command);
        }
        let (name, value) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (arg, None),
        };
        if PRINTS_AND_STOPS.contains(&arg) || OPTIONS_NOT_READ.contains(&name) {
            return Err(NOT_READ);
        }
        if KEPT_FLAGS.contains(&arg) || DROPPED_FLAGS.contains(&arg) {
            index += 1;
            continue;
        }
        if arg == "--bare" {
            command.bare = true;
            index += 1;
            continue;
        }
        if !OPTIONS_WITH_A_VALUE.contains(&name) {
            return Err(NOT_READ);
        }
        let value = match value {
            Some(joined) => {
                index += 1;
                joined.to_string()
            }
            None => {
                if index + 1 >= args.len() || !OPTIONS_WITH_A_SEPARATE_VALUE.contains(&name) {
                    return Err(NOT_READ);
                }
                index += 2;
                args[index - 1].clone()
            }
        };
        match name {
            "-c" => {
                let (key, setting) = match value.split_once('=') {
                    Some((key, setting)) => (key.to_string(), Some(setting.to_string())),
                    None => (value.clone(), None),
                };
                if key.is_empty() {
                    return Err(NOT_READ);
                }
                settings.push((key, setting));
            }
            "--git-dir" => command.git_dir = value,
            "--work-tree" => command.work_tree = value,
            _ => {}
        }
    }
    Err(NOT_READ)
}

/// Read the settings a command's environment gives git. Takes the environment. Returns them in
/// the order git reads them, or None when one cannot be read.
fn environment_settings(environment: &Environment) -> Option<Vec<(String, Option<String>)>> {
    let mut settings = Vec::new();
    if let Some(parameters) = environment.get("GIT_CONFIG_PARAMETERS").filter(|value| !value.is_empty()) {
        settings.extend(quoted_settings(parameters)?);
    }
    if let Some(count) = environment.get("GIT_CONFIG_COUNT").filter(|value| !value.is_empty()) {
        if !count.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        for number in 0..count.parse::<usize>().ok()? {
            let key = environment.get(&format!("GIT_CONFIG_KEY_{number}")).filter(|key| !key.is_empty())?;
            let value = environment.get(&format!("GIT_CONFIG_VALUE_{number}"))?;
            settings.push((key.clone(), Some(value.clone())));
        }
    }
    Some(settings)
}

/// Read `GIT_CONFIG_PARAMETERS`: quoted `'key'='value'` or `'key=value'` items. Takes its value.
/// Returns the settings, or None for a value git did not write.
fn quoted_settings(text: &str) -> Option<Vec<(String, Option<String>)>> {
    let mut settings = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b' ' {
            index += 1;
            continue;
        }
        let (first, next) = quoted(text, index)?;
        index = next;
        if bytes.get(index) == Some(&b'=') {
            let (second, next) = quoted(text, index + 1)?;
            index = next;
            settings.push((first, Some(second)));
        } else {
            match first.split_once('=') {
                Some((key, value)) => settings.push((key.to_string(), Some(value.to_string()))),
                None => settings.push((first, None)),
            }
        }
    }
    Some(settings)
}

/// Read one word quoted the way git quotes it, from `index`. Takes the text and where the word
/// starts. Returns the word and where it ends, or None for a word quoted another way.
fn quoted(text: &str, mut index: usize) -> Option<(String, usize)> {
    let mut word = String::new();
    while text[index..].starts_with('\'') {
        let end = index + 1 + text[index + 1..].find('\'')?;
        word.push_str(&text[index + 1..end]);
        index = end + 1;
        if text[index..].starts_with("\\'") || text[index..].starts_with("\\!") {
            word.push_str(&text[index + 1..index + 2]);
            index += 2;
            continue;
        }
        return Some((word, index));
    }
    None
}
