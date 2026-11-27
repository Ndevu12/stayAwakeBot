//! Reads a git command line the way saw's `command_line` does: the folder it acts on, and the
//! subcommand after aliases with its arguments.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::git_tables::table;

const GIT_AS_COMMANDS: [(&str, &str); 4] = [("--help", "help"), ("-h", "help"), ("--version", "version"), ("-v", "version")];
const MOST_ALIASES: usize = 16;

/// How a command line reads: the subcommand after aliases, its arguments and the folder it acts
/// on, or why it could not be read.
#[derive(Debug, Default)]
pub struct Reading {
    pub readable: bool,
    pub subcommand: Option<String>,
    pub rest: Vec<String>,
    pub folder: Option<PathBuf>,
    pub reason: String,
}

fn unreadable(reason: String) -> Reading {
    Reading { readable: false, reason, ..Reading::default() }
}

fn read_as(subcommand: Option<String>, rest: &[String], folder: PathBuf) -> Reading {
    Reading { readable: true, subcommand, rest: rest.to_vec(), folder: Some(folder), reason: String::new() }
}

/// Read a git command line. Takes the arguments without the program name, the folder it runs in
/// and the reader of the folder's aliases, which takes the folder and the alias. Returns the
/// reading.
pub fn read(args: &[String], folder: &Path, alias_of: &dyn Fn(&Path, &str) -> Option<String>) -> Reading {
    let mut folder = folder.to_path_buf();
    let mut inline: HashMap<String, String> = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if !arg.starts_with('-') {
            break;
        }
        if let Some((_, sub)) = GIT_AS_COMMANDS.iter().find(|(option, _)| *option == arg) {
            return read_as(Some(sub.to_string()), &args[index + 1..], folder);
        }
        if table("global_queries").contains(&arg) || arg.starts_with("--list-cmds=") {
            return read_as(None, &[], folder);
        }
        if table("global_flags").contains(&arg) || table("global_options_with_a_joined_value").iter().any(|p| arg.starts_with(p)) {
            index += 1;
            continue;
        }
        if !table("global_options_with_a_value").contains(&arg) {
            return unreadable(format!("saw checks a command line with the option {arg} first"));
        }
        let Some(value) = args.get(index + 1) else {
            return unreadable(format!("{arg} is missing its value"));
        };
        let key = value.split('=').next().unwrap_or("");
        if arg == "-C" && !value.is_empty() {
            folder = folder.join(value);
        }
        if arg == "-c" && key.to_lowercase().starts_with("include") {
            return unreadable(format!("{arg} {key} changes which commands are aliases"));
        }
        if arg == "-c" {
            if let Some((name, expansion)) = alias_set_inline(value) {
                inline.insert(name, expansion);
            }
        }
        index += 2;
    }
    if index >= args.len() {
        return read_as(None, &[], folder);
    }
    let (mut sub, mut rest) = (args[index].clone(), args[index + 1..].to_vec());
    let mut seen: HashSet<String> = HashSet::new();
    while !is_own_subcommand(&sub) {
        let lowered = sub.to_lowercase();
        let expansion = match inline.get(&lowered) {
            Some(given) => Some(given.clone()),
            None => alias_of(&folder, &sub),
        };
        let Some(expansion) = expansion else { break };
        if expansion.starts_with('!') {
            return unreadable(format!("the alias {sub} runs a shell command"));
        }
        if seen.contains(&sub) || seen.len() >= MOST_ALIASES {
            return unreadable(format!("the alias {sub} expands into itself"));
        }
        seen.insert(sub.clone());
        let words = match shell_words(&expansion) {
            Some(words) if !words.is_empty() && !words[0].starts_with('-') => words,
            _ => return unreadable(format!("the alias {sub} could not be read")),
        };
        rest = words[1..].iter().cloned().chain(rest).collect();
        sub = words[0].clone();
    }
    read_as(Some(sub), &rest, folder)
}

fn alias_set_inline(pair: &str) -> Option<(String, String)> {
    let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
    let (section, name) = key.split_once('.').unwrap_or((key, ""));
    (section.to_lowercase() == "alias" && !name.is_empty()).then(|| (name.to_lowercase(), value.to_string()))
}

/// Whether a subcommand is one saw's tables list, which no alias replaces.
fn is_own_subcommand(sub: &str) -> bool {
    table("subcommands_that_bring_no_files").contains(&sub) || table("subcommands_read_option_by_option").contains(&sub)
}

/// Split text into words the way a POSIX shell quotes them, with no comments. Takes the text.
/// Returns the words, or None for an unclosed quotation or a trailing escape.
pub fn shell_words(text: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '\\' => {
                word.push(chars.next()?);
                in_word = true;
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        other => word.push(other),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => {
                            let escaped = chars.next()?;
                            if escaped != '"' && escaped != '\\' {
                                word.push('\\');
                            }
                            word.push(escaped);
                        }
                        other => word.push(other),
                    }
                }
            }
            other => {
                word.push(other);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Some(words)
}
