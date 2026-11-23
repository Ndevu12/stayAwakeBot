//! The git commands each context may run.

use crate::programs::git::contexts::{Context, KEY_PREFIXES_A_CALLER_MAY_NOT_SET, KEYS_A_CALLER_MAY_NOT_SET};

const GLOBAL_OPTIONS_WITH_VALUE: &[&str] = &["-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"];

pub const UNTRUSTED_SUBCOMMANDS: &[&str] = &[
    "cat-file", "ls-tree", "rev-list", "rev-parse", "for-each-ref", "show-ref", "merge-base", "diff", "diff-tree",
    "log", "show", "ls-files", "hash-object", "read-tree", "write-tree", "update-index", "commit-tree", "mktree",
    "update-ref", "config", "symbolic-ref", "remote", "tag", "worktree", "check-attr",
];
pub const DIFF_SUBCOMMANDS: &[&str] = &["diff", "diff-tree", "log", "show"];
pub const NETWORK_SUBCOMMANDS: &[&str] = &["push", "fetch", "ls-remote", "clone", "pull"];
pub const OPERATOR_CONFIG_SUBCOMMANDS: &[&str] = &["config", "credential", "version"];

const SIGNATURE_READERS: &[&str] = &["--show-signature"];
const TEXT_CONVERTERS: &[&str] = &["--textconv", "--ext-diff", "--filters"];
const ON_A_PRIVATE_INDEX: &[&str] = &["read-tree", "write-tree", "update-index"];
const UPDATE_INDEX_ADDS_BY_NAME: &[&str] = &["--cacheinfo", "--index-info"];

fn refused_arguments(sub: &str) -> Vec<&'static str> {
    let both = |a: &[&'static str], b: &[&'static str]| [a, b].concat();
    match sub {
        "cat-file" => both(TEXT_CONVERTERS, &["--path"]),
        "diff" => [TEXT_CONVERTERS, SIGNATURE_READERS, &["--no-index"]].concat(),
        "diff-tree" | "log" | "show" => both(TEXT_CONVERTERS, SIGNATURE_READERS),
        "rev-list" => SIGNATURE_READERS.to_vec(),
        "ls-files" => vec!["-m", "--modified", "-d", "--deleted", "-k", "--killed", "--eol"],
        "read-tree" => vec!["-u"],
        "update-index" => vec!["--refresh", "--really-refresh", "--again", "-g", "--add"],
        "config" => vec!["--add", "--unset", "--unset-all", "--replace-all", "--rename-section", "--remove-section", "-e", "--edit"],
        "tag" => vec![
            "-a", "--annotate", "-s", "--sign", "-u", "--local-user", "-m", "--message", "-F", "--file", "-d", "--delete",
            "-v", "--verify", "-f", "--force", "-e", "--edit",
        ],
        "symbolic-ref" => vec!["-d", "--delete", "-m"],
        _ => Vec::new(),
    }
}

fn required_one_of(sub: &str) -> &'static [&'static str] {
    match sub {
        "hash-object" => &["--no-filters"],
        "update-index" => &["--cacheinfo", "--index-info", "--force-remove", "--remove"],
        "config" => &["--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l"],
        "tag" => &["-l", "--list", "--points-at", "--contains", "--no-contains", "--merged", "--no-merged"],
        _ => &[],
    }
}

/// Whether a command may run, and why not.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verdict {
    pub refusal: String,
    pub subcommand: String,
    pub reads_configuration: bool,
}

/// Separate git's own options from the subcommand. Takes the arguments. Returns the global options,
/// the subcommand or an empty one, and the rest.
pub fn split(args: &[String]) -> (Vec<String>, String, Vec<String>) {
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') {
        i += if GLOBAL_OPTIONS_WITH_VALUE.contains(&args[i].as_str()) { 2 } else { 1 };
    }
    if i >= args.len() {
        return (args.to_vec(), String::new(), Vec::new());
    }
    (args[..i].to_vec(), args[i].clone(), args[i + 1..].to_vec())
}

fn named(arg: &str, flags: &[&str]) -> bool {
    flags.contains(&arg) || flags.contains(&arg.split('=').next().unwrap_or(arg))
}

fn config_keys_set(global_options: &[String]) -> Vec<String> {
    let mut keys = Vec::new();
    let mut i = 0;
    while i < global_options.len() {
        if global_options[i] == "-c" && i + 1 < global_options.len() {
            keys.push(global_options[i + 1].split('=').next().unwrap_or("").to_lowercase());
            i += 2;
            continue;
        }
        if global_options[i] == "--config-env" || global_options[i].starts_with("--config-env=") {
            keys.push("*".into());
        }
        i += 1;
    }
    keys
}

fn positionals_before_separator(rest: &[String]) -> Vec<&str> {
    rest.iter().take_while(|arg| *arg != "--").filter(|arg| !arg.starts_with('-')).map(String::as_str).collect()
}

fn reads_signatures(rest: &[String]) -> bool {
    rest.iter().any(|arg| {
        ((arg.starts_with("--format=") || arg.starts_with("--pretty=")) && arg.contains("%G")) || arg.contains("%(signature")
    })
}

fn untrusted(sub: &str, rest: &[String], private_index: bool) -> String {
    if !UNTRUSTED_SUBCOMMANDS.contains(&sub) {
        return format!("`git {sub}` can run code a repository configures");
    }
    let refused = refused_arguments(sub);
    for arg in rest.iter().take_while(|arg| *arg != "--") {
        if named(arg, &refused) {
            if sub == "update-index" && arg == "--add" && rest.iter().any(|a| named(a, UPDATE_INDEX_ADDS_BY_NAME)) {
                continue;
            }
            return format!("`git {sub} {arg}` can run code a repository configures, or writes");
        }
    }
    let required = required_one_of(sub);
    if !required.is_empty() && !rest.iter().any(|a| named(a, required)) {
        let mut listed: Vec<&str> = required.to_vec();
        listed.sort_unstable();
        let shown: Vec<String> = listed.iter().map(|flag| format!("'{flag}'")).collect();
        return format!("`git {sub}` without one of [{}]", shown.join(", "));
    }
    if reads_signatures(rest) {
        return format!("`git {sub}` verifying a signature runs the repository's signature program");
    }
    if ON_A_PRIVATE_INDEX.contains(&sub) && !private_index {
        return format!("`git {sub}` outside a private GIT_INDEX_FILE touches the operator's index");
    }
    if sub == "diff" {
        let revisions = positionals_before_separator(rest);
        if revisions.len() < 2 && !revisions.iter().any(|r| r.contains("..")) {
            return "`git diff` against the working tree or index runs the repository's filters".into();
        }
    }
    if sub == "remote" && rest.first().map(String::as_str) != Some("get-url") {
        return "`git remote` other than get-url".into();
    }
    if sub == "worktree" && rest.first().map(String::as_str) != Some("list") {
        return "`git worktree` other than list".into();
    }
    if sub == "symbolic-ref" && positionals_before_separator(rest).len() != 1 {
        return "`git symbolic-ref` writing a ref".into();
    }
    String::new()
}

fn reads_configuration(sub: &str, rest: &[String]) -> bool {
    sub == "config" || (sub == "rev-parse" && rest.iter().any(|a| a == "--git-path"))
}

/// Decide whether a command may run. Takes the context, the arguments and whether the caller names
/// a private index. Returns the verdict.
pub fn judge(context: Context, args: &[String], private_index: bool) -> Verdict {
    let (global_options, sub, rest) = split(args);
    let refuse = |why: String| Verdict { refusal: why, subcommand: sub.clone(), reads_configuration: false };
    for key in config_keys_set(&global_options) {
        if key == "*"
            || KEYS_A_CALLER_MAY_NOT_SET.contains(&key.as_str())
            || KEY_PREFIXES_A_CALLER_MAY_NOT_SET.iter().any(|prefix| key.starts_with(prefix))
        {
            return refuse(format!("a caller may not set `{key}`"));
        }
    }
    if sub.is_empty() {
        return refuse("no git subcommand was named".into());
    }
    let why = match context {
        Context::Untrusted => {
            let why = untrusted(&sub, &rest, private_index);
            let reads = why.is_empty() && reads_configuration(&sub, &rest);
            return Verdict { refusal: why, subcommand: sub, reads_configuration: reads };
        }
        Context::SawOwned if NETWORK_SUBCOMMANDS.contains(&sub.as_str()) => {
            format!("`git {sub}` reaches a remote; that is OPERATOR_PUSH")
        }
        Context::SawOwned => String::new(),
        Context::OperatorPush if !NETWORK_SUBCOMMANDS.contains(&sub.as_str()) || sub == "pull" => {
            format!("`git {sub}` is not a push, fetch, ls-remote or clone")
        }
        Context::OperatorPush => String::new(),
        Context::OperatorConfig if !OPERATOR_CONFIG_SUBCOMMANDS.contains(&sub.as_str()) => {
            format!("`git {sub}` is not a configuration or credential question")
        }
        Context::OperatorConfig if sub == "credential" && rest != ["fill"] => "`git credential` other than fill".into(),
        Context::OperatorConfig => String::new(),
    };
    Verdict { refusal: why, subcommand: sub, reads_configuration: false }
}
