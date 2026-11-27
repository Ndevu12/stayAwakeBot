//! A stand-in that sits where the editor expects `git` or `gh` and asks `saw govern` about a
//! command that may bring files into the folder before it runs. A git command it reads with
//! certainty as one that brings none runs straight through, and the real program runs unchanged
//! whenever saw cannot answer.
//!
//! It is inert unless activated. A placer (the editor extension) activates it per command with
//! `SAW_GOVERN_HOLDING` and points it at the real program and at `saw`. A system install instead
//! sets `SAW_GOVERN_SYSTEM`, and the stand-in makes its own holding directory for each check and
//! removes it afterwards. Without either, every command passes straight through.
//!
//! Invoked by its own name with `git` or `gh` and that tool's arguments, it sends a command saw
//! checks to saw whatever the environment, and never falls back to the real program when saw
//! cannot answer.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal};
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Stdio};
use std::sync::OnceLock;

use saw_mcp::folder_guard::{self, kept_settings, Fingerprint, RunWith};
use saw_mcp::git_tables::table;

fn main() {
    let argv: Vec<String> = env::args().collect();
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    let base = Path::new(argv0).file_name().and_then(|s| s.to_str()).unwrap_or("");
    let base = base.strip_suffix(".exe").unwrap_or(base);
    // Invoked by its own name (not git/gh) and not asked to impersonate a tool: an admin
    // subcommand managing the placement, or a git or gh command saw must check.
    let by_its_own_name = base != "git" && base != "gh" && env::var_os("SAW_STANDIN_TOOL").is_none();
    let rest = argv.get(1..).unwrap_or(&[]);
    let (tool, args, must_check) = match rest.first().map(String::as_str) {
        Some(sub) if by_its_own_name && matches!(sub, "install" | "status" | "uninstall") => {
            exit(admin(sub, &rest[1..]))
        }
        Some(sub) if by_its_own_name && matches!(sub, "git" | "gh") => (sub.to_string(), rest[1..].to_vec(), true),
        _ => match tool_name(argv0) {
            Some(t) => (t, rest.to_vec(), false),
            None => passthrough_raw(&argv),       // unknown name: find a real one and run it
        },
    };
    let real = real_tool(&tool).unwrap_or_else(|| {
        eprintln!("saw: could not find the real {tool}");
        exit(127);
    });
    if governing() || must_check {
        let sent = sent_to_saw(&tool, &args, &real);
        let mut guarded = None;
        if sent == Sent::No && tool == "git" {
            let answer = run_with_for(&real, &args);
            if let Ok(run_with) = &answer {
                run_real_with(&real, &args, run_with);
            }
            guarded = Some(answer);                // saw cannot vouch for running it directly: ask saw
        }
        if sent != Sent::No || guarded.is_some() {
            let refused = matches!(guarded, Some(Err(_)));
            if let Some(code) = govern(&tool, &args, &real, sent != Sent::ToSaw, must_check || refused) {
                exit(code);                        // governed: saw applied it, held it or refused it
            }
        }
        if tool == "git" {
            match guarded.unwrap_or_else(|| run_with_for(&real, &args)) {
                Ok(run_with) => run_real_with(&real, &args, &run_with),
                Err(why) => exit(match real_saw() {   // a refusal stays one whatever saw answered
                    Some(saw) => run_or_leave_in_person(&tool, &args, &why, &real, &saw, &target_repo(&args)),
                    None => {
                        eprintln!("saw: this command could not be checked; the folder is unchanged; {tool} did not run.");
                        2
                    }
                }),
            }
        }
    }
    run_real(&real, &args);                        // not governed, or saw could not answer
}

/// Decide how to run a git command directly: as typed when the repository's own settings start no
/// program or the operator kept them, else with the settings and environment that keep every
/// program they name from starting. A person at a terminal is asked once whether to keep settings
/// saw was not told to keep. Takes the real git and the arguments. Returns how to run it, or why saw
/// cannot vouch for running the command directly.
fn run_with_for(real: &Path, args: &[String]) -> Result<RunWith, String> {
    let folder = env::current_dir().map_err(|error| format!("the current folder cannot be read: {error}"))?;
    let environ: folder_guard::Environment =
        env::vars_os().map(|(name, value)| (name.to_string_lossy().into_owned(), value.to_string_lossy().into_owned())).collect();
    match folder_guard::fingerprint(real, &folder, args, &environ) {
        Ok(None) => return Ok(RunWith::default()),
        Ok(Some(found)) if found.is_empty() => return Ok(RunWith::default()),
        Ok(Some(found)) => {
            let digest = found.digest();
            let recorded = kept_settings::read(&environ, &found.repository);
            if recorded.keeps(&digest) || kept_when_asked(&found, &digest, !recorded.declined(&digest), &folder, &environ) {
                return Ok(RunWith::default());
            }
        }
        Err(_) => {}
    }
    folder_guard::guard(real, &folder, args, &environ)
}

/// Ask the person at a terminal, through `saw govern trust`, whether to keep the programs a
/// repository's own settings start. Ask only a command whose input and both outputs are a terminal,
/// and only about settings no one answered no to. Otherwise say how to keep them. Takes the
/// fingerprint, its digest, whether to ask about it, the folder the command runs in and the
/// environment. Returns whether the operator kept exactly these settings.
fn kept_when_asked(found: &Fingerprint, digest: &str, may_ask: bool, folder: &Path, environ: &folder_guard::Environment) -> bool {
    let trust = match fs::canonicalize(folder).ok().filter(|here| here.starts_with(&found.folder)) {
        Some(_) => "saw govern trust".to_string(),
        None => format!("saw govern trust --repo {}", shell_word(&found.folder.to_string_lossy())),
    };
    let Some(saw) = real_saw().filter(|_| may_ask && attended() && io::stdout().is_terminal()) else {
        eprintln!("saw: this folder's git settings run {}. git ran without them. To keep them for this folder, run: {trust}",
                  named_briefly(&found.named()));
        return false;
    };
    let asked = Command::new(saw)
        .args(["govern", "trust", "--repo"])
        .arg(&found.folder)
        .env_remove("SAW_GOVERN_DECISION")
        .status();
    asked.is_ok_and(|status| status.success()) && kept_settings::read(environ, &found.repository).keeps(digest)
}

/// Name a few of the programs a folder's settings start. Takes their names. Returns the text.
fn named_briefly(names: &[String]) -> String {
    const SHOWN: usize = 4;
    let shown = names.iter().take(SHOWN).cloned().collect::<Vec<_>>().join(", ");
    match names.len().saturating_sub(SHOWN) {
        0 => shown,
        more => format!("{shown} and {more} more"),
    }
}

/// The tool this stand-in impersonates, from how it was invoked. A dev/test build falls back to
/// `SAW_STANDIN_TOOL`.
fn tool_name(argv0: &str) -> Option<String> {
    let base = Path::new(argv0).file_name().and_then(|s| s.to_str()).unwrap_or("");
    let base = base.strip_suffix(".exe").unwrap_or(base);
    match base {
        "git" => Some("git".into()),
        "gh" => Some("gh".into()),
        _ => env::var("SAW_STANDIN_TOOL").ok().filter(|t| t == "git" || t == "gh"),
    }
}

fn governing() -> bool {
    env::var_os("SAW_GOVERN_HOLDING").is_some() || env::var_os("SAW_GOVERN_SYSTEM").is_some()
}



/// A git command line read through git's global options.
struct GitLine<'a> {
    /// Where the subcommand is, when git reaches one.
    subcommand: Option<usize>,
    /// Each `-C <path>` before the subcommand, in order.
    folders: Vec<&'a str>,
    /// Whether every option before the subcommand is one the stand-in reads with certainty.
    read: bool,
    /// The key of each `-c <key>=<value>` before the subcommand.
    settings: Vec<&'a str>,
    /// Whether `--work-tree` names the working tree.
    names_a_work_tree: bool,
}

/// Read git's global options up to the subcommand. Takes the arguments without the program name.
/// Returns the reading, which stops at the first option the stand-in cannot read.
fn read_git_line(args: &[String]) -> GitLine<'_> {
    let mut line =
        GitLine { subcommand: None, folders: Vec::new(), read: true, settings: Vec::new(), names_a_work_tree: false };
    let mut i = 0;
    while let Some(arg) = args.get(i).map(String::as_str) {
        if !arg.starts_with('-') {
            line.subcommand = Some(i);
            return line;
        }
        if table("global_queries").contains(&arg) || arg.starts_with("--list-cmds=") {
            return line;
        }
        if arg == "--work-tree" || arg.starts_with("--work-tree=") {
            line.names_a_work_tree = true;
        }
        if table("global_flags").contains(&arg) || table("global_options_with_a_joined_value").iter().any(|p| arg.starts_with(p)) {
            i += 1;
            continue;
        }
        let Some(value) = args.get(i + 1).filter(|_| table("global_options_with_a_value").contains(&arg)) else {
            line.read = false;
            return line;
        };
        if arg == "-c" && names_commands(value) {
            line.read = false;
            return line;
        }
        if arg == "-C" {
            line.folders.push(value);
        }
        if arg == "-c" {
            line.settings.push(value.split('=').next().unwrap_or(""));
        }
        i += 2;
    }
    line
}

/// Whether a `-c <name>=<value>` sets a key in a section that changes which commands git runs.
fn names_commands(setting: &str) -> bool {
    let section = setting.split(['=', '.']).next().unwrap_or("").to_ascii_lowercase();
    table("sections_that_name_commands").contains(&section.as_str())
}

/// Whether the stand-in sends a command to `saw govern` before it runs, and why.
#[derive(PartialEq)]
enum Sent {
    /// It runs as typed.
    No,
    /// saw checks it.
    ToSaw,
    /// It brings no files, and saw checks what a setting, an option or the environment names.
    ForWhatItNames,
}

/// Decide whether `(tool, args)` goes to `saw govern` first: every git command the stand-in cannot
/// read with certainty as bringing no files into the folder, one that brings none but names a
/// setting, an output file, a program, an option git does not take, a hooks template, a
/// configuration change or a fetch, and
/// gh's bringing-files commands.
fn sent_to_saw(tool: &str, args: &[String], real: &Path) -> Sent {
    match tool {
        "git" => git_sent(args, real),
        "gh" if gh_brings_files_in(args) => Sent::ToSaw,
        _ => Sent::No,
    }
}

/// Decide whether a git command goes to saw first.
fn git_sent(args: &[String], real: &Path) -> Sent {
    let line = read_git_line(args);
    if !line.read {
        return Sent::ToSaw;
    }
    let Some(at) = line.subcommand else { return Sent::No };
    let sub = args[at].as_str();
    if !table("subcommands_that_bring_no_files").contains(&sub) || line.names_a_work_tree || env::var_os("GIT_WORK_TREE").is_some() {
        return Sent::ToSaw;
    }
    let reader = GitReader { real, folder: PathBuf::from(target_repo(args)) };
    if names_what_saw_checks(sub, &args[at + 1..], &line.settings, &reader) {
        Sent::ForWhatItNames
    } else {
        Sent::No
    }
}

/// Whether a command that brings no files names a setting that may run something, an output file,
/// a program, an option git does not take, a hooks template, a configuration change or a fetch.
fn names_what_saw_checks(sub: &str, rest: &[String], settings: &[&str], reader: &GitReader) -> bool {
    let runs_something = |key: &&str| {
        let key = key.to_ascii_lowercase();
        let section = key.split('.').next().unwrap_or("");
        !(table("settings_that_run_nothing").contains(&key.as_str()) || table("sections_that_run_nothing").contains(&section))
    };
    if settings.iter().any(runs_something) || table("settings_variables").iter().any(|name| env::var_os(name).is_some()) {
        return true;
    }
    let every: Vec<&str> = rest.iter().map(String::as_str).collect();
    let resolved = resolve(sub, &every);
    match sub {
        _ if options_send_it_to_saw(sub, &every, resolved.as_ref()) => true,
        "init" | "maintenance" => true,
        "push" | "ls-remote" => resolved.as_ref().is_none_or(|resolved| reaches_this_machine(sub, resolved, reader)),
        "config" => {
            let words: Vec<&str> = every.iter().copied().take_while(|arg| *arg != "--").filter(|arg| !arg.starts_with('-')).collect();
            !config_only_reads(&every, &words)
        }
        "remote" => resolved.as_ref().is_none_or(|resolved| resolved.words.first().is_some_and(|word| word == "update")),
        _ => false,
    }
}

/// The real git and the folder a command runs in, for reading that folder's configuration.
struct GitReader<'a> {
    real: &'a Path,
    folder: PathBuf,
}

/// The options git takes for each subcommand saw reads, which saw reads too.
const OPTIONS: &str = include_str!("../../../../../lib/data/git_subcommand_options.json");

/// The options git takes for one subcommand, by the value each takes, with those whose value names
/// a program to run and those that name a file git writes.
#[derive(Default)]
struct Options {
    next_word: Vec<String>,
    rest_of_word: Vec<String>,
    no_word: Vec<String>,
    long_names: Vec<String>,
    runs_a_program: Vec<String>,
    writes_a_file: Vec<String>,
    fetches: Vec<String>,
    /// Whether the table lists every option git takes without a value too: false where it gives
    /// them as null.
    lists_every_option: bool,
    /// Whether git passes an option it does not take through as output.
    echoes: bool,
}

/// The option table: each subcommand's options, and the options every subcommand takes.
struct OptionTable {
    subcommands: HashMap<String, Options>,
    every_subcommand_takes: Vec<String>,
}

/// Return the option table built into the stand-in. Panics when it cannot be read.
fn option_table() -> &'static OptionTable {
    static READ: OnceLock<OptionTable> = OnceLock::new();
    READ.get_or_init(|| {
        let table: serde_json::Value = serde_json::from_str(OPTIONS).expect("saw's git option table");
        let list = |entry: &serde_json::Value, key: &str| -> Vec<String> {
            entry.get(key).and_then(serde_json::Value::as_array).into_iter().flatten()
                .filter_map(|name| name.as_str().map(String::from)).collect()
        };
        let mut subcommands = HashMap::new();
        for (sub, entry) in table["subcommands"].as_object().expect("saw's git option table lists subcommands") {
            let mut options = Options {
                next_word: list(entry, "takes_the_next_word"),
                rest_of_word: list(entry, "takes_the_rest_of_its_word"),
                no_word: list(entry, "takes_no_word"),
                runs_a_program: list(entry, "runs_a_program"),
                writes_a_file: list(entry, "writes_a_file"),
                fetches: list(entry, "fetches"),
                lists_every_option: !entry.get("takes_no_word").is_some_and(serde_json::Value::is_null),
                echoes: entry.get("echoes_options_it_does_not_take").and_then(serde_json::Value::as_bool) == Some(true),
                ..Options::default()
            };
            let own: Vec<String> = [&options.next_word, &options.rest_of_word, &options.no_word].into_iter().flatten().cloned().collect();
            for group in list(entry, "with") {
                let group = &table["option_groups"][group.as_str()];
                let added = |key: &str| list(group, key).into_iter().filter(|name| !own.contains(name)).collect::<Vec<_>>();
                options.next_word.extend(added("takes_the_next_word"));
                options.rest_of_word.extend(added("takes_the_rest_of_its_word"));
                options.no_word.extend(added("takes_no_word"));
                options.runs_a_program.extend(list(group, "runs_a_program"));
                options.writes_a_file.extend(list(group, "writes_a_file"));
                options.fetches.extend(list(group, "fetches"));
            }
            let mut long_names: Vec<String> = [&options.next_word, &options.rest_of_word, &options.no_word].into_iter()
                .flatten().filter(|name| name.starts_with("--")).cloned().collect();
            long_names.sort();
            long_names.dedup();
            options.long_names = long_names;
            subcommands.insert(sub.clone(), options);
        }
        OptionTable { subcommands, every_subcommand_takes: list(&table, "every_subcommand_takes") }
    })
}

/// Whether a subcommand's options send it to saw: any argument, a value, `--` and the words after
/// it included, that is or begins an option that runs a program, writes a file or fetches, an
/// option git does not take, a leading part naming several, or such an option in the reading.
/// Takes the subcommand, its arguments and their reading. False for a subcommand with its own rule.
fn options_send_it_to_saw(sub: &str, rest: &[&str], resolved: Option<&Resolved>) -> bool {
    if table("subcommands_read_by_their_own_rule").contains(&sub) {
        return false;
    }
    let checked = options_saw_checks(sub);
    if rest.iter().any(|arg| may_name(arg, &checked)) {
        return true;
    }
    resolved.is_none_or(|resolved| resolved.options.iter().any(|(name, _)| checked.contains(name)))
}

/// The options of a subcommand, and of the words it takes, whose value names a program to run,
/// that name a file git writes, or that fetch.
fn options_saw_checks(sub: &str) -> Vec<String> {
    let mut checked = Vec::new();
    for (name, options) in &option_table().subcommands {
        if name == sub || name.strip_prefix(sub).is_some_and(|word| word.starts_with(' ')) {
            checked.extend(options.runs_a_program.iter().chain(&options.writes_a_file).chain(&options.fetches).cloned());
        }
    }
    checked
}

/// A subcommand's arguments read the way git reads them: each option's full name with its value,
/// and the words, those after `--` or `--end-of-options` included.
struct Resolved {
    options: Vec<(String, Option<String>)>,
    words: Vec<String>,
}

/// Whether an argument may name one of the options: a long option that is, or is the leading part
/// of, one, or a bundle of short options holding one.
fn may_name(arg: &str, names: &[String]) -> bool {
    if arg.starts_with("--") {
        let written = arg.split('=').next().unwrap_or("");
        written.len() > 2 && names.iter().any(|name| name.starts_with("--") && name.starts_with(written))
    } else {
        arg.starts_with('-') && names.iter().any(|name| !name.starts_with("--") && arg[1..].contains(&name[1..]))
    }
}

/// Read a subcommand's arguments the way git does: each option up to `--` or `--end-of-options` in
/// full from a unique leading part, its `--no-` form, a bundle of short options, and a value joined
/// to it or in the next word. Each other argument is a word. Returns each option's full name with
/// its value, and the words, None for an option git does not take or cannot tell apart.
fn resolve(sub: &str, args: &[&str]) -> Option<Resolved> {
    let table = option_table();
    let mut options = table.subcommands.get(sub).filter(|options| options.lists_every_option)?;
    let mut given: Vec<(String, Option<String>)> = Vec::new();
    let mut words = Vec::new();
    let mut word_seen = false;
    let mut index = 0;
    while let Some(arg) = args.get(index).copied() {
        index += 1;
        if arg == "--" || arg == "--end-of-options" {
            words.extend(args[index..].iter().map(|word| word.to_string()));
            break;
        }
        if arg == "-" || !arg.starts_with('-') {
            if !word_seen {
                if let Some(word) = table.subcommands.get(&format!("{sub} {arg}")) {
                    options = word;
                }
            }
            word_seen = true;
            words.push(arg.to_string());
            continue;
        }
        if options.echoes || table.every_subcommand_takes.iter().any(|name| name == arg) {
            given.push((arg.to_string(), None));
            continue;
        }
        if arg.starts_with("--") {
            let (written, joined) = arg.split_once('=').map_or((arg, None), |(written, value)| (written, Some(value.to_string())));
            let name = full_long_name(options, written)?;
            let value = if joined.is_none() && options.next_word.contains(&name) {
                index += 1;
                args.get(index - 1).map(|value| value.to_string())
            } else {
                joined
            };
            given.push((name, value));
            continue;
        }
        let mut bundle = &arg[1..];
        while let Some(first) = bundle.chars().next() {
            if first.is_ascii_digit() && options.no_word.iter().any(|name| name == "-NUM") {
                bundle = bundle.trim_start_matches(|c: char| c.is_ascii_digit());
                given.push(("-NUM".to_string(), None));
                continue;
            }
            let name = format!("-{first}");
            bundle = &bundle[first.len_utf8()..];
            if options.next_word.contains(&name) {
                let value = if bundle.is_empty() {
                    index += 1;
                    args.get(index - 1).map(|value| value.to_string())
                } else {
                    Some(bundle.to_string())
                };
                given.push((name, value));
                break;
            }
            if options.rest_of_word.contains(&name) {
                given.push((name, Some(bundle.to_string()).filter(|value| !value.is_empty())));
                break;
            }
            if !options.no_word.contains(&name) {
                return None;
            }
            given.push((name, None));
        }
    }
    Some(Resolved { options: given, words })
}

/// The long option git reads a written one for: itself, or the one option it begins. None for any
/// other.
fn full_long_name(options: &Options, written: &str) -> Option<String> {
    if options.long_names.iter().any(|name| name == written) {
        return Some(written.to_string());
    }
    let mut leading = options.long_names.iter().filter(|name| written.len() > 2 && name.starts_with(written));
    match (leading.next(), leading.next()) {
        (Some(only), None) => Some(only.clone()),
        _ => None,
    }
}

/// Whether a push or ls-remote may reach a repository on this machine or a program: a word that is
/// a folder, or any address git names for it that is not a network address. Takes the subcommand and its
/// reading.
fn reaches_this_machine(sub: &str, resolved: &Resolved, reader: &GitReader) -> bool {
    if resolved.words.first().is_some_and(|word| Path::new(word).is_dir()) {
        return true;
    }
    destinations(sub, resolved, reader).is_none_or(|addresses| !addresses.iter().all(|address| is_network_address(address)))
}

/// The addresses a push or ls-remote reaches, asked of git: each repository the reading names, or
/// with none the remote git would use, through that remote's addresses. None when git names none or
/// cannot answer.
fn destinations(sub: &str, resolved: &Resolved, reader: &GitReader) -> Option<Vec<String>> {
    let pushes = sub == "push";
    let repo_values = resolved.options.iter().filter(|(name, _)| pushes && name == "--repo").filter_map(|(_, value)| value.clone());
    let mut named: Vec<String> = repo_values.chain(resolved.words.first().cloned()).collect();
    if named.is_empty() {
        let branch = git_lines(reader, &["symbolic-ref", "--short", "-q", "HEAD"])?;
        let asked = if pushes { "--format=%(push:remotename)" } else { "--format=%(upstream:remotename)" };
        named = git_lines(reader, &["for-each-ref", asked, &format!("refs/heads/{}", branch[0])])?;
    }
    let mut addresses = Vec::new();
    for repository in named {
        if pushes {
            if let Some(configured) = git_lines(reader, &["remote", "get-url", "--push", "--all", &repository]) {
                addresses.extend(configured);
                continue;
            }
            if git_lines(reader, &["config", "--get-regexp", r"^url\..*\.pushinsteadof$"]).is_some() {
                return None;
            }
        }
        addresses.extend(git_lines(reader, &["ls-remote", "--get-url", &repository])?);
        if pushes {
            addresses.push(repository);
        }
    }
    Some(addresses)
}

/// Ask the real git a question in the folder the command acts on. Returns the answer's lines, None
/// when git cannot run, fails or answers nothing.
fn git_lines(reader: &GitReader, args: &[&str]) -> Option<Vec<String>> {
    let answered = Command::new(reader.real)
        .current_dir(&reader.folder)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|answered| answered.status.success())?;
    let lines: Vec<String> =
        String::from_utf8_lossy(&answered.stdout).lines().filter(|line| !line.trim().is_empty()).map(String::from).collect();
    (!lines.is_empty()).then_some(lines)
}

/// Whether git reaches an address over the network: an `http://`, `https://`, `ssh://` or `git://`
/// address, or `[user@]host:path` with no `::` or `://`, no `/` or `\\` before the first `:` and no
/// drive letter. Every other address, a remote helper's `<transport>::` form and `file://` among them, is
/// not.
fn is_network_address(address: &str) -> bool {
    if ["http://", "https://", "ssh://", "git://"].iter().any(|scheme| address.starts_with(scheme)) {
        return !address.contains("::");
    }
    let Some(colon) = address.find(':') else { return false };
    let host = &address[..colon];
    let drive = host.len() == 1 && host.as_bytes()[0].is_ascii_alphabetic();
    !address.contains("::") && !address.contains("://") && !host.is_empty() && !drive && !host.starts_with('-')
        && !host.contains(['/', '\\'])
}

/// Whether a `git config` command only reads.
fn config_only_reads(options: &[&str], words: &[&str]) -> bool {
    let named: Vec<Option<&str>> =
        options.iter().filter(|arg| arg.starts_with("--")).map(|arg| config_option(arg)).collect();
    if named.iter().any(|option| option.map_or(true, |name| table("config_writes").contains(&name)))
        || options.iter().any(|arg| *arg == "-e")
    {
        return false;
    }
    named.iter().flatten().any(|name| table("config_reads").contains(name))
        || options.iter().any(|arg| *arg == "-l")
        || matches!(words.first(), Some(&"get") | Some(&"list"))
        || (words.len() == 1 && !matches!(words[0], "set" | "unset" | "edit" | "rename-section" | "remove-section"))
}

/// The `git config` long option an argument names, in full: itself, the option its `--no-` form
/// turns off, or the one option it abbreviates. None for an argument naming no listed option, or
/// several.
fn config_option(arg: &str) -> Option<&'static str> {
    let written = arg.split('=').next().unwrap_or("");
    let name = written.strip_prefix("--no-").unwrap_or(&written[2..]);
    let listed = || table("config_reads").iter().chain(table("config_writes")).chain(table("config_other_options")).copied();
    if let Some(exact) = listed().find(|option| &option[2..] == name) {
        return Some(exact);
    }
    let mut abbreviated = listed().filter(|option| !name.is_empty() && option[2..].starts_with(name));
    match (abbreviated.next(), abbreviated.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

/// Whether a gh command brings files into the open folder.
fn gh_brings_files_in(args: &[String]) -> bool {
    let mut words = Vec::new();
    let mut given = args.iter().map(String::as_str).take_while(|a| *a != "--");
    while let Some(arg) = given.next() {
        if table("gh_repository_options").contains(&arg) {
            given.next();
        } else if !arg.starts_with('-') {
            words.push(arg);
        }
    }
    words.len() >= 2 && table("gh_commands_that_bring_files").contains(&words[..2].join(" ").as_str())
}

/// The folder the command acts on: the current directory, moved by each `git -C <path>` before
/// the subcommand.
fn target_repo(args: &[String]) -> String {
    let mut folder = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for path in read_git_line(args).folders.into_iter().filter(|p| !p.is_empty()) {
        folder = folder.join(path);
    }
    folder.to_string_lossy().into_owned()
}

/// What became of a command sent to saw.
enum Checked {
    /// saw applied it, held it, or the user decided: the command ends with this code.
    Ended(i32),
    /// saw answered that it runs as typed.
    RunsAsTyped,
    /// saw could not be reached, or could not answer.
    Unanswered,
}

/// Run the check. Takes the tool, its arguments, the real program, whether the command is sent for
/// what it names and whether saw must check it. Returns an exit code when the command was governed
/// (applied, held or refused), or `None` to run the real program: saw answered that it runs as
/// typed, or saw could not answer a command it was not required to check (fail open, never break
/// git).
fn govern(tool: &str, args: &[String], real: &Path, for_what_it_names: bool, must_check: bool) -> Option<i32> {
    let checked = match real_saw().and_then(|saw| holding_dir(must_check).map(|holding| (saw, holding))) {
        Some((saw, (holding, temporary))) => {
            let checked = govern_with(&saw, tool, args, &holding, temporary, real, for_what_it_names);
            if temporary {
                let _ = std::fs::remove_dir_all(&holding); // never leave a held update on disk
            }
            checked
        }
        None => Checked::Unanswered,
    };
    match checked {
        Checked::Ended(code) => Some(code),
        Checked::RunsAsTyped => None,
        Checked::Unanswered if must_check => {
            eprintln!("saw: this command could not be checked; the folder is unchanged; {tool} did not run.");
            Some(2)
        }
        Checked::Unanswered => None,
    }
}

/// Pick the holding directory for this check: a placer's `SAW_GOVERN_HOLDING` as given, else in
/// system mode (`SAW_GOVERN_SYSTEM`) or when saw must check the command, a new directory under the
/// system temp directory, never a name that already exists. Takes whether saw must check the
/// command. Returns the directory and whether it is the stand-in's own, or None when neither
/// applies or no directory can be made.
fn holding_dir(must_check: bool) -> Option<(PathBuf, bool)> {
    if let Some(given) = env::var_os("SAW_GOVERN_HOLDING") {
        return Some((PathBuf::from(given), false));
    }
    if !must_check {
        env::var_os("SAW_GOVERN_SYSTEM")?;
    }
    let unique = format!(
        "saw-govern-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let temp = env::temp_dir();
    std::fs::create_dir_all(&temp).ok()?;
    let dir = temp.join(unique);
    std::fs::create_dir(&dir).ok()?;
    Some((dir, true))
}

/// Run `saw govern prepare`, then `apply` when it comes back clean. Takes saw, the tool, its
/// arguments, the holding directory, whether it is removed when the check ends, the real program
/// and whether the command is sent for what it names. Returns what became of the command.
fn govern_with(saw: &Path, tool: &str, args: &[String], holding: &Path, holding_is_temporary: bool,
               real: &Path, for_what_it_names: bool) -> Checked {
    let repo = target_repo(args);
    let mut prepare = Command::new(saw);
    prepare
        .args(["govern", "prepare", "--json", "--repo"])
        .arg(&repo)
        .arg("--into")
        .arg(holding)
        .args(if for_what_it_names { &["--brings-no-files"][..] } else { &[][..] })
        .args(if holding_is_temporary && !attended() { &["--no-one-to-ask"][..] } else { &[][..] })
        .args(["--tool", tool, "--"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()); // progress/status reaches the operator
    let Ok(output) = prepare.output() else { return Checked::Unanswered };
    let prepared = output.status;
    let answer: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap_or_default();
    if answer.get("passthrough").and_then(serde_json::Value::as_bool) == Some(true) {
        return Checked::RunsAsTyped;
    }
    if offers_let_in(&answer) {
        let held = prepared.code().filter(|code| *code != 0).unwrap_or(1);
        return Checked::Ended(let_in_or_leave(saw, &answer, held, holding_is_temporary));
    }
    if let Some(reason) = unchecked_reason(&answer) {
        let checked = scan_finished(&answer);
        if !may_run_as_typed(&answer) {
            eprintln!("{}", said(&reason, checked));
            for step in answer.get("next_steps").and_then(serde_json::Value::as_array).into_iter().flatten() {
                if let Some(text) = step.as_str() {
                    eprintln!("  - {text}");
                }
            }
            eprintln!("saw: left the folder unchanged; {tool} did not run.");
            return Checked::Ended(2);
        }
        return Checked::Ended(run_or_leave(tool, args, &reason, checked, real, saw, &scanned_after(&answer, &repo)));
    }
    if !prepared.success() {
        if answer.is_object() {
            say_why_held(&answer);
        } else {
            eprintln!("saw: this update cannot be checked; the folder is unchanged; {tool} did not run.");
        }
        return Checked::Ended(failed(prepared.code()));
    }
    apply_checked(saw, tool, &repo, holding, &answer).map_or(Checked::Unanswered, Checked::Ended)
}

/// Write the update saw checked into the folder, without fetching again, and say what git said.
/// Takes saw, the tool, the open folder, the holding directory and prepare's answer. Returns the
/// exit code, never a success when saw did not write the update, or `None` when apply could not
/// start.
fn apply_checked(saw: &Path, tool: &str, repo: &str, holding: &Path, answer: &serde_json::Value) -> Option<i32> {
    let applied = Command::new(saw)
        .args(["govern", "apply", "--json", "--repo"])
        .arg(repo)
        .arg("--into")
        .arg(holding)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .ok()?;
    if applied.status.success() {
        relay_output(answer);
        return Some(0);
    }
    let written: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&applied.stdout).trim()).unwrap_or_default();
    if written.get("applied").and_then(serde_json::Value::as_bool) != Some(true) {
        let reason = written.get("reason").and_then(serde_json::Value::as_str).unwrap_or(
            "the update could not be written into the open folder, and the folder may have changed; \
             check it with git status");
        eprintln!("saw: {reason}; {tool} did not run.");
    }
    Some(failed(applied.status.code()))
}

/// Pick the exit code a saw step that did not succeed ends the command with. Takes the step's own
/// code, `None` when it has none. Returns a code that is never 0.
fn failed(code: Option<i32>) -> i32 {
    code.filter(|code| *code != 0).unwrap_or(2)
}

/// Write what git wrote when saw ran the command, to the same streams.
fn relay_output(answer: &serde_json::Value) {
    if let Some(text) = answer.pointer("/output/stdout").and_then(serde_json::Value::as_str) {
        print!("{text}");
    }
    if let Some(text) = answer.pointer("/output/stderr").and_then(serde_json::Value::as_str) {
        eprint!("{text}");
    }
}

/// Say that saw held the update, with its verdict and what to do.
fn say_why_held(answer: &serde_json::Value) {
    let verdict = answer.pointer("/scan/results/0/verdict").and_then(serde_json::Value::as_str).unwrap_or("held");
    eprintln!("saw: held this update ({verdict}); the folder is unchanged.");
    for step in answer.get("next_steps").and_then(serde_json::Value::as_array).into_iter().flatten() {
        if let Some(text) = step.as_str() {
            eprintln!("  - {text}");
        }
    }
}

/// The folder to scan after a command saw could not check runs as typed: the one saw names, or else
/// the open folder.
fn scanned_after(answer: &serde_json::Value, repo: &str) -> String {
    answer
        .pointer("/decision/scan_after")
        .and_then(serde_json::Value::as_array)
        .and_then(|command| command.last())
        .and_then(serde_json::Value::as_str)
        .unwrap_or(repo)
        .to_string()
}

/// Whether saw held the update and offers to let it in after review.
fn offers_let_in(answer: &serde_json::Value) -> bool {
    answer
        .pointer("/decision/choices")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|choices| choices.iter().any(|c| c == "let-in"))
}

/// Say why saw held the update and what to do, then ask the user whether to let it in. Never read
/// from the environment: letting in a finding is decided by a person, each time. Takes saw,
/// prepare's answer, the exit code of a held update and whether the holding directory is removed
/// with the check. Returns the exit code: the let-in command's, or `held` when the folder is left
/// unchanged.
fn let_in_or_leave(saw: &Path, answer: &serde_json::Value, held: i32, holding_is_temporary: bool) -> i32 {
    say_why_held(answer);
    let command = command_at(answer, "/decision/let_in");
    if command.len() < 2 {
        return held;
    }
    let typed = answer.pointer("/decision/confirm").and_then(serde_json::Value::as_str) == Some("typed");
    if !attended() {
        let later = command_at(answer, "/decision/let_in_later");
        if !later.is_empty() {
            let later: Vec<String> = later.iter().map(|word| shell_word(word)).collect();
            eprintln!("saw held this update for review and nothing changed. To review it and let it in: {}",
                      later.join(" "));
        } else if !holding_is_temporary {
            eprintln!("saw: after you review it, let it in with: {}{}", command.join(" "),
                      if typed { " --confirm <folder name>" } else { "" });
        }
        return held;
    }
    let mut extra = Vec::new();
    if typed {
        let name = answer.pointer("/decision/type_to_confirm").and_then(serde_json::Value::as_str).unwrap_or("");
        eprint!("saw recommends leaving the folder unchanged. To let it in anyway, type the folder name \
                 ({name}); anything else leaves it unchanged: ");
        extra.push("--confirm".to_string());
        extra.push(read_answer());
    } else {
        eprint!("Let this update in? [y/N] ");
        if !matches!(read_answer().to_lowercase().as_str(), "y" | "yes") {
            eprintln!("saw: left the folder unchanged.");
            return held;
        }
    }
    Command::new(saw).args(&command[1..]).args(&extra).status().ok().and_then(|s| s.code()).unwrap_or(held)
}

/// Read a command saw's answer names. Takes the answer and where the command is in it. Returns its
/// words, none when the answer names no command there.
fn command_at(answer: &serde_json::Value, pointer: &str) -> Vec<String> {
    answer
        .pointer(pointer)
        .and_then(serde_json::Value::as_array)
        .map(|parts| parts.iter().filter_map(|p| p.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Whether a person can be asked: this run reads from a terminal and writes to one.
fn attended() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// Quote a word for a POSIX shell, leaving a word of plain characters unquoted. Takes the word.
/// Returns the word to type.
fn shell_word(word: &str) -> String {
    let literal = !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || "_+:,./-@".contains(c));
    if literal {
        word.to_string()
    } else {
        single_quoted(word)
    }
}

/// Quote a word in single quotes for a POSIX shell. Takes the word. Returns the quoted word.
fn single_quoted(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Read one line the user typed, trimmed.
fn read_answer() -> String {
    let mut answer = String::new();
    let _ = io::stdin().lock().read_line(&mut answer);
    answer.trim().to_string()
}

/// What the user decided about an update saw could not check.
enum Decision {
    RunAsTyped,
    LeaveUnchanged,
}

/// Return the reason `saw govern prepare` gave when it could not check the update and left the
/// decision to the user, or `None` when its answer carries no decision.
fn unchecked_reason(answer: &serde_json::Value) -> Option<String> {
    answer.get("decision")?;
    let reason = answer.get("reason").and_then(serde_json::Value::as_str);
    Some(reason.unwrap_or("the update could not be checked").to_string())
}

/// Whether saw's answer says it checked the command: a finished scan with nothing left unread, or
/// a check that needed no scan.
fn scan_finished(answer: &serde_json::Value) -> bool {
    answer.get("checked").and_then(serde_json::Value::as_bool) == Some(true)
        || (answer.get("scan").is_some()
            && answer.pointer("/scan/any_error").and_then(serde_json::Value::as_bool) == Some(false))
}

/// Whether saw's answer names running the command as typed among its choices.
fn may_run_as_typed(answer: &serde_json::Value) -> bool {
    answer
        .pointer("/decision/choices")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|choices| choices.iter().any(|choice| choice == "run-as-typed"))
}

/// The line that tells the user why the update was not brought in.
fn said(reason: &str, checked: bool) -> String {
    if checked {
        format!("saw: checked this update: {reason}.")
    } else {
        format!("saw: this update cannot be checked: {reason}.")
    }
}

/// Ask the user whether to run a command saw could not check, or checked and could not bring in.
/// Returns their decision, leave-unchanged with no one to ask.
fn decide(tool: &str, args: &[String], reason: &str, checked: bool) -> Decision {
    match env::var("SAW_GOVERN_DECISION").as_deref() {
        Ok("run-as-typed") => return Decision::RunAsTyped,
        Ok("leave-unchanged") => return Decision::LeaveUnchanged,
        _ => {}
    }
    let said = said(reason, checked);
    if !attended() {
        eprintln!("{said}");
        return Decision::LeaveUnchanged;
    }
    let unchecked = if checked { "" } else { " It will not be checked first." };
    eprint!("{said}\nRun `{tool} {}` as typed anyway?{unchecked} [y/N] ", args.join(" "));
    let mut answer = String::new();
    let _ = io::stdin().lock().read_line(&mut answer);
    if matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        Decision::RunAsTyped
    } else {
        Decision::LeaveUnchanged
    }
}

/// Ask whether to run a command saw could not check, then run it as typed and scan the folder, or
/// leave the folder unchanged. Takes the tool, its arguments, saw's reason, whether saw checked it,
/// the real program, saw and the folder to scan. Returns the exit code.
fn run_or_leave(tool: &str, args: &[String], reason: &str, checked: bool, real: &Path, saw: &Path, folder: &str) -> i32 {
    match decide(tool, args, reason, checked) {
        Decision::RunAsTyped => run_then_scan(real, saw, args, folder),
        Decision::LeaveUnchanged => {
            eprintln!("saw: left the folder unchanged; {tool} did not run. To run it as typed, \
                       answer yes in a terminal, or set SAW_GOVERN_DECISION=run-as-typed.");
            2
        }
    }
}

/// Ask the person at a terminal whether to run a command saw's folder guard refused, then run it as
/// typed and scan the folder, or leave the folder unchanged. Only a person answers: a decision set
/// ahead in the environment is not one. Takes the tool, its arguments, the guard's reason, the real
/// program, saw and the folder to scan. Returns the exit code.
fn run_or_leave_in_person(tool: &str, args: &[String], reason: &str, real: &Path, saw: &Path, folder: &str) -> i32 {
    let said = said(reason, false);
    if attended() {
        eprint!("{said}\nRun `{tool} {}` as typed anyway? It will not be checked first. [y/N] ", args.join(" "));
        if matches!(read_answer().to_lowercase().as_str(), "y" | "yes") {
            return run_then_scan(real, saw, args, folder);
        }
    } else {
        eprintln!("{said}");
    }
    eprintln!("saw: left the folder unchanged; {tool} did not run. To run it as typed, answer yes in a terminal.");
    2
}

/// Run the command as typed with the real program, then scan the folder it changed or created.
/// Returns the real program's exit code.
fn run_then_scan(real: &Path, saw: &Path, args: &[String], folder: &str) -> i32 {
    let code = Command::new(real).args(args).status().ok().and_then(|s| s.code()).unwrap_or(127);
    let _ = Command::new(saw).args(["scan", folder, "--no-stream"]).status();
    code
}

fn real_saw() -> Option<PathBuf> {
    if let Some(p) = env::var_os("SAW_BIN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    which("saw", None)
}

/// The real program, never this stand-in. Prefer the placer's explicit path, else search PATH
/// skipping this executable's own directory.
fn real_tool(tool: &str) -> Option<PathBuf> {
    let var = if tool == "git" { "SAW_REAL_GIT" } else { "SAW_REAL_GH" };
    if let Some(p) = env::var_os(var) {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let me = env::current_exe().ok();
    which(tool, me.as_deref().and_then(|p| p.parent()))
}

fn which(program: &str, skip_dir: Option<&Path>) -> Option<PathBuf> {
    let me = env::current_exe().ok().and_then(|p| fs::canonicalize(p).ok());
    for dir in env::split_paths(&env::var_os("PATH").unwrap_or_default()) {
        if Some(dir.as_path()) == skip_dir {
            continue;
        }
        let candidate = dir.join(program);
        if !candidate.is_file() {
            continue;
        }
        // Never run this stand-in itself, even reached through a symlink named `git` or `gh`
        // that a system placement put first on PATH — that would loop forever.
        if fs::canonicalize(&candidate).ok().as_ref() == me.as_ref() {
            continue;
        }
        return Some(candidate);
    }
    None
}

/// Run git with the settings and environment that keep the folder's own programs from starting.
/// Takes the real git, the arguments and how to run them. Replaces this process.
fn run_real_with(real: &Path, args: &[String], run_with: &RunWith) -> ! {
    let err = Command::new(real).args(&run_with.arguments).args(args).envs(run_with.environment.iter().cloned()).exec();
    eprintln!("saw: could not run {}: {err}", real.display());
    exit(127);
}

fn run_real(real: &Path, args: &[String]) -> ! {
    let err = Command::new(real).args(args).exec(); // replaces this process on success
    eprintln!("saw: could not run {}: {err}", real.display());
    exit(127);
}

fn passthrough_raw(argv: &[String]) -> ! {
    // Invoked under an unknown name with no tool override: nothing to govern; try to run a real
    // program of that name so we are never worse than absent.
    let name = argv.first().map(String::as_str).unwrap_or("");
    let base = Path::new(name).file_name().and_then(|s| s.to_str()).unwrap_or("git");
    match which(base, env::current_exe().ok().as_deref().and_then(|p| p.parent())) {
        Some(real) => run_real(&real, &argv[1..]),
        None => {
            eprintln!("saw: {base} not found");
            exit(127)
        }
    }
}

// ---- managing the placement: `saw govern install` / `status` / `uninstall` run these ----

const SHIM_NAMES: [&str; 2] = ["git", "gh"];
const RC_NAMES: [&str; 3] = [".zshrc", ".bashrc", ".profile"];
const BLOCK_BEGIN: &str = "# >>> saw govern >>>";
const BLOCK_END: &str = "# <<< saw govern <<<";

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn home() -> Option<PathBuf> {
    env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from)
}

fn config_home() -> Option<PathBuf> {
    if let Some(x) = env::var_os("XDG_CONFIG_HOME").filter(|x| !x.is_empty()) {
        return Some(PathBuf::from(x));
    }
    home().map(|h| h.join(".config"))
}

fn govern_dir() -> Option<PathBuf> {
    config_home().map(|c| c.join("saw").join("govern"))
}
fn shim_dir() -> Option<PathBuf> {
    govern_dir().map(|g| g.join("bin"))
}
fn activate_path() -> Option<PathBuf> {
    govern_dir().map(|g| g.join("activate.sh"))
}

/// Quote a path for a POSIX shell.
fn sh_quote(path: &Path) -> String {
    single_quoted(&path.to_string_lossy())
}

fn activate_text(shim: &Path, saw: &str) -> String {
    format!(
        "# Written by `saw govern install`. Checks an incoming git or GitHub update before it\n\
         # lands in the folder you are working in. Remove it with `saw govern uninstall`.\n\
         _saw_shim={shim}\n\
         case \":$PATH:\" in\n\
         \x20\x20*\":$_saw_shim:\"*) ;;\n\
         \x20\x20*) PATH=\"$_saw_shim:$PATH\" ;;\n\
         esac\n\
         export PATH\n\
         export SAW_GOVERN_SYSTEM=1\n\
         export SAW_BIN={saw}\n\
         unset _saw_shim\n",
        shim = sh_quote(shim),
        saw = sh_quote(Path::new(saw)),
    )
}

fn rc_block(activate: &Path) -> String {
    let q = sh_quote(activate);
    format!("{BLOCK_BEGIN}\n[ -f {q} ] && . {q}\n{BLOCK_END}\n")
}

/// Rc text with any existing saw govern block removed.
fn strip_block(text: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed == BLOCK_BEGIN {
            skipping = true;
            continue;
        }
        if skipping {
            if trimmed == BLOCK_END {
                skipping = false;
            }
            continue;
        }
        out.push_str(line);
    }
    out
}

fn rc_targets(create_default: bool) -> Vec<PathBuf> {
    let Some(h) = home() else { return vec![] };
    let present: Vec<PathBuf> = RC_NAMES.iter().map(|n| h.join(n)).filter(|p| p.is_file()).collect();
    if !present.is_empty() || !create_default {
        present
    } else {
        vec![h.join(".profile")]
    }
}

fn admin(sub: &str, args: &[String]) -> i32 {
    match sub {
        "install" => admin_install(flag_value(args, "--saw")),
        "status" => admin_status(),
        "uninstall" => admin_uninstall(),
        _ => 2,
    }
}

fn admin_install(saw: Option<String>) -> i32 {
    let me = match env::current_exe() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("saw govern: could not find the stand-in to place.");
            return 1;
        }
    };
    let (Some(shim), Some(act)) = (shim_dir(), activate_path()) else {
        eprintln!("saw govern: HOME is not set, so there is nowhere to install.");
        return 1;
    };
    if fs::create_dir_all(&shim).is_err() {
        eprintln!("saw govern: could not create {}", shim.display());
        return 1;
    }
    let mut placed: Vec<&str> = vec![];
    for name in SHIM_NAMES {
        let link = shim.join(name);
        let _ = fs::remove_file(&link);
        if which(name, Some(&shim)).is_some() && symlink(&me, &link).is_ok() {
            placed.push(name);
        }
    }
    let saw_path = saw
        .or_else(|| real_saw().map(|p| p.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "saw".into());
    if fs::write(&act, activate_text(&shim, &saw_path)).is_err() {
        eprintln!("saw govern: could not write {}", act.display());
        return 1;
    }
    let mut turned_on: Vec<PathBuf> = vec![];
    for rc in rc_targets(true) {
        let text = fs::read_to_string(&rc).unwrap_or_default();
        let mut kept = strip_block(&text);
        if !kept.is_empty() && !kept.ends_with('\n') {
            kept.push('\n');
        }
        kept.push_str(&rc_block(&act));
        if fs::write(&rc, kept).is_ok() {
            turned_on.push(rc);
        }
    }
    if placed.is_empty() {
        println!("saw govern: found no git or gh to check updates for.");
    } else {
        println!("saw govern: now checking incoming updates to {} before they land.", placed.join(" and "));
    }
    for rc in &turned_on {
        println!("  on for new shells in {}", rc.display());
    }
    println!("  to turn it on in this shell now: . {}", act.display());
    println!("  undo any time: saw govern uninstall");
    0
}

fn admin_uninstall() -> i32 {
    if let Some(shim) = shim_dir() {
        for name in SHIM_NAMES {
            let _ = fs::remove_file(shim.join(name));
        }
        let _ = fs::remove_dir(&shim);
    }
    if let Some(act) = activate_path() {
        let _ = fs::remove_file(&act);
    }
    let mut cleaned = 0;
    if let Some(h) = home() {
        for name in RC_NAMES {
            let rc = h.join(name);
            if let Ok(text) = fs::read_to_string(&rc) {
                let kept = strip_block(&text);
                if kept != text && fs::write(&rc, kept).is_ok() {
                    cleaned += 1;
                }
            }
        }
    }
    println!("saw govern: took the stand-in back out ({cleaned} shell file(s) updated).");
    println!("  open a new terminal for it to take effect.");
    0
}

fn admin_status() -> i32 {
    let placed: Vec<&str> = shim_dir()
        .map(|shim| SHIM_NAMES.into_iter().filter(|n| shim.join(n).symlink_metadata().is_ok()).collect())
        .unwrap_or_default();
    let on_now = env::var_os("SAW_GOVERN_SYSTEM").is_some();
    if placed.is_empty() {
        println!("saw govern: not installed for terminals.");
        println!("  turn it on with: saw govern install");
        return 0;
    }
    println!("saw govern: checking updates to {} in terminals.", placed.join(" and "));
    println!(
        "  this shell: {}",
        if on_now { "on" } else { "off — open a new terminal, or source the activate file" }
    );
    0
}
