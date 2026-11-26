//! A stand-in that sits where the editor expects `git` or `gh` and asks `saw govern` about a
//! command that may bring files into the folder before it runs. A git command it reads with
//! certainty as one that brings none runs straight through, and the real program runs unchanged
//! whenever saw cannot answer.
//!
//! It is inert unless activated. A placer (the editor extension) activates it per command with
//! `SAW_GOVERN_HOLDING` and points it at the real program and at `saw`. A system install instead
//! sets `SAW_GOVERN_SYSTEM`, and the stand-in makes its own holding directory for each check and
//! removes it afterwards. Without either, every command passes straight through.

use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal};
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Stdio};

fn main() {
    let argv: Vec<String> = env::args().collect();
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    let base = Path::new(argv0).file_name().and_then(|s| s.to_str()).unwrap_or("");
    let base = base.strip_suffix(".exe").unwrap_or(base);
    // Invoked by its own name (not git/gh) and not asked to impersonate a tool: an admin
    // subcommand managing the placement, never a git command.
    if base != "git" && base != "gh" && env::var_os("SAW_STANDIN_TOOL").is_none() {
        if let Some(sub) = argv.get(1).map(String::as_str) {
            if matches!(sub, "install" | "status" | "uninstall") {
                exit(admin(sub, &argv[2..]));
            }
        }
    }
    let tool = match tool_name(argv.first().map(String::as_str).unwrap_or("")) {
        Some(t) => t,
        None => passthrough_raw(&argv),           // unknown name: find a real one and run it
    };
    let args: Vec<String> = argv.into_iter().skip(1).collect();
    let real = real_tool(&tool).unwrap_or_else(|| {
        eprintln!("saw: could not find the real {tool}");
        exit(127);
    });
    if governing() {
        let sent = sent_to_saw(&tool, &args);
        if sent != Sent::No {
            if let Some(code) = govern(&tool, &args, &real, sent == Sent::ForWhatItNames) {
                exit(code);                        // governed: saw applied it, or held it
            }
        }
    }
    run_real(&real, &args);                        // not governed, or saw could not answer
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

/// Git subcommands that never write files from elsewhere into the folder.
const NEVER_BRINGS_FILES: &[&str] = &[
    "add", "annotate", "blame", "branch", "cat-file", "check-attr", "check-ignore", "check-mailmap",
    "check-ref-format", "cherry", "clean", "commit", "commit-tree", "config", "count-objects", "credential",
    "credential-cache", "credential-store", "describe", "diff", "diff-files", "diff-index", "diff-tree",
    "for-each-ref", "fsck", "gc", "grep", "hash-object", "help", "init", "log", "ls-files", "ls-remote",
    "ls-tree", "maintenance", "merge-base", "mktag", "mktree", "mv", "name-rev", "notes", "pack-refs",
    "prune", "push", "range-diff", "reflog", "remote", "repack", "rev-list", "rev-parse", "rm", "shortlog",
    "show", "show-branch", "show-ref", "stage", "status", "symbolic-ref", "tag", "var", "verify-commit",
    "verify-tag", "version", "whatchanged", "write-tree",
];
/// gh options that take the repository a command acts on as their next argument.
const GH_REPOSITORY_OPTIONS: &[&str] = &["-R", "--repo"];

/// Git's global options that take the next argument as their value.
const GIT_OPTIONS_WITH_VALUE: &[&str] = &["-C", "-c", "--shallow-file", "--git-dir", "--work-tree", "--namespace", "--attr-source"];
/// Git's global options that take their value after `=`.
const GIT_OPTIONS_WITH_JOINED_VALUE: &[&str] = &["--git-dir=", "--work-tree=", "--namespace=", "--attr-source="];
/// Git's global options that take no value.
const GIT_FLAGS: &[&str] = &[
    "-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks",
    "--no-advice", "--bare", "--literal-pathspecs", "--no-literal-pathspecs", "--glob-pathspecs",
    "--noglob-pathspecs", "--icase-pathspecs",
];
/// Git's global options after which git prints something and runs no subcommand.
const GIT_QUERIES: &[&str] = &["-h", "--help", "-v", "--version", "--exec-path", "--html-path", "--man-path", "--info-path"];
/// Configuration sections that change which commands git runs under a name.
const SECTIONS_THAT_NAME_COMMANDS: &[&str] = &["alias", "include", "includeif"];
/// Settings that make git run nothing. Any other setting a command line gives is sent to saw.
const SETTINGS_THAT_RUN_NOTHING: &[&str] = &["user.name", "user.email", "core.quotepath", "init.defaultbranch",
    "commit.gpgsign", "tag.gpgsign", "color.ui"];
/// Sections whose every setting makes git run nothing.
const SECTIONS_THAT_RUN_NOTHING: &[&str] = &["advice", "color"];
/// Subcommands that write a file `--output` names.
const WRITE_AN_OUTPUT: &[&str] = &["diff", "diff-files", "diff-index", "diff-tree", "log", "show", "whatchanged",
    "range-diff"];
/// `git config` options that only read.
const CONFIG_READS: &[&str] = &["--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color",
    "--get-colorbool", "--list", "-l"];
/// `git config` options that write.
const CONFIG_WRITES: &[&str] = &["--add", "--replace-all", "--unset", "--unset-all", "--rename-section",
    "--remove-section", "-e", "--edit"];
/// Environment variables that give git settings.
const SETTINGS_VARIABLES: &[&str] = &["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"];

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
}

/// Read git's global options up to the subcommand. Takes the arguments without the program name.
/// Returns the reading, which stops at the first option the stand-in cannot read.
fn read_git_line(args: &[String]) -> GitLine<'_> {
    let mut line = GitLine { subcommand: None, folders: Vec::new(), read: true, settings: Vec::new() };
    let mut i = 0;
    while let Some(arg) = args.get(i).map(String::as_str) {
        if !arg.starts_with('-') {
            line.subcommand = Some(i);
            return line;
        }
        if GIT_QUERIES.contains(&arg) || arg.starts_with("--list-cmds=") {
            return line;
        }
        if GIT_FLAGS.contains(&arg) || GIT_OPTIONS_WITH_JOINED_VALUE.iter().any(|p| arg.starts_with(p)) {
            i += 1;
            continue;
        }
        let Some(value) = args.get(i + 1).filter(|_| GIT_OPTIONS_WITH_VALUE.contains(&arg)) else {
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
    SECTIONS_THAT_NAME_COMMANDS.contains(&section.as_str())
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
/// setting, an output file, a hooks template, a configuration change or a fetch, and gh's
/// bringing-files commands.
fn sent_to_saw(tool: &str, args: &[String]) -> Sent {
    match tool {
        "git" => git_sent(args),
        "gh" if gh_brings_files_in(args) => Sent::ToSaw,
        _ => Sent::No,
    }
}

/// Decide whether a git command goes to saw first.
fn git_sent(args: &[String]) -> Sent {
    let line = read_git_line(args);
    if !line.read {
        return Sent::ToSaw;
    }
    let Some(at) = line.subcommand else { return Sent::No };
    let sub = args[at].as_str();
    if !NEVER_BRINGS_FILES.contains(&sub) {
        return Sent::ToSaw;
    }
    if names_what_saw_checks(sub, &args[at + 1..], &line.settings) {
        Sent::ForWhatItNames
    } else {
        Sent::No
    }
}

/// Whether a command that brings no files names a setting that may run something, an output file,
/// a hooks template, a configuration change or a fetch.
fn names_what_saw_checks(sub: &str, rest: &[String], settings: &[&str]) -> bool {
    let runs_something = |key: &&str| {
        let key = key.to_ascii_lowercase();
        let section = key.split('.').next().unwrap_or("");
        !(SETTINGS_THAT_RUN_NOTHING.contains(&key.as_str()) || SECTIONS_THAT_RUN_NOTHING.contains(&section))
    };
    if settings.iter().any(runs_something) || SETTINGS_VARIABLES.iter().any(|name| env::var_os(name).is_some()) {
        return true;
    }
    let options: Vec<&str> = rest.iter().map(String::as_str).take_while(|arg| *arg != "--").collect();
    let words: Vec<&str> = options.iter().copied().filter(|arg| !arg.starts_with('-')).collect();
    match sub {
        _ if WRITE_AN_OUTPUT.contains(&sub) => options.iter().any(|arg| *arg == "--output" || arg.starts_with("--output=")),
        "init" => env::var_os("GIT_TEMPLATE_DIR").is_some() || options.iter().any(|arg| {
            let name = arg.split('=').next().unwrap_or("");
            name.len() > 3 && "--template".starts_with(name)
        }),
        "config" => !config_only_reads(&options, &words),
        "remote" => words.first() == Some(&"update")
            || (words.first() == Some(&"add") && options.iter().any(|arg| *arg == "-f" || *arg == "--fetch")),
        _ => false,
    }
}

/// Whether a `git config` command only reads.
fn config_only_reads(options: &[&str], words: &[&str]) -> bool {
    if options.iter().any(|arg| CONFIG_WRITES.contains(&arg.split('=').next().unwrap_or(""))) {
        return false;
    }
    options.iter().any(|arg| CONFIG_READS.contains(arg))
        || matches!(words.first(), Some(&"get") | Some(&"list"))
        || (words.len() == 1 && !matches!(words[0], "set" | "unset" | "edit" | "rename-section" | "remove-section"))
}

/// Whether a gh command brings files into the open folder.
fn gh_brings_files_in(args: &[String]) -> bool {
    let mut words = Vec::new();
    let mut given = args.iter().map(String::as_str).take_while(|a| *a != "--");
    while let Some(arg) = given.next() {
        if GH_REPOSITORY_OPTIONS.contains(&arg) {
            given.next();
        } else if !arg.starts_with('-') {
            words.push(arg);
        }
    }
    matches!(
        (words.first().copied(), words.get(1).copied()),
        (Some("pr"), Some("checkout"))
            | (Some("repo"), Some("sync"))
            | (Some("release"), Some("download"))
            | (Some("run"), Some("download"))
    )
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

/// Run the check. Returns an exit code when the command was governed (applied or held), or `None`
/// to fall back to the real program (saw absent or it could not answer — fail open, never break git).
fn govern(tool: &str, args: &[String], real: &Path, for_what_it_names: bool) -> Option<i32> {
    let saw = real_saw()?;
    let (holding, temporary) = holding_dir()?;
    let code = govern_with(&saw, tool, args, &holding, real, for_what_it_names);
    if temporary {
        let _ = std::fs::remove_dir_all(&holding); // never leave a held update on disk
    }
    code
}

/// The holding directory for this check, and whether the stand-in owns it. A placer's
/// `SAW_GOVERN_HOLDING` is used as given and left in place. In system mode (`SAW_GOVERN_SYSTEM`)
/// a fresh directory is made under the system temp directory and removed when the check is done.
fn holding_dir() -> Option<(PathBuf, bool)> {
    if let Some(given) = env::var_os("SAW_GOVERN_HOLDING") {
        return Some((PathBuf::from(given), false));
    }
    env::var_os("SAW_GOVERN_SYSTEM")?;
    let unique = format!(
        "saw-govern-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let dir = env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).ok()?;
    Some((dir, true))
}

/// Run `saw govern prepare`, then `apply` when it comes back clean. Returns the exit code, or
/// `None` to fall back to the real program (fail open, never break git).
fn govern_with(saw: &Path, tool: &str, args: &[String], holding: &Path, real: &Path,
               for_what_it_names: bool) -> Option<i32> {
    let repo = target_repo(args);
    let mut prepare = Command::new(saw);
    prepare
        .args(["govern", "prepare", "--json", "--repo"])
        .arg(&repo)
        .arg("--into")
        .arg(holding)
        .args(if for_what_it_names { &["--brings-no-files"][..] } else { &[][..] })
        .args(["--tool", tool, "--"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()); // progress/status reaches the operator
    let output = prepare.output().ok()?;
    let prepared = output.status;
    let answer: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap_or_default();
    if answer.get("passthrough").and_then(serde_json::Value::as_bool) == Some(true) {
        return None;
    }
    if offers_let_in(&answer) {
        let held = prepared.code().filter(|code| *code != 0).unwrap_or(1);
        return Some(let_in_or_leave(saw, &answer, held));
    }
    if !prepared.success() {
        if let Some(reason) = unchecked_reason(&String::from_utf8_lossy(&output.stdout)) {
            let checked = scan_finished(&answer);
            if !may_run_as_typed(&answer) {
                eprintln!("{}", said(&reason, checked));
                for step in answer.get("next_steps").and_then(serde_json::Value::as_array).into_iter().flatten() {
                    if let Some(text) = step.as_str() {
                        eprintln!("  - {text}");
                    }
                }
                eprintln!("saw: left the folder unchanged; {tool} did not run.");
                return Some(2);
            }
            return Some(match decide(tool, args, &reason, checked) {
                Decision::RunAsTyped => run_then_scan(real, saw, args, &scanned_after(&answer, &repo)),
                Decision::LeaveUnchanged => {
                    eprintln!("saw: left the folder unchanged; {tool} did not run. To run it as typed, \
                               answer yes in a terminal, or set SAW_GOVERN_DECISION=run-as-typed.");
                    2
                }
            });
        }
        say_why_held(&answer);
        return prepared.code().or(Some(2));
    }
    // Clean or residue: apply the tree saw already checked, without fetching again.
    let applied = Command::new(saw)
        .args(["govern", "apply", "--json", "--repo"])
        .arg(&repo)
        .arg("--into")
        .arg(holding)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .ok()?;
    if applied.success() {
        relay_output(&answer);
    }
    applied.code().or(Some(0))
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
/// from the environment: letting in a finding is decided by a person, each time. Returns the exit
/// code: the let-in command's, or `held` when the folder is left unchanged.
fn let_in_or_leave(saw: &Path, answer: &serde_json::Value, held: i32) -> i32 {
    say_why_held(answer);
    let command: Vec<String> = answer
        .pointer("/decision/let_in")
        .and_then(serde_json::Value::as_array)
        .map(|parts| parts.iter().filter_map(|p| p.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if command.len() < 2 {
        return held;
    }
    let typed = answer.pointer("/decision/confirm").and_then(serde_json::Value::as_str) == Some("typed");
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        eprintln!("saw: after you review it, let it in with: {}{}", command.join(" "),
                  if typed { " --confirm <folder name>" } else { "" });
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
fn unchecked_reason(answer: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(answer.trim()).ok()?;
    parsed.get("decision")?;
    let reason = parsed.get("reason").and_then(serde_json::Value::as_str);
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
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
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
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
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
