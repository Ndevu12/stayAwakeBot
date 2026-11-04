//! A stand-in that sits where the editor expects `git` or `gh` and holds a bringing-files command
//! until `saw govern` has checked what it would bring in. Everything else — and anything saw cannot
//! answer — runs the real program unchanged, so the stand-in can never break the operator's git.
//!
//! It is inert unless activated. A placer (the editor extension) activates it per command with
//! `SAW_GOVERN_HOLDING` and points it at the real program and at `saw`. A system install instead
//! sets `SAW_GOVERN_SYSTEM`, and the stand-in makes its own holding directory for each check and
//! removes it afterwards. Without either, every command passes straight through.

use std::env;
use std::fs;
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
    if governing() && brings_files_in(&tool, &args) {
        if let Some(code) = govern(&tool, &args) {
            exit(code);                            // governed: saw applied it, or held it
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

/// Whether `(tool, args)` brings files into the open folder. Mirrors `lib/git/incoming.classify`;
/// `saw govern` re-decides authoritatively, so a wider guess here only costs a passthrough.
fn brings_files_in(tool: &str, args: &[String]) -> bool {
    let positional: Vec<&str> = positionals(args);
    match tool {
        "git" => match git_subcommand(args).as_deref() {
            Some("pull") | Some("fetch") | Some("merge") | Some("rebase") | Some("checkout")
            | Some("switch") => true,
            Some("submodule") => positional.get(1).copied() == Some("update"),
            _ => false,
        },
        "gh" => matches!(
            (positional.first().copied(), positional.get(1).copied()),
            (Some("pr"), Some("checkout"))
                | (Some("repo"), Some("sync"))
                | (Some("release"), Some("download"))
                | (Some("run"), Some("download"))
        ),
        _ => false,
    }
}

fn positionals<'a>(args: &'a [String]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            break;
        }
        if a.starts_with('-') {
            if matches!(a, "-C" | "-c" | "--git-dir" | "--work-tree") && !a.contains('=') {
                i += 1; // consumes a value
            }
            i += 1;
            continue;
        }
        out.push(a);
        i += 1;
    }
    out
}

fn git_subcommand(args: &[String]) -> Option<String> {
    positionals(args).first().map(|s| s.to_string())
}

/// The repository the command acts on: an explicit `git -C <path>`, else the current directory.
fn target_repo(args: &[String]) -> String {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-C" {
            if let Some(p) = args.get(i + 1) {
                return p.clone();
            }
        }
        i += 1;
    }
    env::current_dir().ok().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| ".".into())
}

/// Run the check. Returns an exit code when the command was governed (applied or held), or `None`
/// to fall back to the real program (saw absent or it could not answer — fail open, never break git).
fn govern(tool: &str, args: &[String]) -> Option<i32> {
    let saw = real_saw()?;
    let (holding, temporary) = holding_dir()?;
    let code = govern_with(&saw, tool, args, &holding);
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
fn govern_with(saw: &Path, tool: &str, args: &[String], holding: &Path) -> Option<i32> {
    let repo = target_repo(args);
    let mut prepare = Command::new(saw);
    prepare
        .args(["govern", "prepare", "--json", "--repo"])
        .arg(&repo)
        .arg("--into")
        .arg(holding)
        .args(["--tool", tool, "--"])
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit()); // progress/status reaches the operator
    let prepared = prepare.status().ok()?;
    if !prepared.success() {
        // Held: suspicious / infected / could not finish. The open folder is unchanged.
        eprintln!("saw: held this update — it was not applied. Run `saw govern` output for why.");
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
    applied.code().or(Some(0))
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
