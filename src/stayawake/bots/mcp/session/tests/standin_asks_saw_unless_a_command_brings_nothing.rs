// Unix only: POSIX shell scripts stand in for git and saw.
#![cfg(unix)]
//! The git stand-in asks saw before every command it cannot read with certainty as one that brings
//! no files into the folder, however it is spelled, and runs the rest straight through.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");
const HELD_INFECTED: &str = r#"{"scan":{"results":[{"verdict":"infected"}]},"next_steps":["Tell whoever pushed it."]}"#;

fn exec_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct Terminal {
    dir: PathBuf,
    real_log: PathBuf,
    saw_log: PathBuf,
}

impl Terminal {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("saw-standin-asks-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let real_log = dir.join("real.log");
        let saw_log = dir.join("saw.log");
        exec_script(&dir.join("real-program"), &format!("#!/bin/sh\necho \"$@\" >> {real_log:?}\n"));
        exec_script(
            &dir.join("fake-saw"),
            &format!(
                "#!/bin/sh\necho \"$@\" >> {saw_log:?}\n\
                 [ \"$1\" = scan ] && exit 0\n\
                 printf '%s\\n' \"$SAW_FAKE_ANSWER\"\nexit \"$SAW_FAKE_EXIT\"\n"
            ),
        );
        Terminal { dir, real_log, saw_log }
    }

    fn run_as(&self, tool: &str, args: &[&str], answer: &str, exit: i32, decision: Option<&str>) -> Output {
        let real = if tool == "git" { "SAW_REAL_GIT" } else { "SAW_REAL_GH" };
        let mut command = Command::new(STANDIN);
        command
            .args(args)
            .current_dir(&self.dir)
            .env("SAW_STANDIN_TOOL", tool)
            .env(real, self.dir.join("real-program"))
            .env("SAW_BIN", self.dir.join("fake-saw"))
            .env("SAW_FAKE_ANSWER", answer)
            .env("SAW_FAKE_EXIT", exit.to_string())
            .env("PATH", &self.dir)
            .env("SAW_GOVERN_HOLDING", self.dir.join("holding"))
            .env_remove("SAW_GOVERN_SYSTEM")
            .env_remove("SAW_GOVERN_DECISION")
            .stdin(Stdio::null());
        if let Some(choice) = decision {
            command.env("SAW_GOVERN_DECISION", choice);
        }
        command.output().unwrap()
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_as("git", args, HELD_INFECTED, 3, None)
    }

    /// Take what a program wrote to its log since the last call, or None when it did not run.
    fn took(&self, log: &Path) -> Option<String> {
        let text = fs::read_to_string(log).ok();
        let _ = fs::remove_file(log);
        text
    }
}

#[test]
fn every_spelling_that_can_bring_files_in_asks_saw_and_never_runs_git_first() {
    let terminal = Terminal::new("bringing");
    let spellings: &[&[&str]] = &[
        &["reset", "--hard", "origin/evil"],
        &["reset", "--soft", "origin/evil"],
        &["restore", "--source", "origin/evil", "-S", "-W", "."],
        &["read-tree", "-u", "--reset", "origin/evil"],
        &["cherry-pick", "origin/evil"],
        &["revert", "origin/evil"],
        &["worktree", "add", "../wt", "origin/evil"],
        &["worktree", "list"],
        &["stash"],
        &["stash", "pop"],
        &["update-index", "--add", "--cacheinfo", "100644", "0123abcd", "loader.js"],
        &["update-ref", "refs/heads/main", "origin/evil"],
        &["co", "origin/evil"],
        &["-c", "alias.x=merge", "x", "origin/evil"],
        &["-c", "Include.path=elsewhere", "status"],
        &["--namespace", "n", "checkout", "origin/evil"],
        &["--attr-source", "HEAD", "checkout", "origin/evil"],
        &["--config-env=alias.x=MERGE", "x", "origin/evil"],
        &["--exec-path=elsewhere", "status"],
        &["--no-such-option", "status"],
        &["chekout", "origin/evil"],
        &["mrege", "origin/evil"],
        &["clone", "https://example.invalid/repo"],
        &["pull"],
        &["checkout", "origin/evil"],
    ];
    for spelling in spellings {
        terminal.run(spelling);
        let asked = terminal.took(&terminal.saw_log).unwrap_or_default();
        assert!(asked.contains("govern prepare"), "{spelling:?} did not ask saw");
        assert_eq!(terminal.took(&terminal.real_log), None, "{spelling:?} ran the real git before saw answered");
    }
}

#[test]
fn a_command_that_brings_no_files_runs_without_asking_saw() {
    let terminal = Terminal::new("straight");
    let spellings: &[&[&str]] = &[
        &["status"],
        &["-c", "core.quotepath=false", "status", "-z"],
        &["--no-pager", "-C", "sub", "log", "-1"],
        &["--version"],
        &["--list-cmds=main"],
        &[],
    ];
    for spelling in spellings {
        terminal.run(spelling);
        assert_eq!(terminal.took(&terminal.saw_log), None, "{spelling:?} asked saw");
        let ran = terminal.took(&terminal.real_log).unwrap_or_default();
        let last = ran.lines().last().unwrap_or_default();
        assert_eq!(last, spelling.join(" "), "{spelling:?} did not run as typed in a folder whose settings start no program: {ran}");
    }
}

#[test]
fn a_command_naming_a_repository_that_cannot_be_read_asks_saw() {
    let terminal = Terminal::new("unreadable");
    terminal.run(&["--git-dir=.git", "rev-parse", "HEAD"]);
    assert!(terminal.took(&terminal.saw_log).unwrap_or_default().contains("govern prepare"), "saw was not asked");
    let ran = terminal.took(&terminal.real_log).unwrap_or_default();
    assert!(!ran.lines().any(|line| line.ends_with("--git-dir=.git rev-parse HEAD")), "git ran before saw answered: {ran}");
}

#[test]
fn a_github_command_that_names_its_repository_asks_saw() {
    let terminal = Terminal::new("gh");
    for spelling in [&["-R", "owner/repo", "pr", "checkout", "7"][..], &["--repo", "owner/repo", "repo", "sync"]] {
        terminal.run_as("gh", spelling, HELD_INFECTED, 3, None);
        assert!(terminal.took(&terminal.saw_log).unwrap_or_default().contains("govern prepare"), "{spelling:?}");
        assert_eq!(terminal.took(&terminal.real_log), None, "{spelling:?} ran gh before saw answered");
    }
    terminal.run_as("gh", &["-R", "owner/repo", "pr", "list"], HELD_INFECTED, 3, None);
    assert_eq!(terminal.took(&terminal.saw_log), None, "listing pull requests asked saw");
}

#[test]
fn saw_checks_the_folder_git_would_act_on() {
    let terminal = Terminal::new("folder");
    terminal.run(&["-C", "a", "-C", "b", "reset", "--hard", "origin/evil"]);
    let expected = format!("--repo {} ", terminal.dir.join("a").join("b").display());
    assert!(terminal.took(&terminal.saw_log).unwrap_or_default().contains(&expected), "saw was not told {expected}");
    terminal.run(&["switch", "-C", "main", "origin/evil"]);
    let expected = format!("--repo {} ", terminal.dir.display());
    assert!(terminal.took(&terminal.saw_log).unwrap_or_default().contains(&expected), "a switch option was read as the folder");
}

#[test]
fn a_command_run_as_typed_is_followed_by_a_scan_of_the_folder_saw_names() {
    let terminal = Terminal::new("scan-after");
    let created = terminal.dir.join("tool");
    let answer = format!(
        r#"{{"reason":"saw does not check that command","decision":{{"choices":["run-as-typed","leave-unchanged"],"scan_after":["saw","scan","{}"]}}}}"#,
        created.display()
    );
    terminal.run_as("git", &["clone", "https://example.invalid/tool"], &answer, 2, Some("run-as-typed"));
    assert!(terminal.took(&terminal.real_log).is_some(), "the clone did not run as typed");
    let said = terminal.took(&terminal.saw_log).unwrap_or_default();
    assert!(said.contains(&format!("scan {} --no-stream", created.display())), "{said}");
}

#[test]
fn a_held_command_says_why_and_what_to_do() {
    let terminal = Terminal::new("held");
    let out = terminal.run(&["update-index", "--add", "--cacheinfo", "100644", "0123abcd", "loader.js"]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("held this update (infected)"), "{said}");
    assert!(said.contains("Tell whoever pushed it."), "{said}");
    assert_eq!(terminal.took(&terminal.real_log), None);
}
