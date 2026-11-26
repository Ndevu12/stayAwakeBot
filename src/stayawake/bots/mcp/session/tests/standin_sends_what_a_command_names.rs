//! A git command the stand-in reads as bringing no files still goes to saw when it names a setting
//! that may run something, a file to write, a hooks template, a configuration change or a fetch,
//! and saw is told the stand-in reads it as bringing no files.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");
const ASKED: &str = r#"{"reason":"the command makes git run files from this folder","checked":true,"decision":{"choices":["run-as-typed","leave-unchanged"]}}"#;

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
        let dir = std::env::temp_dir().join(format!("saw-standin-names-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let real_log = dir.join("real.log");
        let saw_log = dir.join("saw.log");
        exec_script(&dir.join("real-program"), &format!("#!/bin/sh\necho \"$@\" >> {real_log:?}\n"));
        exec_script(
            &dir.join("fake-saw"),
            &format!("#!/bin/sh\necho \"$@\" >> {saw_log:?}\nprintf '%s\\n' '{ASKED}'\nexit 2\n"),
        );
        Terminal { dir, real_log, saw_log }
    }

    fn run(&self, args: &[&str], environment: &[(&str, &str)]) -> Output {
        let mut command = Command::new(STANDIN);
        command
            .args(args)
            .current_dir(&self.dir)
            .env("SAW_STANDIN_TOOL", "git")
            .env("SAW_REAL_GIT", self.dir.join("real-program"))
            .env("SAW_BIN", self.dir.join("fake-saw"))
            .env("PATH", &self.dir)
            .env("SAW_GOVERN_HOLDING", self.dir.join("holding"))
            .env_remove("SAW_GOVERN_SYSTEM")
            .env_remove("SAW_GOVERN_DECISION")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_TEMPLATE_DIR")
            .stdin(Stdio::null());
        for (name, value) in environment {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn took(&self, log: &Path) -> Option<String> {
        let text = fs::read_to_string(log).ok();
        let _ = fs::remove_file(log);
        text
    }
}

#[test]
fn a_command_that_names_what_saw_checks_goes_to_saw_and_does_not_run() {
    let terminal = Terminal::new("named");
    let named: &[(&[&str], &[(&str, &str)])] = &[
        (&["-c", "core.hooksPath=.githooks", "commit", "-m", "x"], &[]),
        (&["-c", "core.fsmonitor=./watch.sh", "status"], &[]),
        (&["commit", "-m", "x"], &[("GIT_CONFIG_PARAMETERS", "'core.hooksPath'='.githooks'")]),
        (&["commit", "-m", "x"], &[("GIT_CONFIG_COUNT", "1")]),
        (&["diff", "--output=loader.js", "HEAD", "origin/evil"], &[]),
        (&["log", "--output", "run.sh", "-1"], &[]),
        (&["init", "--template=hooks-template"], &[]),
        (&["init", "--templ", "hooks-template"], &[]),
        (&["init"], &[("GIT_TEMPLATE_DIR", "hooks-template")]),
        (&["config", "core.hooksPath", ".githooks"], &[]),
        (&["config", "set", "core.hooksPath", ".githooks"], &[]),
        (&["config", "--add", "include.path", "shared.cfg"], &[]),
        (&["config", "--edit"], &[]),
        (&["remote", "add", "-f", "other", "https://example.invalid/r"], &[]),
        (&["remote", "update"], &[]),
    ];
    for (args, environment) in named {
        let out = terminal.run(args, environment);
        let asked = terminal.took(&terminal.saw_log).unwrap_or_default();
        assert!(asked.contains("--brings-no-files"), "{args:?} {environment:?}: saw was not told: {asked:?}");
        assert!(terminal.took(&terminal.real_log).is_none(), "{args:?}: git ran before saw answered");
        assert_ne!(out.status.code(), Some(0), "{args:?}");
    }
}

#[test]
fn a_command_that_names_nothing_saw_checks_runs_as_typed() {
    let terminal = Terminal::new("plain");
    let plain: &[&[&str]] = &[
        &["status"],
        &["-c", "user.name=Me", "-c", "user.email=me@example.invalid", "commit", "-m", "x"],
        &["-c", "color.ui=always", "log"],
        &["-c", "advice.detachedHead=false", "status"],
        &["diff", "HEAD"],
        &["log", "-1", "--", "--output=x"],
        &["init", "new-project"],
        &["config", "--get", "core.hooksPath"],
        &["config", "user.name"],
        &["config", "get", "user.name"],
        &["remote", "add", "origin", "https://example.invalid/r"],
        &["remote", "-v"],
    ];
    for args in plain {
        terminal.run(args, &[]);
        assert!(terminal.took(&terminal.saw_log).is_none(), "{args:?}: saw was asked");
        assert!(terminal.took(&terminal.real_log).is_some(), "{args:?}: git did not run");
    }
}

#[test]
fn a_command_the_stand_in_does_not_read_as_bringing_no_files_is_not_marked() {
    let terminal = Terminal::new("unmarked");
    terminal.run(&["reset", "--hard", "origin/evil"], &[]);
    let asked = terminal.took(&terminal.saw_log).unwrap_or_default();
    assert!(asked.contains("prepare") && !asked.contains("--brings-no-files"), "{asked:?}");
}

#[test]
fn a_check_that_needed_no_scan_is_said_to_be_checked() {
    let terminal = Terminal::new("wording");
    let out = terminal.run(&["config", "core.hooksPath", ".githooks"], &[]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("saw: checked this update"), "{said}");
}
