//! A command the stand-in would run directly, in a folder whose own settings name a program saw
//! cannot keep from starting, never runs as typed on saw's word that it brings no files: the person
//! at a terminal decides, and with no one to ask the folder is left unchanged.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod common;

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");
const RUNS_AS_TYPED: &str = r#"{"passthrough":true,"reason":"the command brings no files in"}"#;

fn exec_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct Folder {
    dir: PathBuf,
    repo: PathBuf,
    real_log: PathBuf,
    saw_log: PathBuf,
}

impl Folder {
    fn new(name: &str) -> Folder {
        let dir = std::env::temp_dir().join(format!("saw-standin-refused-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let git = common::real_git();
        let repo = dir.join("repo");
        let made = Command::new(&git).args(["init", "-q"]).arg(&repo).env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1").stdin(Stdio::null()).status().unwrap();
        assert!(made.success());
        let config = repo.join(".git").join("config");
        let mut text = fs::read_to_string(&config).unwrap();
        text.push_str("[gc]\n\trecentObjectsHook = /nonexistent/planted-program\n");
        fs::write(&config, text).unwrap();
        let (real_log, saw_log) = (dir.join("real.log"), dir.join("saw.log"));
        exec_script(&dir.join("real-git"), &format!("#!/bin/sh\necho \"$@\" >> {real_log:?}\nexec {git:?} \"$@\"\n"));
        exec_script(&dir.join("fake-saw"), &format!("#!/bin/sh\necho \"$@\" >> {saw_log:?}\nprintf '%s\\n' '{RUNS_AS_TYPED}'\n"));
        Folder { dir, repo, real_log, saw_log }
    }

    fn run(&self, decision: Option<&str>) -> Output {
        let mut command = Command::new(STANDIN);
        command
            .arg("status")
            .current_dir(&self.repo)
            .env("SAW_STANDIN_TOOL", "git")
            .env("SAW_REAL_GIT", self.dir.join("real-git"))
            .env("SAW_BIN", self.dir.join("fake-saw"))
            .env("SAW_GOVERN_HOLDING", self.dir.join("holding"))
            .env("HOME", &self.dir)
            .env("XDG_STATE_HOME", self.dir.join("state"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("SAW_GOVERN_SYSTEM")
            .env_remove("SAW_GOVERN_DECISION")
            .stdin(Stdio::null());
        if let Some(choice) = decision {
            command.env("SAW_GOVERN_DECISION", choice);
        }
        command.output().unwrap()
    }

    fn ran_the_command(&self) -> bool {
        fs::read_to_string(&self.real_log).unwrap_or_default().lines().any(|line| line.ends_with("status"))
    }
}

#[test]
fn with_no_one_to_ask_git_does_not_run_and_the_folder_is_unchanged() {
    let folder = Folder::new("unattended");
    let done = folder.run(None);
    assert!(fs::read_to_string(&folder.saw_log).unwrap_or_default().contains("govern prepare"), "saw was not asked");
    assert!(!folder.ran_the_command(), "git ran on saw's word alone");
    assert!(!done.status.success());
    assert!(String::from_utf8_lossy(&done.stderr).contains("left the folder unchanged"), "{}", String::from_utf8_lossy(&done.stderr));
}

#[test]
fn the_operator_who_chooses_to_run_it_as_typed_runs_it() {
    let folder = Folder::new("decided");
    folder.run(Some("run-as-typed"));
    assert!(folder.ran_the_command(), "git did not run after the operator chose to run it");
    assert!(fs::read_to_string(&folder.saw_log).unwrap_or_default().contains("scan"), "the folder was not scanned after");
}
