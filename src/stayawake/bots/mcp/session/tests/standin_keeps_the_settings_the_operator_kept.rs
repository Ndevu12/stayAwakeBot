//! A command the stand-in runs directly keeps the programs a repository's own settings start (its
//! hooks, a git-crypt-style filter, fsmonitor) when the operator kept exactly those settings.
//! Settings the operator did not keep, or that changed after that, do not start. With no one to ask,
//! the stand-in says how to keep them. A decision set ahead in the environment never keeps them.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use saw_mcp::folder_guard::{fingerprint, kept_settings, Environment};

mod common;

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");
const RUNS_AS_TYPED: &str = r#"{"passthrough":true,"reason":"the command brings no files in"}"#;

fn exec_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct Repository {
    dir: PathBuf,
    repo: PathBuf,
    log: PathBuf,
    git: PathBuf,
}

impl Repository {
    fn new(name: &str) -> Repository {
        let dir = std::env::temp_dir().join(format!("saw-standin-kept-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let (git, repo, log) = (common::real_git(), dir.join("repo"), dir.join("programs.log"));
        fs::write(dir.join(".gitconfig"), "[user]\n\tname = Operator\n\temail = operator@example.invalid\n").unwrap();
        fs::create_dir_all(&repo).unwrap();
        let made = Repository { dir, repo, log, git };
        made.real(&["init", "-q", "."]);
        fs::write(made.repo.join(".gitattributes"), "*.secret filter=crypt\n").unwrap();
        fs::write(made.repo.join("notes.secret"), "one\n").unwrap();
        made.real(&["add", "."]);
        made.real(&["commit", "-q", "-m", "first"]);
        let program = made.dir.join("program");
        exec_script(&program, &format!("#!/bin/sh\necho \"$1\" >> {:?}\ncat\n", made.log));
        let mut config = fs::read_to_string(made.repo.join(".git/config")).unwrap();
        config.push_str(&format!("[filter \"crypt\"]\n\tclean = {} cleaned\n\tsmudge = {} smudged\n[core]\n\tfsmonitor = {} fsmonitor\n",
                                 program.display(), program.display(), program.display()));
        fs::write(made.repo.join(".git/config"), config).unwrap();
        exec_script(&made.repo.join(".git/hooks/pre-commit"), &format!("#!/bin/sh\necho hook >> {:?}\n", made.log));
        exec_script(&made.dir.join("fake-saw"), &format!("#!/bin/sh\necho \"$@\" >> {:?}\nprintf '%s\\n' '{RUNS_AS_TYPED}'\n", made.dir.join("saw.log")));
        made
    }

    fn environ(&self) -> Environment {
        let mut environ = Environment::new();
        environ.insert("HOME".into(), self.dir.display().to_string());
        environ.insert("PATH".into(), std::env::var("PATH").unwrap_or_default());
        environ.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        environ.insert("GIT_CONFIG_GLOBAL".into(), self.dir.join(".gitconfig").display().to_string());
        environ.insert("XDG_STATE_HOME".into(), self.dir.join("state").display().to_string());
        environ.insert("XDG_CACHE_HOME".into(), self.dir.join("cache").display().to_string());
        environ
    }

    fn real(&self, args: &[&str]) {
        let done = Command::new(&self.git).arg("-C").arg(&self.repo).args(args).env_clear().envs(self.environ())
            .stdin(Stdio::null()).stdout(Stdio::null()).status().unwrap();
        assert!(done.success(), "git {args:?}");
    }

    fn keep(&self) {
        let found = fingerprint(&self.git, &self.repo, &["status".to_string()], &self.environ()).unwrap().unwrap();
        let record = kept_settings::record_path(&self.environ()).unwrap();
        fs::create_dir_all(record.parent().unwrap()).unwrap();
        let kept = serde_json::json!({"version": 1, "repositories": {found.repository.display().to_string(): found.digest()}});
        fs::write(record, kept.to_string()).unwrap();
    }

    fn standin(&self, args: &[&str], decision: Option<&str>) -> Output {
        let mut command = Command::new(STANDIN);
        command.args(args).current_dir(&self.repo).env_clear().envs(self.environ())
            .env("SAW_STANDIN_TOOL", "git")
            .env("SAW_REAL_GIT", &self.git)
            .env("SAW_BIN", self.dir.join("fake-saw"))
            .env("SAW_GOVERN_HOLDING", self.dir.join("holding"))
            .stdin(Stdio::null());
        if let Some(choice) = decision {
            command.env("SAW_GOVERN_DECISION", choice);
        }
        command.output().unwrap()
    }

    fn commit(&self, decision: Option<&str>) -> Output {
        fs::write(self.repo.join("notes.secret"), "two, longer\n").unwrap();
        let done = self.standin(&["commit", "-q", "-a", "-m", "change"], decision);
        assert!(done.status.success(), "{}", String::from_utf8_lossy(&done.stderr));
        done
    }

    fn ran(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}

#[test]
fn a_kept_repository_runs_its_hook_and_filter_on_commit_and_fsmonitor_on_status() {
    let repository = Repository::new("kept");
    repository.keep();
    let done = repository.commit(None);
    assert!(repository.ran().contains("hook"), "the pre-commit hook did not run: {:?}", repository.ran());
    assert!(repository.ran().contains("cleaned"), "the filter did not run: {:?}", repository.ran());
    assert!(!String::from_utf8_lossy(&done.stderr).contains("saw govern trust"));
    let status = repository.standin(&["status", "--short"], None);
    assert!(status.status.success());
    assert!(repository.ran().contains("fsmonitor"), "fsmonitor did not run: {:?}", repository.ran());
}

#[test]
fn a_repository_not_kept_runs_without_its_programs_and_says_how_to_keep_them() {
    let repository = Repository::new("not-kept");
    let done = repository.commit(None);
    assert_eq!(repository.ran(), "", "a program the operator did not keep ran");
    let said = String::from_utf8_lossy(&done.stderr);
    assert!(said.contains("saw govern trust") && said.contains("the pre-commit hook"), "{said}");
    repository.standin(&["status", "--short"], None);
    assert_eq!(repository.ran(), "", "fsmonitor ran");
}

#[test]
fn settings_that_changed_since_they_were_kept_are_not_kept() {
    let repository = Repository::new("changed");
    repository.keep();
    exec_script(&repository.repo.join(".git/hooks/pre-commit"), &format!("#!/bin/sh\necho changed-hook >> {:?}\n", repository.log));
    let done = repository.commit(None);
    assert_eq!(repository.ran(), "", "a changed hook ran");
    assert!(String::from_utf8_lossy(&done.stderr).contains("saw govern trust"));
}

#[test]
fn a_decision_set_ahead_never_keeps_the_settings() {
    for decision in ["run-as-typed", "yes", "let-in"] {
        let repository = Repository::new(&format!("decided-{decision}"));
        repository.commit(Some(decision));
        assert_eq!(repository.ran(), "", "{decision} started a program the operator did not keep");
        assert!(!kept_settings::record_path(&repository.environ()).unwrap().exists(), "{decision} wrote the record");
    }
}
