//! Tests for running git.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use saw_platform::programs::git::*;

struct GitFixture {
    isolated: saw_platform::sandbox::Isolated,
    root: PathBuf,
    folders: Folders,
    inherited: BTreeMap<String, String>,
}

impl GitFixture {
    fn new(name: &str) -> GitFixture {
        let isolated = saw_platform::sandbox::Isolated::new(name).unwrap();
        let root = isolated.root().to_path_buf();
        let folders = Folders { empty_hooks: isolated.folder("hooks").unwrap(), neutral: isolated.folder("neutral/dir").unwrap() };
        let inherited = isolated.sandbox().env().variables().clone();
        GitFixture { isolated, root, folders, inherited }
    }

    fn repo(&self) -> PathBuf {
        let repo = self.root.join("repo");
        fs::create_dir_all(&repo).unwrap();
        own(&repo);
        let env = self.identity();
        for args in [&["init", "-q"][..], &["commit", "-q", "--allow-empty", "-m", "one"]] {
            let mut request = Request::new(Context::SawOwned, Some(&repo), args);
            request.env = Some(&env);
            output(&request, Path::new("git"), &self.folders, &self.inherited).unwrap();
        }
        repo
    }

    fn identity(&self) -> BTreeMap<String, String> {
        let mut env = self.inherited.clone();
        for (key, value) in [("GIT_AUTHOR_NAME", "t"), ("GIT_AUTHOR_EMAIL", "t@example.invalid"),
                             ("GIT_COMMITTER_NAME", "t"), ("GIT_COMMITTER_EMAIL", "t@example.invalid")] {
            env.insert(key.into(), value.into());
        }
        env
    }

    fn ask(&self, context: Context, repo: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
        output(&Request::new(context, Some(repo), args), Path::new("git"), &self.folders, &self.inherited)
    }

    fn marker_program(&self, name: &str) -> (PathBuf, PathBuf) {
        let marker = self.root.join(format!("{name}-ran"));
        let program = self.root.join(name);
        fs::write(&program, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        (program, marker)
    }
}


#[test]
fn a_command_that_succeeds_answers_with_its_output() {
    let sandbox = GitFixture::new("answers");
    let repo = sandbox.repo();
    let head = sandbox.ask(Context::Untrusted, &repo, &["rev-parse", "HEAD"]).unwrap();
    assert_eq!(String::from_utf8(head).unwrap().trim().len(), 40);
}

#[test]
fn a_command_that_fails_is_an_error_never_an_empty_answer() {
    let sandbox = GitFixture::new("fails");
    let repo = sandbox.repo();
    let answer = sandbox.ask(Context::Untrusted, &repo, &["rev-parse", "--verify", "--quiet", "no-such-ref"]);
    assert!(matches!(answer, Err(GitError::Failed(_))));
}

#[test]
fn a_command_the_context_does_not_allow_is_refused_before_git_runs() {
    let sandbox = GitFixture::new("refused");
    let repo = sandbox.repo();
    assert!(matches!(sandbox.ask(Context::Untrusted, &repo, &["checkout", "-q", "HEAD"]), Err(GitError::Refused(_))));
    disown(&repo);
    assert!(matches!(sandbox.ask(Context::SawOwned, &repo, &["status"]), Err(GitError::Refused(_))));
}

#[test]
fn a_hook_the_repository_holds_never_runs() {
    let sandbox = GitFixture::new("hook");
    let repo = sandbox.repo();
    let (program, marker) = sandbox.marker_program("pre-commit");
    fs::copy(&program, repo.join(".git/hooks/pre-commit")).unwrap();
    let env = sandbox.identity();
    let mut request = Request::new(Context::SawOwned, Some(&repo), &["commit", "-q", "--allow-empty", "-m", "two"]);
    request.env = Some(&env);
    output(&request, Path::new("git"), &sandbox.folders, &sandbox.inherited).unwrap();
    assert!(!marker.exists(), "the repository's hook ran");
}

#[test]
fn a_program_the_repository_configures_never_runs() {
    let sandbox = GitFixture::new("fsmonitor");
    let repo = sandbox.repo();
    let (program, marker) = sandbox.marker_program("fsmonitor");
    let config = repo.join(".git/config");
    let mut text = fs::read_to_string(&config).unwrap();
    text.push_str(&format!("[core]\n\tfsmonitor = {}\n\tpager = {}\n", program.display(), program.display()));
    fs::write(&config, text).unwrap();
    disown(&repo);
    sandbox.ask(Context::Untrusted, &repo, &["ls-files", "-z"]).unwrap();
    sandbox.ask(Context::Untrusted, &repo, &["log", "-1"]).unwrap();
    assert!(!marker.exists(), "a program the repository configures ran");
}

fn git_of(sandbox: &GitFixture) -> Git {
    Git { program: PathBuf::from("git"), folders: sandbox.folders.clone(), inherited: sandbox.inherited.clone() }
}

#[test]
fn a_repository_whose_configuration_would_wait_is_not_asked_and_is_recorded() {
    let sandbox = GitFixture::new("waits");
    let repo = sandbox.repo();
    disown(&repo);
    let config = repo.join(".git/config");
    fs::remove_file(&config).unwrap();
    sandbox.isolated.pipe("repo/.git/config").unwrap();
    let git = git_of(&sandbox);
    let pass = Pass::default();
    let started = std::time::Instant::now();
    for _ in 0..2 {
        let answer = git.run_in(&pass, &Request::new(Context::Untrusted, Some(&repo), &["rev-parse", "HEAD"]));
        assert!(matches!(answer, Err(GitError::WouldWait(_))));
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(pass.stalled().len(), 2);
    assert!(pass.stalled()[0].starts_with("git rev-parse was not run"));
}

#[test]
fn an_ordinary_repository_is_asked_within_a_pass() {
    let sandbox = GitFixture::new("ordinary");
    let repo = sandbox.repo();
    disown(&repo);
    let pass = Pass::default();
    let answer = git_of(&sandbox).run_in(&pass, &Request::new(Context::Untrusted, Some(&repo), &["rev-parse", "HEAD"]));
    assert!(answer.unwrap().succeeded());
    assert!(pass.stalled().is_empty());
}

#[test]
fn z_output_splits_into_its_records() {
    assert_eq!(records(b"a\0b c\0"), vec![&b"a"[..], &b"b c"[..]]);
    assert!(records(b"").is_empty());
}
