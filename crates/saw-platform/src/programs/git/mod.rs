//! Runs git for saw.

pub mod allowlist;
pub mod contexts;
pub mod waiting;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub use contexts::Context;

use crate::programs::{self, Finished, Invocation, RunError};

pub const LOCAL_TIMEOUT: Duration = Duration::from_secs(60);
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(180);

const NO_DIFF_DRIVERS: &[&str] = &["--no-textconv", "--no-ext-diff"];

/// Why git gave no answer.
#[derive(Debug)]
pub enum GitError {
    /// saw refused to run the command under its context.
    Refused(String),
    /// git could not run, or did not finish in time.
    NotRun(RunError),
    /// git ran and failed.
    Failed(Finished),
    /// git was not run: every git command in this repository would wait on its configuration.
    WouldWait(PathBuf),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitError::Refused(message) => write!(f, "{message}"),
            GitError::NotRun(error) => write!(f, "git {error}"),
            GitError::Failed(done) => write!(f, "git exited with {:?}", done.code),
            GitError::WouldWait(repo) => write!(f, "every git command would wait on the configuration of {}", repo.display()),
        }
    }
}

impl std::error::Error for GitError {}

fn owned() -> &'static Mutex<HashSet<PathBuf>> {
    static OWNED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    OWNED.get_or_init(Default::default)
}

fn key(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Record `path` as a repository this process created. Takes the path.
pub fn own(path: &Path) {
    owned().lock().expect("the owned set is never poisoned").insert(key(path));
}

/// Forget `path` as a repository this process created. Takes the path.
pub fn disown(path: &Path) {
    owned().lock().expect("the owned set is never poisoned").remove(&key(path));
}

/// Return whether `path` is a repository this process created. Takes the path.
pub fn is_owned(path: &Path) -> bool {
    owned().lock().expect("the owned set is never poisoned").contains(&key(path))
}

/// saw's own folders git runs with: an empty hooks folder, and a folder outside any repository.
#[derive(Debug, Clone)]
pub struct Folders {
    pub empty_hooks: PathBuf,
    pub neutral: PathBuf,
}

/// One git command to run.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub context: Context,
    pub repo: Option<&'a Path>,
    pub args: Vec<String>,
    /// The whole environment the caller gives, or `None` to use the one saw inherited.
    pub env: Option<&'a BTreeMap<String, String>>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
}

impl<'a> Request<'a> {
    /// Make a request. Takes the context, the repository or none, and the arguments. Returns the request.
    pub fn new(context: Context, repo: Option<&'a Path>, args: &[&str]) -> Self {
        Request { context, repo, args: args.iter().map(|a| a.to_string()).collect(), env: None, stdin: None, timeout: LOCAL_TIMEOUT }
    }
}

/// Prepare one request to run. Takes the request, the git program, saw's folders and the inherited
/// environment. Returns the invocation, or why it is refused.
pub fn prepare(request: &Request, git: &Path, folders: &Folders, inherited: &BTreeMap<String, String>) -> Result<Invocation, GitError> {
    let shown = request.args.iter().take(3).cloned().collect::<Vec<_>>().join(" ");
    let refuse = |why: String| Err(GitError::Refused(format!("saw refused to run git {shown} as {}: {why}", request.context.name())));
    match (request.context.place(), request.repo) {
        (contexts::Where::NoRepository, Some(_)) => {
            return refuse("runs outside any repository, so a repository's configuration is never read".into());
        }
        (contexts::Where::OwnedOrNone, Some(repo)) if !is_owned(repo) => {
            return refuse(format!("{} is not a repository this run created", repo.display()));
        }
        _ => {}
    }
    let private_index = request.env.is_some_and(|env| env.get("GIT_INDEX_FILE").is_some_and(|v| !v.is_empty()));
    let verdict = allowlist::judge(request.context, &request.args, private_index);
    if !verdict.refusal.is_empty() {
        return refuse(verdict.refusal);
    }
    let (callers_globals, sub, mut rest) = allowlist::split(&request.args);
    if matches!(request.context, Context::Untrusted | Context::SawOwned) && allowlist::DIFF_SUBCOMMANDS.contains(&sub.as_str()) {
        rest.splice(0..0, NO_DIFF_DRIVERS.iter().map(|a| a.to_string()));
    }
    let mut args = Vec::new();
    if let Some(repo) = request.repo {
        args.extend(["-C".to_string(), repo.display().to_string()]);
    }
    if !verdict.reads_configuration {
        args.extend(contexts::config_prefix(request.context, &folders.empty_hooks));
    }
    args.extend(callers_globals);
    args.push(sub);
    args.extend(rest);
    let scopes = verdict.reads_configuration.then_some(true);
    let neutral = request.repo.is_none().then_some(folders.neutral.as_path());
    let env = contexts::child_env(request.context, inherited, request.env, scopes, neutral);
    Ok(Invocation {
        program: git.to_path_buf(),
        args,
        env,
        cwd: request.repo.is_none().then(|| folders.neutral.clone()),
        stdin: request.stdin.clone(),
        timeout: request.timeout,
    })
}

/// Run one git command. Takes the request, the git program, saw's folders and the inherited
/// environment. Returns what git did, whatever its exit code, or why it gave no answer.
pub fn run(request: &Request, git: &Path, folders: &Folders, inherited: &BTreeMap<String, String>) -> Result<Finished, GitError> {
    let invocation = prepare(request, git, folders, inherited)?;
    programs::run(&invocation).map_err(GitError::NotRun)
}

/// Run one git command that must succeed. Takes the same as `run`. Returns its standard output, or
/// why there is none.
pub fn output(request: &Request, git: &Path, folders: &Folders, inherited: &BTreeMap<String, String>) -> Result<Vec<u8>, GitError> {
    let done = run(request, git, folders, inherited)?;
    if done.succeeded() { Ok(done.stdout) } else { Err(GitError::Failed(done)) }
}

/// The git program, saw's folders and the inherited environment.
#[derive(Debug, Clone)]
pub struct Git {
    pub program: PathBuf,
    pub folders: Folders,
    pub inherited: BTreeMap<String, String>,
}

impl Git {
    /// Run one command. Takes the request. Returns what git did, or why it gave no answer.
    pub fn run(&self, request: &Request) -> Result<Finished, GitError> {
        run(request, &self.program, &self.folders, &self.inherited)
    }

    /// Run one command that must succeed. Takes the request. Returns its standard output, or why there is none.
    pub fn output(&self, request: &Request) -> Result<Vec<u8>, GitError> {
        output(request, &self.program, &self.folders, &self.inherited)
    }

    /// Run one command within a pass. Takes the pass and the request. Returns what git did, or why
    /// it gave no answer.
    pub fn run_in(&self, pass: &Pass, request: &Request) -> Result<Finished, GitError> {
        if let Some(repo) = request.repo {
            if !reads_named_configuration_only(&request.args) && pass.would_wait(self, repo) {
                let sub = request.args.first().cloned().unwrap_or_default();
                pass.record(format!("git {sub} was not run: every git command would wait on the configuration of {}", repo.display()));
                return Err(GitError::WouldWait(repo.to_path_buf()));
            }
        }
        let answer = self.run(request);
        if let Err(GitError::NotRun(RunError::TimedOut(limit))) = &answer {
            let sub = request.args.first().cloned().unwrap_or_default();
            pass.record(format!("git {sub} did not answer within {}s", limit.as_secs()));
        }
        answer
    }
}

/// One pass over repositories, and the commands it did not run or that did not answer.
#[derive(Debug, Default)]
pub struct Pass {
    answers: Mutex<HashMap<PathBuf, bool>>,
    stalled: Mutex<Vec<String>>,
}

impl Pass {
    /// Return whether every git command in `repo` would wait. Takes the git handle and the repository.
    pub fn would_wait(&self, git: &Git, repo: &Path) -> bool {
        let key = key(repo);
        if let Some(known) = self.answers.lock().expect("the answers are never poisoned").get(&key) {
            return *known;
        }
        let waits = waiting::config_waits(git, repo);
        self.answers.lock().expect("the answers are never poisoned").insert(key, waits);
        waits
    }

    fn record(&self, line: String) {
        self.stalled.lock().expect("the record is never poisoned").push(line);
    }

    /// Return the commands this pass did not run or that did not answer, in order.
    pub fn stalled(&self) -> Vec<String> {
        self.stalled.lock().expect("the record is never poisoned").clone()
    }
}

fn reads_named_configuration_only(args: &[String]) -> bool {
    let (_, sub, rest) = allowlist::split(args);
    sub == "config"
        && rest.iter().any(|flag| {
            matches!(flag.as_str(), "--global" | "--system" | "--file" | "-f" | "--blob")
                || flag.starts_with("--file=")
                || flag.starts_with("--blob=")
        })
}

/// Split `-z` output into its records. Takes the output. Returns the records.
pub fn records(output: &[u8]) -> Vec<&[u8]> {
    let mut parts: Vec<&[u8]> = output.split(|byte| *byte == 0).collect();
    if parts.last().is_some_and(|last| last.is_empty()) {
        parts.pop();
    }
    parts
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    struct GitFixture {
        _held: crate::sandbox::Isolated,
        root: PathBuf,
        folders: Folders,
        inherited: BTreeMap<String, String>,
    }

    impl GitFixture {
        fn new(name: &str) -> GitFixture {
            let isolated = crate::sandbox::Isolated::new(name).unwrap();
            let root = isolated.root().to_path_buf();
            let folders = Folders { empty_hooks: isolated.folder("hooks").unwrap(), neutral: isolated.folder("neutral/dir").unwrap() };
            let inherited = isolated.sandbox().env().variables().clone();
            GitFixture { _held: isolated, root, folders, inherited }
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
        let made = std::process::Command::new("mkfifo").arg(&config).status().unwrap();
        assert!(made.success());
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
}
