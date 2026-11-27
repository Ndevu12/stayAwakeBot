//! Runs the git commands the folder guard reads with: the operator's own git, given the settings
//! and environment saw's Python gives the same reads, several at once, each answered once.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use super::Environment;

const LOCAL_TIMEOUT: Duration = Duration::from_secs(60);
const LOCATION_VARIABLES: [&str; 9] = ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES", "GIT_PREFIX"];
const ISOLATION_VARIABLES: [&str; 3] = ["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"];
const INJECTION_PREFIXES: [&str; 4] = ["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"];
const ACTIVATION_VARIABLES: [&str; 2] = ["SAW_GOVERN_SYSTEM", "SAW_GOVERN_HOLDING"];
const STORED_VIEW: [(&str, &str); 3] = [("GIT_NO_REPLACE_OBJECTS", "1"), ("GIT_GRAFT_FILE", "/dev/null/grafts"), ("GIT_NO_LAZY_FETCH", "1")];
const RUNS_NOTHING: [(&str, &str); 9] = [("core.fsmonitor", "false"), ("diff.external", ""), ("core.pager", "cat"),
    ("core.editor", "false"), ("protocol.allow", "never"), ("gc.auto", "0"), ("maintenance.auto", "false"),
    ("submodule.recurse", "false"), ("credential.helper", "")];

/// Whether a read only reports settings, which git answers from the operator's own scopes too, or
/// reads the repository, which it answers without them and with every program-running setting off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    ReadsSettings,
    ReadsTheRepository,
}

/// One git command the guard reads with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Call {
    /// Where git runs, or None to run it outside every repository.
    pub place: Option<PathBuf>,
    /// The arguments after saw's own.
    pub args: Vec<String>,
    pub kind: Kind,
    /// Variables the command itself names, kept as given.
    pub named: Vec<(String, String)>,
}

impl Call {
    /// A read of settings at a place, or outside every repository.
    pub fn settings(place: Option<&Path>, args: &[&str]) -> Call {
        Call { place: place.map(Path::to_path_buf), args: args.iter().map(|a| a.to_string()).collect(), kind: Kind::ReadsSettings, named: Vec::new() }
    }

    /// A read of the repository at a place.
    pub fn repository(place: &Path, args: &[&str]) -> Call {
        Call { place: Some(place.to_path_buf()), args: args.iter().map(|a| a.to_string()).collect(), kind: Kind::ReadsTheRepository, named: Vec::new() }
    }
}

/// What git answered: its exit code, None when it did not run or did not finish, and its output.
#[derive(Debug, Clone, Default)]
pub struct Answer {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
}

impl Answer {
    /// The output of a command that succeeded, or None.
    pub fn succeeded(&self) -> Option<&[u8]> {
        (self.code == Some(0)).then_some(self.stdout.as_slice())
    }

    /// The output as text, or empty when the command did not succeed.
    pub fn text(&self) -> String {
        self.succeeded().map(|out| String::from_utf8_lossy(out).into_owned()).unwrap_or_default()
    }
}

/// The operator's git, run with the guard's settings, each command answered once.
pub struct Git<'a> {
    program: PathBuf,
    environ: &'a Environment,
    no_hooks: RefCell<Option<PathBuf>>,
    answers: RefCell<HashMap<Call, Answer>>,
    stalled: RefCell<Option<String>>,
}

impl<'a> Git<'a> {
    /// Take the git program and the environment the command runs in.
    pub fn new(program: &Path, environ: &'a Environment) -> Git<'a> {
        Git { program: program.to_path_buf(), environ, no_hooks: RefCell::new(None), answers: RefCell::default(), stalled: RefCell::default() }
    }

    /// Give saw's empty hooks folder, which every read runs from or names as its hooks folder.
    pub fn use_no_hooks_folder(&self, folder: &Path) {
        *self.no_hooks.borrow_mut() = Some(folder.to_path_buf());
    }

    /// The first command that did not finish in time, if any.
    pub fn stalled(&self) -> Option<String> {
        self.stalled.borrow().clone()
    }

    /// Answer one command, running it when it has not run yet.
    pub fn answer(&self, call: &Call) -> Answer {
        self.run_all(std::slice::from_ref(call));
        self.answers.borrow().get(call).cloned().unwrap_or_default()
    }

    /// Run every command not yet answered, all at once.
    pub fn run_all(&self, calls: &[Call]) {
        let pending: Vec<&Call> = {
            let answers = self.answers.borrow();
            let mut pending: Vec<&Call> = calls.iter().filter(|call| !answers.contains_key(*call)).collect();
            pending.dedup();
            pending
        };
        if pending.is_empty() {
            return;
        }
        let commands: Vec<(Call, Command)> = pending.iter().map(|call| ((*call).clone(), self.command(call))).collect();
        let finished: Vec<(Call, Answer, bool)> = std::thread::scope(|scope| {
            let running: Vec<_> = commands.into_iter().map(|(call, command)| scope.spawn(move || {
                let (answer, stalled) = run_one(command);
                (call, answer, stalled)
            })).collect();
            running.into_iter().map(|each| each.join().unwrap_or_else(|_| (Call::settings(None, &[]), Answer::default(), false))).collect()
        });
        for (call, answer, stalled) in finished {
            if stalled && self.stalled.borrow().is_none() {
                *self.stalled.borrow_mut() = Some(format!("git {}", call.args.iter().take(3).cloned().collect::<Vec<_>>().join(" ")));
            }
            self.answers.borrow_mut().insert(call, answer);
        }
    }

    fn command(&self, call: &Call) -> Command {
        let no_hooks = self.no_hooks.borrow().clone().unwrap_or_else(|| PathBuf::from("/nonexistent/saw-no-hooks"));
        let mut command = Command::new(&self.program);
        match &call.place {
            Some(place) => {
                command.arg("-C").arg(place);
            }
            None => {
                command.current_dir(&no_hooks);
            }
        }
        if call.kind == Kind::ReadsTheRepository {
            command.arg("-c").arg(format!("core.hooksPath={}", no_hooks.display()));
            for (key, value) in RUNS_NOTHING {
                command.arg("-c").arg(format!("{key}={value}"));
            }
            command.arg("--literal-pathspecs");
        }
        command.args(&call.args);
        command.env_clear().envs(self.environment(call, &no_hooks));
        command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
        command
    }

    fn environment(&self, call: &Call, no_hooks: &Path) -> Vec<(String, String)> {
        let operator_scopes = call.kind == Kind::ReadsSettings;
        let injects = |key: &str| key == "GIT_CONFIG" || INJECTION_PREFIXES.iter().any(|prefix| key.starts_with(prefix));
        let mut out: HashMap<String, String> = HashMap::new();
        for (key, value) in self.environ {
            if !key.starts_with("GIT_") || (operator_scopes && !LOCATION_VARIABLES.contains(&key.as_str()) && !injects(key)) {
                out.insert(key.clone(), value.clone());
            }
        }
        for (key, value) in &call.named {
            if !injects(key) && !ISOLATION_VARIABLES.contains(&key.as_str()) {
                out.insert(key.clone(), value.clone());
            }
        }
        if !operator_scopes {
            for key in ISOLATION_VARIABLES {
                out.remove(key);
            }
            out.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
            out.insert("GIT_CONFIG_GLOBAL".into(), "/dev/null".into());
        }
        out.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
        out.insert("SAW_HOOK_DISABLED".into(), "1".into());
        for key in ACTIVATION_VARIABLES {
            out.remove(key);
        }
        out.insert("GIT_ALLOW_PROTOCOL".into(), String::new());
        for (key, value) in STORED_VIEW {
            out.insert(key.into(), value.into());
        }
        if call.place.is_none() {
            if let Some(parent) = no_hooks.parent() {
                out.insert("GIT_CEILING_DIRECTORIES".into(), parent.display().to_string());
            }
        }
        out.into_iter().collect()
    }
}

/// Run one command to its end, or stop it when it outlasts the timeout. Returns its answer and
/// whether it stalled.
fn run_one(mut command: Command) -> (Answer, bool) {
    let Ok(mut child) = command.spawn() else { return (Answer::default(), false) };
    let mut stdout = child.stdout.take();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut read = Vec::new();
        if let Some(out) = stdout.as_mut() {
            let _ = out.read_to_end(&mut read);
        }
        let _ = sender.send(read);
    });
    match receiver.recv_timeout(LOCAL_TIMEOUT) {
        Ok(read) => {
            let code = child.wait().ok().and_then(|status| status.code());
            (Answer { code, stdout: read }, false)
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            (Answer::default(), true)
        }
    }
}
