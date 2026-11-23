//! The one place saw runs another program. Every run has a time limit, an environment saw chose,
//! and an answer that is either what the program did or an error: never an empty result that
//! looks like an answer.

pub mod git;

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// What saw hands a program.
#[derive(Debug, Clone, Default)]
pub struct Invocation {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The whole environment the program sees; nothing else is inherited.
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
}

/// What a program did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// The exit code, or `None` when a signal ended it.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Finished {
    /// Whether the program exited with 0.
    pub fn succeeded(&self) -> bool {
        self.code == Some(0)
    }
}

/// Why a program did not give an answer.
#[derive(Debug)]
pub enum RunError {
    /// The program could not be started.
    NotStarted(io::Error),
    /// The program did not finish within its time limit and was stopped.
    TimedOut(Duration),
    /// Talking to the program failed.
    Io(io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::NotStarted(error) => write!(f, "could not start: {error}"),
            RunError::TimedOut(limit) => write!(f, "did not answer within {}s", limit.as_secs()),
            RunError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RunError {}

const POLL: Duration = Duration::from_millis(5);

/// Run one program to completion within its time limit. Returns what it did, or why it did not.
pub fn run(invocation: &Invocation) -> Result<Finished, RunError> {
    let mut command = Command::new(&invocation.program);
    command.args(&invocation.args).env_clear().envs(&invocation.env);
    if let Some(cwd) = &invocation.cwd {
        command.current_dir(cwd);
    }
    command
        .stdin(if invocation.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(RunError::NotStarted)?;
    let feeder = invocation.stdin.clone().zip(child.stdin.take()).map(|(bytes, mut pipe)| {
        thread::spawn(move || {
            let _ = pipe.write_all(&bytes);
        })
    });
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(RunError::Io)? {
            break status;
        }
        if started.elapsed() >= invocation.timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::TimedOut(invocation.timeout));
        }
        thread::sleep(POLL);
    };
    drop(feeder);
    let deadline = started + invocation.timeout;
    Ok(Finished {
        code: status.code(),
        stdout: collected(stdout, deadline, invocation.timeout)?,
        stderr: collected(stderr, deadline, invocation.timeout)?,
    })
}

type Drained = Option<mpsc::Receiver<io::Result<Vec<u8>>>>;

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> Drained {
    pipe.map(|mut pipe| {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = sender.send(pipe.read_to_end(&mut bytes).map(|_| bytes));
        });
        receiver
    })
}

fn collected(drained: Drained, deadline: Instant, limit: Duration) -> Result<Vec<u8>, RunError> {
    let Some(receiver) = drained else { return Ok(Vec::new()) };
    let left = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(left) {
        Ok(read) => read.map_err(RunError::Io),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(RunError::TimedOut(limit)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(RunError::Io(io::Error::other("a reader stopped"))),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str, timeout: Duration) -> Invocation {
        Invocation {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: BTreeMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]),
            timeout,
            ..Invocation::default()
        }
    }

    #[test]
    fn a_program_that_runs_too_long_is_stopped_and_is_an_error() {
        let started = Instant::now();
        let answer = run(&sh("sleep 5", Duration::from_millis(200)));
        assert!(matches!(answer, Err(RunError::TimedOut(_))));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_program_that_cannot_start_is_an_error() {
        let missing = Invocation { program: "/no/such/program".into(), timeout: Duration::from_secs(5), ..Invocation::default() };
        assert!(matches!(run(&missing), Err(RunError::NotStarted(_))));
    }

    #[test]
    fn output_input_and_exit_code_are_kept() {
        let mut echo = sh("cat; echo err >&2; exit 3", Duration::from_secs(5));
        echo.stdin = Some(b"fed".to_vec());
        let done = run(&echo).unwrap();
        assert_eq!((done.code, done.stdout.as_slice(), done.stderr.as_slice()), (Some(3), &b"fed"[..], &b"err\n"[..]));
    }

    #[test]
    fn output_held_open_by_a_child_left_running_ends_at_the_time_limit() {
        let started = Instant::now();
        let answer = run(&sh("sleep 5 & echo started", Duration::from_millis(300)));
        assert!(matches!(answer, Err(RunError::TimedOut(_))));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn only_the_environment_saw_chose_is_seen() {
        let done = run(&sh("echo \"[$HOME]\"", Duration::from_secs(5))).unwrap();
        assert_eq!(done.stdout, b"[]\n");
    }
}
