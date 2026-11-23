//! Tests for running programs.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use saw_platform::programs::*;

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
