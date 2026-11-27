//! The stand-in runs the real git in its place on every system saw ships it for: git's output and
//! exit code come back unchanged, and other names for the stand-in first on PATH are passed over.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

mod common;
use common::real_git;

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");

fn folder(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("saw-runs-git-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn path_of(folders: &[&Path]) -> OsString {
    std::env::join_paths(folders).unwrap()
}

fn as_git(program: &Path, here: &Path, path: &OsString, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(here)
        .env("PATH", path)
        .env("GIT_CEILING_DIRECTORIES", here.parent().unwrap())
        .env_remove("SAW_GOVERN_HOLDING")
        .env_remove("SAW_GOVERN_SYSTEM")
        .env_remove("SAW_REAL_GIT")
        .env_remove("SAW_BIN")
        .stdin(Stdio::null());
    command
}

fn finished(mut command: Command) -> Output {
    let child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (sent, received) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(child.wait_with_output());
    });
    received.recv_timeout(Duration::from_secs(60)).expect("the stand-in ran itself instead of git").unwrap()
}

#[test]
fn git_output_and_exit_code_come_back_unchanged() {
    let git = real_git();
    let here = folder("unchanged");
    let path = path_of(&[git.parent().unwrap()]);
    for args in [&["--version"][..], &["rev-parse", "--git-dir"][..]] {
        let direct = finished(as_git(&git, &here, &path, args));
        let mut through = as_git(Path::new(STANDIN), &here, &path, args);
        through.env("SAW_STANDIN_TOOL", "git");
        let through = finished(through);
        assert_eq!(through.status.code(), direct.status.code(), "git {args:?}");
        assert_eq!(through.stdout, direct.stdout, "git {args:?}");
        assert_eq!(through.stderr, direct.stderr, "git {args:?}");
    }
    assert_ne!(finished(as_git(&git, &here, &path, &["rev-parse", "--git-dir"])).status.code(), Some(0));
}

#[test]
fn other_names_for_the_standin_first_on_path_are_passed_over() {
    let git = real_git();
    let here = folder("other-names");
    let named: Vec<PathBuf> = ["first", "second"].iter().map(|name| here.join(name)).collect();
    for folder in &named {
        fs::create_dir_all(folder).unwrap();
        fs::hard_link(STANDIN, folder.join(format!("git{}", std::env::consts::EXE_SUFFIX))).unwrap();
    }
    let path = path_of(&[&named[0], &named[1], git.parent().unwrap()]);
    let mut through = as_git(Path::new(STANDIN), &here, &path, &["--version"]);
    through.env("SAW_STANDIN_TOOL", "git");
    let through = finished(through);
    let direct = finished(as_git(&git, &here, &path, &["--version"]));
    assert!(through.status.success(), "{}", String::from_utf8_lossy(&through.stderr));
    assert_eq!(through.stdout, direct.stdout);
}
