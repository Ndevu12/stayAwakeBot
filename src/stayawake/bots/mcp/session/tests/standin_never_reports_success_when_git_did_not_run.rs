//! The stand-in tells the user when neither git nor saw wrote what a command would, and the command
//! fails. A decision saw offers is honoured whatever its check exited with.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");
const CLEAN: &str = r#"{"scan":{"any_error":false,"results":[{"verdict":"clean"}]}}"#;
const NOT_WRITTEN: &str = r#"{"applied":false,"reason":"the open folder changed while the update was checked"}"#;
const DECIDE: &str = r#"{"reason":"the repository has no remote to fetch from","decision":{"choices":["run-as-typed","leave-unchanged"]}}"#;

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
        let dir = std::env::temp_dir().join(format!("saw-standin-unwritten-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        let real_log = dir.join("real.log");
        let saw_log = dir.join("saw.log");
        exec_script(&dir.join("real-git"), &format!("#!/bin/sh\necho \"$@\" >> {real_log:?}\n"));
        exec_script(
            &dir.join("fake-saw"),
            &format!(
                "#!/bin/sh\necho \"$@\" >> {saw_log:?}\n\
                 [ \"$1\" = scan ] && exit 0\n\
                 if [ \"$2\" = prepare ]; then printf '%s' \"$SAW_FAKE_PREPARE\"; exit \"$SAW_FAKE_PREPARE_EXIT\"; fi\n\
                 [ -n \"$SAW_FAKE_APPLY_ENDS\" ] && kill -9 $$\n\
                 printf '%s\\n' \"$SAW_FAKE_APPLY\"\nexit \"$SAW_FAKE_APPLY_EXIT\"\n"
            ),
        );
        Terminal { dir, real_log, saw_log }
    }

    fn fetch(&self, prepare: (&str, i32), apply: (&str, i32), extra: &[(&str, &str)]) -> Output {
        let mut command = Command::new(STANDIN);
        command
            .args(["fetch", "origin"])
            .current_dir(&self.dir)
            .env("SAW_STANDIN_TOOL", "git")
            .env("SAW_REAL_GIT", self.dir.join("real-git"))
            .env("SAW_BIN", self.dir.join("fake-saw"))
            .env("PATH", &self.dir)
            .env("SAW_GOVERN_HOLDING", self.dir.join("holding"))
            .env("SAW_FAKE_PREPARE", prepare.0)
            .env("SAW_FAKE_PREPARE_EXIT", prepare.1.to_string())
            .env("SAW_FAKE_APPLY", apply.0)
            .env("SAW_FAKE_APPLY_EXIT", apply.1.to_string())
            .env_remove("SAW_GOVERN_SYSTEM")
            .env_remove("SAW_GOVERN_DECISION")
            .stdin(Stdio::null());
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn real_ran(&self) -> bool {
        fs::read_to_string(&self.real_log).map(|s| !s.trim().is_empty()).unwrap_or(false)
    }

    fn applied(&self) -> bool {
        fs::read_to_string(&self.saw_log).map(|s| s.contains("govern apply")).unwrap_or(false)
    }
}

#[test]
fn an_update_saw_did_not_write_says_so_and_does_not_succeed() {
    let terminal = Terminal::new("refused");
    let out = terminal.fetch((CLEAN, 0), (NOT_WRITTEN, 3), &[]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{said}");
    assert!(said.contains("saw: the open folder changed while the update was checked; git did not run."), "{said}");
    assert!(!terminal.real_ran());
}

#[test]
fn a_write_that_ends_without_an_answer_never_succeeds() {
    let terminal = Terminal::new("ended");
    let out = terminal.fetch((CLEAN, 0), ("", 0), &[("SAW_FAKE_APPLY_ENDS", "1")]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{said}");
    assert!(said.contains("may have changed; check it with git status; git did not run."), "{said}");
    assert!(!terminal.real_ran());
}

#[test]
fn an_update_brought_in_with_conflicts_left_is_not_called_unwritten() {
    let terminal = Terminal::new("conflicts");
    let out = terminal.fetch((CLEAN, 0), (r#"{"applied":true,"conflicts":["a.txt"]}"#, 3), &[]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{said}");
    assert!(!said.contains("did not run"), "{said}");
}

#[test]
fn a_decision_offered_with_a_clean_exit_runs_as_typed_when_the_user_decides_so() {
    let terminal = Terminal::new("decided");
    let out = terminal.fetch((DECIDE, 0), ("", 0), &[("SAW_GOVERN_DECISION", "run-as-typed")]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(terminal.real_ran(), "the user decided to run it as typed");
    assert!(!terminal.applied(), "saw wrote an update it offered a decision about");
}

#[test]
fn a_decision_offered_with_a_clean_exit_leaves_the_folder_when_no_one_decides() {
    let terminal = Terminal::new("undecided");
    let out = terminal.fetch((DECIDE, 0), ("", 0), &[]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{said}");
    assert!(said.contains("git did not run"), "{said}");
    assert!(!terminal.real_ran());
    assert!(!terminal.applied(), "saw wrote an update it offered a decision about");
}

#[test]
fn a_check_that_gives_no_answer_says_git_did_not_run() {
    let terminal = Terminal::new("no-answer");
    let out = terminal.fetch(("", 1), ("", 0), &[]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{said}");
    assert!(said.contains("saw: this update cannot be checked; the folder is unchanged; git did not run."), "{said}");
    assert!(!terminal.real_ran());
    assert!(!terminal.applied());
}
