// Unix only: POSIX shell scripts stand in for git and saw.
#![cfg(unix)]
//! With no one at a terminal, the git stand-in asks the editor that named a questions folder. An
//! answer that matches its question lets exactly the held update in, or runs a command that cannot
//! be checked. Any other answer, a folder saw cannot use, or no answer in time leaves the folder
//! unchanged.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");
const COMMIT: &str = "c0ffee0123456789c0ffee0123456789c0ffee01";
const FAKE_SAW: &str = r#"#!/bin/sh
if [ "$1" = scan ]; then echo scanned >> "$SCAN_LOG"; exit 0; fi
if [ "$2" = prepare ]; then cat "$PREPARE_ANSWER"; exit "$PREPARE_EXIT"; fi
if [ "$2" = apply ]; then for a in "$@"; do printf '[%s]' "$a"; done >> "$APPLY_LOG"; echo '{"applied":true}'; exit 0; fi
exit 1
"#;
const FAKE_GIT: &str = "#!/bin/sh\nif [ \"$1\" = pull ]; then echo \"$@\" >> \"$REAL_LOG\"; fi\n";

type Responder = Box<dyn FnOnce(&Path, &Value) + Send>;

struct Fixture {
    dir: PathBuf,
    questions: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("saw-editor-questions-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = fs::canonicalize(&dir).unwrap();
        for (script, body) in [("fake-saw", FAKE_SAW), ("real-git", FAKE_GIT)] {
            fs::write(dir.join(script), body).unwrap();
            fs::set_permissions(dir.join(script), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let questions = dir.join("questions");
        fs::create_dir(&questions).unwrap();
        fs::set_permissions(&questions, fs::Permissions::from_mode(0o700)).unwrap();
        Fixture { dir, questions }
    }

    fn held(&self, infected: bool) -> &Self {
        let mut decision = json!({
            "choices": ["let-in", "leave-unchanged"],
            "let_in": ["saw", "govern", "apply", "--repo", ".", "--into", "/held", "--accept", COMMIT],
            "confirm": if infected { "typed" } else { "yes" },
            "let_in_later": ["saw", "govern", "let-in"],
        });
        if infected {
            decision["type_to_confirm"] = json!("app");
        }
        let answer = json!({
            "scan": {"any_error": false, "results": [{"verdict": if infected { "infected" } else { "suspicious" },
                "findings": [{"signature_id": "S1", "severity": "high", "path": ".claude/settings.json",
                              "description": "runs a program", "evidence": "x", "confidence": "heuristic"}]}]},
            "next_steps": ["Check .claude/settings.json"],
            "decision": decision,
        });
        self.prepares(&answer, 1)
    }

    fn cannot_check(&self) -> &Self {
        let answer = json!({"reason": "the repository has no remote to fetch from",
                            "decision": {"choices": ["run-as-typed", "leave-unchanged"],
                                         "scan_after": ["saw", "scan", self.dir]}});
        self.prepares(&answer, 2)
    }

    fn prepares(&self, answer: &Value, exit: i32) -> &Self {
        fs::write(self.dir.join("prepare.json"), answer.to_string()).unwrap();
        fs::write(self.dir.join("prepare.exit"), exit.to_string()).unwrap();
        self
    }

    /// Run `git pull` with no terminal and the questions folder named, answering with the responder.
    /// Returns the output and the question the editor saw.
    fn pull(&self, questions: &Path, environment: &[(&str, &str)], respond: Responder) -> (Output, Option<Value>) {
        let finished = Arc::new(AtomicBool::new(false));
        let editor = {
            let (folder, finished) = (self.questions.clone(), finished.clone());
            thread::spawn(move || answer_one_question(&folder, &finished, respond))
        };
        let exit = fs::read_to_string(self.dir.join("prepare.exit")).unwrap_or_else(|_| "0".into());
        let mut command = Command::new(STANDIN);
        command
            .arg("pull")
            .current_dir(&self.dir)
            .env("SAW_STANDIN_TOOL", "git")
            .env("SAW_REAL_GIT", self.dir.join("real-git"))
            .env("SAW_BIN", self.dir.join("fake-saw"))
            .env("SAW_GOVERN_SYSTEM", "1")
            .env("TMPDIR", &self.dir)
            .env("PATH", format!("{}:/usr/bin:/bin", self.dir.display()))
            .env("PREPARE_ANSWER", self.dir.join("prepare.json"))
            .env("PREPARE_EXIT", exit.trim())
            .env("APPLY_LOG", self.dir.join("apply.log"))
            .env("SCAN_LOG", self.dir.join("scan.log"))
            .env("REAL_LOG", self.dir.join("real.log"))
            .env("SAW_GOVERN_QUESTIONS", questions)
            .env("SAW_GOVERN_QUESTIONS_WAIT", "20")
            .env_remove("SAW_GOVERN_HOLDING")
            .env_remove("SAW_GOVERN_DECISION")
            .stdin(Stdio::null());
        for (name, value) in environment {
            command.env(name, value);
        }
        let output = command.output().unwrap();
        finished.store(true, Ordering::SeqCst);
        (output, editor.join().unwrap())
    }

    fn applied(&self) -> String {
        fs::read_to_string(self.dir.join("apply.log")).unwrap_or_default()
    }

    fn real_ran(&self) -> bool {
        fs::read_to_string(self.dir.join("real.log")).is_ok_and(|log| log.contains("pull"))
    }

    fn scanned(&self) -> bool {
        fs::read_to_string(self.dir.join("scan.log")).is_ok_and(|log| log.contains("scanned"))
    }

    fn questions_left(&self) -> Vec<String> {
        fs::read_dir(&self.questions).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect()
    }
}

/// Wait for one question in the folder and hand it to the responder, until the stand-in finishes.
fn answer_one_question(folder: &Path, finished: &AtomicBool, respond: Responder) -> Option<Value> {
    while !finished.load(Ordering::SeqCst) {
        let asked = fs::read_dir(folder).ok()?.filter_map(Result::ok)
            .find(|entry| entry.file_name().to_string_lossy().ends_with(".question.json"));
        if let Some(entry) = asked {
            let question: Value = serde_json::from_str(&fs::read_to_string(entry.path()).unwrap()).unwrap();
            respond(folder, &question);
            return Some(question);
        }
        thread::sleep(Duration::from_millis(10));
    }
    None
}

/// Write an answer whole under the question's answer name.
fn write_answer(folder: &Path, id: &str, answer: &Value) {
    let being_written = folder.join(format!(".{id}.writing"));
    fs::write(&being_written, answer.to_string()).unwrap();
    fs::rename(&being_written, folder.join(format!("{id}.answer.json"))).unwrap();
}

fn answering(answer: Value) -> Responder {
    Box::new(move |folder, question| {
        let id = question["id"].as_str().unwrap().to_string();
        let mut answer = answer;
        if answer.get("id").is_none() {
            answer["id"] = json!(id);
        }
        write_answer(folder, &id, &answer);
    })
}

fn never_answering() -> Responder {
    Box::new(|_, _| {})
}

fn said(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_held_update_comes_in_when_the_editor_lets_exactly_it_in() {
    let f = Fixture::new("let-in");
    f.held(false);
    let (output, question) = f.pull(&f.questions, &[], answering(json!({"answer": "let-in", "accept": COMMIT})));
    assert!(output.status.success(), "{}", said(&output));
    assert!(f.applied().contains(&format!("[apply][--repo][.][--into][/held][--accept][{COMMIT}]")), "{}", f.applied());
    assert!(!f.applied().contains("--confirm"), "{}", f.applied());
    let question = question.expect("the editor was asked");
    assert_eq!(question["schema_version"], json!(1));
    assert_eq!(question["kind"], json!("held"));
    assert_eq!(question["choices"], json!(["let-in", "leave-unchanged"]));
    assert_eq!(question["argv"], json!(["git", "pull"]));
    assert_eq!(question["folder"], json!(f.dir));
    assert_eq!(question["accept"], json!(COMMIT));
    assert_eq!(question["confirm"], json!(false));
    assert_eq!(question["findings"], json!([{"signature_id": "S1", "severity": "high", "path": ".claude/settings.json",
                                             "description": "runs a program"}]));
    assert_eq!(question["next_steps"], json!(["Check .claude/settings.json"]));
    assert_eq!(question["id"].as_str().map(str::len), Some(32));
    assert!(f.questions_left().is_empty(), "saw removes the question and the answer: {:?}", f.questions_left());
}

#[test]
fn an_infected_update_comes_in_with_confirm_set() {
    let f = Fixture::new("infected-confirmed");
    f.held(true);
    let (output, question) = f.pull(&f.questions, &[], answering(json!({"answer": "let-in", "accept": COMMIT, "confirm": true})));
    assert_eq!(question.expect("the editor was asked")["confirm"], json!(true));
    assert!(output.status.success(), "{}", said(&output));
    assert!(f.applied().contains(&format!("[--accept][{COMMIT}][--confirm][app]")), "{}", f.applied());
}

#[test]
fn an_answer_that_does_not_match_its_question_changes_nothing() {
    let cases = [
        ("unknown-id", json!({"id": "0123456789abcdef0123456789abcdef", "answer": "let-in", "accept": COMMIT})),
        ("wrong-commit", json!({"answer": "let-in", "accept": "c0ffee"})),
        ("not-a-choice", json!({"answer": "run-as-typed", "accept": COMMIT})),
        ("left-unchanged", json!({"answer": "leave-unchanged"})),
    ];
    for (name, answer) in cases {
        let f = Fixture::new(name);
        f.held(false);
        let (output, question) = f.pull(&f.questions, &[], answering(answer));
        assert!(question.is_some(), "{name}: the editor was asked");
        assert!(!output.status.success(), "{name}: {}", said(&output));
        assert!(f.applied().is_empty(), "{name}: {}", f.applied());
        assert!(!f.real_ran(), "{name}");
        assert!(said(&output).contains("saw govern let-in"), "{name}: {}", said(&output));
        assert!(f.questions_left().is_empty(), "{name}: {:?}", f.questions_left());
    }
}

#[test]
fn an_infected_update_without_confirm_changes_nothing() {
    let f = Fixture::new("infected-unconfirmed");
    f.held(true);
    let (output, question) = f.pull(&f.questions, &[], answering(json!({"answer": "let-in", "accept": COMMIT})));
    assert!(question.is_some());
    assert!(!output.status.success(), "{}", said(&output));
    assert!(f.applied().is_empty(), "{}", f.applied());
}

#[test]
fn a_linked_answer_changes_nothing() {
    let f = Fixture::new("linked-answer");
    f.held(false);
    let elsewhere = f.dir.join("elsewhere.json");
    let respond: Responder = Box::new(move |folder, question| {
        let id = question["id"].as_str().unwrap();
        fs::write(&elsewhere, json!({"id": id, "answer": "let-in", "accept": COMMIT}).to_string()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, folder.join(format!("{id}.answer.json"))).unwrap();
    });
    let (output, question) = f.pull(&f.questions, &[], respond);
    assert!(question.is_some());
    assert!(!output.status.success(), "{}", said(&output));
    assert!(f.applied().is_empty(), "{}", f.applied());
    assert!(said(&output).contains("it is a link"), "{}", said(&output));
}

#[test]
fn an_answer_written_before_its_question_never_counts() {
    let f = Fixture::new("answered-early");
    f.held(false);
    let early = "0123456789abcdef0123456789abcdef";
    write_answer(&f.questions, early, &json!({"id": early, "answer": "let-in", "accept": COMMIT}));
    let (output, question) = f.pull(&f.questions, &[("SAW_GOVERN_QUESTIONS_WAIT", "1")], never_answering());
    assert!(question.is_some());
    assert!(!output.status.success(), "{}", said(&output));
    assert!(f.applied().is_empty(), "{}", f.applied());
}

#[test]
fn no_answer_in_time_changes_nothing() {
    let f = Fixture::new("no-answer");
    f.held(false);
    let (output, question) = f.pull(&f.questions, &[("SAW_GOVERN_QUESTIONS_WAIT", "1")], never_answering());
    assert!(question.is_some());
    assert!(!output.status.success(), "{}", said(&output));
    assert!(f.applied().is_empty(), "{}", f.applied());
    assert!(said(&output).contains("did not answer in time"), "{}", said(&output));
    assert!(said(&output).contains("saw govern let-in"), "{}", said(&output));
    assert!(f.questions_left().is_empty(), "{:?}", f.questions_left());
}

#[test]
fn a_folder_saw_cannot_use_is_not_asked() {
    let f = Fixture::new("unusable");
    let shared = f.dir.join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();
    let in_a_repository = f.dir.join("repo").join("questions");
    fs::create_dir_all(f.dir.join("repo").join(".git")).unwrap();
    fs::create_dir(&in_a_repository).unwrap();
    fs::set_permissions(&in_a_repository, fs::Permissions::from_mode(0o700)).unwrap();
    let link = f.dir.join("link");
    std::os::unix::fs::symlink(&f.questions, &link).unwrap();
    let cases = [
        ("writable by its group", shared.clone(), "other users may write to it"),
        ("inside a repository", in_a_repository.clone(), "it lies inside a git repository"),
        ("a link", link.clone(), "it is a link"),
        ("relative", PathBuf::from("questions"), "it is not an absolute path"),
        ("missing", f.dir.join("missing"), "it does not exist"),
    ];
    f.held(false);
    for (name, folder, why) in cases {
        let watched = Fixture { dir: f.dir.clone(), questions: if folder.is_absolute() && folder.is_dir() { folder.clone() } else { f.questions.clone() } };
        let (output, question) = watched.pull(&folder, &[], answering(json!({"answer": "let-in", "accept": COMMIT})));
        assert!(question.is_none(), "{name}: saw does not ask through it");
        assert!(!output.status.success(), "{name}: {}", said(&output));
        assert!(f.applied().is_empty(), "{name}: {}", f.applied());
        assert!(said(&output).contains("not using the questions folder") && said(&output).contains(why),
                "{name}: {}", said(&output));
    }
}

#[test]
fn an_editor_runs_a_command_that_cannot_be_checked_as_typed() {
    let f = Fixture::new("run-as-typed");
    f.cannot_check();
    let (output, question) = f.pull(&f.questions, &[], answering(json!({"answer": "run-as-typed"})));
    assert!(output.status.success(), "{}", said(&output));
    assert!(f.real_ran(), "the command runs as typed");
    assert!(f.scanned(), "the folder is scanned afterwards");
    let question = question.expect("the editor was asked");
    assert_eq!(question["kind"], json!("cannot-check"));
    assert_eq!(question["choices"], json!(["run-as-typed", "leave-unchanged"]));
    assert_eq!(question["reason"], json!("the repository has no remote to fetch from"));
    assert_eq!(question["checked"], json!(false));
    assert_eq!(question["argv"], json!(["git", "pull"]));
}

#[test]
fn an_editor_leaves_a_command_that_cannot_be_checked() {
    let f = Fixture::new("leave-unchanged");
    f.cannot_check();
    let (output, question) = f.pull(&f.questions, &[], answering(json!({"answer": "leave-unchanged"})));
    assert!(question.is_some());
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(!f.real_ran(), "the folder is left unchanged");
}

#[test]
fn a_decision_made_ahead_still_comes_first() {
    let f = Fixture::new("decided-ahead");
    f.cannot_check();
    let (output, question) = f.pull(&f.questions, &[("SAW_GOVERN_DECISION", "leave-unchanged")],
                                    answering(json!({"answer": "run-as-typed"})));
    assert!(question.is_none(), "the editor is not asked");
    assert!(!output.status.success(), "{}", said(&output));
    assert!(!f.real_ran());
}
