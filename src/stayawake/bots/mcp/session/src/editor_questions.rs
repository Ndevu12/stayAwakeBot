//! The questions the git stand-in leaves for an editor when no person is at a terminal. An editor
//! names a folder in `SAW_GOVERN_QUESTIONS` for the processes it starts. saw writes each question
//! there as `<id>.question.json`, waits a bounded time for `<id>.answer.json`, and removes both
//! afterwards. Only an answer that matches its question exactly counts.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::folder_guard::lies_inside_a_repository;
use crate::platform;

/// The variable an editor names its questions folder in.
pub const FOLDER_VARIABLE: &str = "SAW_GOVERN_QUESTIONS";
/// The variable that sets how many seconds saw waits for an answer.
pub const WAIT_VARIABLE: &str = "SAW_GOVERN_QUESTIONS_WAIT";
/// The answer that runs a command as typed.
pub const RUN_AS_TYPED: &str = "run-as-typed";
/// The answer that lets in an update saw held.
pub const LET_IN: &str = "let-in";
/// The answer that leaves the folder unchanged.
pub const LEAVE_UNCHANGED: &str = "leave-unchanged";

const SCHEMA_VERSION: u64 = 1;
const DEFAULT_WAIT_SECONDS: u64 = 120;
const LONGEST_WAIT_SECONDS: u64 = 600;
const LONGEST_ANSWER_BYTES: u64 = 64 << 10;
const LOOK_AGAIN_AFTER: Duration = Duration::from_millis(100);
const ID_BYTES: usize = 16;
const QUESTION_ENDING: &str = ".question.json";
const ANSWER_ENDING: &str = ".answer.json";

/// What a question asks.
#[derive(Debug, Clone)]
pub enum Asked {
    /// Whether to run a command that cannot be checked, or was checked and cannot be brought in: saw's
    /// reason and whether saw checked it.
    CannotCheck { reason: String, checked: bool },
    /// Whether to let in an update saw held: the commit to accept, whether the infected update's
    /// confirmation is needed, its findings and the next steps.
    Held { accept: String, confirm: bool, findings: Vec<Value>, next_steps: Vec<String> },
}

/// One question: what it asks, the command line with the tool first, and the folder it ran in.
#[derive(Debug, Clone)]
pub struct Question {
    pub asked: Asked,
    pub argv: Vec<String>,
    pub folder: String,
}

impl Question {
    /// The answers this question takes.
    pub fn choices(&self) -> [&'static str; 2] {
        match self.asked {
            Asked::CannotCheck { .. } => [RUN_AS_TYPED, LEAVE_UNCHANGED],
            Asked::Held { .. } => [LET_IN, LEAVE_UNCHANGED],
        }
    }

    /// Write the question for the editor. Takes its id. Returns the document.
    fn to_json(&self, id: &str) -> Value {
        let mut document = json!({
            "schema_version": SCHEMA_VERSION,
            "id": id,
            "choices": self.choices(),
            "argv": self.argv,
            "folder": self.folder,
        });
        match &self.asked {
            Asked::CannotCheck { reason, checked } => {
                document["kind"] = json!("cannot-check");
                document["reason"] = json!(reason);
                document["checked"] = json!(checked);
            }
            Asked::Held { accept, confirm, findings, next_steps } => {
                document["kind"] = json!("held");
                document["findings"] = json!(findings);
                document["next_steps"] = json!(next_steps);
                document["accept"] = json!(accept);
                document["confirm"] = json!(confirm);
            }
        }
        document
    }

    /// Say why an answer does not count for this question. Takes the answer and the question's id.
    /// Returns the answer chosen, or why it does not count.
    fn counted(&self, answer: &Value, id: &str) -> Result<&'static str, &'static str> {
        if answer.get("id").and_then(Value::as_str) != Some(id) {
            return Err("its id is not this question's");
        }
        let given = answer.get("answer").and_then(Value::as_str).unwrap_or("");
        let Some(chosen) = self.choices().into_iter().find(|choice| *choice == given) else {
            return Err("its answer is not one of this question's choices");
        };
        if let (Asked::Held { accept, confirm, .. }, LET_IN) = (&self.asked, chosen) {
            if answer.get("accept").and_then(Value::as_str) != Some(accept.as_str()) {
                return Err("it does not accept the commit saw checked");
            }
            if *confirm && answer.get("confirm").and_then(Value::as_bool) != Some(true) {
                return Err("an infected update is let in only with confirm set to true");
            }
        }
        Ok(chosen)
    }
}

/// The questions folder an editor named, and how long saw waits for an answer there.
#[derive(Debug)]
pub struct QuestionsFolder {
    folder: PathBuf,
    wait: Duration,
}

impl QuestionsFolder {
    /// Read the questions folder an editor named in this process's environment, and how long to wait.
    /// Say on standard error why a folder named there is not used. Returns it, or None for none named
    /// or one that cannot be used.
    pub fn named() -> Option<Self> {
        let named = env::var_os(FOLDER_VARIABLE).filter(|value| !value.is_empty())?;
        let folder = PathBuf::from(named);
        if let Err(why) = usable(&folder) {
            eprintln!("saw: not using the questions folder {}: {why}.", folder.display());
            return None;
        }
        Some(QuestionsFolder { folder, wait: wait_from_environment() })
    }

    /// Ask the editor a question and wait for its answer. Takes the question. Returns the answer
    /// chosen, or None for an answer that does not count or none in time.
    pub fn ask(&self, question: &Question) -> Option<&'static str> {
        let id = match new_id() {
            Ok(id) => id,
            Err(error) => {
                eprintln!("saw: could not ask the editor: {error}.");
                return None;
            }
        };
        let asking = Asking::new(&self.folder, &id);
        if let Err(error) = asking.write(&question.to_json(&id)) {
            eprintln!("saw: could not ask the editor: {error}.");
            return None;
        }
        eprintln!("saw: asked the editor; waiting up to {} seconds for its answer.", self.wait.as_secs());
        let deadline = Instant::now() + self.wait;
        loop {
            match asking.read_answer() {
                Some(Ok(answer)) => {
                    return match question.counted(&answer, &id) {
                        Ok(chosen) => Some(chosen),
                        Err(why) => {
                            eprintln!("saw: the editor's answer does not count: {why}.");
                            None
                        }
                    };
                }
                Some(Err(why)) => {
                    eprintln!("saw: the editor's answer does not count: {why}.");
                    return None;
                }
                None if Instant::now() >= deadline => {
                    eprintln!("saw: the editor did not answer in time.");
                    return None;
                }
                None => thread::sleep(LOOK_AGAIN_AFTER),
            }
        }
    }
}

/// Say why a folder cannot hold questions. Takes the folder. Returns why, or Ok for an absolute
/// path to a folder, not a link, this user owns, only its owner may write to, outside every git
/// repository.
fn usable(folder: &Path) -> Result<(), &'static str> {
    if !folder.is_absolute() {
        return Err("it is not an absolute path");
    }
    let found = fs::symlink_metadata(folder).map_err(|_| "it does not exist")?;
    if found.file_type().is_symlink() {
        return Err("it is a link");
    }
    if !found.is_dir() {
        return Err("it is not a folder");
    }
    if !platform::belongs_to_this_user(folder, &found) {
        return Err("it belongs to another user");
    }
    if platform::others_may_write(&found) {
        return Err("other users may write to it");
    }
    if lies_inside_a_repository(folder) {
        return Err("it lies inside a git repository");
    }
    Ok(())
}

/// Read how long to wait for an answer: the seconds `SAW_GOVERN_QUESTIONS_WAIT` names, at most ten
/// minutes, else two minutes. Say on standard error when the value is not a number of seconds.
fn wait_from_environment() -> Duration {
    let seconds = match env::var(WAIT_VARIABLE) {
        Ok(text) => text.trim().parse::<u64>().unwrap_or_else(|_| {
            eprintln!("saw: {WAIT_VARIABLE} is not a number of seconds; waiting {DEFAULT_WAIT_SECONDS}.");
            DEFAULT_WAIT_SECONDS
        }),
        Err(_) => DEFAULT_WAIT_SECONDS,
    };
    Duration::from_secs(seconds.min(LONGEST_WAIT_SECONDS))
}

/// Make a question's id: 128 random bits, in hex.
fn new_id() -> io::Result<String> {
    let mut bytes = [0u8; ID_BYTES];
    platform::fill_random(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// One question's files in the questions folder, removed when it is dropped.
struct Asking {
    question: PathBuf,
    being_written: PathBuf,
    answer: PathBuf,
}

impl Asking {
    fn new(folder: &Path, id: &str) -> Self {
        Asking {
            question: folder.join(format!("{id}{QUESTION_ENDING}")),
            being_written: folder.join(format!(".{id}.question.tmp")),
            answer: folder.join(format!("{id}{ANSWER_ENDING}")),
        }
    }

    /// Write the question whole under its own name, a new file first then renamed. Takes the
    /// document. Returns why it could not be written.
    fn write(&self, document: &Value) -> io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&self.being_written)?;
        file.write_all(format!("{document}\n").as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&self.being_written, &self.question)
    }

    /// Read the answer. Returns None until a JSON object is there, the answer once one is, or why
    /// the file there cannot be an answer: a link, not a regular file, another user's file or one
    /// longer than the limit.
    fn read_answer(&self) -> Option<Result<Value, &'static str>> {
        let found = fs::symlink_metadata(&self.answer).ok()?;
        if found.file_type().is_symlink() {
            return Some(Err("it is a link"));
        }
        if !found.is_file() {
            return Some(Err("it is not a regular file"));
        }
        if !platform::belongs_to_this_user(&self.answer, &found) {
            return Some(Err("it belongs to another user"));
        }
        let mut text = String::new();
        let file = fs::File::open(&self.answer).ok()?;
        file.take(LONGEST_ANSWER_BYTES + 1).read_to_string(&mut text).ok()?;
        if text.len() as u64 > LONGEST_ANSWER_BYTES {
            return Some(Err("it is too long"));
        }
        serde_json::from_str::<Value>(&text).ok().filter(Value::is_object).map(Ok)
    }
}

impl Drop for Asking {
    fn drop(&mut self) {
        for file in [&self.being_written, &self.question, &self.answer] {
            let _ = fs::remove_file(file);
        }
    }
}
