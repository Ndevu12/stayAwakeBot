//! Answer process questions given as JSON lines. Used to compare with `main`.

use std::collections::BTreeMap;
use std::io::{self, BufRead, ErrorKind};
use std::path::PathBuf;

use saw_platform::elevate::Outcome as Asked;
use saw_platform::processes::program_gone::{self, FileStatus, Readers};
use saw_platform::processes::{self, stopping, windows_rows, Identity, Reading};
use serde_json::{json, Value};

fn identity_json(who: &Option<Identity>) -> Value {
    match who {
        None => Value::Null,
        Some(w) => json!([w.pid, w.ppid, w.uid, w.start_time, w.zombie, w.held_uids]),
    }
}

fn identity_from(value: &Value) -> Option<Identity> {
    let a = value.as_array()?;
    Some(Identity {
        pid: a[0].as_u64()? as u32,
        ppid: a[1].as_u64()? as u32,
        uid: a[2].as_i64()?,
        start_time: a[3].as_i64()?,
        zombie: a[4].as_bool()?,
        held_uids: a[5].as_array()?.iter().filter_map(Value::as_i64).collect(),
    })
}

fn reading_from(name: &str) -> Reading {
    match name {
        "running" => Reading::Running,
        "gone" => Reading::Gone,
        "not-ours" => Reading::NotOurs,
        _ => Reading::Unsupported,
    }
}

struct Scripted(Value);

fn failure(kind: &str) -> io::Error {
    io::Error::from(match kind {
        "perm" => ErrorKind::PermissionDenied,
        "missing" => ErrorKind::NotFound,
        _ => ErrorKind::Other,
    })
}

impl Readers for Scripted {
    fn path(&self, _pid: u32) -> Option<PathBuf> {
        self.0["path"].as_str().map(PathBuf::from)
    }
    fn running(&self, _pid: u32) -> io::Result<FileStatus> {
        match &self.0["running"] {
            Value::String(path) => program_gone::status(std::path::Path::new(path)),
            other => Err(failure(other["error"].as_str().unwrap_or(""))),
        }
    }
    fn filesystem(&self, _pid: u32) -> io::Result<u64> {
        self.0["filesystem"].as_u64().ok_or_else(|| failure("other"))
    }
    fn account(&self, _pid: u32) -> Option<i64> {
        self.0["account"].as_i64()
    }
    fn as_root(&self) -> bool {
        self.0["as_root"].as_bool().unwrap_or(false)
    }
}

fn main() -> Result<(), String> {
    for line in io::stdin().lock().lines() {
        let case: Value = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let pid = case["pid"].as_u64().unwrap_or(0) as u32;
        let answer = match case["ask_about"].as_str().unwrap_or("") {
            "identify" => {
                let (who, reading) = processes::identify(pid);
                json!([identity_json(&who), reading.name()])
            }
            "started" => json!(processes::started(pid).map(|s| json!([s.at_ns.to_string(), s.name, s.ppid]))),
            "path" => json!(processes::program_path(pid).map(|p| p.display().to_string())),
            "signature" => json!(processes::ps_signature(pid)),
            "parents" => json!(processes::parent_map().into_iter().map(|(k, v)| (k.to_string(), v)).collect::<BTreeMap<_, _>>()),
            "snapshot" => {
                let snap = processes::snapshot();
                let rows: Vec<Value> = snap.processes.iter().map(|p| json!([p.pid, p.argv, p.argv_unreadable, identity_json(&p.identity)])).collect();
                json!({"processes": rows, "unreadable": snap.unreadable, "supported": snap.supported, "note": snap.scope_note()})
            }
            "gone_live" => json!(program_gone::program_is_gone(pid)),
            "gone" => json!(program_gone::program_is_gone_with(pid, &Scripted(case.clone()))),
            "root_changes" => json!(program_gone::only_root_changes(std::path::Path::new(case["folder"].as_str().unwrap_or("")), std::path::Path::new(""))),
            "cim" => {
                let split = |line: &str| -> Option<Vec<String>> { Some(line.split_whitespace().map(String::from).collect()) };
                json!(windows_rows::rows_from_cim(case["text"].as_str().unwrap_or(""), &split).map(|rows| rows
                    .into_iter()
                    .map(|r| json!({"pid": r.pid, "ppid": r.ppid, "argv": r.argv, "path": r.path, "start": r.start, "uid": r.uid}))
                    .collect::<Vec<_>>()))
            }
            "still" => {
                let known = identity_from(&case["known"]).ok_or("known")?;
                let now = (identity_from(&case["now"]), reading_from(case["reading"].as_str().unwrap_or("")));
                json!(stopping::still_with(&known, &|_| now.clone()).map_or("running", |o| o.name()))
            }
            "stop" => {
                let (who, _) = processes::identify(pid);
                let mut known = who.ok_or("no such process")?;
                if let Some(start) = case["start_time"].as_i64() {
                    known.start_time = start;
                }
                let outcome = match case["action"].as_str().unwrap_or("") {
                    "freeze" => stopping::freeze(&known),
                    "resume" => stopping::resume(&known),
                    _ => stopping::end(&known),
                };
                json!([outcome.name(), case["action"] == "end" && outcome == stopping::Outcome::Signalled && stopping::has_ended(&known)])
            }
            "as_root" => {
                let pids: Vec<u32> = serde_json::from_value(case["pids"].clone()).map_err(|e| e.to_string())?;
                let found: BTreeMap<u32, String> = serde_json::from_value::<BTreeMap<String, String>>(case["signatures"].clone())
                    .map_err(|e| e.to_string())?
                    .into_iter()
                    .filter_map(|(k, v)| Some((k.parse().ok()?, v)))
                    .collect();
                let before = case["before"].clone();
                let after = case["after"].clone();
                let asked = std::cell::RefCell::new(Vec::<Vec<String>>::new());
                let outcome = match case["outcome"].as_str().unwrap_or("") {
                    "granted" => Asked::Granted,
                    "declined" => Asked::Declined,
                    _ => Asked::NotAvailable,
                };
                let run = |argv: &[String]| {
                    asked.borrow_mut().push(argv.to_vec());
                    (outcome, String::new())
                };
                let signature = |pid: u32| {
                    let table = if asked.borrow().len() >= 2 { &after } else { &before };
                    table[pid.to_string()].as_str().map(String::from)
                };
                let (result, ended) = stopping::end_as_root(&pids, &found, &run, &signature);
                json!([result.name(), ended, asked.into_inner()])
            }
            other => return Err(format!("unknown question {other}")),
        };
        println!("{answer}");
    }
    Ok(())
}
