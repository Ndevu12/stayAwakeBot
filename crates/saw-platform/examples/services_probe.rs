//! Answer service-manager, session-bus and Windows-lock questions given as JSON lines. Used to
//! compare with `main`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use saw_platform::programs::Runner;
use saw_platform::services::{self, session_bus, Job, Manager, Platform};
use saw_platform::windows_security;
use serde_json::{json, Value};

struct Scripted {
    codes: Vec<Value>,
    seen: RefCell<Vec<Value>>,
}

impl Runner for Scripted {
    fn run(&self, argv: &[String], env: Option<&BTreeMap<String, String>>) -> io::Result<Option<i32>> {
        let copy = argv.iter().position(|a| a == "/XML").and_then(|i| std::fs::read(&argv[i + 1]).ok());
        let index = self.seen.borrow().len();
        self.seen.borrow_mut().push(json!([argv, env, copy.map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>())]));
        match self.codes.get(index).cloned().unwrap_or(json!(0)) {
            Value::Number(code) => Ok(Some(code.as_i64().unwrap_or(0) as i32)),
            _ => Err(io::Error::other("could not run")),
        }
    }
}

fn main() -> Result<(), String> {
    for line in io::stdin().lock().lines() {
        let case: Value = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let runner = Scripted { codes: case["codes"].as_array().cloned().unwrap_or_default(), seen: RefCell::new(Vec::new()) };
        let text = |key: &str| case[key].as_str().map(String::from);
        let answer = match case["ask_about"].as_str().unwrap_or("") {
            "candidates" => json!([Platform::current().candidates(), services::every_candidate()]),
            "manage" => {
                let platform = match case["platform"].as_str().unwrap_or("") {
                    "linux" => Platform::Systemd,
                    "windows" => Platform::WindowsScheduler,
                    _ => Platform::Launchd,
                };
                let env: Option<BTreeMap<String, String>> = serde_json::from_value(case["env"].clone()).map_err(|e| e.to_string())?;
                let manager = Manager { platform, program: PathBuf::from("/sys/manager"), account: case["account"].as_u64().map(|a| a as u32), env };
                let job = Job { label: "com.example.job", unit: "example.service", task: "example" };
                let item = PathBuf::from(text("item").unwrap_or_default());
                let result = match case["action"].as_str().unwrap_or("") {
                    "activate" => json!(manager.activate(job, &item, &runner)),
                    "running" => json!(manager.is_running(job, &runner)),
                    _ => {
                        manager.deactivate(job, &item, &runner);
                        Value::Null
                    }
                };
                json!([result, runner.seen.into_inner(), Path::new(&format!("{}.utf16", item.display())).exists()])
            }
            "user_manager" => json!(session_bus::user_manager_env_for(case["uid"].as_u64().unwrap_or(0) as u32, text("runtime").as_deref(), text("given").as_deref())),
            "bus" => json!(session_bus::session_bus_env_for(case["uid"].as_u64().unwrap_or(0) as u32, text("runtime").as_deref())),
            "grade" => json!(windows_security::grade(text("owner").as_deref(), text("acting").as_deref())),
            "lock" => {
                let path = PathBuf::from(text("path").unwrap_or_default());
                let sid = text("sid").unwrap_or_default();
                let program = Some(Path::new(r"C:\icacls.exe"));
                let result = match case["action"].as_str().unwrap_or("") {
                    "deny" => windows_security::deny_writes(&path, &sid, &runner, program),
                    "allow" => windows_security::allow_writes(&path, &sid, &runner, program),
                    _ => windows_security::give_to_administrators(&path, &runner, program),
                };
                json!([result, runner.seen.into_inner().iter().map(|s| s[0].clone()).collect::<Vec<_>>()])
            }
            other => return Err(format!("unknown question {other}")),
        };
        println!("{answer}");
    }
    Ok(())
}
