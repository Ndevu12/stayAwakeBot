//! Answer account, elevation and system-program questions given as JSON lines. Used to compare
//! with `main`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::path::PathBuf;

use saw_platform::account::{self, Via};
use saw_platform::elevate::{self, Host};
use saw_platform::env::Environment;
use saw_platform::programs::{Finished, RunError};
use saw_platform::system_programs;

struct Scripted {
    case: serde_json::Value,
    seen: RefCell<Vec<Vec<String>>>,
}

impl Host for Scripted {
    fn trusted_sudo(&self) -> Option<PathBuf> {
        self.case["sudo"].as_str().map(PathBuf::from)
    }
    fn can_ask(&self) -> bool {
        self.case["ask"].as_bool().unwrap_or(false)
    }
    fn is_administrator(&self) -> bool {
        self.case["admin"].as_bool().unwrap_or(false)
    }
    fn run_quietly(&self, argv: &[String]) -> Result<Finished, RunError> {
        self.seen.borrow_mut().push(argv.to_vec());
        match self.case["quiet"].as_i64() {
            Some(code) => Ok(Finished { code: Some(code as i32), stdout: Vec::new(), stderr: Vec::new() }),
            None => Err(RunError::Io(io::Error::other("could not run"))),
        }
    }
    fn run_on_terminal(&self, argv: &[String]) -> Result<Option<i32>, RunError> {
        self.seen.borrow_mut().push(argv.to_vec());
        match self.case["asked"].as_i64() {
            Some(code) => Ok(Some(code as i32)),
            None => Err(RunError::Io(io::Error::other("could not run"))),
        }
    }
}

fn main() -> Result<(), String> {
    for line in io::stdin().lock().lines() {
        let case: serde_json::Value = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let answer = match case["ask_about"].as_str().unwrap_or("") {
            "acting" => {
                let variables: BTreeMap<String, String> = serde_json::from_value(case["env"].clone()).map_err(|e| e.to_string())?;
                let effective = case["euid"].as_u64().map(|v| v as u32);
                let found = account::acting_for_with(&Environment::from_variables(variables), effective, &account::account_by_uid, &account::account_by_name);
                match found {
                    None => serde_json::Value::Null,
                    Some(o) => serde_json::json!([o.name, o.uid, o.home.display().to_string(), if o.via == Via::Raised { "raised" } else { "environment" }]),
                }
            }
            "admin" => {
                let groups = case["groups"].as_array().into_iter().flatten().filter_map(|g| g.as_str().map(String::from)).collect();
                serde_json::json!(elevate::administers(&groups))
            }
            "sudo" => serde_json::json!(elevate::trusted_sudo().map(|p| p.display().to_string())),
            "system" => {
                let candidates: Vec<String> = serde_json::from_value(case["candidates"].clone()).map_err(|e| e.to_string())?;
                let borrowed: Vec<&str> = candidates.iter().map(String::as_str).collect();
                serde_json::json!(system_programs::system_program(&borrowed).map(|p| p.display().to_string()))
            }
            _ => {
                let host = Scripted { case: case.clone(), seen: RefCell::new(Vec::new()) };
                let argv: Vec<String> = vec!["chflags".into(), "uchg".into(), "/x".into()];
                let (outcome, _) = elevate::run_as_root(&argv, &host);
                serde_json::json!([outcome.name(), host.seen.into_inner()])
            }
        };
        println!("{answer}");
    }
    Ok(())
}
