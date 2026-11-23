//! Read git requests as JSON lines and print how saw would run each: the refusal, or the
//! arguments, environment and folder. Used to compare with `main`.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use saw_platform::programs::git::{self, Context, Folders, Request};

fn context(name: &str) -> Context {
    match name {
        "UNTRUSTED" => Context::Untrusted,
        "SAW_OWNED" => Context::SawOwned,
        "OPERATOR_PUSH" => Context::OperatorPush,
        _ => Context::OperatorConfig,
    }
}

fn main() -> Result<(), String> {
    let stdin = io::stdin();
    let mut out = io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let case: serde_json::Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        let text = |key: &str| case[key].as_str().unwrap_or_default().to_string();
        let map = |key: &str| -> Option<BTreeMap<String, String>> {
            case[key].as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect())
        };
        let folders = Folders { empty_hooks: PathBuf::from(text("hooks")), neutral: PathBuf::from(text("neutral")) };
        let repo = case["repo"].as_str().map(PathBuf::from);
        if case["owned"].as_bool() == Some(true) {
            if let Some(repo) = &repo {
                git::own(repo);
            }
        }
        let callers = map("env");
        let inherited = map("inherited").unwrap_or_default();
        let args: Vec<String> = case["args"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)).collect();
        let request = Request { context: context(&text("context")), repo: repo.as_deref(), args, env: callers.as_ref(), stdin: None, timeout: Duration::from_secs(1) };
        let answer = match git::prepare(&request, Path::new("git"), &folders, &inherited) {
            Ok(invocation) => {
                let argv: Vec<String> = std::iter::once("git".to_string()).chain(invocation.args).collect();
                let cwd = invocation.cwd.map(|p| p.display().to_string());
                serde_json::json!({"argv": argv, "env": invocation.env, "cwd": cwd})
            }
            Err(error) => serde_json::json!({"refused": error.to_string()}),
        };
        if let Some(repo) = &repo {
            git::disown(repo);
        }
        writeln!(out, "{answer}").map_err(|e| e.to_string())?;
    }
    Ok(())
}
