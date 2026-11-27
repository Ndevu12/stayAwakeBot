//! The stand-in reads the same fingerprint of a repository's own program-running settings as saw's
//! Python: both read every case in `settings_fingerprint_cases.json`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use saw_mcp::folder_guard::{fingerprint, Environment};

mod common;
use common::real_git;

const CASES: &str = include_str!("settings_fingerprint_cases.json");
const ROOT: &str = "@ROOT@";

fn build(root: &Path, case: &serde_json::Value, operator: &str, git: &Path) -> Environment {
    let _ = fs::remove_dir_all(root);
    fs::create_dir_all(root).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let shown = root.display().to_string();
    let global = root.join(".gitconfig");
    let own = case["operator_settings"].as_str().unwrap_or(operator).replace(ROOT, &shown);
    fs::write(&global, own).unwrap();
    let made = Command::new(git).args(["init", "-q"]).arg(root.join("repo")).env_clear().env("HOME", &root)
        .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null").stdin(Stdio::null()).status().unwrap();
    assert!(made.success());
    let config = root.join("repo/.git/config");
    let text = fs::read_to_string(&config).unwrap() + case["settings"].as_str().unwrap();
    fs::write(&config, text).unwrap();
    for (path, contents) in case["files"].as_object().unwrap() {
        let at = root.join(path);
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        fs::write(at, contents.as_str().unwrap()).unwrap();
    }
    let mut environ = Environment::new();
    environ.insert("HOME".into(), shown.clone());
    environ.insert("PATH".into(), std::env::var("PATH").unwrap_or_default());
    environ.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
    environ.insert("GIT_CONFIG_GLOBAL".into(), global.display().to_string());
    environ.insert("XDG_STATE_HOME".into(), root.join("state").display().to_string());
    environ.insert("XDG_CONFIG_HOME".into(), root.join("config").display().to_string());
    environ
}

#[test]
fn every_shared_case_reads_the_same_fingerprint() {
    let cases: serde_json::Value = serde_json::from_str(CASES).unwrap();
    let operator = cases["operator_settings"].as_str().unwrap();
    let git = real_git();
    for case in cases["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let root: PathBuf = std::env::temp_dir().join(format!("saw-fingerprint-{}-{name}", std::process::id()));
        let environ = build(&root, case, operator, &git);
        let shown = fs::canonicalize(&root).unwrap().display().to_string();
        let read = fingerprint(&git, &root.join("repo"), &["status".to_string()], &environ)
            .unwrap_or_else(|why| panic!("{name}: {why}"))
            .unwrap_or_else(|| panic!("{name}: no repository"));
        let expected: Vec<Vec<String>> = case["expected"].as_array().unwrap().iter()
            .map(|entry| entry.as_array().unwrap().iter().map(|part| part.as_str().unwrap().replace(ROOT, &shown)).collect())
            .collect();
        assert_eq!(read.entries, expected, "{name}");
        assert_eq!(read.is_empty(), expected.is_empty(), "{name}");
        if let Some(digest) = case["digest"].as_str() {
            assert_eq!(read.digest(), digest, "{name}");
        }
        let _ = fs::remove_dir_all(&root);
    }
}
