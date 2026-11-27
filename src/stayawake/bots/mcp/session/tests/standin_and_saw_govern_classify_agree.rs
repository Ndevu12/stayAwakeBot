//! The git stand-in sends to saw exactly the command lines `saw govern classify` answers as checked:
//! both read the same table of command lines, which saw's Python tests read too. A line the stand-in
//! runs directly may be sent to saw instead when the repository it names cannot be read.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");
/// Answers the questions the stand-in asks git about where a push or ls-remote goes the way git
/// answers them outside a repository, and leaves them out of the record of git running.
const ANSWERS_LOOKUPS: &str = r#"case "$*" in
  "remote get-url --push --all "*) exit 2 ;;
  "config --get-regexp ^url"*) exit 1 ;;
  "symbolic-ref --short -q HEAD") exit 1 ;;
  "ls-remote --get-url"*) [ -n "$3" ] && echo "$3"; exit 0 ;;
esac
"#;
const COMMAND_LINES: &str = include_str!("command_lines_saw_checks.json");
const HELD: &str = r#"{"scan":{"results":[{"verdict":"infected"}]},"next_steps":["Review it."]}"#;
const SETTINGS_VARIABLES: &[&str] = &["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM", "GIT_CONFIG", "GIT_CONFIG_NOSYSTEM", "GIT_WORK_TREE", "GIT_DIR"];

fn exec_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn the_stand_in_sends_to_saw_exactly_the_lines_saw_answers_as_checked() {
    let dir = std::env::temp_dir().join(format!("saw-standin-agrees-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("sub")).unwrap();
    let dir = fs::canonicalize(&dir).unwrap();
    let (real_log, saw_log) = (dir.join("real.log"), dir.join("saw.log"));
    exec_script(&dir.join("real-program"), &format!("#!/bin/sh\n{ANSWERS_LOOKUPS}echo \"$@\" >> {real_log:?}\n"));
    exec_script(&dir.join("fake-saw"), &format!("#!/bin/sh\necho \"$@\" >> {saw_log:?}\nprintf '%s\\n' '{HELD}'\nexit 3\n"));
    let lines: Vec<serde_json::Value> = serde_json::from_str(COMMAND_LINES).unwrap();
    assert!(lines.len() > 20);
    for line in lines {
        let tool = line["tool"].as_str().unwrap();
        let args: Vec<&str> = line["args"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        let checked = line["checked"].as_bool().unwrap();
        let mut command = Command::new(STANDIN);
        command
            .args(&args)
            .current_dir(&dir)
            .env("SAW_STANDIN_TOOL", tool)
            .env(if tool == "git" { "SAW_REAL_GIT" } else { "SAW_REAL_GH" }, dir.join("real-program"))
            .env("SAW_BIN", dir.join("fake-saw"))
            .env("PATH", &dir)
            .env("SAW_GOVERN_HOLDING", dir.join("holding"))
            .env_remove("SAW_GOVERN_SYSTEM")
            .env_remove("SAW_GOVERN_DECISION")
            .stdin(Stdio::null());
        for name in SETTINGS_VARIABLES {
            command.env_remove(name);
        }
        command.output().unwrap();
        let asked_saw = fs::remove_file(&saw_log).is_ok();
        let ran_git = fs::remove_file(&real_log).is_ok();
        let names_its_repository = args.iter().any(|arg| arg.starts_with("--git-dir") || arg.starts_with("--work-tree") || *arg == "--bare");
        if !checked && names_its_repository && asked_saw {
            continue;
        }
        assert_eq!((asked_saw, ran_git), (checked, !checked), "{tool} {args:?}");
    }
}
