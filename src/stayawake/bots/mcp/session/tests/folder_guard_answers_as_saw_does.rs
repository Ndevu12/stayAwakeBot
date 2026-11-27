#![cfg(unix)]
//! The stand-in works out the settings and environment that keep a git command from starting a
//! program the folder's own settings name, the same ones `saw govern classify` answers: both answer
//! every case in `folder_guard_cases.json`, which saw's Python tests check too.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use saw_mcp::folder_guard::{guard, Environment};

mod common;
use common::real_git;

const CASES: &str = include_str!("folder_guard_cases.json");
const NO_HOOKS: &str = "@NO_HOOKS@";

fn init(git: &Path, home: &Path, args: &[&str]) {
    let done = Command::new(git)
        .arg("init")
        .arg("-q")
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(done.success(), "git init {args:?}");
}

fn in_repo(git: &Path, root: &Path, args: &[&str]) {
    let done = Command::new(git)
        .arg("-C")
        .arg(root.join("repo"))
        .args(["-c", "user.name=saw", "-c", "user.email=saw@example.invalid"])
        .args(args)
        .env_clear()
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(done.success(), "git {args:?}");
}

/// Make the folder one case runs in. Returns the folder the command runs in.
fn build_folder(root: &Path, case: &serde_json::Value, git: &Path) -> PathBuf {
    fs::create_dir_all(root).unwrap();
    let shown = |path: &Path| path.display().to_string();
    let (folder, settings) = match case["layout"].as_str().unwrap() {
        "plain" => {
            fs::create_dir_all(root.join("folder")).unwrap();
            return root.join("folder");
        }
        "bare" => {
            init(git, root, &["--bare", &shown(&root.join("repo.git"))]);
            (root.join("repo.git"), root.join("repo.git"))
        }
        layout => {
            init(git, root, &[&shown(&root.join("repo"))]);
            let mut settings = root.join("repo").join(".git");
            if layout == "submodule" {
                init(git, root, &["--bare", &shown(&settings.join("modules").join("sub"))]);
                settings = settings.join("modules").join("sub");
            }
            let mut folder = root.join("repo");
            if layout == "elsewhere" {
                folder = root.join("folder");
                fs::create_dir_all(&folder).unwrap();
            }
            if layout == "worktree" {
                in_repo(git, root, &["commit", "-q", "--allow-empty", "-m", "base"]);
                in_repo(git, root, &["worktree", "add", "-q", "--detach", &shown(&root.join("wt"))]);
                folder = root.join("wt");
                let own = case["worktree_settings"].as_str().unwrap_or("");
                fs::write(settings.join("worktrees").join("wt").join("config.worktree"), own).unwrap();
            }
            (folder, settings)
        }
    };
    let config = settings.join("config");
    let mut text = fs::read_to_string(&config).unwrap();
    text.push_str(case["settings"].as_str().unwrap());
    fs::write(&config, text).unwrap();
    for (name, included) in case["included"].as_object().into_iter().flatten() {
        fs::write(settings.join(name), included.as_str().unwrap()).unwrap();
    }
    folder
}

/// Answer one case with the stand-in's guard, saw's empty hooks folder spelled `@NO_HOOKS@`.
fn answer(git: &Path, folder: &Path, case: &serde_json::Value, environ: &Environment) -> serde_json::Value {
    let args: Vec<String> = case["args"].as_array().unwrap().iter().map(|arg| arg.as_str().unwrap().to_string()).collect();
    let Ok(run_with) = guard(git, folder, &args, environ) else { return serde_json::json!({"refused": true}) };
    let hooks = Path::new(&environ["XDG_STATE_HOME"]).join("saw").join("git-runs-no-hooks").display().to_string();
    let spelled = |text: &str| text.replace(&hooks, NO_HOOKS);
    serde_json::json!({
        "settings": run_with.settings.iter().map(|(key, value)| serde_json::json!([spelled(key), spelled(value)])).collect::<Vec<_>>(),
        "arguments": run_with.arguments.iter().map(|arg| spelled(arg)).collect::<Vec<_>>(),
        "environment": run_with.environment.iter().map(|(name, value)| (name.clone(), serde_json::Value::from(spelled(value)))).collect::<serde_json::Map<_, _>>(),
    })
}

#[test]
fn the_stand_in_answers_every_shared_case_as_saw_does() {
    let table: serde_json::Value = serde_json::from_str(CASES).unwrap();
    let cases = table["cases"].as_array().unwrap();
    assert!(cases.len() >= 25);
    let git = real_git();
    let made = std::env::temp_dir().join(format!("saw-folder-guard-{}", std::process::id()));
    let _ = fs::remove_dir_all(&made);
    fs::create_dir_all(&made).unwrap();
    let home = fs::canonicalize(&made).unwrap();
    fs::write(home.join(".gitconfig"), table["operator_settings"].as_str().unwrap()).unwrap();
    let mut differ = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let folder = build_folder(&home.join("cases").join(name), case, &git);
        let mut environ: Environment = HashMap::from([
            ("HOME".to_string(), home.display().to_string()),
            ("XDG_STATE_HOME".to_string(), home.join("state").display().to_string()),
            ("PATH".to_string(), std::env::var("PATH").unwrap_or_default()),
            ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        ]);
        for (key, value) in case["environment"].as_object().into_iter().flatten() {
            environ.insert(key.clone(), value.as_str().unwrap().to_string());
        }
        let found = answer(&git, &folder, case, &environ);
        if found != case["expected"] {
            differ.push(format!("{name}:\n  saw:       {}\n  stand-in:  {found}", case["expected"]));
        }
    }
    let _ = fs::remove_dir_all(&made);
    assert!(differ.is_empty(), "the stand-in answers differently from saw:\n{}", differ.join("\n"));
}
