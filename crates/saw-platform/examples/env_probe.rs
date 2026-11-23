//! Print every environment answer for each set of variables given as a JSON line. Used to compare
//! with `main`.

use std::collections::BTreeMap;
use std::io::{self, BufRead};

use saw_platform::env::Environment;

fn main() -> Result<(), String> {
    for line in io::stdin().lock().lines() {
        let variables: BTreeMap<String, String> = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let env = Environment::from_variables(variables);
        let answer = serde_json::json!({
            "github_token": env.github_token(),
            "github_repository": env.github_repository(),
            "github_slug": env.github_slug(),
            "slack_webhook": env.slack_webhook(),
            "no_color": env.no_color(),
            "clicolor_force": env.clicolor_force(),
            "is_ci": env.is_ci(),
            "stream_disabled": env.stream_disabled(),
            "stream_forced": env.stream_forced(),
            "hook_disabled": env.hook_disabled(),
            "hook_timeout": env.hook_timeout(None),
            "hook_timeout_push": env.hook_timeout(Some("pre-push")),
            "xdg_config_home": env.xdg_config_home().display().to_string(),
            "xdg_cache_home": env.xdg_cache_home().display().to_string(),
            "xdg_state_home": env.xdg_state_home().display().to_string(),
            "autorun_baseline_path": env.autorun_baseline_path().map(|p| p.display().to_string()),
            "is_ephemeral_runner": env.is_ephemeral_runner(),
        });
        println!("{answer}");
    }
    Ok(())
}
