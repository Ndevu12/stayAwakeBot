//! Print where each of saw's stores is, for environments and keys given as JSON lines. Used to
//! compare with `main`.

use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::path::Path;

use saw_platform::env::Environment;
use saw_platform::sandbox::stores::Stores;

fn main() -> Result<(), String> {
    for line in io::stdin().lock().lines() {
        let case: serde_json::Value = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let variables: BTreeMap<String, String> = serde_json::from_value(case["env"].clone()).map_err(|e| e.to_string())?;
        let env = Environment::from_variables(variables);
        let stores = Stores::new(&env);
        let key = |name: &str| case[name].as_str().unwrap_or("").to_string();
        let shown = |p: std::path::PathBuf| p.display().to_string();
        println!("{}", serde_json::json!({
            "git_template": shown(stores.git_template()), "hooks": shown(stores.hooks()),
            "hook_install": shown(stores.hook_install()), "hook_history_checked": shown(stores.hook_history_checked()),
            "hook_settings_scans": shown(stores.hook_settings_scans()), "hook_warnings_shown": shown(stores.hook_warnings_shown()),
            "hook_checks_made": shown(stores.hook_checks_made()), "hook_scan_cache": shown(stores.hook_scan_cache()),
            "govern_applied": shown(stores.govern_applied()), "govern_accepted": shown(stores.govern_accepted()),
            "clean_contents_folder": shown(stores.clean_contents_folder()),
            "clean_contents": shown(stores.clean_contents(Path::new(&key("root")))),
            "push_record": shown(stores.push_record(Path::new(&key("git_dir")))),
            "set_aside_hooks": shown(stores.set_aside_hooks()), "watch_install": shown(stores.watch_install()),
            "live_code": shown(stores.live_code()), "agent_approvals": shown(stores.agent_approvals()),
            "editor_changes": shown(stores.editor_changes()), "captured": shown(stores.captured()),
            "govern_status": shown(stores.govern_status()), "autorun_baseline": shown(stores.autorun_baseline()),
            "amend_state": shown(stores.amend_state(&key("slug"))), "advisories": shown(stores.advisories()),
            "github_app": shown(stores.github_app()), "github_app_earlier": shown(stores.github_app_earlier()),
            "watch_schedule": shown(stores.watch_schedule()),
            "watch_shared": shown(stores.watch_shared(&env.home())),
        }));
    }
    Ok(())
}
