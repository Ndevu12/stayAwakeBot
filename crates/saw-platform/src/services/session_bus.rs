//! The environment that reaches this account's own service manager and session bus.

use std::collections::BTreeMap;
use std::path::Path;

#[cfg(unix)]
fn status(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|found| (found.mode() & 0o170000, found.uid()))
}

#[cfg(not(unix))]
fn status(_path: &Path) -> Option<(u32, u32)> {
    None
}

/// Return an account's runtime folder. Takes the account id and the folder given, if any.
pub fn runtime_folder(user: u32, runtime: Option<&str>) -> String {
    runtime.filter(|r| !r.is_empty()).map(String::from).unwrap_or_else(|| format!("/run/user/{user}"))
}

/// Return the environment this account's service manager is reached with, or an empty one.
pub fn user_manager_env() -> BTreeMap<String, String> {
    #[cfg(unix)]
    return user_manager_env_for(crate::account::user_id(), None, std::env::var("XDG_RUNTIME_DIR").ok().as_deref());
    #[cfg(not(unix))]
    return BTreeMap::new();
}

/// Return the environment an account's service manager is reached with, or an empty one. Takes
/// the account id, the runtime folder to try first and the one saw was given.
pub fn user_manager_env_for(user: u32, runtime: Option<&str>, given: Option<&str>) -> BTreeMap<String, String> {
    let first = runtime_folder(user, runtime);
    for folder in [Some(first.as_str()), given].into_iter().flatten().filter(|f| !f.is_empty()) {
        if status(Path::new(folder)) == Some((0o040000, user)) {
            let mut env = BTreeMap::from([("XDG_RUNTIME_DIR".to_string(), folder.to_string())]);
            env.extend(session_bus_env_for(user, Some(folder)).unwrap_or_default());
            return env;
        }
    }
    BTreeMap::new()
}

/// Return the environment a program needs to reach an account's session bus, or none. Takes the
/// account id and the runtime folder.
pub fn session_bus_env_for(user: u32, runtime: Option<&str>) -> Option<BTreeMap<String, String>> {
    let folder = runtime_folder(user, runtime);
    let socket = format!("{folder}/bus");
    if status(Path::new(&socket))? != (0o140000, user) {
        return None;
    }
    Some(BTreeMap::from([
        ("XDG_RUNTIME_DIR".to_string(), folder),
        ("DBUS_SESSION_BUS_ADDRESS".to_string(), format!("unix:path={socket}")),
    ]))
}
