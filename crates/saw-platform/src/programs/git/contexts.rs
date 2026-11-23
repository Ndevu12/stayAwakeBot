//! The contexts a git command runs under.

use std::collections::BTreeMap;
use std::path::Path;

/// Where a context may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Where {
    AnyRepository,
    OwnedOrNone,
    NoRepository,
}

/// One context a git command runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Context {
    Untrusted,
    SawOwned,
    OperatorPush,
    OperatorConfig,
}

const NO_EXECUTION: &[(&str, &str)] = &[
    ("core.fsmonitor", "false"), ("diff.external", ""), ("core.pager", "cat"), ("core.editor", "false"),
    ("sequence.editor", "false"), ("protocol.allow", "never"), ("gc.auto", "0"), ("maintenance.auto", "false"),
    ("credential.helper", ""), ("log.showSignature", "false"), ("log.mailmap", "false"),
    ("log.diffMerges", "separate"), ("commit.gpgSign", "false"), ("tag.gpgSign", "false"),
    ("gpg.program", "false"), ("gpg.openpgp.program", "false"), ("gpg.x509.program", "false"),
    ("gpg.ssh.program", "false"), ("gpg.ssh.defaultKeyCommand", "false"), ("core.sshCommand", "false"),
    ("core.askPass", "false"), ("submodule.recurse", "false"), ("fetch.recurseSubmodules", "false"),
];

const OPERATOR_NETWORK: &[(&str, &str)] = &[
    ("core.fsmonitor", "false"), ("core.pager", "cat"), ("core.editor", "false"), ("protocol.allow", "never"),
    ("gc.auto", "0"), ("maintenance.auto", "false"), ("log.showSignature", "false"), ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"),
];

const OPERATOR_LOCAL: &[(&str, &str)] =
    &[("core.fsmonitor", "false"), ("core.pager", "cat"), ("core.editor", "false"), ("protocol.allow", "never")];

pub const OPERATOR_TRANSPORTS: &[&str] = &["https", "ssh"];

pub const HOOK_NAMES: &[&str] = &[
    "applypatch-msg", "commit-msg", "fsmonitor-watchman", "p4-changelist", "p4-post-changelist", "p4-pre-submit",
    "p4-prepare-changelist", "post-applypatch", "post-checkout", "post-commit", "post-index-change", "post-merge",
    "post-receive", "post-rewrite", "post-update", "pre-applypatch", "pre-auto-gc", "pre-commit", "pre-merge-commit",
    "pre-push", "pre-rebase", "pre-receive", "prepare-commit-msg", "proc-receive", "push-to-checkout",
    "reference-transaction", "sendemail-validate", "update",
];

pub const KEYS_A_CALLER_MAY_NOT_SET: &[&str] = &[
    "core.hookspath", "core.fsmonitor", "diff.external", "core.pager", "core.editor", "sequence.editor",
    "protocol.allow", "credential.helper", "core.askpass", "core.sshcommand", "gc.auto", "maintenance.auto",
    "submodule.recurse", "fetch.recursesubmodules",
];

pub const KEY_PREFIXES_A_CALLER_MAY_NOT_SET: &[&str] = &["protocol.", "hook.", "include.", "includeif."];

const LOCATION_VARS: &[&str] = &[
    "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES", "GIT_PREFIX",
];
const CONFIG_INJECTION_PREFIXES: &[&str] = &["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"];
const ISOLATION_VARS: &[&str] = &["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"];
const STORED_VIEW: &[(&str, &str)] = &[("GIT_NO_REPLACE_OBJECTS", "1"), ("GIT_NO_LAZY_FETCH", "1")];
pub const GOVERN_ACTIVATION: &[&str] = &["SAW_GOVERN_SYSTEM", "SAW_GOVERN_HOLDING"];
pub const SAW_HOOK_DISABLED: &str = "SAW_HOOK_DISABLED";

impl Context {
    /// Return the context's name.
    pub fn name(self) -> &'static str {
        match self {
            Context::Untrusted => "UNTRUSTED",
            Context::SawOwned => "SAW_OWNED",
            Context::OperatorPush => "OPERATOR_PUSH",
            Context::OperatorConfig => "OPERATOR_CONFIG",
        }
    }

    /// Return the `-c` pairs this context sets.
    pub fn overrides(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Context::Untrusted | Context::SawOwned => NO_EXECUTION,
            Context::OperatorPush => OPERATOR_NETWORK,
            Context::OperatorConfig => OPERATOR_LOCAL,
        }
    }

    /// Return whether the operator's own configuration is kept.
    pub fn operator_scopes(self) -> bool {
        matches!(self, Context::OperatorPush | Context::OperatorConfig)
    }

    /// Return where this context may run.
    pub fn place(self) -> Where {
        match self {
            Context::Untrusted => Where::AnyRepository,
            Context::SawOwned | Context::OperatorPush => Where::OwnedOrNone,
            Context::OperatorConfig => Where::NoRepository,
        }
    }

    /// Return whether pathspecs are literal.
    pub fn literal_pathspecs(self) -> bool {
        matches!(self, Context::Untrusted | Context::SawOwned)
    }
}

/// Build the options a context places before the caller's arguments. Takes the context and saw's
/// empty hooks folder. Returns the options.
pub fn config_prefix(context: Context, empty_hooks: &Path) -> Vec<String> {
    let mut out = vec!["-c".to_string(), format!("core.hooksPath={}", empty_hooks.display())];
    for event in HOOK_NAMES {
        out.extend(["-c".to_string(), format!("hook.{event}.enabled=false")]);
    }
    for (key, value) in context.overrides() {
        out.extend(["-c".to_string(), format!("{key}={value}")]);
    }
    if context == Context::OperatorPush {
        for transport in OPERATOR_TRANSPORTS {
            out.extend(["-c".to_string(), format!("protocol.{transport}.allow=always")]);
        }
    }
    if context.literal_pathspecs() {
        out.push("--literal-pathspecs".to_string());
    }
    out
}

fn injects_config(key: &str) -> bool {
    key == "GIT_CONFIG" || CONFIG_INJECTION_PREFIXES.iter().any(|prefix| key.starts_with(prefix))
}

/// Build the environment git runs in. Takes the context, the inherited environment, the caller's
/// environment or none, whether the command reads the operator's configuration, and saw's neutral
/// folder or none. Returns the environment.
pub fn child_env(
    context: Context,
    inherited: &BTreeMap<String, String>,
    callers: Option<&BTreeMap<String, String>>,
    operator_scopes: Option<bool>,
    neutral: Option<&Path>,
) -> BTreeMap<String, String> {
    let scopes = operator_scopes.unwrap_or(context.operator_scopes());
    let source = callers.unwrap_or(inherited);
    let mut out = BTreeMap::new();
    for (key, value) in source {
        if !key.starts_with("GIT_") {
            out.insert(key.clone(), value.clone());
            continue;
        }
        let explicit = callers.is_some() && inherited.get(key) != Some(value);
        if explicit && !injects_config(key) && !ISOLATION_VARS.contains(&key.as_str()) {
            out.insert(key.clone(), value.clone());
        } else if scopes && !LOCATION_VARS.contains(&key.as_str()) && !injects_config(key) {
            out.insert(key.clone(), value.clone());
        }
    }
    if !scopes {
        for key in ISOLATION_VARS {
            out.remove(*key);
        }
        out.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        out.insert("GIT_CONFIG_GLOBAL".into(), null_device().into());
    }
    out.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    out.insert(SAW_HOOK_DISABLED.into(), "1".into());
    for key in GOVERN_ACTIVATION {
        out.remove(*key);
    }
    let protocols = if context == Context::OperatorPush { OPERATOR_TRANSPORTS.join(":") } else { String::new() };
    out.insert("GIT_ALLOW_PROTOCOL".into(), protocols);
    for (key, value) in STORED_VIEW {
        out.insert((*key).into(), (*value).into());
    }
    out.insert("GIT_GRAFT_FILE".into(), Path::new(null_device()).join("grafts").display().to_string());
    if let Some(neutral) = neutral {
        let parent = neutral.parent().unwrap_or(neutral);
        out.insert("GIT_CEILING_DIRECTORIES".into(), parent.display().to_string());
    }
    out
}

/// Return the path that reads as empty on this system.
pub fn null_device() -> &'static str {
    if cfg!(windows) { "nul" } else { "/dev/null" }
}
