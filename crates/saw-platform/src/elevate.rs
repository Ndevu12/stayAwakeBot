//! Asks for privilege for one action, through the system's own prompt, rather than requiring it
//! for a whole command.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::programs::{self, Finished, Invocation, RunError};

const TIMEOUT: Duration = Duration::from_secs(120);
const ADMINISTRATOR_GROUPS: &[&str] = &["wheel", "sudo", "admin"];

/// How asking for privilege ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    NotAvailable,
    CannotAsk,
    NotAnAdministrator,
    Declined,
    Granted,
}

impl Outcome {
    /// Return the outcome's name, as saw writes it.
    pub fn name(self) -> &'static str {
        match self {
            Outcome::NotAvailable => "not-available",
            Outcome::CannotAsk => "cannot-ask",
            Outcome::NotAnAdministrator => "not-an-administrator",
            Outcome::Declined => "declined",
            Outcome::Granted => "granted",
        }
    }
}

/// What asking for privilege needs from the machine.
pub trait Host {
    /// Return a `sudo` saw may trust, or none.
    fn trusted_sudo(&self) -> Option<PathBuf>;
    /// Tell whether there is a terminal the system can ask on.
    fn can_ask(&self) -> bool;
    /// Tell whether this account administers the machine.
    fn is_administrator(&self) -> bool;
    /// Run a command without a terminal. Takes the command. Returns what it did.
    fn run_quietly(&self, argv: &[String]) -> Result<Finished, RunError>;
    /// Run a command on the terminal. Takes the command. Returns its exit code.
    fn run_on_terminal(&self, argv: &[String]) -> Result<Option<i32>, RunError>;
    /// Run a step with progress output held off the terminal. Takes the step.
    fn while_quiet(&self, step: &mut dyn FnMut()) {
        step();
    }
}

/// Return a `sudo` owned by root, set to run as its owner, that no one else can change, or none.
#[cfg(unix)]
pub fn trusted_sudo() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    ["/usr/bin/sudo", "/bin/sudo"].iter().map(Path::new).find(|candidate| {
        std::fs::metadata(candidate).is_ok_and(|found| found.uid() == 0 && found.mode() & 0o022 == 0 && found.mode() & 0o4000 != 0)
    }).map(Path::to_path_buf)
}

/// Return a `sudo` saw may trust, or none.
#[cfg(not(unix))]
pub fn trusted_sudo() -> Option<PathBuf> {
    None
}

/// Tell whether there is a terminal the system can ask for permission on.
pub fn can_ask() -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").is_ok()
}

/// Tell whether groups include one that administers the machine. Takes the group names.
pub fn administers(groups: &std::collections::BTreeSet<String>) -> bool {
    ADMINISTRATOR_GROUPS.iter().any(|group| groups.contains(*group))
}

/// The machine saw runs on, for asking for privilege.
pub struct System {
    pub env: BTreeMap<String, String>,
}

impl System {
    fn invocation(&self, argv: &[String]) -> Invocation {
        Invocation { program: PathBuf::from(&argv[0]), args: argv[1..].to_vec(), env: self.env.clone(), timeout: TIMEOUT, ..Invocation::default() }
    }
}

impl Host for System {
    fn trusted_sudo(&self) -> Option<PathBuf> {
        trusted_sudo()
    }

    fn can_ask(&self) -> bool {
        can_ask()
    }

    fn is_administrator(&self) -> bool {
        administers(&crate::account::group_names())
    }

    fn run_quietly(&self, argv: &[String]) -> Result<Finished, RunError> {
        programs::run(&self.invocation(argv))
    }

    fn run_on_terminal(&self, argv: &[String]) -> Result<Option<i32>, RunError> {
        programs::run_on_terminal(&self.invocation(argv))
    }
}

/// Run a command as root, leaving it to the system's own prompt to ask for permission when it
/// must. Takes the command and the machine. Returns how it ended and a sentence about it.
pub fn run_as_root(argv: &[String], host: &dyn Host) -> (Outcome, String) {
    let Some(sudo) = host.trusted_sudo() else {
        return (Outcome::NotAvailable, "no trustworthy sudo was found on this machine".into());
    };
    let sudo = sudo.display().to_string();
    let quiet: Vec<String> = [sudo.clone(), "-n".into(), "--".into()].into_iter().chain(argv.iter().cloned()).collect();
    match host.run_quietly(&quiet) {
        Ok(done) if done.succeeded() => return (Outcome::Granted, "already granted".into()),
        Ok(_) => {}
        Err(error) => return (Outcome::NotAvailable, error.to_string()),
    }
    if !host.is_administrator() {
        return (Outcome::NotAnAdministrator, "this account does not administer the machine".into());
    }
    if !host.can_ask() {
        return (Outcome::CannotAsk, "permission is needed and there is no terminal for the system to ask on".into());
    }
    let asking: Vec<String> = [sudo, "--".into()].into_iter().chain(argv.iter().cloned()).collect();
    let mut answer = None;
    host.while_quiet(&mut || answer = Some(host.run_on_terminal(&asking)));
    match answer {
        Some(Ok(Some(0))) => (Outcome::Granted, "granted".into()),
        Some(Err(error)) => (Outcome::Declined, error.to_string()),
        _ => (Outcome::Declined, "not granted".into()),
    }
}
