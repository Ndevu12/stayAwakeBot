//! Asks this machine's service manager to start, stop and keep a job.

pub mod session_bus;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::files::{read_regular, Follow};
use crate::programs::Runner;

const MOST_ITEM_BYTES: u64 = 256 << 10;
const WINDOWS_FOLDER: &str = r"C:\Windows";

/// The service managers saw works with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Launchd,
    Systemd,
    WindowsScheduler,
}

impl Platform {
    /// Return the service manager this system runs.
    pub fn current() -> Platform {
        if cfg!(windows) {
            Platform::WindowsScheduler
        } else if cfg!(target_os = "linux") {
            Platform::Systemd
        } else {
            Platform::Launchd
        }
    }

    /// Return the paths this service manager's own program may have on this system.
    pub fn candidates(self) -> Vec<String> {
        match self {
            Platform::Systemd => vec!["/usr/bin/systemctl".into(), "/bin/systemctl".into()],
            Platform::Launchd => vec!["/bin/launchctl".into(), "/usr/bin/launchctl".into()],
            Platform::WindowsScheduler => vec![format!("{}\\System32\\schtasks.exe", crate::system_programs::windows_system_root())],
        }
    }
}

/// Return every service-manager program saw names, on every system.
pub fn every_candidate() -> Vec<String> {
    let mut all: Vec<String> = [Platform::Systemd, Platform::Launchd].iter().flat_map(|p| p.candidates()).collect();
    all.push(format!("{WINDOWS_FOLDER}\\System32\\schtasks.exe"));
    all
}

/// The names one job has under each service manager.
#[derive(Debug, Clone, Copy)]
pub struct Job<'a> {
    pub label: &'a str,
    pub unit: &'a str,
    pub task: &'a str,
}

/// One service manager on this machine.
#[derive(Debug, Clone)]
pub struct Manager {
    pub platform: Platform,
    pub program: PathBuf,
    pub account: Option<u32>,
    pub env: Option<BTreeMap<String, String>>,
}

impl Manager {
    /// Return this machine's service manager, or none.
    pub fn find() -> Option<Manager> {
        let platform = Platform::current();
        let candidates = platform.candidates();
        let borrowed: Vec<&str> = candidates.iter().map(String::as_str).collect();
        let program = crate::system_programs::system_program(&borrowed)?;
        #[cfg(unix)]
        let account = Some(crate::account::user_id());
        #[cfg(not(unix))]
        let account = None;
        let env = (platform == Platform::Systemd).then(session_bus::user_manager_env);
        Some(Manager { platform, program, account, env })
    }

    fn program(&self) -> String {
        self.program.display().to_string()
    }

    fn succeeds(&self, commands: &[Vec<String>], runner: &dyn Runner) -> bool {
        commands.iter().all(|argv| matches!(runner.run(argv, self.env.as_ref()), Ok(Some(0))))
    }

    fn words(&self, rest: &[&str]) -> Vec<String> {
        std::iter::once(self.program()).chain(rest.iter().map(|w| w.to_string())).collect()
    }

    /// Start a job now. Takes the job, its item and the runner. Returns whether it started.
    pub fn activate(&self, job: Job, item: &Path, runner: &dyn Runner) -> bool {
        let commands = match self.platform {
            Platform::WindowsScheduler => return self.register_windows(job, item, runner),
            Platform::Systemd => vec![self.words(&["--user", "daemon-reload"]), self.words(&["--user", "enable", "--now", job.unit])],
            Platform::Launchd => {
                let Some(account) = self.account else { return false };
                vec![self.words(&["bootstrap", &format!("gui/{account}"), &item.display().to_string()])]
            }
        };
        self.succeeds(&commands, runner)
    }

    fn register_windows(&self, job: Job, item: &Path, runner: &dyn Runner) -> bool {
        let Ok(raw) = read_regular(item, MOST_ITEM_BYTES, Follow::NoLinks, None) else { return false };
        let mut copy_name = item.file_name().unwrap_or_default().to_os_string();
        copy_name.push(".utf16");
        let copy = item.with_file_name(copy_name);
        let Ok(text) = String::from_utf8(raw) else {
            let _ = std::fs::remove_file(&copy);
            return false;
        };
        let mut wide = vec![0xFF, 0xFE];
        wide.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let registered = std::fs::write(&copy, wide).is_ok() && {
            let commands = [
                self.words(&["/Create", "/TN", job.task, "/XML", &copy.display().to_string(), "/F"]),
                self.words(&["/Run", "/TN", job.task]),
            ];
            self.succeeds(&commands, runner)
        };
        let _ = std::fs::remove_file(&copy);
        registered
    }

    /// Tell whether the service manager holds a job now. Takes the job and the runner.
    pub fn is_running(&self, job: Job, runner: &dyn Runner) -> bool {
        let argv = match self.platform {
            Platform::WindowsScheduler => self.words(&["/Query", "/TN", job.task]),
            Platform::Systemd => self.words(&["--user", "is-active", "--quiet", job.unit]),
            Platform::Launchd => {
                let Some(account) = self.account else { return false };
                self.words(&["print", &format!("gui/{account}/{}", job.label)])
            }
        };
        self.succeeds(&[argv], runner)
    }

    /// Stop a job now. Takes the job, its item and the runner.
    pub fn deactivate(&self, job: Job, item: &Path, runner: &dyn Runner) {
        let argv = match self.platform {
            Platform::WindowsScheduler => self.words(&["/Delete", "/TN", job.task, "/F"]),
            Platform::Systemd => self.words(&["--user", "disable", "--now", job.unit]),
            Platform::Launchd => {
                let Some(account) = self.account else { return };
                self.words(&["bootout", &format!("gui/{account}"), &item.display().to_string()])
            }
        };
        let _ = runner.run(&argv, self.env.as_ref());
    }
}
