//! Freezes a process, ends it, and proves it ended.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::identity::{identify, Identity, Reading};
use crate::elevate;

const SETTLE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(20);

/// What sending a process a signal did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Signalled,
    AlreadyGone,
    Recycled,
    Refused,
    NeedsPrivilege,
}

impl Outcome {
    /// Return the outcome's name, as saw writes it.
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Signalled => "signalled",
            Outcome::AlreadyGone => "already-gone",
            Outcome::Recycled => "recycled",
            Outcome::Refused => "refused",
            Outcome::NeedsPrivilege => "needs-privilege",
        }
    }
}

/// Tell whether a process id still names the process an identity describes. Takes the identity
/// and the reader of a process's identity. Returns what was found instead, or none.
pub fn still_with(known: &Identity, read: &dyn Fn(u32) -> (Option<Identity>, Reading)) -> Option<Outcome> {
    let (who, reading) = read(known.pid);
    if reading == Reading::NotOurs {
        return Some(Outcome::NeedsPrivilege);
    }
    let who = match (reading, who) {
        (Reading::Gone | Reading::Unsupported, _) | (_, None) => return Some(Outcome::AlreadyGone),
        (_, Some(who)) => who,
    };
    if who.zombie {
        return Some(Outcome::AlreadyGone);
    }
    if (who.start_time, who.uid) != (known.start_time, known.uid) {
        return Some(Outcome::Recycled);
    }
    None
}

fn still(known: &Identity) -> Option<Outcome> {
    still_with(known, &identify)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn send(known: &Identity, signal: libc::c_int) -> Outcome {
    if let Some(outcome) = still(known) {
        return outcome;
    }
    // SAFETY: kill takes a process id and a signal number and touches no memory.
    if unsafe { libc::kill(known.pid as libc::pid_t, signal) } == 0 {
        return Outcome::Signalled;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Outcome::AlreadyGone,
        Some(libc::EPERM) | Some(libc::EACCES) => Outcome::NeedsPrivilege,
        _ => Outcome::Refused,
    }
}

/// Stop a process running without ending it. Takes its identity. Returns what that did.
pub fn freeze(known: &Identity) -> Outcome {
    #[cfg(unix)]
    return send(known, libc::SIGSTOP);
    #[cfg(windows)]
    return windows::suspend(known, true);
}

/// Let a frozen process run again. Takes its identity. Returns what that did.
pub fn resume(known: &Identity) -> Outcome {
    #[cfg(unix)]
    return send(known, libc::SIGCONT);
    #[cfg(windows)]
    return windows::suspend(known, false);
}

/// End a process. Takes its identity. Returns what that did.
pub fn end(known: &Identity) -> Outcome {
    #[cfg(unix)]
    return send(known, libc::SIGKILL);
    #[cfg(windows)]
    return windows::terminate(known);
}

/// Tell whether a process is no longer running. Takes its identity.
pub fn has_ended(known: &Identity) -> bool {
    has_ended_with(known, &identify, SETTLE)
}

/// Tell whether a process is no longer running, asking until a deadline. Takes its identity, the
/// reader of a process's identity and how long to keep asking.
pub fn has_ended_with(known: &Identity, read: &dyn Fn(u32) -> (Option<Identity>, Reading), settle: Duration) -> bool {
    let deadline = Instant::now() + settle;
    loop {
        match still_with(known, read) {
            Some(Outcome::AlreadyGone | Outcome::Recycled) => return true,
            Some(Outcome::Refused | Outcome::NeedsPrivilege) => return false,
            _ => {}
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

const KILL_PROGRAMS: &[&str] = &["/bin/kill", "/usr/bin/kill"];

/// End processes as root, asking once for all of them. Takes the process ids, the
/// signature each had when it was found, the way to run a command as root and the reader of a
/// process's signature. Returns how asking ended and the processes that ended.
pub fn end_as_root(
    pids: &[u32],
    signatures: &BTreeMap<u32, String>,
    run_as_root: &dyn Fn(&[String]) -> (elevate::Outcome, String),
    signature: &dyn Fn(u32) -> Option<String>,
) -> (elevate::Outcome, Vec<u32>) {
    end_as_root_using(KILL_PROGRAMS, pids, signatures, run_as_root, signature)
}

fn end_as_root_using(
    kill_programs: &[&str],
    pids: &[u32],
    signatures: &BTreeMap<u32, String>,
    run_as_root: &dyn Fn(&[String]) -> (elevate::Outcome, String),
    signature: &dyn Fn(u32) -> Option<String>,
) -> (elevate::Outcome, Vec<u32>) {
    let still: Vec<u32> = pids.iter().copied().filter(|pid| signature(*pid).as_ref() == signatures.get(pid)).collect();
    if still.is_empty() {
        return (elevate::Outcome::Granted, Vec::new());
    }
    let Some(binary) = crate::system_programs::system_program(kill_programs) else { return (elevate::Outcome::NotAvailable, Vec::new()) };
    let binary = binary.display().to_string();
    let named: Vec<String> = still.iter().map(u32::to_string).collect();
    let command = |flag: &str| -> Vec<String> { [binary.clone(), flag.to_string()].into_iter().chain(named.iter().cloned()).collect() };
    let (outcome, _) = run_as_root(&command("-STOP"));
    if outcome != elevate::Outcome::Granted {
        return (outcome, Vec::new());
    }
    run_as_root(&command("-KILL"));
    (elevate::Outcome::Granted, still.into_iter().filter(|pid| signature(*pid).is_none()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::Isolated;

    #[test]
    fn a_kill_program_root_does_not_own_is_never_run_as_root() {
        let sandbox = Isolated::new("kill").unwrap();
        let planted = sandbox.file("kill", b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&planted, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let planted = planted.display().to_string();
        let asked = std::cell::RefCell::new(0);
        let run = |_: &[String]| {
            *asked.borrow_mut() += 1;
            (elevate::Outcome::Granted, String::new())
        };
        let found = BTreeMap::from([(7, "a".to_string())]);
        let outcome = end_as_root_using(&[planted.as_str()], &[7], &found, &run, &|_| Some("a".to_string()));
        assert_eq!(outcome, (elevate::Outcome::NotAvailable, Vec::new()));
        assert_eq!(*asked.borrow(), 0);
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use super::{still, Outcome};
    use crate::processes::Identity;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED};
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_ALL_ACCESS, PROCESS_SUSPEND_RESUME};

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSuspendProcess(handle: windows_sys::Win32::Foundation::HANDLE) -> i32;
        fn NtResumeProcess(handle: windows_sys::Win32::Foundation::HANDLE) -> i32;
    }

    pub(super) fn suspend(known: &Identity, stop: bool) -> Outcome {
        if let Some(outcome) = still(known) {
            return outcome;
        }
        // SAFETY: OpenProcess takes plain values and returns a handle or null.
        let handle = unsafe { OpenProcess(PROCESS_SUSPEND_RESUME, 0, known.pid) };
        if handle.is_null() {
            // SAFETY: GetLastError reads this thread's last error.
            let denied = unsafe { GetLastError() } == ERROR_ACCESS_DENIED;
            return if stop && denied { Outcome::NeedsPrivilege } else { Outcome::Refused };
        }
        // SAFETY: the handle is open and is closed once below.
        let status = unsafe { if stop { NtSuspendProcess(handle) } else { NtResumeProcess(handle) } };
        // SAFETY: the handle is open.
        unsafe { CloseHandle(handle) };
        if status != 0 { Outcome::Refused } else { Outcome::Signalled }
    }

    pub(super) fn terminate(known: &Identity) -> Outcome {
        if let Some(outcome) = still(known) {
            return outcome;
        }
        // SAFETY: OpenProcess takes plain values and returns a handle or null.
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, known.pid) };
        // SAFETY: GetLastError reads this thread's last error.
        let failed = || if unsafe { GetLastError() } == ERROR_ACCESS_DENIED { Outcome::NeedsPrivilege } else { Outcome::Refused };
        if handle.is_null() {
            return failed();
        }
        // SAFETY: the handle is open.
        let ended = unsafe { TerminateProcess(handle, 15) } != 0;
        let outcome = if ended { Outcome::Signalled } else { failed() };
        // SAFETY: the handle is open and is closed once.
        unsafe { CloseHandle(handle) };
        outcome
    }
}
