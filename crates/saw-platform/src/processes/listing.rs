//! Every running process with the arguments it was started with, and its parent.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use super::identity::Identity;
use super::{platform_name, words};

/// One running process and the arguments the kernel holds for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub argv: Vec<String>,
    pub argv_unreadable: bool,
    pub identity: Option<Identity>,
}

impl Process {
    /// Return the program the process names first, or none.
    pub fn program(&self) -> Option<&str> {
        self.argv.first().map(String::as_str)
    }
}

/// Every process this account could list, and how many would not give their arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub processes: Vec<Process>,
    pub unreadable: usize,
    pub supported: bool,
}

impl Snapshot {
    fn empty(supported: bool) -> Snapshot {
        Snapshot { processes: Vec::new(), unreadable: 0, supported }
    }

    fn add(&mut self, pid: u32, argv: Option<Vec<String>>, identity: Option<Identity>) {
        match argv {
            Some(argv) => self.processes.push(Process { pid, argv, argv_unreadable: false, identity }),
            None => {
                self.unreadable += 1;
                self.processes.push(Process { pid, argv: Vec::new(), argv_unreadable: true, identity });
            }
        }
    }

    /// Return what the snapshot did not see, in saw's words, or an empty text.
    pub fn scope_note(&self) -> String {
        if !self.supported {
            return format!("process arguments cannot be read on {} — no start-up command was examined for any running process", platform_name());
        }
        if self.unreadable > 0 {
            return format!(
                "{} of {} running processes did not yield their arguments (processes of other users); their command lines were not examined",
                self.unreadable,
                self.processes.len()
            );
        }
        String::new()
    }
}

/// Return every running process this account can list, with its arguments where readable.
pub fn snapshot() -> Snapshot {
    #[cfg(windows)]
    return super::windows_rows::snapshot_of(super::windows_rows::system_rows());
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        #[cfg(target_os = "macos")]
        let argmax = darwin::argmax();
        let mut snap = Snapshot::empty(true);
        for pid in live_pids() {
            #[cfg(target_os = "macos")]
            let argv = darwin::argv(pid, argmax);
            #[cfg(target_os = "linux")]
            let argv = linux_argv(pid);
            snap.add(pid, argv, super::identity::identify(pid).0);
        }
        return snap;
    }
    #[allow(unreachable_code)]
    Snapshot::empty(false)
}

pub(crate) fn add_row(snap: &mut Snapshot, pid: u32, argv: Option<Vec<String>>, identity: Identity) {
    snap.add(pid, argv, Some(identity));
}

pub(crate) fn unsupported() -> Snapshot {
    Snapshot::empty(false)
}

pub(crate) fn supported() -> Snapshot {
    Snapshot::empty(true)
}

/// Run the system's own `ps`. Takes its arguments. Returns what it printed, or none.
fn run_ps(args: &[&str]) -> Option<String> {
    let binary = crate::system_programs::system_program(&["/bin/ps", "/usr/bin/ps"])?;
    let env = BTreeMap::from([("LC_ALL".to_string(), "C".to_string()), ("PATH".to_string(), "/usr/bin:/bin".to_string())]);
    let invocation = crate::programs::Invocation {
        program: binary,
        args: args.iter().map(|a| a.to_string()).collect(),
        env,
        timeout: Duration::from_secs(10),
        ..crate::programs::Invocation::default()
    };
    let done = crate::programs::run(&invocation).ok()?;
    Some(String::from_utf8_lossy(&done.stdout).into_owned())
}

fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn proc_pids() -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut pids: Vec<u32> = entries
        .filter_map(|entry| entry.ok()?.file_name().to_str().filter(|name| is_digits(name))?.parse().ok())
        .collect();
    pids.sort_unstable();
    pids
}

/// Return the ids of the running processes.
pub fn live_pids() -> Vec<u32> {
    if cfg!(target_os = "linux") {
        return proc_pids();
    }
    let Some(out) = run_ps(&["-axo", "pid="]) else { return Vec::new() };
    let mut pids: Vec<u32> = words(&out).into_iter().filter(|w| is_digits(w)).filter_map(|w| w.parse().ok()).collect();
    pids.sort_unstable();
    pids
}

#[cfg(target_os = "linux")]
fn linux_argv(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    Some(raw.split(|b| *b == 0).filter(|p| !p.is_empty()).map(|p| String::from_utf8_lossy(p).into_owned()).collect())
}

/// Return the file a process runs, or none. Takes the process id.
pub fn program_path(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    return std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    #[cfg(windows)]
    return super::windows_rows::row_of(pid).0.and_then(|row| row.path).map(PathBuf::from);
    #[cfg(target_os = "macos")]
    return darwin::program_path(pid);
    #[allow(unreachable_code)]
    None
}

/// Return a process's signature, or none. Takes the process id.
pub fn ps_signature(pid: u32) -> Option<String> {
    if cfg!(target_os = "linux") {
        let raw = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
        let raw = String::from_utf8_lossy(&raw);
        let fields = super::stat_fields(&raw)?;
        return Some(format!("{}|{}", fields.get(1)?, fields.get(19)?));
    }
    let out = run_ps(&["-o", "ppid=,uid=,lstart=", "-p", &pid.to_string()])?;
    let line = words(&out).join(" ");
    (!line.is_empty()).then_some(line)
}

/// Return every process's parent.
#[allow(unreachable_code)]
pub fn parent_map() -> BTreeMap<u32, u32> {
    let mut pairs = BTreeMap::new();
    if cfg!(target_os = "linux") {
        for pid in proc_pids() {
            let Ok(raw) = std::fs::read(format!("/proc/{pid}/stat")) else { continue };
            let raw = String::from_utf8_lossy(&raw);
            if let Some(ppid) = super::stat_fields(&raw).and_then(|f| f.get(1)?.parse::<u32>().ok()) {
                pairs.insert(pid, ppid);
            }
        }
        return pairs;
    }
    #[cfg(windows)]
    return super::windows_rows::system_rows().unwrap_or_default().into_iter().map(|row| (row.pid, row.ppid)).collect();
    let Some(text) = run_ps(&["-axo", "pid=,ppid="]) else { return pairs };
    for line in text.lines() {
        let bits = words(line);
        if bits.len() == 2 && is_digits(bits[0]) && is_digits(bits[1]) {
            if let (Ok(pid), Ok(ppid)) = (bits[0].parse(), bits[1].parse()) {
                pairs.insert(pid, ppid);
            }
        }
    }
    pairs
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod darwin {
    use std::path::PathBuf;

    const ARGMAX_FALLBACK: usize = 256 * 1024;

    pub(super) fn argmax() -> usize {
        let mut value: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>();
        let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
        // SAFETY: the name, value and size are locals that outlive the call.
        let status = unsafe { libc::sysctl(mib.as_mut_ptr(), 2, (&mut value as *mut libc::c_int).cast(), &mut size, std::ptr::null_mut(), 0) };
        if status == 0 && value > 0 {
            value as usize
        } else {
            ARGMAX_FALLBACK
        }
    }

    pub(super) fn argv(pid: u32, argmax: usize) -> Option<Vec<String>> {
        let mut buffer = vec![0u8; argmax];
        let mut size = argmax;
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
        // SAFETY: the name, buffer and size are locals that outlive the call, with the buffer's length.
        let status = unsafe { libc::sysctl(mib.as_mut_ptr(), 3, buffer.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0) };
        if status != 0 {
            return None;
        }
        let raw = &buffer[..size.min(argmax)];
        if raw.len() < 4 {
            return None;
        }
        let argc = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if argc == 0 {
            return None;
        }
        let mut args: Vec<String> = Vec::new();
        for part in raw[4..].split(|b| *b == 0).skip(1) {
            if part.is_empty() && args.is_empty() {
                continue;
            }
            if args.len() >= argc {
                break;
            }
            args.push(String::from_utf8_lossy(part).into_owned());
        }
        (!args.is_empty()).then_some(args)
    }

    pub(super) fn program_path(pid: u32) -> Option<PathBuf> {
        let mut buffer = vec![0u8; 4096];
        // SAFETY: the buffer is a local of the given length that outlives the call.
        let length = unsafe { libc::proc_pidpath(pid as libc::c_int, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if length <= 0 {
            return None;
        }
        let bytes: Vec<u8> = buffer.into_iter().take_while(|b| *b != 0).collect();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (!text.is_empty()).then(|| PathBuf::from(text))
    }
}
