//! Who a process is.

/// What reading a process found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    Running,
    Gone,
    NotOurs,
    Unsupported,
}

impl Reading {
    /// Return the reading's name, as saw writes it.
    pub fn name(self) -> &'static str {
        match self {
            Reading::Running => "running",
            Reading::Gone => "gone",
            Reading::NotOurs => "not-ours",
            Reading::Unsupported => "unsupported",
        }
    }
}

/// One process's id, parent, account and start.
#[derive(Debug, Clone, Eq)]
pub struct Identity {
    pub pid: u32,
    pub ppid: u32,
    pub uid: i64,
    pub start_time: i64,
    pub zombie: bool,
    pub held_uids: Vec<i64>,
}

impl PartialEq for Identity {
    fn eq(&self, other: &Identity) -> bool {
        (self.pid, self.ppid, self.uid, self.start_time, self.zombie) == (other.pid, other.ppid, other.uid, other.start_time, other.zombie)
    }
}

impl Identity {
    /// Tell whether another identity is the same process. Takes the other identity.
    pub fn is_same(&self, other: Option<&Identity>) -> bool {
        other.is_some_and(|other| (self.pid, self.start_time) == (other.pid, other.start_time))
    }
}

/// When a process started, the short name of what it runs, and its parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    pub at_ns: i128,
    pub name: String,
    pub ppid: u32,
}

/// Return a process's identity and what reading it found. Takes the process id.
pub fn identify(pid: u32) -> (Option<Identity>, Reading) {
    #[cfg(target_os = "macos")]
    return darwin::identify(pid);
    #[cfg(target_os = "linux")]
    return linux::identify(pid);
    #[cfg(windows)]
    return match super::windows_rows::row_of(pid) {
        (Some(row), _) => (Some(row.identity()), Reading::Running),
        (None, reading) => (None, reading),
    };
    #[allow(unreachable_code)]
    (None, Reading::Unsupported)
}

/// Return a process's start, or none. Takes the process id.
pub fn started(pid: u32) -> Option<Start> {
    #[cfg(target_os = "macos")]
    return darwin::started(pid);
    #[cfg(target_os = "linux")]
    return linux::started(pid);
    #[cfg(windows)]
    return super::windows_rows::row_of(pid).0.map(|row| {
        let name = row.path.as_deref().map(|p| p.rsplit(['\\', '/']).next().unwrap_or("").to_string()).unwrap_or_default();
        Start { at_ns: row.start as i128 * 1_000_000, name, ppid: row.ppid }
    });
    #[allow(unreachable_code)]
    None
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) mod darwin {
    use super::{Identity, Reading, Start};

    const ZOMBIE: u32 = 5;

    /// Read a process's kernel record. Takes the process id. Returns it, or what was found instead.
    pub(crate) fn bsd_info(pid: u32) -> Result<libc::proc_bsdinfo, Reading> {
        // SAFETY: an all-zero proc_bsdinfo is a valid value of that plain struct.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: the record is a local of the given size that outlives the call.
        let read = unsafe { libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) };
        if read == size {
            return Ok(info);
        }
        let denied = std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        Err(if denied { Reading::NotOurs } else { Reading::Gone })
    }

    pub(super) fn identify(pid: u32) -> (Option<Identity>, Reading) {
        match bsd_info(pid) {
            Ok(info) => (
                Some(Identity {
                    pid,
                    ppid: info.pbi_ppid,
                    uid: info.pbi_uid as i64,
                    start_time: info.pbi_start_tvsec as i64,
                    zombie: info.pbi_status == ZOMBIE,
                    held_uids: vec![info.pbi_ruid as i64, info.pbi_uid as i64, info.pbi_svuid as i64],
                }),
                Reading::Running,
            ),
            Err(reading) => (None, reading),
        }
    }

    pub(super) fn started(pid: u32) -> Option<Start> {
        let info = bsd_info(pid).ok()?;
        let bytes: Vec<u8> = info.pbi_comm.iter().map(|c| *c as u8).take_while(|b| *b != 0).collect();
        Some(Start {
            at_ns: info.pbi_start_tvsec as i128 * 1_000_000_000 + info.pbi_start_tvusec as i128 * 1_000,
            name: String::from_utf8_lossy(&bytes).into_owned(),
            ppid: info.pbi_ppid,
        })
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use super::{Identity, Reading, Start};
    use crate::processes::{stat_fields, words};
    use std::io::ErrorKind;

    fn read(path: &str) -> std::io::Result<String> {
        std::fs::read(path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }

    pub(super) fn identify(pid: u32) -> (Option<Identity>, Reading) {
        let texts = read(&format!("/proc/{pid}/stat")).and_then(|raw| Ok((raw, read(&format!("/proc/{pid}/status"))?)));
        let (raw, status) = match texts {
            Ok(both) => both,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => return (None, Reading::NotOurs),
            Err(_) => return (None, Reading::Gone),
        };
        let parsed = stat_fields(&raw).and_then(|fields| {
            Some((fields.first()?.to_string(), fields.get(1)?.parse::<u32>().ok()?, fields.get(19)?.parse::<i64>().ok()?))
        });
        let Some((state, ppid, start)) = parsed else { return (None, Reading::Gone) };
        let (mut uid, mut held) = (-1, Vec::new());
        if let Some(line) = status.split_terminator(['\n', '\r']).find(|line| line.starts_with("Uid:")) {
            let values: Option<Vec<i64>> = words(line)[1..].iter().map(|v| v.parse::<i64>().ok()).collect();
            if let Some(values) = values.filter(|v| !v.is_empty()) {
                uid = values[0];
                held = values;
            }
        }
        (Some(Identity { pid, ppid, uid, start_time: start, zombie: state == "Z", held_uids: held }), Reading::Running)
    }

    pub(super) fn started(pid: u32) -> Option<Start> {
        let raw = read(&format!("/proc/{pid}/stat")).ok()?;
        let booted = read("/proc/stat").ok()?;
        // SAFETY: sysconf takes a constant and has no other effect.
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as i128;
        let name = raw.get(raw.find('(')? + 1..raw.rfind(')')?)?.to_string();
        let fields = stat_fields(&raw)?;
        let ppid = fields.get(1)?.parse::<u32>().ok()?;
        let since_boot = fields.get(19)?.parse::<i128>().ok()?;
        let boot = booted.lines().find(|line| line.starts_with("btime ")).and_then(|line| words(line).get(1)?.parse::<i128>().ok())?;
        if ticks <= 0 {
            return None;
        }
        Some(Start { at_ns: boot * 1_000_000_000 + (since_boot * 1_000_000_000).div_euclid(ticks), name, ppid })
    }
}
