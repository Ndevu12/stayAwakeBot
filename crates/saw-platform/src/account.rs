//! Looks up accounts and groups, and the account saw acts for.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::env::Environment;

/// One account in the system's account database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
}

/// How the account saw acts for was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// From the environment, with no privilege raised.
    Environment,
    /// From the escalation markers, under raised privilege.
    Raised,
}

/// The account a host-level command acts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    pub name: String,
    pub uid: Option<u32>,
    pub home: PathBuf,
    pub via: Via,
}

const ESCALATION_UIDS: &[&str] = &["SUDO_UID", "PKEXEC_UID"];
const ESCALATION_NAMES: &[&str] = &["SUDO_USER", "DOAS_USER"];

/// Return the id of the user saw runs as.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn user_id() -> u32 {
    // SAFETY: getuid has no arguments and cannot fail.
    unsafe { libc::getuid() }
}

/// Return the effective id of the user saw runs as.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn from_entry(status: libc::c_int, found: *mut libc::passwd, entry: &libc::passwd) -> Option<Account> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    if status != 0 || found.is_null() || entry.pw_dir.is_null() || entry.pw_name.is_null() {
        return None;
    }
    // SAFETY: on success both fields are NUL-terminated strings inside the caller's buffer.
    let (name, dir) = unsafe { (CStr::from_ptr(entry.pw_name), CStr::from_ptr(entry.pw_dir)) };
    Some(Account { name: name.to_string_lossy().into_owned(), uid: entry.pw_uid, home: PathBuf::from(OsStr::from_bytes(dir.to_bytes())) })
}

/// Return the account with an id, or none. Takes the id.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn account_by_uid(uid: u32) -> Option<Account> {
    // SAFETY: an all-zero passwd is a valid value of that plain struct.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: the pointers are to locals that outlive the call, with the buffer's length.
    let status = unsafe { libc::getpwuid_r(uid, &mut entry, buffer.as_mut_ptr(), buffer.len(), &mut found) };
    from_entry(status, found, &entry)
}

/// Return the account with a name, or none. Takes the name.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn account_by_name(name: &str) -> Option<Account> {
    let wanted = std::ffi::CString::new(name).ok()?;
    // SAFETY: an all-zero passwd is a valid value of that plain struct.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: the pointers are to locals that outlive the call, with the buffer's length.
    let status = unsafe { libc::getpwnam_r(wanted.as_ptr(), &mut entry, buffer.as_mut_ptr(), buffer.len(), &mut found) };
    from_entry(status, found, &entry)
}

/// Return the names of the groups saw runs in.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn group_names() -> BTreeSet<String> {
    // SAFETY: a zero count asks only for how many groups there are.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut ids = vec![0 as libc::gid_t; count.max(0) as usize];
    // SAFETY: the buffer is a local of the given length that outlives the call.
    let filled = unsafe { libc::getgroups(ids.len() as libc::c_int, ids.as_mut_ptr()) };
    ids.truncate(filled.max(0) as usize);
    // SAFETY: getgid has no arguments and cannot fail.
    ids.push(unsafe { libc::getgid() });
    let mut names = BTreeSet::new();
    for id in ids {
        // SAFETY: an all-zero group is a valid value of that plain struct.
        let mut entry: libc::group = unsafe { std::mem::zeroed() };
        let mut buffer = vec![0 as libc::c_char; 16 * 1024];
        let mut found: *mut libc::group = std::ptr::null_mut();
        // SAFETY: the pointers are to locals that outlive the call, with the buffer's length.
        let status = unsafe { libc::getgrgid_r(id, &mut entry, buffer.as_mut_ptr(), buffer.len(), &mut found) };
        if status == 0 && !found.is_null() && !entry.gr_name.is_null() {
            // SAFETY: on success `gr_name` is a NUL-terminated string inside the buffer.
            names.insert(unsafe { std::ffi::CStr::from_ptr(entry.gr_name) }.to_string_lossy().into_owned());
        }
    }
    names
}

/// Return the home folder the account database names for the user saw runs as, or none.
#[cfg(unix)]
pub fn home_folder() -> Option<PathBuf> {
    account_by_uid(user_id()).map(|account| account.home)
}

/// Return the home folder the account database names for a user, or none. Takes the user name.
#[cfg(unix)]
pub fn home_of_user(user: &str) -> Option<PathBuf> {
    account_by_name(user).map(|account| account.home)
}

/// Return the account with an id, or none. Takes the id.
#[cfg(not(unix))]
pub fn account_by_uid(_uid: u32) -> Option<Account> {
    None
}

/// Return the account with a name, or none. Takes the name.
#[cfg(not(unix))]
pub fn account_by_name(_name: &str) -> Option<Account> {
    None
}

/// Return the home folder the account database names for the user saw runs as, or none.
#[cfg(not(unix))]
pub fn home_folder() -> Option<PathBuf> {
    None
}

/// Return the home folder the account database names for a user, or none. Takes the user name.
#[cfg(not(unix))]
pub fn home_of_user(_user: &str) -> Option<PathBuf> {
    None
}

/// Return the names of the groups saw runs in.
#[cfg(not(unix))]
pub fn group_names() -> BTreeSet<String> {
    BTreeSet::new()
}

/// Return the account a command acts for, or none. Takes the environment.
pub fn acting_for(env: &Environment) -> Option<Operator> {
    #[cfg(unix)]
    return acting_for_with(env, Some(effective_user_id()), &account_by_uid, &account_by_name);
    #[cfg(not(unix))]
    return acting_for_with(env, None, &account_by_uid, &account_by_name);
}

/// Return the account a command acts for, from given facts. Takes the environment, the effective
/// user id when there is one, and the account lookups by id and by name. Returns the account, or
/// none.
pub fn acting_for_with(
    env: &Environment,
    effective: Option<u32>,
    by_uid: &dyn Fn(u32) -> Option<Account>,
    by_name: &dyn Fn(&str) -> Option<Account>,
) -> Option<Operator> {
    let variables = env.variables();
    if effective == Some(0) {
        let named_by_uid = ESCALATION_UIDS.iter().find_map(|key| {
            let raw = variables.get(*key).filter(|v| !v.is_empty())?;
            by_uid(crate::env::python_int(raw)?)
        });
        let named_by_name = ESCALATION_NAMES.iter().find_map(|key| by_name(variables.get(*key).filter(|v| !v.is_empty())?));
        if let (Some(a), Some(b)) = (&named_by_uid, &named_by_name) {
            if a.uid != b.uid {
                return None;
            }
        }
        let record = named_by_uid.or(named_by_name)?;
        return Some(Operator { name: record.name, uid: Some(record.uid), home: record.home, via: Via::Raised });
    }
    let home = variables.get("HOME").filter(|h| !h.is_empty())?;
    Some(Operator { name: variables.get("USER").cloned().unwrap_or_default(), uid: effective, home: PathBuf::from(home), via: Via::Environment })
}

/// Return the user id of the account a command acts for. Takes the environment.
pub fn acting_uid(env: &Environment) -> Option<u32> {
    match acting_for(env) {
        Some(Operator { uid: Some(uid), .. }) => Some(uid),
        _ => {
            #[cfg(unix)]
            return Some(effective_user_id());
            #[cfg(not(unix))]
            return None;
        }
    }
}
