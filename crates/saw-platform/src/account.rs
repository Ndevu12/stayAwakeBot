//! Looks up the account saw runs as.

use std::path::PathBuf;

/// Return the id of the user saw runs as.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn user_id() -> u32 {
    // SAFETY: getuid has no arguments and cannot fail.
    unsafe { libc::getuid() }
}

/// Return the home folder the account database names for the user saw runs as, or none.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn home_folder() -> Option<PathBuf> {
    // SAFETY: an all-zero passwd is a valid value of that plain struct.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: the pointers are to locals that outlive the call, with the buffer's length.
    let status = unsafe { libc::getpwuid_r(user_id(), &mut entry, buffer.as_mut_ptr(), buffer.len(), &mut found) };
    directory(status, found, &entry)
}

/// Return the home folder the account database names for a user, or none. Takes the user name.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn home_of_user(user: &str) -> Option<PathBuf> {
    let name = std::ffi::CString::new(user).ok()?;
    // SAFETY: an all-zero passwd is a valid value of that plain struct.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: the pointers are to locals that outlive the call, with the buffer's length.
    let status = unsafe { libc::getpwnam_r(name.as_ptr(), &mut entry, buffer.as_mut_ptr(), buffer.len(), &mut found) };
    directory(status, found, &entry)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn directory(status: libc::c_int, found: *mut libc::passwd, entry: &libc::passwd) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    if status != 0 || found.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: on success `pw_dir` is a NUL-terminated string inside the caller's buffer.
    let dir = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
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
