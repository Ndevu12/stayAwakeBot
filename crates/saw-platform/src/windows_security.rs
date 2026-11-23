//! Locks a folder on Windows against an account.

use std::path::Path;

use crate::programs::Runner;

/// The Administrators group.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// The system account.
pub const SYSTEM: &str = "S-1-5-18";

/// Tell whether this process is an administrator.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn administrator() -> bool {
    // SAFETY: IsUserAnAdmin takes no arguments.
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

/// Tell whether this process is an administrator.
#[cfg(not(windows))]
pub fn administrator() -> bool {
    false
}

/// Grade who holds a lock. Takes the owner's account and the account saw acts for. Returns `root`,
/// `self` or `other`.
pub fn grade(owner: Option<&str>, acting: Option<&str>) -> &'static str {
    let Some(owner) = owner.filter(|o| !o.is_empty()) else { return "other" };
    let folded = owner.to_uppercase();
    if folded == SYSTEM || folded == ADMINISTRATORS {
        return "root";
    }
    if acting.is_some_and(|a| !a.is_empty() && folded == a.to_uppercase()) {
        return "self";
    }
    "other"
}

fn access_control_program() -> Option<std::path::PathBuf> {
    let candidate = format!("{}\\System32\\icacls.exe", crate::system_programs::windows_system_root());
    crate::system_programs::system_program(&[candidate.as_str()])
}

fn run_access_control(argv: &[String], runner: &dyn Runner, program: Option<&Path>) -> bool {
    if let Some(path) = argv.first() {
        platform::clear_read_only(path);
    }
    let Some(tool) = program.map(Path::to_path_buf).or_else(access_control_program) else { return false };
    let command: Vec<String> = std::iter::once(tool.display().to_string()).chain(argv.iter().cloned()).collect();
    matches!(runner.run(&command, None), Ok(Some(0)))
}

/// Lock a folder against an account. Takes the folder, the account, the runner and the
/// access-control program when it is given. Returns whether reading it back shows the lock.
pub fn deny_writes(path: &Path, sid: &str, runner: &dyn Runner, program: Option<&Path>) -> bool {
    if sid.is_empty() {
        return false;
    }
    let argv = [path.display().to_string(), "/deny".into(), format!("*{sid}:(OI)(CI)(WD,AD,DC,DE)"), "/C".into()];
    run_access_control(&argv, runner, program) && write_denied(path, sid)
}

/// Remove a folder's lock against an account. Takes the folder, the account, the runner and the
/// access-control program when it is given. Returns whether reading it back shows it gone.
pub fn allow_writes(path: &Path, sid: &str, runner: &dyn Runner, program: Option<&Path>) -> bool {
    if sid.is_empty() {
        return false;
    }
    let argv = [path.display().to_string(), "/remove:d".into(), format!("*{sid}"), "/C".into()];
    run_access_control(&argv, runner, program) && !write_denied(path, sid)
}

/// Give a folder to the Administrators group. Takes the folder, the runner and the access-control
/// program when it is given. Returns whether reading it back shows that owner.
pub fn give_to_administrators(path: &Path, runner: &dyn Runner, program: Option<&Path>) -> bool {
    let argv = [path.display().to_string(), "/setowner".into(), format!("*{ADMINISTRATORS}"), "/C".into()];
    run_access_control(&argv, runner, program) && owner_sid(path).is_some_and(|owner| owner.to_uppercase() == ADMINISTRATORS)
}

/// Return the account this process runs as, or none.
pub fn current_sid() -> Option<String> {
    platform::current_sid()
}

/// Return who owns a path, or none. Takes the path.
pub fn owner_sid(path: &Path) -> Option<String> {
    platform::owner_sid(path)
}

/// Tell whether an account is locked out of adding or removing anything in a folder. Takes the
/// folder and the account.
pub fn write_denied(path: &Path, sid: &str) -> bool {
    !sid.is_empty() && platform::write_denied(path, sid)
}

#[cfg(not(windows))]
mod platform {
    use std::path::Path;

    pub(super) fn clear_read_only(_path: &str) {}

    pub(super) fn current_sid() -> Option<String> {
        None
    }

    pub(super) fn owner_sid(_path: &Path) -> Option<String> {
        None
    }

    pub(super) fn write_denied(_path: &Path, _sid: &str) -> bool {
        false
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod platform {
    use std::path::Path;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, GetTokenInformation, TokenUser, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const DENIED: u8 = 1;
    const WRITE_BITS: u32 = 0x0002 | 0x0004 | 0x0040 | 0x0001_0000;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn clear_read_only(path: &str) {
        let name = wide(path);
        // SAFETY: `name` is NUL-terminated and outlives the call.
        unsafe { SetFileAttributesW(name.as_ptr(), FILE_ATTRIBUTE_DIRECTORY) };
    }

    fn sid_text(sid: PSID) -> Option<String> {
        let mut rendered: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` points at a valid SID for the duration of the call.
        if unsafe { ConvertSidToStringSidW(sid, &mut rendered) } == 0 || rendered.is_null() {
            return None;
        }
        let mut length = 0;
        // SAFETY: the string ends with a NUL inside its allocation.
        while unsafe { *rendered.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: `length` units were read above from this string.
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(rendered, length) });
        // SAFETY: the string came from ConvertSidToStringSidW and is freed once.
        unsafe { LocalFree(rendered.cast()) };
        Some(text)
    }

    pub(super) fn current_sid() -> Option<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the token is a local that receives the handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let mut needed = 0u32;
        // SAFETY: a null buffer with a zero length asks only for the size.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: the buffer is a local at least `needed` bytes long.
        let read = needed > 0 && unsafe { GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), needed, &mut needed) } != 0;
        let text = if read {
            // SAFETY: on success the buffer starts with a TOKEN_USER.
            sid_text(unsafe { (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid })
        } else {
            None
        };
        // SAFETY: the token is open and is closed once.
        unsafe { CloseHandle(token) };
        text
    }

    pub(super) fn owner_sid(path: &Path) -> Option<String> {
        let name = wide(&path.display().to_string());
        let mut owner: PSID = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated and the out-pointers are locals.
        let status = unsafe {
            GetNamedSecurityInfoW(name.as_ptr(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut descriptor)
        };
        let text = if status == 0 { sid_text(owner) } else { None };
        if !descriptor.is_null() {
            // SAFETY: the descriptor came from GetNamedSecurityInfoW and is freed once.
            unsafe { LocalFree(descriptor) };
        }
        text
    }

    pub(super) fn write_denied(path: &Path, sid: &str) -> bool {
        let name = wide(&path.display().to_string());
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated and the out-pointers are locals.
        let status = unsafe {
            GetNamedSecurityInfoW(name.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), &mut dacl, std::ptr::null_mut(), &mut descriptor)
        };
        let found = status == 0 && !dacl.is_null() && denies(dacl, &sid.to_uppercase());
        if !descriptor.is_null() {
            // SAFETY: the descriptor came from GetNamedSecurityInfoW and is freed once.
            unsafe { LocalFree(descriptor) };
        }
        found
    }

    fn denies(dacl: *mut ACL, wanted: &str) -> bool {
        // SAFETY: an all-zero size record is a valid value of that plain struct.
        let mut size: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `dacl` is valid while its descriptor is held and `size` is a local.
        if unsafe { GetAclInformation(dacl, (&mut size as *mut ACL_SIZE_INFORMATION).cast(), std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation) } == 0 {
            return false;
        }
        for index in 0..size.AceCount {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `dacl` is valid and `ace` is a local.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                continue;
            }
            let bytes = ace as *const u8;
            // SAFETY: every entry starts with a type byte, a flags byte and a 16-bit size.
            let (kind, length) = unsafe { (*bytes, u16::from_le_bytes([*bytes.add(2), *bytes.add(3)])) };
            if kind != DENIED || length < 8 {
                continue;
            }
            // SAFETY: a deny entry of at least 8 bytes holds its mask at offset 4.
            let mask = unsafe { u32::from_le_bytes([*bytes.add(4), *bytes.add(5), *bytes.add(6), *bytes.add(7)]) };
            if mask & WRITE_BITS == 0 {
                continue;
            }
            // SAFETY: a deny entry's SID starts at offset 8.
            if sid_text(unsafe { bytes.add(8) } as PSID).is_some_and(|text| text.to_uppercase() == wanted) {
                return true;
            }
        }
        false
    }
}
