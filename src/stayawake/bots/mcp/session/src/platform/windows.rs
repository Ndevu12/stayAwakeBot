//! The Windows answers: volume serial numbers and file indexes, owner SIDs, `PATHEXT`, and a child
//! program in place of `exec`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::Command;
use std::ptr::null_mut;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TokenOwner, TokenUser, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The file that reads as empty and takes every write.
pub const NULL_DEVICE: &str = "nul";

/// What separates the folders in a list of them, as in `PATH`.
pub const PATH_LIST_SEPARATOR: char = ';';

/// Whether a shell's startup files can turn the stand-in on for new terminals.
pub const SHELL_FILES_TURN_ON_TERMINALS: bool = false;

const PROGRAM_EXTENSIONS_WHEN_UNSET: &str = ".COM;.EXE;.BAT;.CMD";

/// Spell an environment variable's name the way this system compares names: in upper case. Takes
/// the name.
pub fn environment_key(name: &str) -> String {
    name.to_uppercase()
}

/// The home folder `~` names: `USERPROFILE`, else `HOMEDRIVE` and `HOMEPATH`. Takes the
/// environment. Returns it, or None when neither is set.
pub fn home_folder(environ: &HashMap<String, String>) -> Option<String> {
    if let Some(profile) = environ.get("USERPROFILE") {
        return Some(profile.clone());
    }
    let path = environ.get("HOMEPATH")?;
    Some(format!("{}{path}", environ.get("HOMEDRIVE").map(String::as_str).unwrap_or("")))
}

/// Name the file a path reaches, links followed: its volume serial number and file index. Takes
/// the path. Returns them, or why the file cannot be read.
pub fn file_id(path: &Path) -> io::Result<(u64, u64)> {
    let file = fs::OpenOptions::new().access_mode(0).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(path)?;
    // SAFETY: the handle is open for the call and `info` is a plain structure the call fills.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok((u64::from(info.dwVolumeSerialNumber), index))
}

/// Make a folder and the folders above it, each taking the access its parent gives. Takes the path.
pub fn create_private_folder(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).create(path)
}

/// Whether the user this process runs as owns a file: its owner is that user, or the owner this
/// process gives what it makes. Takes the path and the file's own details. Returns false when the
/// owner cannot be read.
pub fn belongs_to_this_user(path: &Path, _found: &fs::Metadata) -> bool {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `wide` ends in a NUL; the call points `owner` into `descriptor`, freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(wide.as_ptr(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, null_mut(),
                              null_mut(), null_mut(), &mut descriptor)
    };
    if status != ERROR_SUCCESS {
        return false;
    }
    let user = token_information(TokenUser);
    let default_owner = token_information(TokenOwner);
    // SAFETY: each buffer holds what GetTokenInformation wrote for its class.
    let mine: Vec<PSID> = unsafe {
        user.iter().map(|held| (*held.as_ptr().cast::<TOKEN_USER>()).User.Sid)
            .chain(default_owner.iter().map(|held| (*held.as_ptr().cast::<TOKEN_OWNER>()).Owner))
            .collect()
    };
    // SAFETY: `owner` stays valid until `descriptor` is freed, and every SID in `mine` while its buffer lives.
    let owned = !owner.is_null() && mine.iter().any(|&sid| unsafe { EqualSid(owner, sid) } != 0);
    unsafe { LocalFree(descriptor) };
    owned
}

/// Whether a file's mode lets its group or other users write to it: never on Windows, which has no
/// such mode. Takes the file's own details.
pub fn others_may_write(_found: &fs::Metadata) -> bool {
    false
}

/// Fill a buffer with random bytes from the system. Takes the buffer. Returns why it could not.
pub fn fill_random(buffer: &mut [u8]) -> io::Result<()> {
    let size = u32::try_from(buffer.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the buffer is valid for `size` bytes, and the system's own generator needs no handle.
    let status = unsafe { BCryptGenRandom(null_mut(), buffer.as_mut_ptr(), size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status < 0 {
        return Err(io::Error::other(format!("the system gave no random bytes ({status:#x})")));
    }
    Ok(())
}

/// Read one class of this process's token. Takes the class. Returns the buffer the token wrote,
/// aligned for the structure it holds, or None when it cannot be read.
fn token_information(class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the token handle is closed below; the buffer is sized to what the first call asks.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut needed = 0u32;
        GetTokenInformation(token, class, null_mut(), 0, &mut needed);
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let size = u32::try_from(buffer.len() * 8).unwrap_or(0);
        let read = GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), size, &mut needed);
        CloseHandle(token);
        (read != 0).then_some(buffer)
    }
}

/// The bytes of a file name, the order saw's Python sorts names in: its UTF-8. Takes the name.
pub fn name_bytes(name: &OsStr) -> Cow<'_, [u8]> {
    Cow::Owned(name.to_string_lossy().into_owned().into_bytes())
}

/// The file names a program can have in a folder on `PATH`: the name as given when it ends in an
/// extension `PATHEXT` lists, else the name with each of them in turn. Takes the program's name.
pub fn program_file_names(program: &str) -> Vec<String> {
    let listed = std::env::var("PATHEXT").ok().filter(|value| !value.is_empty());
    let extensions: Vec<String> = listed.as_deref().unwrap_or(PROGRAM_EXTENSIONS_WHEN_UNSET)
        .split(';').filter(|extension| !extension.is_empty()).map(str::to_lowercase).collect();
    let written = Path::new(program).extension().and_then(OsStr::to_str).map(|extension| format!(".{extension}"));
    if written.is_some_and(|written| extensions.iter().any(|known| same_file_name(known, &written))) {
        return vec![program.to_string()];
    }
    extensions.iter().map(|extension| format!("{program}{extension}")).collect()
}

/// Whether two file names name the same file in one folder: the same letters in either case.
/// Takes both names.
pub fn same_file_name(one: &str, other: &str) -> bool {
    one.to_lowercase() == other.to_lowercase()
}

/// Put a link at a path that runs a program. Takes the program and the link's path.
pub fn place_link(program: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(program, link)
}

/// Run a program in place of this process: with this process's console, input and output, waited
/// for, then exit with its code. Takes the command. Returns why it could not start.
pub fn run_in_place_of_this_process(command: &mut Command) -> io::Error {
    // SAFETY: the handler only returns, and stays registered for the life of the process.
    unsafe { SetConsoleCtrlHandler(Some(leave_console_events_to_the_program), 1) };
    match command.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => error,
    }
}

/// Take a console event, Ctrl+C among them, and leave it to the program this process waits for.
unsafe extern "system" fn leave_console_events_to_the_program(_event: u32) -> BOOL {
    1
}
