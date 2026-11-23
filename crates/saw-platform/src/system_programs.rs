//! Finds a program the operating system ships, by absolute path and never through `PATH`.

use std::path::{Path, PathBuf};

/// Return the folder that holds the Windows system folder, or `C:\Windows` when it cannot be read.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn windows_system_root() -> String {
    let mut buffer = [0u16; 260];
    // SAFETY: the buffer is a local of the given length that the call fills.
    let length = unsafe { windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length > 0 && (length as usize) < buffer.len() {
        let system = String::from_utf16_lossy(&buffer[..length as usize]);
        if let Some(parent) = Path::new(&system).parent().map(|p| p.display().to_string()).filter(|p| !p.is_empty()) {
            return parent;
        }
    }
    r"C:\Windows".to_string()
}

/// Return the folder that holds the Windows system folder.
#[cfg(not(windows))]
pub fn windows_system_root() -> String {
    r"C:\Windows".to_string()
}

/// Tell whether a path is a file in the Windows system folder. Takes the path and the system root.
/// Returns the answer.
pub fn in_windows_system_folder(candidate: &str, root: &str) -> bool {
    let text = candidate.replace('/', "\\");
    if text.split('\\').any(|part| part == "..") {
        return false;
    }
    let base = root.replace('/', "\\").trim_end_matches('\\').to_string();
    let lowered = text.to_lowercase();
    ["System32", "SysWOW64"].iter().any(|folder| {
        let prefix = format!("{base}\\{folder}\\").to_lowercase();
        lowered.starts_with(&prefix) && lowered.len() > prefix.len()
    })
}

/// Return the first of the paths that is a program the operating system owns. Takes absolute
/// paths in order of preference. Returns the program, or none.
pub fn system_program(candidates: &[&str]) -> Option<PathBuf> {
    let root = windows_system_root();
    candidates.iter().find(|candidate| owned_by_the_system(candidate, &root)).map(PathBuf::from)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn owned_by_the_system(candidate: &str, _root: &str) -> bool {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let path = Path::new(candidate);
    if !path.is_absolute() {
        return false;
    }
    let Ok(found) = std::fs::metadata(path) else { return false };
    let Ok(name) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    let runnable = unsafe { libc::access(name.as_ptr(), libc::X_OK) } == 0;
    found.is_file() && runnable && found.uid() == 0 && found.mode() & 0o022 == 0
}

#[cfg(windows)]
fn owned_by_the_system(candidate: &str, root: &str) -> bool {
    in_windows_system_folder(candidate, root) && std::fs::metadata(candidate).is_ok_and(|found| found.is_file())
}
