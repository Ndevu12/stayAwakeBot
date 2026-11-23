//! Reads Windows processes from the system's own process query.

use sha2::{Digest, Sha256};

use super::identity::{Identity, Reading};
use super::listing::Snapshot;

/// One process from the Windows process query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub pid: u32,
    pub ppid: u32,
    pub argv: Option<Vec<String>>,
    pub path: Option<String>,
    pub start: i64,
    pub uid: i64,
}

impl Row {
    /// Return the identity this row describes.
    pub fn identity(&self) -> Identity {
        let held = if self.uid >= 0 { vec![self.uid] } else { Vec::new() };
        Identity { pid: self.pid, ppid: self.ppid, uid: self.uid, start_time: self.start, zombie: false, held_uids: held }
    }
}

/// Return the number an identity carries for an account name, or -1 when there is none. Takes
/// the name.
pub fn account_number(name: &str) -> i64 {
    if name.is_empty() {
        return -1;
    }
    let digest = Sha256::digest(name.as_bytes());
    let number = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) as i64;
    if number == 0 { 1 } else { number }
}

/// Return a process start in milliseconds, or 0 when there is none. Takes the query's value.
pub fn windows_start(value: &serde_json::Value) -> i64 {
    match value {
        serde_json::Value::Number(number) => number.as_i64().or_else(|| number.as_f64().map(|f| f.trunc() as i64)).unwrap_or(0),
        serde_json::Value::String(text) => {
            let Some((_, after)) = text.split_once("/Date(") else { return 0 };
            let digits = after.split(')').next().unwrap_or("").split('+').next().unwrap_or("").split('-').next().unwrap_or("");
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                digits.parse().unwrap_or(0)
            } else {
                0
            }
        }
        _ => 0,
    }
}

fn whole_number(value: Option<&serde_json::Value>) -> Option<u32> {
    value.filter(|v| v.is_i64() || v.is_u64()).and_then(|v| u32::try_from(v.as_i64()?).ok())
}

/// Read process rows from the query's JSON document. Takes the document and the splitter for each
/// command line. Returns the rows, or none when the document is not that JSON.
pub fn rows_from_cim(text: &str, split: &dyn Fn(&str) -> Option<Vec<String>>) -> Option<Vec<Row>> {
    let data: serde_json::Value = serde_json::from_str(text).ok()?;
    let items = match data {
        serde_json::Value::Array(items) => items,
        other => vec![other],
    };
    let mut rows = Vec::new();
    for item in &items {
        let Some(object) = item.as_object() else { continue };
        let Some(pid) = whole_number(object.get("ProcessId")) else { continue };
        let text_of = |key: &str| object.get(key).and_then(|v| v.as_str()).map(String::from);
        let command = text_of("CommandLine").filter(|c| !c.is_empty());
        rows.push(Row {
            pid,
            ppid: whole_number(object.get("ParentProcessId")).unwrap_or(0),
            argv: command.and_then(|c| split(&c)),
            path: text_of("ExecutablePath"),
            start: windows_start(object.get("CreationDate").unwrap_or(&serde_json::Value::Null)),
            uid: account_number(&text_of("User").unwrap_or_default()),
        });
    }
    Some(rows)
}

/// Return a snapshot built from process rows, unsupported when there are none. Takes the rows.
pub fn snapshot_of(rows: Option<Vec<Row>>) -> Snapshot {
    let Some(rows) = rows else { return super::listing::unsupported() };
    let mut snap = super::listing::supported();
    for row in rows {
        let identity = row.identity();
        super::listing::add_row(&mut snap, row.pid, row.argv, identity);
    }
    snap
}

/// Return one process's row and what reading it found. Takes the process id.
pub fn row_of(pid: u32) -> (Option<Row>, Reading) {
    match system_rows() {
        None => (None, Reading::Unsupported),
        Some(rows) => match rows.into_iter().find(|row| row.pid == pid) {
            Some(row) => (Some(row), Reading::Running),
            None => (None, Reading::Gone),
        },
    }
}

const QUERY: &str = "Get-CimInstance Win32_Process | ForEach-Object { \
$user = ''; try { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; \
if ($o.User) { $user = $o.User } } catch {} \
[pscustomobject]@{ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; \
CommandLine=$_.CommandLine; ExecutablePath=$_.ExecutablePath; \
CreationDate=$_.CreationDate; User=$user} } | ConvertTo-Json -Compress";

/// Return this machine's processes from the system's process query, or none.
pub fn system_rows() -> Option<Vec<Row>> {
    let root = crate::system_programs::windows_system_root();
    let shell = format!("{root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    let binary = crate::system_programs::system_program(&[shell.as_str()])?;
    let invocation = crate::programs::Invocation {
        program: binary,
        args: ["-NoProfile", "-NonInteractive", "-Command", QUERY].iter().map(|a| a.to_string()).collect(),
        env: crate::env::Environment::from_process().variables().clone(),
        timeout: std::time::Duration::from_secs(30),
        ..crate::programs::Invocation::default()
    };
    let done = crate::programs::run(&invocation).ok()?;
    let out = String::from_utf8_lossy(&done.stdout).into_owned();
    if done.code != Some(0) || out.trim().is_empty() {
        return None;
    }
    rows_from_cim(&out, &split_command)
}

/// Split a command line as this system does. Takes the line. Returns the arguments, or none.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn split_command(line: &str) -> Option<Vec<String>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
    let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
    let mut count = 0i32;
    // SAFETY: `wide` is a NUL-terminated string that outlives the call.
    let parsed = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    if parsed.is_null() || count <= 0 {
        return None;
    }
    let mut args = Vec::new();
    for index in 0..count as usize {
        // SAFETY: the array holds `count` NUL-terminated strings until it is freed below.
        let item = unsafe { *parsed.add(index) };
        let mut length = 0;
        // SAFETY: each string ends with a NUL inside the array's allocation.
        while unsafe { *item.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: `length` units were read above from this string.
        args.push(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(item, length) }));
    }
    // SAFETY: the array came from CommandLineToArgvW and is freed once.
    unsafe { LocalFree(parsed.cast()) };
    Some(args)
}

/// Split a command line as this system does. Takes the line. Returns the arguments, or none.
#[cfg(not(windows))]
pub fn split_command(_line: &str) -> Option<Vec<String>> {
    None
}
