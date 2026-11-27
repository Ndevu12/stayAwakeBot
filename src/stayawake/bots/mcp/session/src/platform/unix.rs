//! The Unix answers: devices and inodes, user ids, file modes, and `exec`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// The file that reads as empty and takes every write.
pub const NULL_DEVICE: &str = "/dev/null";

/// What separates the folders in a list of them, as in `PATH`.
pub const PATH_LIST_SEPARATOR: char = ':';

/// Whether a shell's startup files can turn the stand-in on for new terminals.
pub const SHELL_FILES_TURN_ON_TERMINALS: bool = true;

/// Spell an environment variable's name the way this system compares names: as written. Takes
/// the name.
pub fn environment_key(name: &str) -> String {
    name.to_string()
}

/// The home folder `~` names. Takes the environment. Returns it, or None when `HOME` is not set.
pub fn home_folder(environ: &HashMap<String, String>) -> Option<String> {
    environ.get("HOME").cloned()
}

/// Name the file a path reaches, links followed: its device and inode. Takes the path. Returns
/// them, or why the file cannot be read.
pub fn file_id(path: &Path) -> io::Result<(u64, u64)> {
    fs::metadata(path).map(|found| (found.dev(), found.ino()))
}

/// Make a folder and the folders above it, the new ones open to their owner alone. Takes the path.
pub fn create_private_folder(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
}

/// Whether the user this process runs as owns a file. Takes the file's own details.
pub fn belongs_to_this_user(_path: &Path, found: &fs::Metadata) -> bool {
    found.uid() == fs::metadata("/proc/self").map(|own| own.uid()).unwrap_or_else(|_| current_uid())
}

/// Whether a file's mode lets its group or other users write to it. Takes the file's own details.
pub fn others_may_write(found: &fs::Metadata) -> bool {
    found.mode() & 0o022 != 0
}

/// Fill a buffer with random bytes from the system. Takes the buffer. Returns why it could not.
pub fn fill_random(buffer: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    fs::File::open("/dev/urandom")?.read_exact(buffer)
}

/// The user this process runs as, read from a file it makes.
fn current_uid() -> u32 {
    static PROBES: AtomicU64 = AtomicU64::new(0);
    let probe_number = PROBES.fetch_add(1, Ordering::Relaxed);
    let probe = std::env::temp_dir().join(format!("saw-uid-{}-{probe_number}", std::process::id()));
    let uid = fs::File::create(&probe).and_then(|_| fs::metadata(&probe)).map(|found| found.uid()).unwrap_or(u32::MAX);
    let _ = fs::remove_file(&probe);
    uid
}

/// The bytes of a file name, the order saw's Python sorts names in. Takes the name.
pub fn name_bytes(name: &OsStr) -> Cow<'_, [u8]> {
    Cow::Borrowed(name.as_bytes())
}

/// The file names a program can have in a folder on `PATH`. Takes the program's name. Returns
/// the name as given.
pub fn program_file_names(program: &str) -> Vec<String> {
    vec![program.to_string()]
}

/// Whether two file names name the same file in one folder: the same bytes. Takes both names.
pub fn same_file_name(one: &str, other: &str) -> bool {
    one == other
}

/// Put a link at a path that runs a program. Takes the program and the link's path.
pub fn place_link(program: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(program, link)
}

/// Run a program in place of this process, which it replaces. Takes the command. Returns why it
/// could not start.
pub fn run_in_place_of_this_process(command: &mut Command) -> io::Error {
    command.exec()
}
