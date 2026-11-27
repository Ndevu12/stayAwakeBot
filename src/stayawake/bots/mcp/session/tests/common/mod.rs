//! What the stand-in's crate tests share.

use std::fs;
use std::io::Read;
use std::path::PathBuf;

/// The first git on PATH that is not a stand-in.
pub fn real_git() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|candidate| {
            let Ok(target) = fs::canonicalize(candidate) else { return false };
            let mut head = [0u8; 512];
            let read = fs::File::open(&target).and_then(|mut file| file.read(&mut head)).unwrap_or(0);
            target.is_file()
                && target.file_name().is_some_and(|name| name != "saw-git-standin")
                && !head[..read].windows(18).any(|window| window == b"saw-govern-standin")
        })
        .expect("a git that is not a stand-in on PATH")
}
