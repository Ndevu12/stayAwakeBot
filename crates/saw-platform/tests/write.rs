//! Tests for safe writes.

#![cfg(unix)]

use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use saw_platform::sandbox::Isolated;
use saw_platform::sandbox::write::*;

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn a_file_is_written_in_one_step_and_reads_back() {
    let sandbox = Isolated::new("plain").unwrap();
    let root = sandbox.folder("work").unwrap();
    let file = root.join("made/on/the/way/state.json");
    replace(&file, b"{}", Mode::Set(0o600), AtALink::Refuse).unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"{}");
    assert_eq!(mode_of(&file), 0o600);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    replace(&file, b"[]", Mode::AsAPlainWrite, AtALink::Refuse).unwrap();
    assert_eq!(mode_of(&file), 0o640);
}

#[test]
fn a_link_at_the_name_is_refused_followed_or_replaced() {
    let sandbox = Isolated::new("at-name").unwrap();
    let root = sandbox.folder("work").unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(root.join("target.json"), b"old").unwrap();
    symlink(root.join("target.json"), root.join("link.json")).unwrap();
    assert!(matches!(replace(&root.join("link.json"), b"new", Mode::Set(0o600), AtALink::Refuse), Err(WriteError::Redirected(_))));
    replace(&root.join("link.json"), b"through", Mode::Set(0o600), AtALink::FollowTrusted).unwrap();
    assert_eq!(fs::read(root.join("target.json")).unwrap(), b"through");
    replace(&root.join("link.json"), b"replaced", Mode::Set(0o600), AtALink::Replace).unwrap();
    assert!(!fs::symlink_metadata(root.join("link.json")).unwrap().file_type().is_symlink());
    assert_eq!(fs::read(root.join("target.json")).unwrap(), b"through");
}

#[test]
fn a_link_others_could_have_placed_is_refused() {
    let sandbox = Isolated::new("others").unwrap();
    let root = sandbox.folder("work").unwrap();
    fs::create_dir_all(root.join("real")).unwrap();
    for (holder, writable_by_others, expect_refused) in [("private", 0o755, false), ("shared", 0o757, true)] {
        fs::create_dir_all(root.join(holder)).unwrap();
        symlink(root.join("real"), root.join(holder).join("way")).unwrap();
        fs::set_permissions(root.join(holder), fs::Permissions::from_mode(writable_by_others)).unwrap();
        let answer = replace(&root.join(holder).join("way/file.txt"), b"x", Mode::Set(0o600), AtALink::Refuse);
        assert_eq!(matches!(answer, Err(WriteError::Redirected(_))), expect_refused, "{holder}");
    }
}

#[test]
fn a_failed_write_leaves_nothing_behind() {
    let sandbox = Isolated::new("failed").unwrap();
    let root = sandbox.folder("work").unwrap();
    let answer = write_with(&root.join("never.json"), Mode::Set(0o600), AtALink::Refuse, |_| Err(io::Error::other("stopped")));
    assert!(answer.is_err());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn a_loop_of_links_is_refused() {
    let sandbox = Isolated::new("loop").unwrap();
    let root = sandbox.folder("work").unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(root.join("b"), root.join("a")).unwrap();
    symlink(root.join("a"), root.join("b")).unwrap();
    assert!(matches!(replace(&root.join("a/file.txt"), b"x", Mode::Set(0o600), AtALink::Refuse), Err(WriteError::Redirected(_))));
}
