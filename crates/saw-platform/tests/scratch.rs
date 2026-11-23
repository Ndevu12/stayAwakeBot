//! Tests for temporary work areas.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use saw_platform::sandbox::Isolated;
use saw_platform::sandbox::scratch::*;

#[test]
fn a_folder_that_denies_removal_is_reopened_and_removed() {
    let sandbox = Isolated::new("denies").unwrap();
    let base = sandbox.folder("denies").unwrap();
    let inner = base.join("shut");
    fs::create_dir_all(inner.join("deeper")).unwrap();
    fs::write(inner.join("deeper/file"), b"x").unwrap();
    fs::set_permissions(&inner, fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(remove_tree(&base), "");
    assert!(!base.exists());
}

#[test]
fn a_teardown_runs_before_its_area_is_removed() {
    let sandbox = Isolated::new("teardown").unwrap();
    let run = sandbox.sandbox().scratch();
    let ran = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&ran);
    let area = run.new_dir("a holding copy", Some(Box::new(move |_| {
        seen.store(true, Ordering::SeqCst);
        String::new()
    }))).unwrap();
    assert!(run.release().is_empty());
    assert!(ran.load(Ordering::SeqCst));
    assert!(!area.exists());
}
