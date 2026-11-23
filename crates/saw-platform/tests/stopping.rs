//! Tests for stopping processes.

use std::collections::BTreeMap;

use saw_platform::elevate;
use saw_platform::processes::stopping::*;
use saw_platform::sandbox::Isolated;

#[test]
fn a_kill_program_root_does_not_own_is_never_run_as_root() {
    let sandbox = Isolated::new("kill").unwrap();
    let planted = sandbox.file("kill", b"#!/bin/sh\n").unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&planted, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let planted = planted.display().to_string();
    let asked = std::cell::RefCell::new(0);
    let run = |_: &[String]| {
        *asked.borrow_mut() += 1;
        (elevate::Outcome::Granted, String::new())
    };
    let found = BTreeMap::from([(7, "a".to_string())]);
    let outcome = end_as_root_with(&[planted.as_str()], &[7], &found, &run, &|_| Some("a".to_string()));
    assert_eq!(outcome, (elevate::Outcome::NotAvailable, Vec::new()));
    assert_eq!(*asked.borrow(), 0);
}
