//! Each system names a file the same way for every spelling of its path, and a folder this process
//! makes belongs to the user it runs as.

use std::fs;
use std::path::{Path, PathBuf};

use saw_mcp::platform::{belongs_to_this_user, create_private_folder, file_id, program_file_names, same_file_name};

fn folder(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("saw-platform-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn every_name_for_a_file_reaches_one_identity() {
    let here = folder("identity");
    fs::write(here.join("one"), "one").unwrap();
    fs::write(here.join("other"), "one").unwrap();
    fs::hard_link(here.join("one"), here.join("second-name")).unwrap();
    let one = file_id(&here.join("one")).unwrap();
    assert_eq!(file_id(&here.join(".").join("one")).unwrap(), one);
    assert_eq!(file_id(&here.join("second-name")).unwrap(), one);
    assert_ne!(file_id(&here.join("other")).unwrap(), one);
    assert_ne!(file_id(&here).unwrap(), one);
    assert!(file_id(&here.join("absent")).is_err());
}

#[test]
fn a_folder_this_process_makes_belongs_to_its_user() {
    let made = folder("owner").join("state").join("saw");
    create_private_folder(&made).unwrap();
    let found = fs::symlink_metadata(&made).unwrap();
    assert!(found.is_dir());
    assert!(belongs_to_this_user(&made, &found));
}

#[cfg(windows)]
#[test]
fn a_file_whose_owner_cannot_be_read_belongs_to_no_one_here() {
    let here = folder("unread-owner");
    let found = fs::symlink_metadata(&here).unwrap();
    assert!(!belongs_to_this_user(&here.join("absent"), &found));
}

#[test]
fn a_program_is_looked_for_by_the_names_this_system_runs() {
    let names = program_file_names("git");
    assert!(names.iter().any(|name| same_file_name(name, &format!("git{}", std::env::consts::EXE_SUFFIX))), "{names:?}");
    assert!(same_file_name("git", "git"));
    assert_eq!(same_file_name("GIT", "git"), cfg!(windows));
}
