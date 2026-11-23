//! Tests for reading files.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use saw_platform::files::*;
use saw_platform::sandbox::Isolated;

#[test]
fn a_pipe_is_refused_without_waiting() {
    let sandbox = Isolated::new("pipe").unwrap();
    let pipe = sandbox.pipe("named.js").unwrap();
    let started = Instant::now();
    assert!(matches!(read_regular(&pipe, 1 << 20, Follow::Links, None), Err(ReadError::NotRegular)));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_link_is_read_only_when_links_are_followed() {
    let sandbox = Isolated::new("link").unwrap();
    let root = sandbox.root().to_path_buf();
    fs::write(root.join("real.txt"), b"content").unwrap();
    std::os::unix::fs::symlink(root.join("real.txt"), root.join("link.txt")).unwrap();
    assert!(matches!(read_regular(&root.join("link.txt"), 100, Follow::NoLinks, None), Err(ReadError::NotRegular)));
    assert_eq!(read_regular(&root.join("link.txt"), 100, Follow::Links, None).unwrap(), b"content");
}

#[test]
fn a_file_over_the_limit_or_replaced_is_not_read() {
    let sandbox = Isolated::new("limits").unwrap();
    let root = sandbox.root().to_path_buf();
    fs::write(root.join("big.txt"), vec![b'a'; 100]).unwrap();
    fs::write(root.join("other.txt"), b"x").unwrap();
    assert!(matches!(read_regular(&root.join("big.txt"), 10, Follow::NoLinks, None), Err(ReadError::TooLarge(100))));
    let other = identity(&root.join("other.txt"), Follow::NoLinks).unwrap();
    assert!(matches!(read_regular(&root.join("big.txt"), 1000, Follow::NoLinks, Some(other)), Err(ReadError::Replaced)));
    let own = identity(&root.join("big.txt"), Follow::NoLinks).unwrap();
    assert_eq!(read_regular(&root.join("big.txt"), 1000, Follow::NoLinks, Some(own)).unwrap().len(), 100);
}

#[test]
fn the_head_and_the_tail_are_read() {
    let sandbox = Isolated::new("head-tail").unwrap();
    let root = sandbox.root().to_path_buf();
    fs::write(root.join("long.txt"), b"0123456789").unwrap();
    assert_eq!(head_and_tail(&root.join("long.txt"), 3, Follow::NoLinks).unwrap(), (b"012".to_vec(), b"789".to_vec()));
    assert_eq!(head_and_tail(&root.join("long.txt"), 20, Follow::NoLinks).unwrap().1, b"0123456789".to_vec());
}

#[test]
fn a_folder_that_cannot_be_listed_is_reported() {
    use std::os::unix::fs::PermissionsExt;
    let sandbox = Isolated::new("unwalkable").unwrap();
    let root = sandbox.root().to_path_buf();
    fs::create_dir_all(root.join("shut")).unwrap();
    fs::set_permissions(root.join("shut"), fs::Permissions::from_mode(0o000)).unwrap();
    let found = walk(&root, &root, &|_| false);
    fs::set_permissions(root.join("shut"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(found.unwalkable.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(), vec![PathBuf::from("shut")]);
}
