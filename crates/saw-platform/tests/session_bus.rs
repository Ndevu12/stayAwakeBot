//! Tests for reaching the account's own service manager and session bus.

use saw_platform::services::session_bus::runtime_folder;

#[test]
fn an_empty_runtime_folder_counts_as_none_given() {
    assert_eq!(runtime_folder(1001, Some("")), "/run/user/1001");
    assert_eq!(runtime_folder(1001, None), "/run/user/1001");
    assert_eq!(runtime_folder(1001, Some("/run/other")), "/run/other");
}
