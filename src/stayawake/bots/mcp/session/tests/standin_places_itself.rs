//! `saw govern install` / `status` / `uninstall` run the stand-in by its own name with a
//! subcommand. It places itself as git/gh ahead of the real tools, turns itself on for new shells,
//! and takes it all back — never touching anything but its own block in a shell file.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");

fn sandbox(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("saw-place-{}-{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn admin(home: &Path, sub: &str) -> Output {
    Command::new(STANDIN)
        .args([sub, "--saw", "/opt/saw/bin/saw"])
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap()
}

fn shim(home: &Path) -> PathBuf {
    home.join(".config/saw/govern/bin")
}
fn activate(home: &Path) -> PathBuf {
    home.join(".config/saw/govern/activate.sh")
}

#[test]
fn install_places_the_shim_and_turns_it_on_then_uninstall_takes_it_back() {
    let home = sandbox("roundtrip");
    fs::write(home.join(".zshrc"), "export FOO=1\n").unwrap();

    assert!(admin(&home, "install").status.success());
    assert!(shim(&home).join("git").symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(fs::read_link(shim(&home).join("git")).unwrap(), PathBuf::from(STANDIN));
    let act = fs::read_to_string(activate(&home)).unwrap();
    assert!(act.contains("SAW_GOVERN_SYSTEM=1"));
    assert!(act.contains("SAW_BIN='/opt/saw/bin/saw'"));
    let rc = fs::read_to_string(home.join(".zshrc")).unwrap();
    assert!(rc.contains("export FOO=1"), "the operator's own lines are kept");
    assert!(rc.contains("# >>> saw govern >>>"));

    assert!(admin(&home, "uninstall").status.success());
    assert!(!shim(&home).join("git").exists());
    assert!(!activate(&home).exists());
    let rc = fs::read_to_string(home.join(".zshrc")).unwrap();
    assert_eq!(rc, "export FOO=1\n", "uninstall restores the shell file exactly");
}

#[test]
fn installing_twice_leaves_one_block_and_creates_profile_when_none_exists() {
    let home = sandbox("idempotent");
    assert!(admin(&home, "install").status.success());
    assert!(admin(&home, "install").status.success());
    let rc = fs::read_to_string(home.join(".profile")).unwrap(); // created when no rc exists
    assert_eq!(rc.matches("# >>> saw govern >>>").count(), 1);
}

#[test]
fn status_reports_not_installed_then_installed() {
    let home = sandbox("status");
    let before = admin(&home, "status");
    assert!(String::from_utf8_lossy(&before.stdout).contains("not installed"));
    admin(&home, "install");
    let after = admin(&home, "status");
    assert!(String::from_utf8_lossy(&after.stdout).contains("terminals"));
}

fn system_git_dir() -> PathBuf {
    for dir in ["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"] {
        if Path::new(dir).join("git").is_file() {
            return PathBuf::from(dir);
        }
    }
    panic!("the test needs a system git on PATH");
}

#[test]
fn a_shim_symlink_first_on_path_runs_the_real_git_not_itself() {
    // The system layout: a `git` symlink to the stand-in, first on PATH, with the real git after it.
    // A non-bringing command must reach the real git, not re-exec the stand-in forever. The real git
    // is the installed one — execing a just-written script here races the kernel (ETXTBSY) on a
    // loaded CI runner, and the recursion guard, not the fake, is what this test is for.
    use std::os::unix::fs::symlink;
    let home = sandbox("no-recurse");
    let shimd = home.join("shim");
    fs::create_dir_all(&shimd).unwrap();
    symlink(STANDIN, shimd.join("git")).unwrap();

    let out = Command::new(shimd.join("git")) // invoked via the symlink → argv0 basename is "git"
        .args(["--version"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", format!("{}:{}", shimd.display(), system_git_dir().display()))
        .env("SAW_GOVERN_SYSTEM", "1") // system mode active, but no SAW_REAL_GIT
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("git version"),
        "the real git must run, not the stand-in looping"
    );
}
