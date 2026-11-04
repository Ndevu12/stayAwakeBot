//! The git/gh stand-in: it holds a bringing-files command for `saw govern`, passes everything else
//! straight through, and — this is load-bearing — never breaks git when saw cannot answer.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const STANDIN: &str = env!("CARGO_BIN_EXE_saw-git-standin");

fn exec_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct Fixture {
    dir: PathBuf,
    real_log: PathBuf,
    apply_log: PathBuf,
    real_git: PathBuf,
    saw: PathBuf,
    holding: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("saw-standin-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let real_log = dir.join("real.log");
        let apply_log = dir.join("apply.log");
        let real_git = dir.join("real-git");
        exec_script(&real_git, &format!("#!/bin/sh\necho \"$@\" >> {:?}\n", real_log));
        let saw = dir.join("fake-saw");
        exec_script(
            &saw,
            &format!(
                "#!/bin/sh\n\
                 if [ \"$2\" = prepare ]; then\n\
                 \t[ -n \"$SAW_FAKE_HELD\" ] && exit 2\n\
                 \techo '{{\"schema_version\":1,\"scan\":{{}}}}'; exit 0\n\
                 fi\n\
                 if [ \"$2\" = apply ]; then echo applied >> {:?}; echo '{{\"applied\":true}}'; exit 0; fi\n\
                 exit 1\n",
                apply_log
            ),
        );
        let holding = dir.join("holding");
        Fixture { dir: dir.clone(), real_log, apply_log, real_git, saw, holding }
    }

    fn run(&self, args: &[&str], activated: bool, saw_present: bool, held: bool) -> std::process::ExitStatus {
        let mut c = Command::new(STANDIN);
        c.args(args)
            .current_dir(&self.dir)
            .env("SAW_STANDIN_TOOL", "git")
            .env("SAW_REAL_GIT", &self.real_git)
            .env("PATH", &self.dir) // no real `saw` here unless SAW_BIN points at the fake
            .env("REAL_LOG", &self.real_log);
        c.env("SAW_BIN", if saw_present { self.saw.clone() } else { self.dir.join("no-such-saw") });
        if activated {
            c.env("SAW_GOVERN_HOLDING", &self.holding);
        }
        if held {
            c.env("SAW_FAKE_HELD", "1");
        }
        // the fake real-git writes to $REAL_LOG; the fake saw writes apply to its second arg path
        c.env("APPLY_LOG", &self.apply_log);
        c.status().unwrap()
    }

    fn real_ran(&self) -> bool {
        fs::read_to_string(&self.real_log).map(|s| !s.trim().is_empty()).unwrap_or(false)
    }
    fn applied(&self) -> bool {
        fs::read_to_string(&self.apply_log).map(|s| s.contains("applied")).unwrap_or(false)
    }
}

#[test]
fn a_non_bringing_files_command_passes_straight_through() {
    let f = Fixture::new("status");
    assert!(f.run(&["status"], true, true, false).success());
    assert!(f.real_ran(), "git status must run the real git");
    assert!(!f.applied(), "saw must not govern status");
}

#[test]
fn a_pull_is_checked_and_applied_when_clean() {
    let f = Fixture::new("pull-clean");
    assert!(f.run(&["pull"], true, true, false).success());
    assert!(f.applied(), "a clean pull is applied through saw govern");
    assert!(!f.real_ran(), "the raw pull is not run; the scanned tree is applied");
}

#[test]
fn a_held_update_runs_neither_apply_nor_the_real_command() {
    let f = Fixture::new("pull-held");
    assert!(!f.run(&["pull"], true, true, true).success());
    assert!(!f.applied(), "a held update is not applied");
    assert!(!f.real_ran(), "a held update does not fall through to the real pull");
}

#[test]
fn it_is_inert_until_a_placer_activates_it() {
    let f = Fixture::new("inert");
    assert!(f.run(&["pull"], false, true, false).success());
    assert!(f.real_ran(), "without activation the stand-in just runs the real git");
    assert!(!f.applied());
}

#[test]
fn it_fails_open_to_the_real_git_when_saw_is_absent() {
    let f = Fixture::new("saw-absent");
    assert!(f.run(&["pull"], true, false, false).success());
    assert!(f.real_ran(), "saw absent must never break git — fall through to the real pull");
    assert!(!f.applied());
}

// ---- system mode: activated by SAW_GOVERN_SYSTEM, makes and cleans its own holding ----

fn run_system(f: &Fixture, args: &[&str], tmp: &Path, held: bool) -> std::process::ExitStatus {
    let mut c = Command::new(STANDIN);
    c.args(args)
        .current_dir(&f.dir)
        .env("SAW_STANDIN_TOOL", "git")
        .env("SAW_REAL_GIT", &f.real_git)
        .env("PATH", &f.dir)
        .env("SAW_BIN", &f.saw)
        .env("TMPDIR", tmp) // the stand-in's own holding lands here
        .env("SAW_GOVERN_SYSTEM", "1"); // system mode, no SAW_GOVERN_HOLDING
    if held {
        c.env("SAW_FAKE_HELD", "1");
    }
    c.status().unwrap()
}

#[test]
fn system_mode_checks_and_applies_a_clean_update_then_cleans_up() {
    let f = Fixture::new("system-clean");
    let tmp = f.dir.join("systmp");
    fs::create_dir_all(&tmp).unwrap();
    let status = run_system(&f, &["pull"], &tmp, false);
    assert!(status.success());
    assert!(f.applied(), "a clean update should be applied in system mode");
    assert!(!f.real_ran(), "the raw git must not run when the update was governed");
    assert_eq!(fs::read_dir(&tmp).unwrap().count(), 0, "the system-mode holding must be removed");
}

#[test]
fn system_mode_holds_an_infected_update_without_running_raw_git_and_cleans_up() {
    let f = Fixture::new("system-held");
    let tmp = f.dir.join("systmp");
    fs::create_dir_all(&tmp).unwrap();
    let status = run_system(&f, &["pull"], &tmp, true);
    assert!(!status.success(), "a held update exits non-zero");
    assert!(!f.applied(), "a held update is not applied");
    assert!(!f.real_ran(), "the raw git must not run for a held update");
    assert_eq!(fs::read_dir(&tmp).unwrap().count(), 0, "the held update's holding must be removed");
}

#[test]
fn without_either_activation_a_bringing_files_command_passes_through() {
    let f = Fixture::new("system-inert");
    let tmp = f.dir.join("systmp");
    fs::create_dir_all(&tmp).unwrap();
    // neither SAW_GOVERN_HOLDING nor SAW_GOVERN_SYSTEM
    let status = Command::new(STANDIN)
        .args(["pull"])
        .current_dir(&f.dir)
        .env("SAW_STANDIN_TOOL", "git")
        .env("SAW_REAL_GIT", &f.real_git)
        .env("PATH", &f.dir)
        .env("SAW_BIN", &f.saw)
        .env("TMPDIR", &tmp)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(f.real_ran(), "with no activation the real git runs");
    assert!(!f.applied(), "nothing is governed when inert");
}
