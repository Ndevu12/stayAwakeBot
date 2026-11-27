//! Finds the repository a command acts on, the way git finds it, as saw's `replay.locate` does.

use std::path::{Path, PathBuf};

use super::git::{Call, Git, Kind};
use super::paths;
use super::surface;
use super::typed_command::TypedCommand;
use super::Environment;

const NOT_A_REPOSITORY: &str = "the folder is not in a git repository saw can read";

/// Find the git directory a command acts on. Takes the git runner, the folder it runs in, the
/// command and its environment. Returns the git directory, None for no repository, or the reason
/// the repository it acts on cannot be read.
pub fn repository(git: &Git, place: &Path, command: &TypedCommand, environ: &Environment) -> Result<Option<PathBuf>, String> {
    match locate(git, place, command) {
        Ok((git_dir, common_dir)) => {
            let shared = surface::common_dir_of(&git_dir, environ);
            if paths::real_path(&shared) != paths::real_path(&common_dir) {
                return Err("the command names a common directory of its own".to_string());
            }
            Ok(Some(git_dir))
        }
        Err(why) if command.names_its_repository() || looks_like_a_repository(place) => {
            Err(format!("{}: {why}", place.display()))
        }
        Err(_) => Ok(None),
    }
}

fn asking(command: &TypedCommand, place: &Path, args: &[&str]) -> Call {
    let mut asked: Vec<String> = Vec::new();
    for (key, value) in &command.settings {
        if let Some(value) = value.as_ref().filter(|_| matches!(key.to_lowercase().as_str(), "core.worktree" | "core.bare")) {
            asked.push("-c".into());
            asked.push(format!("{key}={value}"));
        }
    }
    asked.extend(command.location_options());
    asked.extend(args.iter().map(|arg| arg.to_string()));
    Call { place: Some(place.to_path_buf()), args: asked, kind: Kind::ReadsTheRepository, named: command.locations.clone() }
}

/// Ask git where the command's repository is. Returns its git directory and common directory, or
/// why git cannot find one.
fn locate(git: &Git, place: &Path, command: &TypedCommand) -> Result<(PathBuf, PathBuf), &'static str> {
    let found = asking(command, place, &["rev-parse", "--path-format=absolute", "--absolute-git-dir", "--git-common-dir",
        "--is-inside-work-tree", "--show-object-format", "--git-path", "index", "--git-path", "objects"]);
    let placed = asking(command, place, &["rev-parse", "--show-toplevel", "--show-prefix"]);
    git.run_all(&[found.clone(), placed.clone()]);
    let found = git.answer(&found);
    let lines = split_lines(&found.text());
    if found.succeeded().is_none() || lines.len() != 6 {
        return Err(NOT_A_REPOSITORY);
    }
    let placed = git.answer(&placed);
    let top = if placed.succeeded().is_some() { split_lines(&placed.text()).into_iter().next().unwrap_or_default() } else { String::new() };
    if lines[2] == "true" && top.is_empty() {
        return Err(NOT_A_REPOSITORY);
    }
    let alternates = command.locations.iter().find(|(name, _)| name == "GIT_ALTERNATE_OBJECT_DIRECTORIES").map(|(_, value)| value.as_str()).unwrap_or("");
    if alternates.split(':').filter(|entry| !entry.is_empty()).any(|entry| !Path::new(entry).is_absolute()) {
        return Err("the object directories the command names cannot be read");
    }
    Ok((PathBuf::from(&lines[0]), PathBuf::from(&lines[1])))
}

/// Split text into lines the way Python's `str.splitlines` does for `\n`, `\r\n` and `\r`.
pub fn split_lines(text: &str) -> Vec<String> {
    text.replace("\r\n", "\n").replace('\r', "\n").split_terminator('\n').map(str::to_string).collect()
}

/// Whether git could find a repository at or above a folder.
fn looks_like_a_repository(place: &Path) -> bool {
    let resolved = paths::real_path(place);
    std::iter::once(place).chain(resolved.ancestors().skip(1)).any(|at| paths::lexists(&at.join(".git")) || surface::is_git_directory(at))
}
