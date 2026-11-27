//! Reads every program-running entry of a repository's own configuration, as saw's `exec_surface`
//! reads it when it is given the git directory: its own settings and what they include, every view
//! of it, and its submodules at any depth. Settings are read as data and never run.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::exec_keys::{rule_for, ExecKey, Runs};
use super::git::{Call, Git};
use super::paths::{self, file_identity, Identity};
use super::Environment;

const MAX_INCLUDE_DEPTH: usize = 10;
const MAX_GIT_DIRS: usize = 256;
const MAX_CONFIG_BYTES: u64 = 4 << 20;
const EXPANDED_BY_GIT: [&str; 2] = ["%(", ":("];
const REPOSITORY_SCOPES: [&[u8]; 2] = [b"local", b"worktree"];

/// One key set in a configuration file.
#[derive(Debug, Clone)]
struct Entry {
    key: String,
    value: Option<String>,
    source: PathBuf,
}

/// One program-running entry the folder's settings hold: its rule and its key in git's listing.
#[derive(Debug, Clone)]
pub struct Found {
    pub rule: &'static ExecKey,
    pub key: String,
}

/// What git reports it reads for one repository view.
struct Reported {
    files: Vec<PathBuf>,
    hooks_paths: Vec<String>,
    toplevel: Option<PathBuf>,
    git_runs_here: bool,
}

type ConfigFile = (Vec<(String, Option<String>)>, Option<String>);

/// The reading of one repository and everything it reaches.
pub struct Surface<'a> {
    git: &'a Git<'a>,
    environ: &'a Environment,
    pub commands: Vec<Found>,
    pub unexamined: Vec<String>,
    git_dirs: Vec<PathBuf>,
    work_trees: HashMap<PathBuf, PathBuf>,
    files_read: HashMap<PathBuf, ConfigFile>,
}

#[derive(Default)]
struct Collected {
    files: HashSet<Identity>,
    hook_dirs: HashSet<(Identity, bool)>,
}

/// Read what git would run for the repository at a git directory. Takes the git runner, the git
/// directory and the environment. Returns the reading, with what could not be read in `unexamined`.
pub fn read<'a>(git: &'a Git<'a>, git_dir: &Path, environ: &'a Environment) -> Surface<'a> {
    let mut surface = Surface { git, environ, commands: Vec::new(), unexamined: Vec::new(), git_dirs: Vec::new(),
        work_trees: HashMap::new(), files_read: HashMap::new() };
    let common_dir = common_dir_of(git_dir, environ);
    if !git_dir.is_dir() {
        surface.unexamined.push(format!("{}: not a directory", git_dir.display()));
        return surface;
    }
    surface.git_dirs.push(git_dir.to_path_buf());
    if common_dir != git_dir {
        surface.git_dirs.push(common_dir.clone());
    }
    let mut pending = surface.read_repository(Some(git_dir.to_path_buf()), git_dir, false);
    while !pending.is_empty() {
        let (module, module_tree) = pending.remove(0);
        if surface.git_dirs.contains(&module) {
            continue;
        }
        if let Some(tree) = &module_tree {
            surface.work_trees.entry(module.clone()).or_insert_with(|| tree.clone());
        }
        if surface.git_dirs.len() >= MAX_GIT_DIRS {
            surface.unexamined.push(format!("{}: more than {MAX_GIT_DIRS} repositories", module.display()));
            break;
        }
        surface.git_dirs.push(module.clone());
        let nested = surface.read_repository(module_tree, &module, true);
        pending.extend(nested);
    }
    surface
}

impl<'a> Surface<'a> {
    fn resolve(&self, base: &Path, value: &str) -> PathBuf {
        paths::resolve(base, value, self.environ)
    }

    /// Read one configuration file as data, without following its includes. Returns its pairs in
    /// file order and None, or no pairs and the reason it was not read. An absent file reads empty.
    fn list_config_file(&self, path: &Path) -> ConfigFile {
        if !paths::lexists(path) {
            return (Vec::new(), None);
        }
        if !paths::is_regular_file(path) {
            return (Vec::new(), Some("not a regular file".into()));
        }
        match fs::metadata(path) {
            Ok(found) if found.len() > MAX_CONFIG_BYTES => return (Vec::new(), Some("too large to read".into())),
            Err(error) => return (Vec::new(), Some(paths::error_name(&error).into())),
            _ => {}
        }
        let shown = path.display().to_string();
        let answer = self.git.answer(&Call::settings(None, &["config", "--file", &shown, "--no-includes", "--list", "-z"]));
        match answer.code {
            None => (Vec::new(), Some("git could not be run".into())),
            Some(0) => (split_entries(&answer.stdout), None),
            Some(_) => (Vec::new(), Some("git could not read it".into())),
        }
    }

    /// Start reading the files a repository's settings live in, all at once.
    fn read_ahead(&self, files: &[PathBuf]) {
        let calls: Vec<Call> = files
            .iter()
            .filter(|path| paths::is_regular_file(path))
            .map(|path| {
                let shown = path.display().to_string();
                Call::settings(None, &["config", "--file", &shown, "--no-includes", "--list", "-z"])
            })
            .collect();
        self.git.run_all(&calls);
    }

    /// Read a configuration file and every file it includes, each conditional include taken.
    /// Returns the entries in the order git applies them, with those `opened` collects left out.
    fn read_config(&mut self, path: &Path, depth: usize, seen: &HashSet<PathBuf>, mut unsure: Option<&mut Vec<String>>,
                   cached: bool, mut opened: Option<&mut Vec<Entry>>) -> Vec<Entry> {
        let (pairs, why) = if cached {
            let written = absolute(path);
            if !self.files_read.contains_key(&written) {
                let listed = self.list_config_file(path);
                self.files_read.insert(written.clone(), listed);
            }
            self.files_read[&written].clone()
        } else {
            self.list_config_file(path)
        };
        if let Some(why) = why {
            self.unexamined.push(format!("{}: {why}", path.display()));
            return Vec::new();
        }
        let real = paths::real_path(path);
        let parent = path.parent().unwrap_or(Path::new("")).to_path_buf();
        let mut entries = Vec::new();
        for (key, value) in pairs {
            entries.push(Entry { key: key.clone(), value: value.clone(), source: path.to_path_buf() });
            let Some(value) = value.filter(|value| !value.is_empty() && is_include(&key)) else { continue };
            let target = self.resolve(&parent, &value);
            if EXPANDED_BY_GIT.iter().any(|prefix| value.starts_with(prefix)) {
                if let Some(unsure) = unsure.as_deref_mut() {
                    unsure.push(format!("{}: {key} names a path only git can resolve", path.display()));
                }
            }
            if depth + 1 >= MAX_INCLUDE_DEPTH {
                self.unexamined.push(format!("{}: includes nest deeper than {MAX_INCLUDE_DEPTH}", target.display()));
                continue;
            }
            let mut deeper = seen.clone();
            deeper.insert(real.clone());
            for (each, as_opened) in [(Some(target), false), (self.opened_instead(&parent, &value), true)] {
                let Some(each) = each else { continue };
                if (as_opened && opened.is_none()) || deeper.contains(&paths::real_path(&each)) {
                    continue;
                }
                let read = self.read_config(&each, depth + 1, &deeper, unsure.as_deref_mut(), cached, opened.as_deref_mut());
                match (as_opened, opened.as_deref_mut()) {
                    (true, Some(opened)) => opened.extend(read),
                    _ => entries.extend(read),
                }
            }
        }
        entries
    }

    /// Find the file the system opens for an include. Returns it, or None for the one `resolve` names.
    fn opened_instead(&self, base: &Path, value: &str) -> Option<PathBuf> {
        let expanded = PathBuf::from(paths::expand_user(value, self.environ));
        let joined = if expanded.is_absolute() { expanded } else { base.join(expanded) };
        let opened = fs::canonicalize(&joined).ok()?;
        (opened != paths::real_path(&paths::normalize(&joined))).then_some(opened)
    }

    /// Read the configuration of one repository in the order git applies it.
    fn repo_config(&mut self, git_dir: &Path, common_dir: &Path, unsure: &mut Vec<String>, opened: &mut Vec<Entry>) -> Vec<Entry> {
        let mut files = vec![common_dir.join("config"), common_dir.join("config.worktree")];
        if git_dir.join("config.worktree") != files[1] {
            files.push(git_dir.join("config.worktree"));
        }
        self.read_ahead(&files);
        let none = HashSet::new();
        let mut entries = Vec::new();
        for file in files {
            entries.extend(self.read_config(&file, 0, &none, Some(&mut *unsure), true, Some(&mut *opened)));
        }
        entries
    }

    /// Ask git which settings files it reads for one repository view.
    fn repository_settings(&self, place: &Path) -> Option<Reported> {
        let state = Call::repository(place, &["rev-parse", "--is-bare-repository", "--show-toplevel"]);
        let bare = Call::repository(place, &["rev-parse", "--is-bare-repository"]);
        let listing = Call::settings(Some(place), &["config", "--list", "--show-origin", "--show-scope", "-z"]);
        self.git.run_all(&[state.clone(), bare.clone(), listing.clone()]);
        let state = self.git.answer(&state);
        let toplevel = match state.succeeded() {
            Some(out) => out.split(|byte| *byte == b'\n').nth(1).filter(|line| !line.is_empty())
                .map(|line| PathBuf::from(String::from_utf8_lossy(line).into_owned())),
            None => {
                let bare = self.git.answer(&bare);
                match bare.code {
                    None => return None,
                    Some(0) => None,
                    Some(_) => return Some(Reported { files: Vec::new(), hooks_paths: Vec::new(), toplevel: None, git_runs_here: false }),
                }
            }
        };
        let listed = self.git.answer(&listing);
        let listed = listed.succeeded()?;
        let fields: Vec<&[u8]> = listed.split(|byte| *byte == 0).collect();
        let mut files: Vec<PathBuf> = Vec::new();
        let mut sets_hooks_path = false;
        for triple in fields.chunks_exact(3) {
            let (scope, origin, entry) = (triple[0], triple[1], triple[2]);
            if !REPOSITORY_SCOPES.contains(&scope) || !origin.starts_with(b"file:") {
                continue;
            }
            let path = PathBuf::from(String::from_utf8_lossy(&origin[5..]).into_owned());
            let path = if path.is_absolute() { path } else { place.join(path) };
            if !files.contains(&path) {
                files.push(path);
            }
            let key = entry.split(|byte| *byte == b'\n').next().unwrap_or_default();
            sets_hooks_path = sets_hooks_path || String::from_utf8_lossy(key).to_lowercase() == "core.hookspath";
        }
        let mut hooks_paths = Vec::new();
        if sets_hooks_path {
            let expanded = self.git.answer(&Call::settings(Some(place), &["config", "--type=path", "--show-scope", "-z", "--get-all", "core.hookspath"]));
            let expanded = match expanded.succeeded() {
                Some(out) => out.to_vec(),
                None => {
                    let unset = self.git.answer(&Call::settings(Some(place), &["config", "--type=path", "--get-all", "core.hookspath"]));
                    if unset.code != Some(1) {
                        return None;
                    }
                    Vec::new()
                }
            };
            let parts: Vec<&[u8]> = expanded.split(|byte| *byte == 0).collect();
            for pair in parts.chunks_exact(2) {
                if REPOSITORY_SCOPES.contains(&pair[0]) {
                    hooks_paths.push(String::from_utf8_lossy(pair[1]).into_owned());
                }
            }
        }
        Some(Reported { files, hooks_paths, toplevel, git_runs_here: true })
    }

    /// Collect what one repository runs in every view of it. Returns the git directory of every
    /// submodule its views hold, each with its working tree when one is known.
    fn read_repository(&mut self, tree: Option<PathBuf>, git_dir: &Path, as_a_submodule: bool) -> Vec<(PathBuf, Option<PathBuf>)> {
        let common_dir = common_dir_of(git_dir, self.environ);
        let mut collected = Collected::default();
        let (mut unsure, mut opened) = (Vec::new(), Vec::new());
        let entries = self.repo_config(git_dir, &common_dir, &mut unsure, &mut opened);
        if as_a_submodule {
            if let Some(configured) = last(&entries, "core.worktree") {
                let resolved = self.resolve(git_dir, &configured);
                self.work_trees.insert(git_dir.to_path_buf(), resolved);
            }
        }
        let recorded = if as_a_submodule { self.work_trees.get(git_dir).cloned().or(tree) } else { tree };
        let tree = recorded.unwrap_or_else(|| git_dir.to_path_buf());
        let git_can_run = (tree == git_dir || self.belongs(&tree, git_dir)) && tree.is_dir();
        let answer = if git_can_run { Some(self.repository_settings(&tree)) } else { None };
        let mut all = entries.clone();
        all.extend(opened);
        self.read_view(&tree, &common_dir, all, unsure, answer, &mut collected);
        let main_worktree = self.main_worktree(&common_dir, &entries);
        if main_worktree.is_none() && paths::real_path(git_dir) != paths::real_path(&common_dir) {
            self.unexamined.push(format!("{}: git could not tell where this repository's main working tree is, \
                                          so what git runs there is not known", common_dir.display()));
        }
        let mut views = vec![(git_dir.to_path_buf(), tree.clone()), (common_dir.clone(), main_worktree.unwrap_or_else(|| common_dir.clone()))];
        views.extend(self.linked_worktrees(&common_dir));
        let views: Vec<(PathBuf, PathBuf)> = views
            .into_iter()
            .map(|(view_git_dir, view_tree)| {
                let place = if self.belongs(&view_tree, &view_git_dir) { view_tree } else { view_git_dir.clone() };
                (view_git_dir, place)
            })
            .collect();
        let mut submodules = self.submodules_of(Some(&common_dir), &tree);
        let mut read_views: HashSet<Identity> = HashSet::new();
        for (position, (view_git_dir, view_tree)) in views.into_iter().enumerate() {
            if !read_views.insert(file_identity(&view_git_dir)) {
                continue;
            }
            if position == 0 {
                continue;
            }
            let (mut unsure, mut opened) = (Vec::new(), Vec::new());
            let mut entries = self.repo_config(&view_git_dir, &common_dir, &mut unsure, &mut opened);
            entries.extend(opened);
            let answer = Some(self.repository_settings(&view_tree));
            self.read_view(&view_tree, &common_dir, entries, unsure, answer, &mut collected);
            let holds_its_own_modules = paths::real_path(&view_git_dir) != paths::real_path(&common_dir);
            submodules.extend(self.submodules_of(holds_its_own_modules.then_some(view_git_dir.as_path()), &view_tree));
        }
        submodules
    }

    /// Collect what git runs for one view of a repository: the commands its settings name, from
    /// saw's reading joined with every file git reports it reads. Takes git's answer for the view,
    /// None when git cannot run there.
    fn read_view(&mut self, tree: &Path, common_dir: &Path, mut entries: Vec<Entry>, unsure: Vec<String>,
                 ask: Option<Option<Reported>>, collected: &mut Collected) {
        let mut identity_of: HashMap<PathBuf, Identity> = HashMap::new();
        for entry in &entries {
            identity_of.entry(entry.source.clone()).or_insert_with(|| file_identity(&entry.source));
        }
        let asked = ask.is_some();
        let mut answer = ask.flatten();
        let refused = answer.as_ref().is_some_and(|reported| !reported.git_runs_here);
        let git_can_run_here = asked && !refused;
        if refused {
            answer = None;
        }
        if let Some(reported) = &answer {
            let mut known: HashSet<Identity> = identity_of.values().cloned().collect();
            for path in &reported.files {
                if known.contains(&file_identity(path)) {
                    continue;
                }
                let seen: HashSet<PathBuf> = entries.iter().map(|entry| paths::real_path(&entry.source)).collect();
                let added = self.read_config(path, 0, &seen, None, false, None);
                for entry in &added {
                    identity_of.entry(entry.source.clone()).or_insert_with(|| file_identity(&entry.source));
                }
                entries.extend(added);
                known.insert(file_identity(path));
            }
        }
        for entry in &entries {
            if collected.files.contains(&identity_of[&entry.source]) {
                continue;
            }
            if let Some(rule) = rule_for(&entry.key) {
                self.commands.push(Found { rule, key: entry.key.clone() });
            }
        }
        collected.files.extend(identity_of.values().cloned());
        let mut unsure = unsure;
        let effective: Option<PathBuf> = if refused {
            None
        } else {
            match &answer {
                None => {
                    let effective = self.hooks_dir(tree, common_dir, &entries, &mut unsure);
                    if git_can_run_here {
                        self.unexamined.extend(unsure);
                        self.unexamined.push(format!("{}: git did not report which settings it reads", tree.display()));
                    }
                    Some(effective)
                }
                Some(reported) => match reported.hooks_paths.last() {
                    None => Some(common_dir.join("hooks")),
                    Some(last) if last.is_empty() => None,
                    Some(last) => Some(self.resolve(reported.toplevel.as_deref().unwrap_or(tree), last)),
                },
            }
        };
        for (directory, runs) in [(effective, true), (Some(common_dir.join("hooks")), false)] {
            let Some(directory) = directory else { continue };
            let same = file_identity(&directory);
            if collected.hook_dirs.contains(&(same.clone(), true)) || collected.hook_dirs.contains(&(same.clone(), runs)) {
                continue;
            }
            collected.hook_dirs.insert((same, runs));
            if directory.is_dir() {
                if let Err(error) = fs::read_dir(&directory) {
                    self.unexamined.push(format!("{}: {}", directory.display(), paths::error_name(&error)));
                }
            }
        }
    }

    /// Find the hooks directory a repository's parsed settings name.
    fn hooks_dir(&self, tree: &Path, common_dir: &Path, entries: &[Entry], unsure: &mut Vec<String>) -> PathBuf {
        let configured = entries.iter().rev().find(|entry| {
            rule_for(&entry.key).is_some_and(|rule| rule.runs == Runs::HooksDirectory) && entry.value.as_deref().is_some_and(|v| !v.is_empty())
        });
        let Some((entry, value)) = configured.and_then(|entry| entry.value.as_deref().map(|value| (entry, value))) else {
            return common_dir.join("hooks");
        };
        if EXPANDED_BY_GIT.iter().any(|prefix| value.starts_with(prefix)) {
            unsure.push(format!("{}: {} names a path only git can resolve", entry.source.display(), entry.key));
        }
        self.resolve(tree, value)
    }

    /// Tell whether a working tree is a view of a git directory: its `.git` leads back to it.
    fn belongs(&self, tree: &Path, git_dir: &Path) -> bool {
        git_dir_of(tree, self.environ).is_some_and(|found| file_identity(&found) == file_identity(git_dir))
    }

    /// Find every linked worktree of a repository, each git directory with its working tree, or
    /// with the git directory itself when the tree is gone.
    fn linked_worktrees(&mut self, common_dir: &Path) -> Vec<(PathBuf, PathBuf)> {
        let place = common_dir.join("worktrees");
        let listed = match fs::read_dir(&place) {
            Ok(listed) => listed,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => {
                self.unexamined.push(format!("{}: {}", place.display(), paths::error_name(&error)));
                return Vec::new();
            }
        };
        let mut git_dirs: Vec<PathBuf> = listed.flatten().map(|entry| entry.path()).filter(|path| path.is_dir()).collect();
        git_dirs.sort();
        git_dirs
            .into_iter()
            .map(|git_dir| {
                let pointer = paths::read_regular_text(&git_dir.join("gitdir")).map(|text| text.trim().to_string()).filter(|text| !text.is_empty());
                let tree = pointer.map(|pointer| self.resolve(&git_dir, &pointer)).and_then(|file| file.parent().map(Path::to_path_buf));
                match tree {
                    Some(tree) if tree.is_dir() => (git_dir, tree),
                    _ => (git_dir.clone(), git_dir),
                }
            })
            .collect()
    }

    /// Find a repository's main working tree: the common directory itself for a bare one, or None
    /// when the repository does not record where it is.
    fn main_worktree(&self, common_dir: &Path, entries: &[Entry]) -> Option<PathBuf> {
        if common_dir.file_name().is_some_and(|name| name == ".git") {
            return common_dir.parent().map(Path::to_path_buf);
        }
        if let Some(configured) = last(entries, "core.worktree") {
            return Some(self.resolve(common_dir, &configured));
        }
        let bare = last(entries, "core.bare")?;
        matches!(bare.to_lowercase().as_str(), "true" | "yes" | "on" | "1").then(|| common_dir.to_path_buf())
    }

    /// Find the submodules one view holds: the git directories under its `modules/` and those its
    /// tree's `.gitmodules` and index place, recording each tree found.
    fn submodules_of(&mut self, git_dir: Option<&Path>, tree: &Path) -> Vec<(PathBuf, Option<PathBuf>)> {
        let mut found: Vec<(PathBuf, Option<PathBuf>)> = match git_dir {
            Some(git_dir) => self.module_git_dirs(git_dir).into_iter().map(|module| (module, None)).collect(),
            None => Vec::new(),
        };
        if Some(tree) != git_dir && tree.is_dir() {
            for (module, module_tree) in self.submodule_pointers(tree) {
                self.work_trees.entry(module.clone()).or_insert_with(|| module_tree.clone());
                found.push((module, Some(module_tree)));
            }
            for path in self.gitlinks(tree) {
                let module_tree = tree.join(path);
                let module = if module_tree.is_dir() { git_dir_of(&module_tree, self.environ) } else { None };
                if let Some(module) = module {
                    self.work_trees.entry(module.clone()).or_insert_with(|| module_tree.clone());
                    found.push((module, Some(module_tree)));
                }
            }
        }
        found
    }

    /// Walk the git directories of submodules stored under a git directory's `modules/`,
    /// shallowest first.
    fn module_git_dirs(&mut self, git_dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut pending = vec![git_dir.join("modules")];
        while !pending.is_empty() && found.len() < MAX_GIT_DIRS {
            let here = pending.remove(0);
            if !here.is_dir() {
                continue;
            }
            let mut children: Vec<PathBuf> = match fs::read_dir(&here) {
                Ok(listed) => listed.flatten().map(|entry| entry.path()).collect(),
                Err(error) => {
                    self.unexamined.push(format!("{}: {}", here.display(), paths::error_name(&error)));
                    continue;
                }
            };
            children.sort();
            for child in children {
                if !child.is_dir() || paths::is_symlink(&child) {
                    continue;
                }
                if child.join("HEAD").exists() && child.join("config").exists() {
                    pending.push(child.join("modules"));
                    found.push(child);
                } else {
                    pending.push(child);
                }
            }
        }
        if !pending.is_empty() {
            self.unexamined.push(format!("{}: more than {MAX_GIT_DIRS} submodules", git_dir.join("modules").display()));
        }
        found
    }

    /// Find the git directory of each submodule `.gitmodules` places, with the tree it serves.
    fn submodule_pointers(&mut self, tree: &Path) -> Vec<(PathBuf, PathBuf)> {
        let listed = tree.join(".gitmodules");
        let (pairs, why) = self.list_config_file(&listed);
        if let Some(why) = why {
            self.unexamined.push(format!("{}: {why}", listed.display()));
        }
        let mut found = Vec::new();
        for (key, value) in pairs {
            let lowered = key.to_lowercase();
            let Some(value) = value.filter(|v| !v.is_empty() && lowered.starts_with("submodule.") && lowered.ends_with(".path")) else { continue };
            let dot_git = self.resolve(tree, &value).join(".git");
            if dot_git.is_dir() && !paths::is_symlink(&dot_git) {
                let parent = dot_git.parent().unwrap_or(tree).to_path_buf();
                found.push((dot_git, parent));
            } else if paths::lexists(&dot_git) {
                if let Some(target) = pointer(&dot_git, self.environ) {
                    found.push((target, dot_git.parent().unwrap_or(tree).to_path_buf()));
                }
            }
        }
        found
    }

    /// Ask git which paths its index records as submodules, relative to the tree.
    fn gitlinks(&self, tree: &Path) -> Vec<String> {
        let listed = self.git.answer(&Call::repository(tree, &["ls-files", "--stage", "-z"]));
        let Some(listed) = listed.succeeded() else { return Vec::new() };
        listed
            .split(|byte| *byte == 0)
            .filter_map(|record| {
                let tab = record.iter().position(|byte| *byte == b'\t')?;
                record[..tab].starts_with(b"160000 ").then(|| String::from_utf8_lossy(&record[tab + 1..]).into_owned())
            })
            .collect()
    }
}

/// Split `git config --list -z` output into keys and values, None for a bare key.
pub fn split_entries(listed: &[u8]) -> Vec<(String, Option<String>)> {
    String::from_utf8_lossy(listed)
        .split('\0')
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| match chunk.split_once('\n') {
            Some((key, value)) => (key.to_string(), Some(value.to_string())),
            None => (chunk.to_string(), None),
        })
        .collect()
}

fn is_include(key: &str) -> bool {
    let lowered = key.to_lowercase();
    lowered == "include.path" || (lowered.starts_with("includeif.") && lowered.ends_with(".path"))
}

fn last(entries: &[Entry], key: &str) -> Option<String> {
    entries.iter().rev().find(|entry| entry.key.to_lowercase() == key && entry.value.as_deref().is_some_and(|v| !v.is_empty()))
        .and_then(|entry| entry.value.clone())
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() { paths::normalize(path) } else { paths::normalize(&std::env::current_dir().unwrap_or_default().join(path)) }
}

/// Follow a `gitdir:` pointer file. Returns the directory it names, or None.
fn pointer(dot_git: &Path, environ: &Environment) -> Option<PathBuf> {
    let text = paths::read_regular_text(dot_git)?;
    let target = text.strip_prefix("gitdir:")?.trim();
    (!target.is_empty()).then(|| paths::resolve(dot_git.parent().unwrap_or(Path::new("")), target, environ))
}

/// Find the git directory of a working tree.
fn git_dir_of(tree: &Path, environ: &Environment) -> Option<PathBuf> {
    let dot_git = tree.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    if paths::lexists(&dot_git) { pointer(&dot_git, environ) } else { None }
}

/// Find where a git directory keeps what its worktrees share.
pub fn common_dir_of(git_dir: &Path, environ: &Environment) -> PathBuf {
    match paths::read_regular_text(&git_dir.join("commondir")).map(|text| text.trim().to_string()).filter(|text| !text.is_empty()) {
        Some(text) => paths::resolve(git_dir, &text, environ),
        None => git_dir.to_path_buf(),
    }
}

/// Tell whether a path is a git directory: it holds a HEAD git accepts, and an objects and a refs
/// directory.
pub fn is_git_directory(path: &Path) -> bool {
    let common = if paths::lexists(&path.join("commondir")) { followed(&path.join("commondir")) } else { Some(path.to_path_buf()) };
    common.is_some_and(|common| valid_head(&path.join("HEAD")) && common.join("objects").is_dir() && common.join("refs").is_dir())
}

fn followed(pointer: &Path) -> Option<PathBuf> {
    let text = paths::read_regular_text(pointer)?;
    let value = text.trim();
    (!value.is_empty()).then(|| paths::real_path(&pointer.parent().unwrap_or(Path::new("")).join(value)))
}

fn valid_head(head: &Path) -> bool {
    if paths::is_symlink(head) {
        return fs::read_link(head).is_ok_and(|target| target.to_string_lossy().starts_with("refs/"));
    }
    let Some(text) = paths::read_regular_text(head) else { return false };
    if let Some(rest) = text.strip_prefix("ref:") {
        return rest.trim_start().starts_with("refs/");
    }
    let word = text.split_whitespace().next().unwrap_or("");
    matches!(word.len(), 40 | 64) && word.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
