//! Print, for each repository path given on standard input, whether every git command there
//! would wait on its configuration. Used to compare with `main`.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use saw_platform::programs::git::{Folders, Git, waiting};

fn main() -> Result<(), String> {
    let mut lines = io::stdin().lock().lines();
    let folders_line = lines.next().ok_or("no folders")?.map_err(|e| e.to_string())?;
    let (hooks, neutral) = folders_line.split_once('\t').ok_or("folders are hooks<TAB>neutral")?;
    let inherited: BTreeMap<String, String> = std::env::vars().collect();
    let git = Git { program: PathBuf::from("git"), folders: Folders { empty_hooks: hooks.into(), neutral: neutral.into() }, inherited };
    let mut out = io::stdout();
    for line in lines {
        let path = line.map_err(|e| e.to_string())?;
        writeln!(out, "{}", waiting::config_waits(&git, Path::new(&path))).map_err(|e| e.to_string())?;
    }
    Ok(())
}
