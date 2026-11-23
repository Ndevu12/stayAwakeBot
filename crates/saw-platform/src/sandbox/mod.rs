//! The places saw keeps its own things: where they are, the run's temporary area, and how saw
//! writes there.

pub mod paths;
pub mod scratch;
pub mod stores;
pub mod write;

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::env::Environment;
use crate::sandbox::scratch::Scratch;
use crate::sandbox::stores::Stores;

/// saw's own places for one environment: its stores and this run's temporary area.
pub struct Sandbox {
    env: Environment,
    scratch: Scratch,
}

impl Sandbox {
    /// Make the sandbox for an environment. Takes the environment. Returns the sandbox.
    pub fn new(env: Environment) -> Sandbox {
        let scratch = Scratch::new(scratch::temp_folder(&env));
        Sandbox { env, scratch }
    }

    /// Return the environment.
    pub fn env(&self) -> &Environment {
        &self.env
    }

    /// Return where each store is.
    pub fn stores(&self) -> Stores<'_> {
        Stores::new(&self.env)
    }

    /// Return this run's temporary area.
    pub fn scratch(&self) -> &Scratch {
        &self.scratch
    }
}

/// A sandbox on a private root of its own, removed when dropped.
pub struct Isolated {
    root: PathBuf,
    sandbox: Sandbox,
}

impl Isolated {
    /// Make an isolated sandbox with its own home, configuration, cache, state and temporary
    /// folders. Takes a name for it. Returns it, or why it was not made.
    pub fn new(name: &str) -> io::Result<Isolated> {
        let parent = std::env::temp_dir();
        let made = scratch::make_unique_folder(&parent, &format!("saw-sandbox-{}-", scratch::slug(name)))?;
        let root = fs::canonicalize(made)?;
        let home = root.join("home");
        let mut variables = BTreeMap::new();
        for (key, folder) in [
            ("HOME", home.clone()),
            ("XDG_CONFIG_HOME", home.join(".config")),
            ("XDG_CACHE_HOME", home.join(".cache")),
            ("XDG_STATE_HOME", home.join(".local").join("state")),
            ("TMPDIR", root.join("tmp")),
        ] {
            fs::create_dir_all(&folder)?;
            variables.insert(key.to_string(), folder.display().to_string());
        }
        if let Ok(path) = std::env::var("PATH") {
            variables.insert("PATH".to_string(), path);
        }
        Ok(Isolated { sandbox: Sandbox::new(Environment::from_variables(variables)), root })
    }

    /// Return the private root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the sandbox on this root.
    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    /// Return a path under the root, making the folders above it. Takes the relative path.
    /// Returns the path, or why its folders were not made.
    pub fn path(&self, relative: &str) -> io::Result<PathBuf> {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(path)
    }

    /// Make a folder under the root. Takes the relative path. Returns the folder, or why it was
    /// not made.
    pub fn folder(&self, relative: &str) -> io::Result<PathBuf> {
        let path = self.root.join(relative);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Write a file under the root. Takes the relative path and its bytes. Returns the file, or
    /// why it was not written.
    pub fn file(&self, relative: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let path = self.path(relative)?;
        fs::write(&path, bytes)?;
        Ok(path)
    }

    /// Make a named pipe under the root. Takes the relative path. Returns the pipe, or why it was
    /// not made.
    #[cfg(unix)]
    #[allow(unsafe_code)]
    pub fn pipe(&self, relative: &str) -> io::Result<PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        let path = self.path(relative)?;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("a NUL in the path"))?;
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(path)
    }
}

impl Drop for Isolated {
    fn drop(&mut self) {
        let _ = self.sandbox.scratch.release();
        let _ = scratch::remove_tree(&self.root);
    }
}
