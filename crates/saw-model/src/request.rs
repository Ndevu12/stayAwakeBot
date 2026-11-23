//! The request a surface sends the engine.

use std::path::PathBuf;
use std::time::Duration;

/// What to judge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// A folder or file on this machine.
    Path(PathBuf),
    /// A repository on GitHub, named `owner/name`.
    Remote(String),
    /// What a push would publish: each ref, from the commit the remote has to the one pushed.
    Push { repository: PathBuf, refs: Vec<PushedRef> },
    /// The files an incoming update brought, in the place saw holds them.
    Arrived { root: PathBuf, paths: Vec<String> },
}

/// One ref a push moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedRef {
    pub name: String,
    pub from: Option<String>,
    pub to: String,
}

/// How deep to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Depth {
    /// Also read what the default scan leaves out.
    pub deep: bool,
    /// Also read what the repository stores on other branches, tags and earlier commits.
    pub history: bool,
}

impl Depth {
    /// The default depth.
    pub const DEFAULT: Depth = Depth { deep: false, history: false };

    /// Combine two depths. Takes the other depth. Returns a depth that reads everything either reads.
    pub fn raised(self, other: Depth) -> Depth {
        Depth { deep: self.deep || other.deep, history: self.history || other.history }
    }
}

/// Why a surface asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Scan,
    Hook,
    Push,
    Fix,
    Govern,
}

/// One request to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub subject: Subject,
    pub depth: Depth,
    /// How long the judgement may take, or `None` for no limit.
    pub budget: Option<Duration>,
    pub purpose: Purpose,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raising_a_depth_never_lowers_it() {
        let all = [Depth::DEFAULT, Depth { deep: true, history: false }, Depth { deep: false, history: true },
                   Depth { deep: true, history: true }];
        for a in all {
            for b in all {
                let raised = a.raised(b);
                assert!(raised.deep >= a.deep && raised.deep >= b.deep);
                assert!(raised.history >= a.history && raised.history >= b.history);
                assert_eq!(raised, b.raised(a));
            }
        }
    }
}
