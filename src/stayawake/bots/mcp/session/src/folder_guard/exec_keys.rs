//! The configuration keys whose value git executes, read from `lib/data/git_exec_keys.json`, the
//! file saw's Python reads too.

use serde::Deserialize;
use std::sync::OnceLock;

const KEYS_FILE: &str = include_str!("../../../../../lib/data/git_exec_keys.json");

/// How a listed key's value is run, as far as keeping it from running depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runs {
    /// The value names the directory hooks run from.
    HooksDirectory,
    /// The value switches a command-running transport on.
    EnablesTransport,
    /// A boolean value is a toggle, anything else a command line.
    UnlessBoolean,
    /// Any other way of running the value.
    Other,
}

/// How a folder's own value of a key is kept from running.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Override {
    /// The other key set to `value` in place of this one. `{subsection}` stands for this key's.
    pub setting: Option<String>,
    /// The environment variable set to `value` in place of this key.
    pub environment: Option<String>,
    /// The value `setting` or `environment` is set to.
    #[serde(default)]
    pub value: String,
    /// The key whose empty value clears the list this key adds to.
    pub reset: Option<String>,
    /// Nothing keeps this key from running.
    #[serde(default)]
    pub refuse: bool,
}

/// One entry of the key list.
#[derive(Debug, Clone)]
pub struct ExecKey {
    /// The key in git's listing, lowercased. `*` matches any text.
    pub key: String,
    /// How its value is run.
    pub runs: Runs,
    /// How a folder's own value is kept from running.
    pub replaced_by: Override,
}

impl ExecKey {
    /// Say whether a listed key is this entry. Takes the key from git's listing.
    pub fn matches(&self, key: &str) -> bool {
        wildcard_matches(self.key.as_bytes(), key.to_lowercase().as_bytes())
    }
}

#[derive(Deserialize)]
struct KeysFile {
    keys: Vec<ListedKey>,
    always_set: Vec<AlwaysSet>,
}

#[derive(Deserialize)]
struct ListedKey {
    key: String,
    #[serde(default)]
    runs: Option<String>,
    #[serde(default, rename = "override")]
    replaced_by: Override,
}

#[derive(Deserialize)]
struct AlwaysSet {
    key: String,
    value: String,
}

struct Loaded {
    keys: Vec<ExecKey>,
    always_set: Vec<(String, String)>,
}

fn loaded() -> &'static Loaded {
    static LOADED: OnceLock<Loaded> = OnceLock::new();
    LOADED.get_or_init(|| {
        let file: KeysFile = serde_json::from_str(KEYS_FILE).expect("saw's git exec keys");
        let keys = file
            .keys
            .into_iter()
            .map(|listed| ExecKey {
                runs: match listed.runs.as_deref() {
                    Some("hooks-directory") => Runs::HooksDirectory,
                    Some("enables-transport") => Runs::EnablesTransport,
                    Some("unless-boolean") => Runs::UnlessBoolean,
                    _ => Runs::Other,
                },
                key: listed.key,
                replaced_by: listed.replaced_by,
            })
            .collect();
        Loaded { keys, always_set: file.always_set.into_iter().map(|entry| (entry.key, entry.value)).collect() }
    })
}

/// Return the listed keys in file order.
pub fn exec_keys() -> &'static [ExecKey] {
    &loaded().keys
}

/// Return the settings every command saw does not check runs with, each key with its value.
pub fn always_set() -> &'static [(String, String)] {
    &loaded().always_set
}

/// Look up a key from git's listing. Returns its entry, or None for a key git does not execute.
pub fn rule_for(key: &str) -> Option<&'static ExecKey> {
    exec_keys().iter().find(|rule| rule.matches(key))
}

/// Take a key from git's listing. Returns its subsection with its case kept, or None.
pub fn subsection(key: &str) -> Option<&str> {
    let (first, last) = (key.find('.')?, key.rfind('.')?);
    (first < last).then(|| &key[first + 1..last])
}

/// Match a pattern whose `*` stands for any text against a text, byte by byte.
fn wildcard_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut resume: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            resume = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((star, from)) = resume {
            p = star + 1;
            t = from + 1;
            resume = Some((star, from + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}
