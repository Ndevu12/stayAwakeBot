//! The questions `saw fix --ask=jsonl` asks, and the answers it reads back.

use serde::{Deserialize, Serialize};

/// The schema version the questions are written in.
pub const ASK_SCHEMA_VERSION: u32 = 1;

/// One question line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "lowercase", deny_unknown_fields)]
pub enum AskEvent {
    Ask { schema_version: u32, id: String, question: Question },
}

/// What saw asks about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Question {
    /// A file saw is unsure about.
    File {
        path: String,
        category: String,
        signature_id: String,
        description: String,
        confirmed: bool,
        introduced_by: String,
        arrived_with_removed: Vec<String>,
        origin_unread: bool,
        supply: bool,
        sha256: String,
        withheld: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        restore: Option<Restore>,
    },
    /// A commit that brought files in alongside what is being removed.
    Delivery {
        commit: String,
        known_as: Vec<String>,
        date: String,
        subject: String,
        recorded: bool,
        removing: Vec<String>,
        files: Vec<ArrivedFile>,
        changed: Vec<String>,
    },
    /// A package the project declares.
    Package { name: String, versions: Vec<String>, manifests: Vec<Manifest> },
}

/// An earlier version a file can be put back to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restore {
    pub commit: String,
    pub blob: String,
}

/// A file a delivery brought.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArrivedFile {
    pub path: String,
    pub blob: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub named_by: Option<u64>,
}

/// A manifest that declares a package, and the change saw proposes there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed: Option<String>,
}

/// One answer line a caller writes back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Answer {
    pub id: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_with_fields_saw_does_not_read_is_still_read() {
        let answer: Answer =
            serde_json::from_str(r#"{"id": "q1", "action": "take-out", "chosen": ["a.js"], "note": "mine"}"#).unwrap();
        assert_eq!((answer.action.as_str(), answer.chosen), ("take-out", Some(vec!["a.js".to_string()])));
    }
}
