//! Read a document on standard input and write it back. Takes the document's name (`scan`,
//! `govern`…, `progress`, `ask`, or `any`) and the style (`line`, `indented`, `compact` or
//! `line-keeping-non-ascii`).

use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

use saw_model::document::Document;
use saw_model::documents::{audit, auth_status, capabilities, doctor, fix, govern, guard_drift, hook_status, scan,
                           watch_status};
use saw_model::events::{ask, progress};
use saw_model::json::{self, Style};

fn rewrite<T: DeserializeOwned + Serialize>(text: &str, style: Style) -> Result<String, serde_json::Error> {
    json::to_string(&serde_json::from_str::<T>(text)?, style)
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let style = match args.get(1).map(String::as_str) {
        Some("indented") => Style::INDENTED,
        Some("compact") => Style::COMPACT,
        Some("line-keeping-non-ascii") => Style::LINE_KEEPING_NON_ASCII,
        _ => Style::LINE,
    };
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).map_err(|error| error.to_string())?;
    let written = match args.first().map(String::as_str) {
        Some("scan") => rewrite::<scan::ScanDocument>(&text, style),
        Some("fix") => rewrite::<fix::FixDocument>(&text, style),
        Some("doctor") => rewrite::<doctor::DoctorDocument>(&text, style),
        Some("auth-status") => rewrite::<auth_status::AuthStatusDocument>(&text, style),
        Some("guard-drift") => rewrite::<guard_drift::GuardDriftDocument>(&text, style),
        Some("audit") => rewrite::<audit::AuditDocument>(&text, style),
        Some("hook-status") => rewrite::<hook_status::HookStatusDocument>(&text, style),
        Some("capabilities") => rewrite::<capabilities::CapabilitiesDocument>(&text, style),
        Some("govern") => rewrite::<govern::GovernDocument>(&text, style),
        Some("watch-status") => rewrite::<watch_status::WatchStatusDocument>(&text, style),
        Some("progress") => rewrite::<progress::ProgressEvent>(&text, style),
        Some("ask") => rewrite::<ask::AskEvent>(&text, style),
        _ => rewrite::<Document>(&text, style),
    };
    let out = written.map_err(|error| error.to_string())?;
    io::stdout().write_all(out.as_bytes()).map_err(|error| error.to_string())
}
