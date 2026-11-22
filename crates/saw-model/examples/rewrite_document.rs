//! Read a document on standard input and write it back. Takes the contract to read it as (`scan`,
//! or `any`) and the style (`line`, `indented` or `compact`).

use std::io::{self, Read, Write};

use saw_model::document::Document;
use saw_model::json::{self, Style};
use saw_model::scan::ScanDocument;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let style = match args.get(1).map(String::as_str) {
        Some("indented") => Style::INDENTED,
        Some("compact") => Style::COMPACT,
        _ => Style::LINE,
    };
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).expect("standard input reads");
    let written = match args.first().map(String::as_str) {
        Some("scan") => serde_json::from_str::<ScanDocument>(&text).and_then(|doc| json::to_string(&doc, style)),
        _ => serde_json::from_str::<Document>(&text).and_then(|doc| json::to_string(&doc, style)),
    };
    let out = written.map_err(|error| error.to_string())?;
    io::stdout().write_all(out.as_bytes()).map_err(|error| error.to_string())
}
