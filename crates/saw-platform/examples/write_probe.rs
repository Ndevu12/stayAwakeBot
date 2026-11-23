//! Write bytes to a file as `saw-platform` writes saw's own files, and print the outcome. Used to
//! compare with `main`.

use std::io::Write;
use std::path::Path;

use saw_platform::sandbox::write::{self, AtALink, Mode, WriteError};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path, text, mode, at_a_link] = args.as_slice() else { return Err("path text mode link".into()) };
    let mode = if mode == "plain" { Mode::AsAPlainWrite } else { Mode::Set(u32::from_str_radix(mode, 8).map_err(|e| e.to_string())?) };
    let at_a_link = match at_a_link.as_str() {
        "refuse" => AtALink::Refuse,
        "follow" => AtALink::FollowTrusted,
        _ => AtALink::Replace,
    };
    let outcome = match write::write_with(Path::new(path), mode, at_a_link, |file| file.write_all(text.as_bytes())) {
        Ok(()) => "written",
        Err(WriteError::Redirected(_)) => "redirected",
        Err(_) => "failed",
    };
    println!("{outcome}");
    Ok(())
}
