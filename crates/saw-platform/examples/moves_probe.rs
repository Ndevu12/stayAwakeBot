//! Run one of saw-platform's mode, folder, rename, move or copy operations and print the outcome.
//! Used to compare with `main`.

use std::ffi::OsStr;
use std::path::Path;

use saw_platform::write::{self, WriteError};

fn outcome(result: Result<String, WriteError>) -> String {
    match result {
        Ok(detail) => format!("done {detail}").trim().to_string(),
        Err(WriteError::Redirected(_)) => "redirected".into(),
        Err(WriteError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => "exists".into(),
        Err(_) => "failed".into(),
    }
}

fn main() -> Result<(), String> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let p = |i: usize| Path::new(&a[i]);
    let answer = match a[0].as_str() {
        "set_mode" => outcome(write::set_mode(p(1), u32::from_str_radix(&a[2], 8).map_err(|e| e.to_string())?).map(|_| String::new())),
        "new_folder" => outcome(write::new_folder(p(1), &a[2], 0o755, 1000).map(|made| made.file_name().unwrap().to_string_lossy().into_owned())),
        "rename_in" => outcome(write::rename_in(p(1), &a[2], &a[3]).map(|_| String::new())),
        "rename_beside" => outcome(write::rename_beside(p(1), &a[2], &a[3]).map(|_| String::new())),
        "move_into" => outcome(write::move_into(p(1), p(2), &a[3]).map(|_| String::new())),
        "copy" => {
            let origin = write::open_folder(p(1), false, 0o777).map_err(|e| e.to_string())?;
            let destination = write::open_folder(p(3), false, 0o777).map_err(|e| e.to_string())?;
            outcome(origin.copy_into(OsStr::new(&a[2]), &destination, OsStr::new(&a[4])).map(|folder| folder.to_string()).map_err(WriteError::Io))
        }
        _ => return Err("unknown operation".into()),
    };
    println!("{answer}");
    Ok(())
}
