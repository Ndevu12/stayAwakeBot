//! Run a scratch scenario in a temporary folder and print the folder names for purposes. Used to
//! compare with `main`.

use std::path::PathBuf;

use saw_platform::sandbox::scratch::{Scratch, slug};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("slugs") {
        for purpose in &args[1..] {
            println!("{}", slug(purpose));
        }
        return Ok(());
    }
    let temp = PathBuf::from(&args[0]);
    let keep = args.get(1).map(String::as_str) == Some("keep");
    let run = Scratch::new(temp);
    run.new_dir("git outside any repository", None).map_err(|e| e.to_string())?;
    let file = run.new_file("a key", ".pem", 0o600).map_err(|e| e.to_string())?;
    if keep {
        run.kept_dir("Reports for you").map_err(|e| e.to_string())?;
    }
    println!("made");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    println!("{}", run.release_path(&file));
    println!("{}", run.release().len());
    Ok(())
}
