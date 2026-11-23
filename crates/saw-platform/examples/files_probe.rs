//! Print a folder's walk, or a file's overlapping windows, as JSON. Used to compare with `main`.

use std::fs::File;
use std::path::Path;

use saw_platform::files;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let answer = match args.first().map(String::as_str) {
        Some("walk") => {
            let leave_out: Vec<String> = args[2..].to_vec();
            let found = files::walk(Path::new(&args[1]), Path::new(&args[1]), &|name| leave_out.iter().any(|l| l == name));
            let shown: Vec<String> = found.files.iter().map(|p| p.display().to_string()).collect();
            serde_json::json!({"files": shown, "pruned": found.pruned, "unwalkable": found.unwalkable.len()})
        }
        Some("windows") => {
            let path = Path::new(&args[1]);
            let window: usize = args[2].parse().map_err(|_| "window")?;
            let overlap: usize = args[3].parse().map_err(|_| "overlap")?;
            let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
            let mut file = File::open(path).map_err(|e| e.to_string())?;
            let found = files::windows(&mut file, size, window, overlap).map_err(|e| e.to_string())?;
            let shown: Vec<serde_json::Value> = found
                .iter()
                .map(|w| serde_json::json!([w.lines_before, String::from_utf8_lossy(&w.bytes)]))
                .collect();
            serde_json::Value::Array(shown)
        }
        _ => return Err("walk <root> [left-out…] | windows <file> <window> <overlap>".into()),
    };
    println!("{answer}");
    Ok(())
}
