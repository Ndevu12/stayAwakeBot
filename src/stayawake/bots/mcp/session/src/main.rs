use std::path::PathBuf;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut python = None;
    while let Some(arg) = args.next() {
        if arg == "--python" {
            python = args.next();
        }
    }
    let Some(python) = python.filter(|path| !path.is_empty()) else {
        eprintln!("saw mcp could not start. The answer is not verified.");
        return ExitCode::from(2);
    };
    match saw_mcp::run(PathBuf::from(python)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("saw mcp could not start. The answer is not verified.");
            ExitCode::from(2)
        }
    }
}
