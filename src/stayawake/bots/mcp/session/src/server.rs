use std::path::PathBuf;
use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use rmcp::transport::stdio;
use rmcp::{tool, tool_handler, tool_router, ServiceExt, ServerHandler};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

use crate::worker::{Answer, Worker};

#[derive(Debug, Deserialize, JsonSchema)]
struct FolderArgs {
    /// The folder to scan.
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FilesArgs {
    /// The files to scan.
    paths: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct VerdictArgs {
    /// The file or folder to report.
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AuditArgs {
    /// Run the audit again. Leave this unset to keep the audit this session already ran.
    #[serde(default)]
    again: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GovernArgs {
    /// The repository the command acts on — the open folder.
    repo: String,
    /// Which tool the command is: "git" or "gh".
    tool: String,
    /// The command's arguments, without the program name — e.g. ["pull"] or ["pr","checkout","12"].
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Clone)]
struct Saw {
    worker: Arc<Mutex<Worker>>,
}

impl Saw {
    fn new(python: PathBuf) -> Self {
        Self { worker: Arc::new(Mutex::new(Worker::python(python))) }
    }
}

fn unanswered() -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text("not verified")])
}

fn answered(answer: Answer) -> CallToolResult {
    let mut blocks = vec![ContentBlock::text(answer.verdict.clone())];
    if let Some(document) = answer.document {
        blocks.push(ContentBlock::text(document.to_string()));
    }
    if answer.verdict == "not verified" && blocks.len() == 1 {
        CallToolResult::error(blocks)
    } else {
        CallToolResult::success(blocks)
    }
}

#[tool_router]
impl Saw {
    #[tool(description = "Scan a folder and report the verdict. The document is the same one saw scan --json prints. This does not change files.")]
    async fn saw_scan_folder(&self, Parameters(args): Parameters<FolderArgs>) -> CallToolResult {
        if args.path.is_empty() {
            return unanswered();
        }
        let mut worker = self.worker.lock().await;
        answered(worker.ask("scan", json!({"path": args.path})).await)
    }

    #[tool(description = "Scan these files and report the verdict. The document is the same one saw scan --json prints. This does not change files.")]
    async fn saw_scan_files(&self, Parameters(args): Parameters<FilesArgs>) -> CallToolResult {
        if args.paths.is_empty() || args.paths.iter().any(|path| path.is_empty()) {
            return unanswered();
        }
        let mut worker = self.worker.lock().await;
        answered(worker.ask("scan_files", json!({"paths": args.paths})).await)
    }

    #[tool(description = "Report the verdict for a file or folder. A path that has not changed keeps the verdict already reported. This does not change files.")]
    async fn saw_verdict(&self, Parameters(args): Parameters<VerdictArgs>) -> CallToolResult {
        if args.path.is_empty() {
            return unanswered();
        }
        let mut worker = self.worker.lock().await;
        answered(worker.ask("verdict", json!({"path": args.path})).await)
    }

    #[tool(description = "Report this machine's audit. The first answer stands until asked again. The document is the same one saw audit --json prints. This does not change files.")]
    async fn saw_audit_summary(&self, Parameters(args): Parameters<AuditArgs>) -> CallToolResult {
        let mut worker = self.worker.lock().await;
        answered(worker.ask("audit", json!({"again": args.again})).await)
    }
    #[tool(description = "Get saw's check for an incoming git or GitHub update that brings files in, before it reaches the open folder, when saw is not already in front of your git. Give the repository, the tool (git or gh) and the command's arguments; saw checks what would arrive in a holding area it owns and applies it only on a clean or residue verdict, otherwise the open folder is unchanged. Where a stand-in already governs your git, run it the normal way instead. Wait for the result.")]
    async fn saw_govern_update(&self, Parameters(args): Parameters<GovernArgs>) -> CallToolResult {
        if args.repo.is_empty() || !(args.tool == "git" || args.tool == "gh") {
            return unanswered();
        }
        let mut worker = self.worker.lock().await;
        answered(worker.ask("govern", json!({"repo": args.repo, "tool": args.tool, "args": args.args})).await)
    }
}

#[tool_handler(
    name = "saw",
    version = "1",
    instructions = "Ask the person before you install, build, or run anything in this folder. When the verdict is infected, suspicious, residue, or not verified, stop and ask the person. When an audit says unsafe or incomplete, stop and ask the person. When you bring files in — pull, fetch, checkout, switch, merge, rebase, submodule update, or a GitHub command that lands files — let saw check the update before it reaches the folder: run git the normal way, wait for the verdict, and act only when it is clean or residue. Never reach around the check to a raw git, and tell the person. A held update did not land and the folder is unchanged. Where saw is not already in front of your git, call saw_govern_update to get the same check instead of running the command yourself."
)]
impl ServerHandler for Saw {}

pub async fn run(python: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let service = Saw::new(python).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
