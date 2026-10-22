use std::fs;
use std::process::Stdio;

use rmcp::model::CallToolRequestParams;
use rmcp::transport::TokioChildProcess;
use rmcp::ServiceExt;
use serde_json::json;
use tokio::process::Command;

fn fake_worker(root: &std::path::Path) {
    let module = root.join("stayawake/bots/mcp");
    fs::create_dir_all(&module).unwrap();
    for parent in ["stayawake", "stayawake/bots", "stayawake/bots/mcp"] {
        fs::write(root.join(parent).join("__init__.py"), "").unwrap();
    }
    fs::write(module.join("worker.py"), concat!(
        "import json, sys\n",
        "while True:\n",
        "    line = sys.stdin.readline()\n",
        "    if not line:\n",
        "        break\n",
        "    req = json.loads(line)\n",
        "    body = {'verdict': 'clean', 'document': {'schema_version': 1}}\n",
        "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': body}) + '\\n')\n",
        "    sys.stdout.flush()\n",
    )).unwrap();
}

#[tokio::test]
async fn an_editor_hears_the_verdict_first() {
    let root = std::env::temp_dir().join(format!("saw-mcp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fake_worker(&root);
    let mut command = Command::new(env!("CARGO_BIN_EXE_saw-mcp"));
    command.arg("--python").arg("python3")
        .env("PYTHONPATH", &root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let client = ().serve(TokioChildProcess::new(command).expect("session"))
        .await
        .expect("handshake");
    let tools = client.list_all_tools().await.expect("tools");
    let names: Vec<String> = tools.into_iter().map(|tool| tool.name.to_string()).collect();
    for name in ["saw_scan_folder", "saw_scan_files", "saw_verdict", "saw_audit_summary"] {
        assert!(names.iter().any(|found| found == name), "{names:?}");
    }

    let empty = json!({"path": ""}).as_object().unwrap().clone();
    let missing = client.call_tool(
        CallToolRequestParams::new("saw_scan_folder").with_arguments(empty),
    ).await.expect("empty path");
    assert_eq!(missing.content[0].as_text().unwrap().text, "not verified");
    assert_eq!(missing.is_error, Some(true));

    let folder = json!({"path": "/any"}).as_object().unwrap().clone();
    let answered = client.call_tool(
        CallToolRequestParams::new("saw_scan_folder").with_arguments(folder),
    ).await.expect("scan");
    assert_eq!(answered.content[0].as_text().unwrap().text, "clean");
    assert_ne!(answered.is_error, Some(true));
    let _ = client.cancel().await;
}
