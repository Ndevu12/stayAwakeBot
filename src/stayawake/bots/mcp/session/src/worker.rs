use std::path::PathBuf;
use std::process::Stdio;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};

pub struct Answer {
    pub verdict: String,
    pub document: Option<Value>,
}

impl Answer {
    fn missing() -> Self {
        Self { verdict: "not verified".into(), document: None }
    }
}

pub struct Worker {
    program: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<tokio::process::ChildStdout>>,
    next_id: u64,
}

impl Worker {
    pub fn python(python: PathBuf) -> Self {
        Self::launching(python, vec!["-m".into(), "stayawake.bots.mcp.worker".into()])
    }

    pub(crate) fn launching(program: PathBuf, args: Vec<String>) -> Self {
        Self { program, args, env: Vec::new(), child: None, stdin: None, stdout: None, next_id: 1 }
    }

    #[cfg(test)]
    pub(crate) fn with_env(mut self, name: &str, value: impl Into<String>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }

    async fn stop(&mut self) {
        self.stdin.take();
        self.stdout.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
    }

    async fn start(&mut self) -> bool {
        self.stop().await;
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        for (name, value) in &self.env {
            command.env(name, value);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let Ok(mut child) = command.spawn() else {
            return false;
        };
        self.stdin = child.stdin.take();
        self.stdout = child.stdout.take().map(BufReader::new);
        let ready = self.stdin.is_some() && self.stdout.is_some();
        self.child = Some(child);
        ready
    }

    async fn round(&mut self, method: &str, extra: &Value) -> Option<Answer> {
        let id = self.next_id;
        self.next_id += 1;
        let mut request = serde_json::Map::new();
        request.insert("jsonrpc".into(), json!("2.0"));
        request.insert("id".into(), json!(id));
        request.insert("method".into(), json!(method));
        request.insert("params".into(), extra.clone());
        let mut line = serde_json::to_vec(&request).ok()?;
        line.push(b'\n');
        self.stdin.as_mut()?.write_all(&line).await.ok()?;
        self.stdin.as_mut()?.flush().await.ok()?;
        let mut buf = String::new();
        if self.stdout.as_mut()?.read_line(&mut buf).await.ok()? == 0 {
            return None;
        }
        let value: Value = serde_json::from_str(&buf).ok()?;
        if value.get("id") != Some(&json!(id)) {
            return None;
        }
        if let Some(error) = value.get("error") {
            let verdict = error.get("message").and_then(Value::as_str).unwrap_or("not verified");
            if verdict.is_empty() {
                return None;
            }
            return Some(Answer { verdict: verdict.to_string(), document: None });
        }
        let result = value.get("result")?;
        let verdict = result.get("verdict")?.as_str()?.to_string();
        if verdict.is_empty() {
            return None;
        }
        let document = match result.get("document") {
            Some(doc) if doc.is_object() => Some(doc.clone()),
            Some(_) => return None,
            None => None,
        };
        Some(Answer { verdict, document })
    }

    pub async fn ask(&mut self, method: &str, extra: Value) -> Answer {
        if self.child.is_none() && !self.start().await {
            return Answer::missing();
        }
        if let Some(answer) = self.round(method, &extra).await {
            return answer;
        }
        if !self.start().await {
            return Answer::missing();
        }
        self.round(method, &extra).await.unwrap_or_else(Answer::missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn python() -> Option<PathBuf> {
        ["python3", "python"].into_iter().map(PathBuf::from).find(|candidate| {
            std::process::Command::new(candidate).arg("-c").arg("import sys").output().is_ok()
        })
    }

    #[tokio::test]
    async fn a_failed_worker_is_started_once_more() {
        let program = python().expect("python");
        let dir = std::env::temp_dir().join(format!("saw-worker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let count = dir.join("count");
        let _ = std::fs::remove_file(&count);
        let script = dir.join("reply.py");
        std::fs::write(&script, concat!(
            "import json, os, sys\n",
            "path = os.environ['SAW_TEST_COUNT']\n",
            "n = int(open(path).read()) if os.path.exists(path) else 0\n",
            "n += 1\n",
            "open(path, 'w').write(str(n))\n",
            "if n == 1:\n",
            "    raise SystemExit(1)\n",
            "req = json.loads(sys.stdin.readline())\n",
            "sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': {'verdict': 'clean', 'document': {'schema_version': 1}}}) + '\\n')\n",
            "sys.stdout.flush()\n",
        )).unwrap();
        let mut worker = Worker::launching(program, vec![script.to_string_lossy().into_owned()])
            .with_env("SAW_TEST_COUNT", count.to_string_lossy());
        let answer = worker.ask("scan", json!({"path": "/any"})).await;
        assert_eq!(answer.verdict, "clean");
        assert_eq!(answer.document.unwrap()["schema_version"], 1);
        worker.stop().await;
    }
}
