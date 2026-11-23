//! Answer proxy and request questions given as JSON lines. Used to compare with `main`.

use std::io::{self, BufRead};
use std::time::Duration;

use saw_platform::network::{self, proxy, NetworkError, Request};
use serde_json::{json, Value};

fn pairs(value: &Value) -> Vec<(String, String)> {
    value.as_array().into_iter().flatten().filter_map(|p| Some((p[0].as_str()?.to_string(), p[1].as_str()?.to_string()))).collect()
}

fn main() -> Result<(), String> {
    for line in io::stdin().lock().lines() {
        let case: Value = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let env = pairs(&case["env"]);
        let answer = match case["ask_about"].as_str().unwrap_or("") {
            "proxy" => match proxy::proxy_for(case["host"].as_str().unwrap_or(""), &env) {
                Ok(None) => Value::Null,
                Ok(Some(p)) => json!([p.hostport, p.authorization]),
                Err(_) => json!({"error": true}),
            },
            _ => {
                let request = Request {
                    method: "GET".into(),
                    url: case["url"].as_str().unwrap_or("").into(),
                    headers: pairs(&case["headers"]),
                    timeout: Duration::from_secs(5),
                    ..Request::default()
                };
                match network::fetch(&request, &env) {
                    Ok(r) => json!({"status": r.status}),
                    Err(NetworkError::Failed { code, .. }) => json!({"error": "failed", "code": code}),
                    Err(NetworkError::NotHttps) => json!({"error": "NotHttps"}),
                    Err(other) => json!({"error": other.to_string()}),
                }
            }
        };
        println!("{answer}");
    }
    Ok(())
}
