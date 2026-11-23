//! Answer shell-pattern and system-proxy questions given as JSON lines. Used to compare with
//! `main`.

use std::io::{self, BufRead};

use saw_platform::network::proxy;
use saw_platform::network::system_proxy::{self, Bypass, SystemProxies};
use saw_platform::registry::Data;
use saw_platform::shell_pattern;
use serde_json::{json, Value};

fn text(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

fn data(value: &Value) -> Data {
    match (value[0].as_str().unwrap_or(""), &value[1]) {
        ("sz", v) => Data::Text(text(v)),
        ("dword", v) => Data::Number(v.as_u64().unwrap_or(0)),
        ("multi", v) => Data::Texts(v.as_array().into_iter().flatten().map(text).collect()),
        _ => Data::Empty,
    }
}

fn shown(settings: &SystemProxies) -> Value {
    let bypass = match &settings.bypass {
        Bypass::MacOs { exclude_simple, exceptions } => json!({"exclude_simple": exclude_simple, "exceptions": exceptions}),
        other => json!(format!("{other:?}")),
    };
    json!([settings.proxies, bypass])
}

fn main() -> Result<(), String> {
    for line in io::stdin().lock().lines() {
        let case: Value = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let host = text(&case["host"]);
        let answer = match case["ask_about"].as_str().unwrap_or("") {
            "pattern" => json!([shell_pattern::matches(&text(&case["name"]), &text(&case["pattern"])),
                                shell_pattern::matches_windows(&text(&case["name"]), &text(&case["pattern"]))]),
            "macos_bypass" => {
                let exceptions: Vec<String> = case["exceptions"].as_array().into_iter().flatten().map(text).collect();
                json!(system_proxy::macos_bypass(&host, case["exclude_simple"].as_bool().unwrap_or(false), &exceptions))
            }
            "scutil" => shown(&system_proxy::macos_proxies(&system_proxy::parse_scutil(&text(&case["text"])))),
            "live" => match system_proxy::read() {
                Ok(settings) => shown(&settings),
                Err(error) => json!({"error": error}),
            },
            "windows" => {
                let values: Vec<(String, Data)> = case["values"].as_object().into_iter().flatten().map(|(k, v)| (k.clone(), data(v))).collect();
                let settings = system_proxy::windows_proxies(&values);
                let hosts: Vec<String> = case["hosts"].as_array().into_iter().flatten().map(text).collect();
                json!([settings.proxies, hosts.iter().map(|h| settings.bypasses(h)).collect::<Vec<_>>()])
            }
            "choose" => {
                let env: Vec<(String, String)> = case["env"].as_array().into_iter().flatten().map(|p| (text(&p[0]), text(&p[1]))).collect();
                let scutil = text(&case["scutil"]);
                let read_system_settings = || Ok(system_proxy::macos_proxies(&system_proxy::parse_scutil(&scutil)));
                match proxy::proxy_for_with(&host, &env, &read_system_settings) {
                    Ok(None) => Value::Null,
                    Ok(Some(p)) => json!([p.hostport, p.authorization]),
                    Err(_) => json!({"error": true}),
                }
            }
            other => return Err(format!("unknown question {other}")),
        };
        println!("{answer}");
    }
    Ok(())
}
