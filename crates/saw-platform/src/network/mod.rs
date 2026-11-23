//! Makes HTTPS requests through the system's own `curl`.

pub mod proxy;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use crate::programs::{self, Invocation};

/// The oldest `curl` saw works with.
pub const MINIMUM_CURL: (u32, u32, u32) = (7, 55, 0);
const MOST_REDIRECTS: u32 = 10;
const WHOLE_REQUEST_LIMIT: Duration = Duration::from_secs(3600);

/// One HTTPS request.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
    pub most_bytes: Option<u64>,
    pub save_to: Option<PathBuf>,
}

/// What the server answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Return a header's first value, or none. Takes the header's name in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

/// Why a request got no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    CurlMissing(Vec<String>),
    CurlTooOld(String),
    NotHttps(String),
    BadRequest(String),
    BadProxy(String),
    Failed { code: Option<i32>, detail: String },
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::CurlMissing(places) => write!(out, "curl was not found at {}", places.join(" or ")),
            NetworkError::CurlTooOld(found) => {
                let (major, minor, patch) = MINIMUM_CURL;
                write!(out, "curl {found} is older than {major}.{minor}.{patch}")
            }
            NetworkError::NotHttps(url) => write!(out, "not an https address: {url}"),
            NetworkError::BadRequest(detail) | NetworkError::BadProxy(detail) => write!(out, "{detail}"),
            NetworkError::Failed { detail, .. } => write!(out, "{detail}"),
        }
    }
}

/// Return the places the system's `curl` may be.
pub fn curl_candidates() -> Vec<String> {
    if cfg!(windows) {
        vec![format!("{}\\System32\\curl.exe", crate::system_programs::windows_system_root())]
    } else {
        vec!["/usr/bin/curl".into(), "/bin/curl".into()]
    }
}

/// Return a `curl` version from what `curl --version` printed, or none. Takes the text.
pub fn curl_version(printed: &str) -> Option<(u32, u32, u32)> {
    let word = printed.lines().next()?.split_whitespace().nth(1)?;
    let mut parts = word.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).map(|p| p.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??, parts.next().flatten().unwrap_or(0)))
}

fn minimal_env() -> BTreeMap<String, String> {
    std::env::vars().filter(|(name, _)| name.eq_ignore_ascii_case("SystemRoot")).collect()
}

/// Return the system's `curl`, or why it cannot be used.
pub fn find_curl() -> Result<PathBuf, NetworkError> {
    static FOUND: OnceLock<Result<PathBuf, NetworkError>> = OnceLock::new();
    FOUND
        .get_or_init(|| {
            let candidates = curl_candidates();
            let borrowed: Vec<&str> = candidates.iter().map(String::as_str).collect();
            let curl = crate::system_programs::system_program(&borrowed).ok_or_else(|| NetworkError::CurlMissing(candidates.clone()))?;
            let invocation = Invocation {
                program: curl.clone(),
                args: vec!["--disable".into(), "--version".into()],
                env: minimal_env(),
                timeout: Duration::from_secs(10),
                ..Invocation::default()
            };
            let printed = programs::run(&invocation).map(|done| String::from_utf8_lossy(&done.stdout).into_owned()).unwrap_or_default();
            match curl_version(&printed) {
                Some(found) if found >= MINIMUM_CURL => Ok(curl),
                Some((major, minor, patch)) => Err(NetworkError::CurlTooOld(format!("{major}.{minor}.{patch}"))),
                None => Err(NetworkError::CurlTooOld("of an unknown version".into())),
            }
        })
        .clone()
}

/// Return a value written for a `curl` configuration. Takes the value.
pub fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn has_control(text: &str) -> bool {
    text.chars().any(|c| c == '\r' || c == '\n' || c == '\0')
}

/// Return the host and port of an https address, or none. Takes the address.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.get(..8).filter(|scheme| scheme.eq_ignore_ascii_case("https://")).map(|_| &url[8..])?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(proxy::unquote(&rest[..end]))
}

/// Return the configuration `curl` reads for a request, or why it cannot be made. Takes the
/// request, the proxy, and the files for the body sent, the body received and the headers.
pub fn configuration(request: &Request, proxy: Option<&proxy::Proxy>, sent: Option<&Path>, received: &Path, headers: &Path) -> Result<String, NetworkError> {
    if host_of(&request.url).is_none() {
        return Err(NetworkError::NotHttps(request.url.clone()));
    }
    if request.url.chars().any(|c| c <= ' ' || c == '\u{7f}') {
        return Err(NetworkError::BadRequest(format!("URL can't contain control characters: {:?}", request.url)));
    }
    let seconds = request.timeout.as_secs().max(1);
    let mut lines = vec![
        format!("url = {}", quoted(&request.url)),
        "proto = \"=https\"".into(),
        "proto-redir = \"=https\"".into(),
        "tlsv1.2".into(),
        "location".into(),
        format!("max-redirs = {MOST_REDIRECTS}"),
        format!("connect-timeout = {seconds}"),
        "speed-limit = 1".into(),
        format!("speed-time = {seconds}"),
        "silent".into(),
        "show-error".into(),
        format!("request = {}", quoted(if request.method.is_empty() { "GET" } else { &request.method })),
        format!("output = {}", quoted(&received.display().to_string())),
        format!("dump-header = {}", quoted(&headers.display().to_string())),
        "write-out = \"%{http_code}\"".into(),
    ];
    for (name, value) in &request.headers {
        if has_control(name) || has_control(value) || name.contains(':') {
            return Err(NetworkError::BadRequest(format!("Invalid header {name:?}")));
        }
        lines.push(format!("header = {}", quoted(&format!("{name}: {value}"))));
    }
    if let Some(sent) = sent {
        lines.push(format!("data-binary = {}", quoted(&format!("@{}", sent.display()))));
    }
    if let Some(most) = request.most_bytes {
        lines.push(format!("max-filesize = {most}"));
    }
    match proxy {
        Some(proxy) => {
            if has_control(&proxy.hostport) {
                return Err(NetworkError::BadProxy(format!("Invalid proxy {:?}", proxy.hostport)));
            }
            lines.push(format!("proxy = {}", quoted(&format!("http://{}", proxy.hostport))));
            if let Some(authorization) = &proxy.authorization {
                lines.push(format!("proxy-header = {}", quoted(&format!("Proxy-Authorization: {authorization}"))));
            }
        }
        None => lines.push("noproxy = \"*\"".into()),
    }
    Ok(lines.join("\n") + "\n")
}

/// Return the headers of the last response in what `curl` wrote. Takes the text.
pub fn last_headers(text: &str) -> Vec<(String, String)> {
    let blocks: Vec<&str> = text.split("\r\n\r\n").flat_map(|b| b.split("\n\n")).filter(|b| b.trim_start().starts_with("HTTP/")).collect();
    let Some(last) = blocks.last() else { return Vec::new() };
    last.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect()
}

/// Send a request. Takes the request and the environment in its order. Returns the answer, or why
/// there is none.
pub fn fetch(request: &Request, environment: &[(String, String)]) -> Result<Response, NetworkError> {
    let curl = find_curl()?;
    let host = host_of(&request.url).ok_or_else(|| NetworkError::NotHttps(request.url.clone()))?;
    let proxy = proxy::proxy_for(&host, environment).map_err(NetworkError::BadProxy)?;
    let folder = crate::sandbox::scratch::make_unique_folder(&std::env::temp_dir(), "saw-request-")
        .map_err(|error| NetworkError::Failed { code: None, detail: error.to_string() })?;
    let answer = fetch_in(&curl, request, proxy.as_ref(), &folder);
    crate::sandbox::scratch::remove_tree(&folder);
    answer
}

/// Return how `curl` is run for a request. Takes `curl` and the request's configuration.
pub fn invocation(curl: &Path, config: String) -> Invocation {
    Invocation {
        program: curl.to_path_buf(),
        args: vec!["--disable".into(), "--config".into(), "-".into()],
        env: minimal_env(),
        stdin: Some(config.into_bytes()),
        timeout: WHOLE_REQUEST_LIMIT,
        ..Invocation::default()
    }
}

fn fetch_in(curl: &Path, request: &Request, proxy: Option<&proxy::Proxy>, folder: &Path) -> Result<Response, NetworkError> {
    let failed = |detail: String| NetworkError::Failed { code: None, detail };
    let sent = match &request.body {
        Some(body) => {
            let path = folder.join("sent");
            std::fs::write(&path, body).map_err(|e| failed(e.to_string()))?;
            Some(path)
        }
        None => None,
    };
    let received = request.save_to.clone().unwrap_or_else(|| folder.join("received"));
    let headers = folder.join("headers");
    let config = configuration(request, proxy, sent.as_deref(), &received, &headers)?;
    let done = programs::run(&invocation(curl, config)).map_err(|e| failed(e.to_string()))?;
    if done.code != Some(0) {
        return Err(NetworkError::Failed { code: done.code, detail: String::from_utf8_lossy(&done.stderr).trim().to_string() });
    }
    let status = String::from_utf8_lossy(&done.stdout).trim().parse::<u16>().map_err(|_| failed("curl gave no status".into()))?;
    let header_text = std::fs::read(&headers).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let body = if request.save_to.is_some() { Vec::new() } else { std::fs::read(&received).unwrap_or_default() };
    Ok(Response { status, headers: last_headers(&header_text), body })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_secret() -> Request {
        Request {
            method: "POST".into(),
            url: "https://api.example.com/repos/a/b?x=1".into(),
            headers: vec![("Authorization".into(), "Bearer secret-token-value".into())],
            body: Some(b"{\"secret\": \"body-value\"}".to_vec()),
            timeout: Duration::from_secs(15),
            ..Request::default()
        }
    }

    #[test]
    fn nothing_from_a_request_reaches_the_command_line() {
        let request = request_with_secret();
        let config = configuration(&request, None, Some(Path::new("/s/sent")), Path::new("/s/received"), Path::new("/s/headers")).unwrap();
        let run = invocation(Path::new("/usr/bin/curl"), config.clone());
        let argv = run.args.join(" ");
        for secret in ["secret-token-value", "api.example.com", "body-value", "/s/sent"] {
            assert!(!argv.contains(secret), "{secret} on the command line");
        }
        assert!(config.contains("secret-token-value"));
        assert!(run.env.keys().all(|name| name.eq_ignore_ascii_case("SystemRoot")));
    }

    #[test]
    fn only_https_and_clean_headers_are_sent() {
        let mut request = request_with_secret();
        let paths = (Path::new("/r"), Path::new("/h"));
        request.url = "http://api.example.com/".into();
        assert!(matches!(configuration(&request, None, None, paths.0, paths.1), Err(NetworkError::NotHttps(_))));
        request.url = "https://api.example.com/\nx".replace("\\n", "\n");
        assert!(configuration(&request, None, None, paths.0, paths.1).is_err());
        request = request_with_secret();
        request.headers.push(("X-Injected".into(), "a\r\nHost: evil".into()));
        assert!(matches!(configuration(&request, None, None, paths.0, paths.1), Err(NetworkError::BadRequest(_))));
    }

    #[test]
    fn versions_and_headers_are_read() {
        assert_eq!(curl_version("curl 8.7.1 (x86_64-apple-darwin22.0) libcurl/8.7.1"), Some((8, 7, 1)));
        assert_eq!(curl_version("curl 7.55.1 (Windows) libcurl/7.55.1"), Some((7, 55, 1)));
        assert_eq!(curl_version("curl 8.10.0-DEV (x)"), Some((8, 10, 0)));
        assert_eq!(curl_version(""), None);
        assert!(curl_version("curl 7.54.9 (x)").unwrap() < MINIMUM_CURL);
        let dumped = "HTTP/1.1 200 Connection established\r\n\r\nHTTP/2 301\r\nlocation: /b\r\n\r\nHTTP/2 200\r\nX-OAuth-Scopes: repo, workflow\r\nlink: <x>; rel=\"next\"\r\n\r\n";
        let response = Response { status: 200, headers: last_headers(dumped), body: Vec::new() };
        assert_eq!(response.header("x-oauth-scopes"), Some("repo, workflow"));
        assert_eq!(response.header("Link"), Some("<x>; rel=\"next\""));
        assert_eq!(response.header("location"), None);
        assert_eq!(quoted("a\"b\\c\td"), "\"a\\\"b\\\\c\\td\"");
    }
}
