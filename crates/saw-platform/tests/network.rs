//! Tests for the HTTPS client.

use std::path::Path;
use std::time::Duration;

use saw_platform::network::{configuration, curl_version, invocation, last_headers, proxy, quoted, NetworkError, Request, Response, MINIMUM_CURL};

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
    let leaked = ["secret-token-value", "api.example.com", "body-value", "/s/sent"].iter().filter(|value| argv.contains(**value)).count();
    assert_eq!(leaked, 0);
    assert!(config.contains("secret-token-value"));
    assert!(run.env.keys().all(|name| name.eq_ignore_ascii_case("SystemRoot")));
}

#[test]
fn only_https_and_clean_headers_are_sent() {
    let mut request = request_with_secret();
    let paths = (Path::new("/r"), Path::new("/h"));
    request.url = "http://api.example.com/".into();
    assert!(matches!(configuration(&request, None, None, paths.0, paths.1), Err(NetworkError::NotHttps)));
    request.url = "https://api.example.com/\nx".replace("\\n", "\n");
    assert!(configuration(&request, None, None, paths.0, paths.1).is_err());
    request = request_with_secret();
    request.headers.push(("X-Injected".into(), "a\r\nHost: evil".into()));
    assert!(matches!(configuration(&request, None, None, paths.0, paths.1), Err(NetworkError::BadRequest(_))));
}

#[test]
fn no_error_repeats_an_address_or_a_header() {
    let mut request = request_with_secret();
    let paths = (Path::new("/r"), Path::new("/h"));
    let mut messages = Vec::new();
    request.url = "http://hooks.example.com/secret-path".into();
    messages.push(configuration(&request, None, None, paths.0, paths.1).unwrap_err().to_string());
    request.url = "https://hooks.example.com/secret-path\tx".into();
    messages.push(configuration(&request, None, None, paths.0, paths.1).unwrap_err().to_string());
    request = request_with_secret();
    request.headers.push(("Authorization".into(), "Bearer secret-path\r\n".into()));
    messages.push(configuration(&request, None, None, paths.0, paths.1).unwrap_err().to_string());
    let proxy = proxy::Proxy { hostport: "secret-path\n".into(), authorization: None };
    messages.push(configuration(&request_with_secret(), Some(&proxy), None, paths.0, paths.1).unwrap_err().to_string());
    messages.push(proxy::parse_proxy("http:/user:secret-path@host").unwrap_err());
    assert_eq!(messages.iter().filter(|m| m.contains("secret-path") || m.contains("hooks.example.com")).count(), 0);
    assert_eq!(messages.len(), 5);
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
