//! Chooses the proxy a request goes through from the proxy environment variables.

use std::collections::BTreeMap;

/// The proxy one request goes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub hostport: String,
    pub authorization: Option<String>,
}

/// Return the proxies the environment names, by scheme. Takes the environment in its order.
pub fn proxies_from(environment: &[(String, String)]) -> BTreeMap<String, String> {
    let mut proxies = BTreeMap::new();
    let mut named = Vec::new();
    for (name, value) in environment {
        let chars: Vec<char> = name.chars().collect();
        let count = chars.len();
        if count > 5 && chars[count - 6] == '_' && chars[count - 5..].iter().collect::<String>().to_lowercase() == "proxy" {
            let scheme = chars[..count - 6].iter().collect::<String>().to_lowercase();
            if !value.is_empty() {
                proxies.insert(scheme.clone(), value.clone());
            }
            named.push((name, value, scheme));
        }
    }
    if environment.iter().any(|(name, _)| name == "REQUEST_METHOD") {
        proxies.remove("http");
    }
    for (name, value, scheme) in named {
        if name.ends_with("_proxy") {
            if value.is_empty() {
                proxies.remove(&scheme);
            } else {
                proxies.insert(scheme, value.clone());
            }
        }
    }
    proxies
}

fn split_port(host: &str) -> (&str, Option<&str>) {
    if let Some(colon) = host.rfind(':') {
        let port = &host[colon + 1..];
        if port.bytes().all(|b| b.is_ascii_digit()) {
            return (&host[..colon], (!port.is_empty()).then_some(port));
        }
    }
    (host, None)
}

/// Tell whether a host goes around the proxy. Takes the host, with its port when it has one, and
/// the proxies by scheme.
pub fn bypass(host: &str, proxies: &BTreeMap<String, String>) -> bool {
    let Some(no_proxy) = proxies.get("no") else { return false };
    if no_proxy == "*" {
        return true;
    }
    let host = host.to_lowercase();
    let (hostonly, _) = split_port(&host);
    for name in no_proxy.split(',') {
        let name = name.trim_matches(crate::env::is_python_space).trim_start_matches('.').to_lowercase();
        if name.is_empty() {
            continue;
        }
        if hostonly == name || host == name {
            return true;
        }
        let suffix = format!(".{name}");
        if hostonly.ends_with(&suffix) || host.ends_with(&suffix) {
            return true;
        }
    }
    false
}

/// Return a proxy's user, password and host, or why it cannot be read. Takes the proxy's text.
pub fn parse_proxy(proxy: &str) -> Result<(Option<String>, Option<String>, String), String> {
    let rest = proxy.find(':').filter(|colon| *colon > 0 && !proxy[..*colon].contains('/')).map(|colon| &proxy[colon + 1..]);
    let authority = match rest {
        Some(rest) if rest.starts_with('/') => {
            if !rest.starts_with("//") {
                return Err("the proxy setting has no host".into());
            }
            let end = match rest.find('@') {
                Some(at) => rest[at..].find('/').map(|i| at + i),
                None => rest[2..].find('/').map(|i| i + 2),
            };
            &rest[2..end.unwrap_or(rest.len()).max(2)]
        }
        _ => proxy,
    };
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    let (user, password) = match userinfo {
        Some(info) => match info.split_once(':') {
            Some((user, password)) => (Some(user.to_string()), Some(password.to_string())),
            None => (Some(info.to_string()), None),
        },
        None => (None, None),
    };
    Ok((user, password, hostport.to_string()))
}

/// Return the proxy for a request to a host, none to go direct, or why the proxy cannot be read.
/// Takes the host, with its port when it has one, and the environment in its order.
pub fn proxy_for(host: &str, environment: &[(String, String)]) -> Result<Option<Proxy>, String> {
    proxy_for_with(host, environment, &super::system_proxy::read)
}

/// Return the proxy for a request to a host, none to go direct, or why the proxy cannot be read.
/// Takes the host, with its port when it has one, the environment in its order, and the reader of
/// the system's proxy settings.
pub fn proxy_for_with(
    host: &str,
    environment: &[(String, String)],
    read_system_settings: &dyn Fn() -> Result<super::system_proxy::SystemProxies, String>,
) -> Result<Option<Proxy>, String> {
    let from_environment = proxies_from(environment);
    let settings = if from_environment.is_empty() { Some(read_system_settings()?) } else { None };
    let proxies = settings.as_ref().map_or(&from_environment, |s| &s.proxies);
    let Some(proxy) = proxies.get("https") else { return Ok(None) };
    let (user, password, hostport) = parse_proxy(proxy)?;
    let goes_around = match &settings {
        None => bypass(host, &from_environment),
        Some(system) => system.bypasses(host),
    };
    if !host.is_empty() && goes_around {
        return Ok(None);
    }
    let authorization = match (user.filter(|u| !u.is_empty()), password.filter(|p| !p.is_empty())) {
        (Some(user), Some(password)) => Some(format!("Basic {}", base64(format!("{}:{}", unquote(&user), unquote(&password)).as_bytes()))),
        _ => None,
    };
    Ok(Some(Proxy { hostport: unquote(&hostport), authorization }))
}

/// Decode percent escapes. Takes the text. Returns it decoded.
pub fn unquote(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                out.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let joined = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for (position, shift) in [18, 12, 6, 0].iter().enumerate() {
            if position <= chunk.len() {
                out.push(TABLE[(joined >> shift & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
