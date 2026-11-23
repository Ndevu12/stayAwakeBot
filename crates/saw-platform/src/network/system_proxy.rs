//! Reads the proxy settings of macOS and of Windows.

use std::collections::BTreeMap;

use crate::registry::{self, Data, Hive};
use crate::shell_pattern;

/// How a system's settings send hosts around the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bypass {
    None,
    MacOs { exclude_simple: bool, exceptions: Vec<String> },
    Windows { enabled: bool, overrides: Option<String> },
}

/// A system's proxies by scheme and its rule for going around them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProxies {
    pub proxies: BTreeMap<String, String>,
    pub bypass: Bypass,
}

impl SystemProxies {
    /// Return settings with no proxy.
    pub fn none() -> SystemProxies {
        SystemProxies { proxies: BTreeMap::new(), bypass: Bypass::None }
    }

    /// Tell whether a host goes around the proxy. Takes the host, with its port when it has one.
    pub fn bypasses(&self, host: &str) -> bool {
        match &self.bypass {
            Bypass::None => false,
            Bypass::MacOs { exclude_simple, exceptions } => macos_bypass(host, *exclude_simple, exceptions),
            Bypass::Windows { enabled, overrides } => *enabled && overrides.as_deref().is_some_and(|o| !o.is_empty() && windows_bypass(host, o)),
        }
    }
}

/// One value in what `scutil --proxy` printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    Text(String),
    List(Vec<String>),
}

/// Read what `scutil --proxy` printed. Takes the text. Returns the top-level settings by name.
pub fn parse_scutil(text: &str) -> BTreeMap<String, Setting> {
    let mut settings = BTreeMap::new();
    let mut depth = 0usize;
    let mut open_list: Option<(String, Vec<String>, usize)> = None;
    for line in text.lines().map(str::trim) {
        if line == "}" {
            if open_list.as_ref().is_some_and(|(_, _, at)| *at == depth) {
                let (name, items, _) = open_list.take().unwrap_or_default();
                settings.insert(name, Setting::List(items));
            }
            depth = depth.saturating_sub(1);
            continue;
        }
        if line.ends_with('{') {
            depth += 1;
            if depth == 2 {
                if let Some((name, _)) = line.split_once(" : ").filter(|(_, value)| value.starts_with("<array>")) {
                    open_list = Some((name.to_string(), Vec::new(), depth));
                }
            }
            continue;
        }
        let Some((name, value)) = line.split_once(" : ") else { continue };
        match &mut open_list {
            Some((_, items, at)) if *at == depth => items.push(value.to_string()),
            None if depth == 1 => {
                settings.insert(name.to_string(), Setting::Text(value.to_string()));
            }
            _ => {}
        }
    }
    settings
}

fn number(settings: &BTreeMap<String, Setting>, name: &str) -> Option<i64> {
    match settings.get(name)? {
        Setting::Text(text) => text.parse::<i64>().ok().map(|n| n as i32 as i64),
        Setting::List(_) => None,
    }
}

/// Return the macOS proxy settings from what `scutil --proxy` printed. Takes the settings.
pub fn macos_proxies(settings: &BTreeMap<String, Setting>) -> SystemProxies {
    let mut proxies = BTreeMap::new();
    for (scheme, prefix) in [("http", "HTTP"), ("https", "HTTPS"), ("ftp", "FTP"), ("gopher", "Gopher")] {
        if number(settings, &format!("{prefix}Enable")).unwrap_or(0) == 0 {
            continue;
        }
        let Some(Setting::Text(host)) = settings.get(&format!("{prefix}Proxy")) else { continue };
        let address = match number(settings, &format!("{prefix}Port")) {
            Some(port) => format!("http://{host}:{port}"),
            None => format!("http://{host}"),
        };
        proxies.insert(scheme.to_string(), address);
    }
    let exceptions = match settings.get("ExceptionsList") {
        Some(Setting::List(items)) => items.clone(),
        _ => Vec::new(),
    };
    let exclude_simple = number(settings, "ExcludeSimpleHostnames").unwrap_or(0) != 0;
    SystemProxies { proxies, bypass: Bypass::MacOs { exclude_simple, exceptions } }
}

fn split_port(host: &str) -> &str {
    match host.rfind(':') {
        Some(colon) if colon + 1 < host.len() && host[colon + 1..].bytes().all(|b| b.is_ascii_digit()) => &host[..colon],
        _ => host,
    }
}

fn ipv4(text: &str) -> Option<u32> {
    if text.contains('/') {
        return None;
    }
    let octets: Vec<&str> = text.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut value = 0u32;
    for octet in octets {
        let valid = !octet.is_empty() && octet.len() <= 3 && octet.bytes().all(|b| b.is_ascii_digit()) && (octet == "0" || !octet.starts_with('0'));
        let number: u32 = octet.parse().ok().filter(|n| valid && *n <= 255)?;
        value = value << 8 | number;
    }
    Some(value)
}

fn leading_address(value: &str) -> Option<(&str, Option<&str>)> {
    let digits = |text: &str| text.bytes().take_while(u8::is_ascii_digit).count();
    let mut end = digits(value);
    if end == 0 {
        return None;
    }
    while value[end..].starts_with('.') && digits(&value[end + 1..]) > 0 {
        end += 1 + digits(&value[end + 1..]);
    }
    let rest = &value[end..];
    let mask = (rest.starts_with('/') && digits(&rest[1..]) > 0).then(|| &rest[1..1 + digits(&rest[1..])]);
    Some((&value[..end], mask))
}

/// Tell whether macOS settings send a host around the proxy. Takes the host, with its port when it
/// has one, whether simple host names go around, and the exceptions.
pub fn macos_bypass(host: &str, exclude_simple: bool, exceptions: &[String]) -> bool {
    if !host.contains('.') && exclude_simple {
        return true;
    }
    let address = ipv4(split_port(host));
    for value in exceptions.iter().filter(|v| !v.is_empty()) {
        match (leading_address(value), address) {
            (Some((base, mask)), Some(address)) => {
                let parts: Vec<Option<u128>> = base.split('.').map(|p| p.parse::<u128>().ok().filter(|n| *n < 1 << 32)).collect();
                let bits = match mask {
                    None => 8 * parts.len() as u128,
                    Some(mask) => mask.parse::<u128>().unwrap_or(u128::MAX),
                };
                if bits > 32 {
                    continue;
                }
                let mut padded: Vec<Option<u128>> = parts.into_iter().chain(std::iter::repeat(Some(0))).take(4).collect();
                let Some(numbers) = padded.iter_mut().map(|p| p.take()).collect::<Option<Vec<u128>>>() else { continue };
                let base = numbers[0] << 24 | numbers[1] << 16 | numbers[2] << 8 | numbers[3];
                let shift = 32 - bits as u32;
                if (address as u128) >> shift == base >> shift {
                    return true;
                }
            }
            _ => {
                if shell_pattern::matches(host, value) {
                    return true;
                }
            }
        }
    }
    false
}

fn python_text(data: &Data) -> String {
    match data {
        Data::Text(text) => text.clone(),
        Data::Number(number) => number.to_string(),
        Data::Texts(items) => format!("[{}]", items.iter().map(|i| format!("'{i}'")).collect::<Vec<_>>().join(", ")),
        Data::Bytes(bytes) => format!("b'{}'", bytes.iter().map(|b| format!("\\x{b:02x}")).collect::<String>()),
        Data::Empty => "None".into(),
    }
}

fn truthy(data: &Data) -> bool {
    match data {
        Data::Text(text) => !text.is_empty(),
        Data::Number(number) => *number != 0,
        Data::Texts(items) => !items.is_empty(),
        Data::Bytes(bytes) => !bytes.is_empty(),
        Data::Empty => false,
    }
}

fn value<'a>(values: &'a [(String, Data)], name: &str) -> Option<&'a Data> {
    values.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, data)| data)
}

fn has_scheme(address: &str) -> bool {
    address.find("://").is_some_and(|at| at > 0 && !address[..at].contains(['/', ':']))
}

/// Return the Windows proxy settings from the Internet Settings values. Takes the values.
pub fn windows_proxies(values: &[(String, Data)]) -> SystemProxies {
    let enabled = value(values, "ProxyEnable").is_some_and(truthy);
    let overrides = value(values, "ProxyOverride").map(python_text);
    let bypass = Bypass::Windows { enabled: value(values, "ProxyEnable").is_some() && enabled, overrides };
    let mut proxies = BTreeMap::new();
    if !enabled {
        return SystemProxies { proxies, bypass };
    }
    let Some(server) = value(values, "ProxyServer").map(python_text) else { return SystemProxies { proxies, bypass } };
    let server = if !server.contains('=') && !server.contains(';') { format!("http={server};https={server};ftp={server}") } else { server };
    for part in server.split(';') {
        let Some((protocol, address)) = part.split_once('=') else { return SystemProxies { proxies, bypass } };
        let mut address = address.to_string();
        if !has_scheme(&address) {
            if ["http", "https", "ftp"].contains(&protocol) {
                address = format!("http://{address}");
            } else if protocol == "socks" {
                address = format!("socks://{address}");
            }
        }
        proxies.insert(protocol.to_string(), address);
    }
    if let Some(socks) = proxies.get("socks").filter(|s| !s.is_empty()).cloned() {
        let address = match socks.strip_prefix("socks://") {
            Some(rest) => format!("socks4://{rest}"),
            None => socks,
        };
        for scheme in ["http", "https"] {
            if proxies.get(scheme).is_none_or(|current| current.is_empty()) {
                proxies.insert(scheme.to_string(), address.clone());
            }
        }
    }
    SystemProxies { proxies, bypass }
}

/// Tell whether a Windows proxy override list sends a host around the proxy. Takes the host, with
/// its port when it has one, and the list.
pub fn windows_bypass(host: &str, overrides: &str) -> bool {
    let host = split_port(host);
    overrides.split(';').map(|test| test.trim_matches(crate::env::is_python_space)).any(|test| {
        if test == "<local>" {
            !host.contains('.')
        } else {
            shell_pattern::matches_windows(host, test)
        }
    })
}

/// Return this system's proxy settings, or why they cannot be read.
pub fn read() -> Result<SystemProxies, String> {
    if cfg!(target_os = "macos") {
        let scutil = crate::system_programs::system_program(&["/usr/sbin/scutil"]).ok_or("the system proxy settings could not be read")?;
        let invocation = crate::programs::Invocation {
            program: scutil,
            args: vec!["--proxy".into()],
            timeout: std::time::Duration::from_secs(10),
            ..crate::programs::Invocation::default()
        };
        let done = crate::programs::run(&invocation).map_err(|_| "the system proxy settings could not be read".to_string())?;
        if done.code != Some(0) {
            return Err("the system proxy settings could not be read".into());
        }
        return Ok(macos_proxies(&parse_scutil(&String::from_utf8_lossy(&done.stdout))));
    }
    if cfg!(windows) {
        let values = registry::values(Hive::CurrentUser, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false)
            .ok_or("the system proxy settings could not be read")?;
        return Ok(windows_proxies(&values));
    }
    Ok(SystemProxies::none())
}
