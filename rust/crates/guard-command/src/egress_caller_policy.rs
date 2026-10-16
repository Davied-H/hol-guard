//! Managed-network policy for the brokered egress caller.
//!
//! Port of `mdm/network_transport.py`'s `platform_system_proxies`,
//! `validated_proxy_url` and `proxy_map`, plus the destination refusal the
//! managed policy applies to every hop. The resident is network-denied for
//! package evaluation, so these are the caller's rules: which destinations it
//! will touch at all, and which proxy each exchange goes through.
//!
//! Resolving the managed policy document itself stays with the Python side
//! until the native verifier-key bootstrap lands; [`ManagedEgressPolicy`]
//! takes an already-resolved [`ManagedNetworkPolicy`].

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::egress_caller::{EgressPolicy, EgressProxy};
use crate::restricted_archive_transport::PUBLIC_REGISTRIES;

/// `platform_system_proxies` runs one short-lived probe; past this it is a
/// read of OS configuration that did not answer, which is "no proxy".
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// A proxy configuration larger than this is malformed, not a configuration.
const MAX_PROBE_OUTPUT_BYTES: usize = 64 * 1024;

/// `ProxyMode` (mdm/contracts.py).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// No proxy; a configured `proxy_url` is a policy contradiction.
    None,
    /// Whatever the operating system is configured to use.
    #[default]
    System,
    /// The policy's own `proxy_url`, which must be HTTPS.
    Explicit,
}

/// `ManagedNetworkPolicy` (mdm/contracts.py:329).
#[derive(Debug, Clone, Default)]
pub struct ManagedNetworkPolicy {
    pub proxy_mode: ProxyMode,
    pub proxy_url: Option<String>,
    pub ca_bundle_path: Option<PathBuf>,
    pub allow_public_registries: bool,
}

impl ManagedNetworkPolicy {
    /// The policy a machine with no managed document has: the Python default
    /// (`proxy_mode="system"`, public registries allowed).
    pub fn unmanaged_default() -> Self {
        Self {
            proxy_mode: ProxyMode::System,
            proxy_url: None,
            ca_bundle_path: None,
            allow_public_registries: true,
        }
    }
}

/// `validated_proxy_url` (mdm/network_transport.py:145).
///
/// A proxy URL carries no credentials, no path, no query and no fragment, and
/// it is normalised to `scheme://host:port` so two spellings of one proxy
/// compare equal. `reason_code` is the caller's refusal code; embedded
/// credentials always refuse as `managed_proxy_credentials_forbidden`,
/// matching the Python contract.
pub fn validated_proxy_url(
    value: &str,
    require_https: bool,
    reason_code: &'static str,
) -> Result<String, &'static str> {
    if value != value.trim() || value.chars().any(char::is_whitespace) {
        return Err(reason_code);
    }
    let (scheme, rest) = value.split_once("://").ok_or(reason_code)?;
    let scheme = scheme.to_ascii_lowercase();
    let allowed = if require_https {
        scheme == "https"
    } else {
        scheme == "http" || scheme == "https"
    };
    if !allowed {
        return Err(reason_code);
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, remainder) = rest.split_at(authority_end);
    // `urlsplit` keeps the path, query and fragment out of `netloc`; the
    // Python check accepts only an empty or root path and no query or
    // fragment, so anything else here is the same refusal.
    if !remainder.is_empty() && remainder != "/" {
        return Err(reason_code);
    }
    if authority.is_empty() || authority.ends_with(':') {
        return Err(reason_code);
    }
    if authority.contains('@') {
        return Err("managed_proxy_credentials_forbidden");
    }
    let (host, port_text) = split_authority(authority).ok_or(reason_code)?;
    if host.is_empty() {
        return Err(reason_code);
    }
    let port = match port_text {
        None => {
            if scheme == "https" {
                443
            } else {
                80
            }
        }
        Some(text) => {
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(reason_code);
            }
            match text.parse::<u16>() {
                Ok(0) | Err(_) => return Err(reason_code),
                Ok(value) => value,
            }
        }
    };
    let host = host.to_ascii_lowercase();
    let authority_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Ok(format!("{scheme}://{authority_host}:{port}"))
}

/// `proxy_map` (mdm/network_transport.py:169).
pub fn proxy_map(policy: &ManagedNetworkPolicy) -> Result<BTreeMap<String, String>, &'static str> {
    match policy.proxy_mode {
        ProxyMode::None => {
            if policy.proxy_url.is_some() {
                return Err("managed_proxy_url_mode_mismatch");
            }
            Ok(BTreeMap::new())
        }
        ProxyMode::Explicit => {
            let configured = policy
                .proxy_url
                .as_deref()
                .ok_or("managed_proxy_url_required")?;
            let proxy = validated_proxy_url(configured, true, "managed_proxy_url_invalid")?;
            Ok(BTreeMap::from([
                ("http".to_owned(), proxy.clone()),
                ("https".to_owned(), proxy),
            ]))
        }
        ProxyMode::System => {
            if policy.proxy_url.is_some() {
                return Err("managed_proxy_url_mode_mismatch");
            }
            let mut proxies = BTreeMap::new();
            for (scheme, proxy) in platform_system_proxies() {
                if scheme != "http" && scheme != "https" {
                    continue;
                }
                proxies.insert(
                    scheme,
                    validated_proxy_url(&proxy, false, "managed_system_proxy_invalid")?,
                );
            }
            Ok(proxies)
        }
    }
}

/// `platform_system_proxies` (mdm/network_transport.py:70).
///
/// Reads the operating system's own proxy configuration. The user's
/// environment is not managed authority, so `HTTP_PROXY` and friends are
/// never consulted here.
pub fn platform_system_proxies() -> BTreeMap<String, String> {
    system_proxies()
}

#[cfg(target_os = "macos")]
fn system_proxies() -> BTreeMap<String, String> {
    match probe_output("/usr/sbin/scutil", &["--proxy"]) {
        Some(stdout) => parse_scutil_proxies(&stdout),
        None => BTreeMap::new(),
    }
}

/// `winreg` reads `Internet Settings` directly; `reg.exe` reads the same two
/// values out of the same hives, in the same order, without linking the
/// registry API into the runtime.
#[cfg(windows)]
fn system_proxies() -> BTreeMap<String, String> {
    for hive in ["HKCU", "HKLM"] {
        let key = format!(r"{hive}\Software\Microsoft\Windows\CurrentVersion\Internet Settings");
        let Some(stdout) = probe_output("reg.exe", &["query", key.as_str()]) else {
            continue;
        };
        let values = parse_reg_values(&stdout);
        let enabled = values
            .get("proxyenable")
            .and_then(|value| parse_reg_dword(value))
            .is_some_and(|flag| flag != 0);
        let Some(server) = values.get("proxyserver") else {
            continue;
        };
        if !enabled || server.is_empty() {
            continue;
        }
        return parse_windows_proxy_server(server);
    }
    BTreeMap::new()
}

#[cfg(not(any(target_os = "macos", windows)))]
fn system_proxies() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// `scutil --proxy` prints a property list; the Python port reads the
/// `HTTPEnable`/`HTTPProxy`/`HTTPPort` triples out of it and ignores the rest.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_scutil_proxies(stdout: &str) -> BTreeMap<String, String> {
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for line in stdout.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        // `^\s*([A-Za-z]+)\s*:\s*(.+?)\s*$`: a plain alphabetic key and a
        // non-empty value, so the plist's braces and array indices are skipped.
        if name.is_empty()
            || value.is_empty()
            || !name.bytes().all(|byte| byte.is_ascii_alphabetic())
        {
            continue;
        }
        values.insert(name, value);
    }
    let mut proxies = BTreeMap::new();
    for (scheme, prefix) in [("http", "HTTP"), ("https", "HTTPS")] {
        let enabled = values.get(format!("{prefix}Enable").as_str()) == Some(&"1");
        let Some(host) = values.get(format!("{prefix}Proxy").as_str()) else {
            continue;
        };
        if !enabled || host.is_empty() {
            continue;
        }
        let default_port = if scheme == "https" { "443" } else { "80" };
        let port = values
            .get(format!("{prefix}Port").as_str())
            .copied()
            .unwrap_or(default_port);
        proxies.insert(scheme.to_owned(), format!("http://{host}:{port}"));
    }
    proxies
}

/// `reg query` prints `    Name    REG_TYPE    data` under the key's header.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_reg_values(stdout: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in stdout.lines() {
        let mut fields = line.trim().split_whitespace();
        let (Some(name), Some(kind)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !kind.starts_with("REG_") {
            continue;
        }
        let data = fields.collect::<Vec<_>>().join(" ");
        values.insert(name.to_ascii_lowercase(), data);
    }
    values
}

/// `REG_DWORD` data prints as `0x1`.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_reg_dword(value: &str) -> Option<u32> {
    let text = value.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => text.parse::<u32>().ok(),
    }
}

/// `ProxyServer` is either one address for every scheme or a `;`-separated
/// list of `scheme=address` pairs.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_windows_proxy_server(server: &str) -> BTreeMap<String, String> {
    if !server.contains('=') {
        return BTreeMap::from([
            ("http".to_owned(), format!("http://{server}")),
            ("https".to_owned(), format!("http://{server}")),
        ]);
    }
    let mut proxies = BTreeMap::new();
    for item in server.split(';') {
        let Some((scheme, address)) = item.split_once('=') else {
            continue;
        };
        if (scheme != "http" && scheme != "https") || address.is_empty() {
            continue;
        }
        proxies.insert(scheme.to_owned(), format!("http://{address}"));
    }
    proxies
}

/// `subprocess.run([...], capture_output=True, timeout=5)`; `None` stands for
/// the `OSError`/`TimeoutExpired` the Python port treats as "no proxy".
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn probe_output(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = Vec::new();
        let read = stdout
            .by_ref()
            .take(MAX_PROBE_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut buffer);
        let _ = sender.send(read.ok().map(|_| buffer));
    });
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    if !status.success() {
        return None;
    }
    let buffer = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()??;
    if buffer.len() > MAX_PROBE_OUTPUT_BYTES {
        return None;
    }
    String::from_utf8(buffer).ok()
}

/// The destination and proxy rules of a resolved managed network policy.
pub struct ManagedEgressPolicy {
    allow_public_registries: bool,
    proxies: BTreeMap<String, String>,
}

impl ManagedEgressPolicy {
    /// `Err(code)` is a policy that cannot be honoured — a mode/URL mismatch
    /// or an unusable proxy — which must fail the evaluation closed rather
    /// than fall back to a direct connection.
    pub fn resolve(policy: &ManagedNetworkPolicy) -> Result<Self, &'static str> {
        Ok(Self {
            allow_public_registries: policy.allow_public_registries,
            proxies: proxy_map(policy)?,
        })
    }

    /// The resolved proxy per scheme, for a caller that reports it.
    pub fn proxies(&self) -> &BTreeMap<String, String> {
        &self.proxies
    }
}

impl EgressPolicy for ManagedEgressPolicy {
    fn validate(&self, url: &str) -> Result<(), String> {
        let Some(hostname) = canonical_hostname(url) else {
            return Err("managed_destination_invalid".to_owned());
        };
        if !self.allow_public_registries && PUBLIC_REGISTRIES.contains(&hostname.as_str()) {
            return Err("managed_public_registry_disabled".to_owned());
        }
        Ok(())
    }

    fn proxy(&self, url: &str) -> EgressProxy {
        let scheme = url
            .split_once("://")
            .map(|(scheme, _)| scheme.to_ascii_lowercase())
            .unwrap_or_default();
        // A managed policy that selects no proxy is a direct connection, not
        // an invitation to read the environment: `session.trust_env` is false
        // whenever a managed policy applies.
        match self.proxies.get(&scheme) {
            Some(proxy) => EgressProxy::Url(proxy.clone()),
            None => EgressProxy::Direct,
        }
    }
}

/// `_canonical_hostname` (mdm/network_transport.py:131) over a whole URL:
/// one root-label dot is accepted and the name is IDNA-encoded so a Unicode
/// spelling of a refused registry compares equal to it.
fn canonical_hostname(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    let (host, _) = split_authority(authority)?;
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    idna::domain_to_ascii(host).ok().map(|ascii| {
        // `domain_to_ascii` lower-cases ASCII already; an IP literal passes
        // through unchanged.
        ascii.to_ascii_lowercase()
    })
}

/// Split `host[:port]`, keeping a bracketed IPv6 literal whole. `None` is a
/// netloc no parser would accept, such as `a:b:c`.
fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        return match after {
            "" => Some((host, None)),
            _ => Some((host, Some(after.strip_prefix(':')?))),
        };
    }
    match authority.split_once(':') {
        None => Some((authority, None)),
        Some((host, port)) if !port.contains(':') => Some((host, Some(port))),
        Some(_) => None,
    }
}

#[cfg(test)]
#[path = "egress_caller_policy_tests.rs"]
mod tests;
