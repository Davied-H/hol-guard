//! The managed-network rules the brokered egress caller performs exchanges
//! under: `validated_proxy_url`, `proxy_map`, the two OS proxy readers and
//! the destination refusal.

use super::*;
use crate::egress_caller::{EgressPolicy, EgressProxy, UnmanagedEgressPolicy};

fn explicit(url: &str) -> ManagedNetworkPolicy {
    ManagedNetworkPolicy {
        proxy_mode: ProxyMode::Explicit,
        proxy_url: Some(url.to_owned()),
        ca_bundle_path: None,
        allow_public_registries: true,
    }
}

#[test]
fn validated_proxy_url_normalises_host_and_port() {
    assert_eq!(
        validated_proxy_url("https://Proxy.Example:8443", true, "code"),
        Ok("https://proxy.example:8443".to_owned())
    );
    assert_eq!(
        validated_proxy_url("https://proxy.example", true, "code"),
        Ok("https://proxy.example:443".to_owned())
    );
    assert_eq!(
        validated_proxy_url("http://proxy.example/", false, "code"),
        Ok("http://proxy.example:80".to_owned())
    );
    assert_eq!(
        validated_proxy_url("https://[2001:DB8::1]:8443", true, "code"),
        Ok("https://[2001:db8::1]:8443".to_owned())
    );
}

#[test]
fn validated_proxy_url_refuses_unusable_spellings() {
    for value in [
        " https://proxy.example",
        "https://proxy.example ",
        "https://proxy\u{a0}.example",
        "https://proxy.example:",
        "https://proxy.example:0",
        "https://proxy.example:http",
        "https://proxy.example/path",
        "https://proxy.example/?q=1",
        "https://proxy.example/#frag",
        "https://",
        "proxy.example:8443",
        "socks5://proxy.example:1080",
    ] {
        assert_eq!(
            validated_proxy_url(value, true, "managed_proxy_url_invalid"),
            Err("managed_proxy_url_invalid"),
            "{value}"
        );
    }
}

#[test]
fn validated_proxy_url_requires_https_only_when_asked() {
    assert_eq!(
        validated_proxy_url("http://proxy.example:3128", true, "code"),
        Err("code")
    );
    assert_eq!(
        validated_proxy_url("http://proxy.example:3128", false, "code"),
        Ok("http://proxy.example:3128".to_owned())
    );
}

#[test]
fn validated_proxy_url_refuses_embedded_credentials_with_its_own_code() {
    assert_eq!(
        validated_proxy_url("https://user:secret@proxy.example:8443", true, "code"),
        Err("managed_proxy_credentials_forbidden")
    );
    assert_eq!(
        validated_proxy_url("https://user@proxy.example:8443", true, "code"),
        Err("managed_proxy_credentials_forbidden")
    );
}

#[test]
fn proxy_map_explicit_mode_covers_both_schemes() {
    let proxies = proxy_map(&explicit("https://proxy.example:8443")).expect("resolved");
    assert_eq!(
        proxies.get("http").map(String::as_str),
        Some("https://proxy.example:8443")
    );
    assert_eq!(
        proxies.get("https").map(String::as_str),
        Some("https://proxy.example:8443")
    );
}

#[test]
fn proxy_map_refuses_mode_and_url_contradictions() {
    let mut policy = explicit("https://proxy.example:8443");
    policy.proxy_mode = ProxyMode::None;
    assert_eq!(proxy_map(&policy), Err("managed_proxy_url_mode_mismatch"));
    policy.proxy_mode = ProxyMode::System;
    assert_eq!(proxy_map(&policy), Err("managed_proxy_url_mode_mismatch"));
    let missing = ManagedNetworkPolicy {
        proxy_mode: ProxyMode::Explicit,
        ..ManagedNetworkPolicy::unmanaged_default()
    };
    assert_eq!(proxy_map(&missing), Err("managed_proxy_url_required"));
    assert_eq!(
        proxy_map(&explicit("http://proxy.example:3128")),
        Err("managed_proxy_url_invalid")
    );
}

#[test]
fn proxy_map_without_a_proxy_is_empty() {
    let policy = ManagedNetworkPolicy {
        proxy_mode: ProxyMode::None,
        ..ManagedNetworkPolicy::unmanaged_default()
    };
    assert!(proxy_map(&policy).expect("resolved").is_empty());
}

#[test]
fn scutil_output_yields_the_enabled_schemes_only() {
    let stdout = concat!(
        "<dictionary> {\n",
        "  HTTPEnable : 1\n",
        "  HTTPProxy : proxy.example\n",
        "  HTTPPort : 3128\n",
        "  HTTPSEnable : 0\n",
        "  HTTPSProxy : secure.example\n",
        "  ExceptionsList : <array> {\n",
        "    0 : *.local\n",
        "  }\n",
        "}\n",
    );
    let proxies = parse_scutil_proxies(stdout);
    assert_eq!(
        proxies.get("http").map(String::as_str),
        Some("http://proxy.example:3128")
    );
    assert!(proxies.get("https").is_none());
}

#[test]
fn scutil_output_falls_back_to_the_scheme_default_port() {
    let stdout = "HTTPSEnable : 1\nHTTPSProxy : secure.example\n";
    assert_eq!(
        parse_scutil_proxies(stdout)
            .get("https")
            .map(String::as_str),
        Some("http://secure.example:443")
    );
}

#[test]
fn registry_values_and_dwords_parse() {
    let stdout = concat!(
        "\r\n",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\r\n",
        "    ProxyEnable    REG_DWORD    0x1\r\n",
        "    ProxyServer    REG_SZ    proxy.example:8080\r\n",
        "    AutoDetect    REG_DWORD    0x0\r\n",
    );
    let values = parse_reg_values(stdout);
    assert_eq!(
        values.get("proxyserver").map(String::as_str),
        Some("proxy.example:8080")
    );
    assert_eq!(
        parse_reg_dword(values.get("proxyenable").expect("present")),
        Some(1)
    );
    assert_eq!(
        parse_reg_dword(values.get("autodetect").expect("present")),
        Some(0)
    );
    assert_eq!(parse_reg_dword("12"), Some(12));
    assert_eq!(parse_reg_dword("not-a-number"), None);
}

#[test]
fn windows_proxy_server_covers_both_shapes() {
    assert_eq!(
        parse_windows_proxy_server("proxy.example:8080")
            .get("https")
            .map(String::as_str),
        Some("http://proxy.example:8080")
    );
    let per_scheme = parse_windows_proxy_server(
        "http=plain.example:80;https=secure.example:443;ftp=ftp.example:21",
    );
    assert_eq!(
        per_scheme.get("http").map(String::as_str),
        Some("http://plain.example:80")
    );
    assert_eq!(
        per_scheme.get("https").map(String::as_str),
        Some("http://secure.example:443")
    );
    assert!(per_scheme.get("ftp").is_none());
}

#[test]
fn managed_policy_refuses_public_registries_when_disabled() {
    let policy = ManagedEgressPolicy::resolve(&ManagedNetworkPolicy {
        proxy_mode: ProxyMode::None,
        proxy_url: None,
        ca_bundle_path: None,
        allow_public_registries: false,
    })
    .expect("resolved");
    assert_eq!(
        policy.validate("https://registry.npmjs.org/left-pad"),
        Err("managed_public_registry_disabled".to_owned())
    );
    // One root-label dot and a mixed-case spelling are the same destination.
    assert_eq!(
        policy.validate("https://PyPI.org./simple/requests/"),
        Err("managed_public_registry_disabled".to_owned())
    );
    assert_eq!(
        policy.validate("https://registry.internal.example/left-pad"),
        Ok(())
    );
}

#[test]
fn managed_policy_allows_public_registries_by_default() {
    let policy = ManagedEgressPolicy::resolve(&ManagedNetworkPolicy {
        proxy_mode: ProxyMode::None,
        ..ManagedNetworkPolicy::unmanaged_default()
    })
    .expect("resolved");
    assert_eq!(
        policy.validate("https://registry.npmjs.org/left-pad"),
        Ok(())
    );
}

#[test]
fn managed_policy_refuses_a_url_with_no_host() {
    let policy = ManagedEgressPolicy::resolve(&ManagedNetworkPolicy {
        proxy_mode: ProxyMode::None,
        ..ManagedNetworkPolicy::unmanaged_default()
    })
    .expect("resolved");
    for url in ["https:///simple/", "not-a-url", "https://a:b:c/x"] {
        assert_eq!(
            policy.validate(url),
            Err("managed_destination_invalid".to_owned()),
            "{url}"
        );
    }
}

#[test]
fn managed_policy_selects_the_scheme_proxy_and_never_the_environment() {
    let policy =
        ManagedEgressPolicy::resolve(&explicit("https://proxy.example:8443")).expect("resolved");
    assert!(matches!(
        policy.proxy("https://registry.npmjs.org/left-pad"),
        EgressProxy::Url(url) if url == "https://proxy.example:8443"
    ));
    let direct = ManagedEgressPolicy::resolve(&ManagedNetworkPolicy {
        proxy_mode: ProxyMode::None,
        ..ManagedNetworkPolicy::unmanaged_default()
    })
    .expect("resolved");
    assert!(matches!(
        direct.proxy("https://registry.npmjs.org/left-pad"),
        EgressProxy::Direct
    ));
}

#[test]
fn an_unmanaged_caller_keeps_the_environment_proxy() {
    assert!(matches!(
        UnmanagedEgressPolicy.proxy("https://registry.npmjs.org/left-pad"),
        EgressProxy::Environment
    ));
}
