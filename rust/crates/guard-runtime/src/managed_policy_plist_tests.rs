//! Both plist serialisations must read back as the same document, because a
//! profile delivered by macOS configuration management is binary while a
//! hand-written one is XML.

use super::*;
use serde_json::json;

/// `plutil -convert binary1` of the same document the XML case carries.
const BINARY: &[u8] = include_bytes!("../testdata/managed_policy/binary-policy.plist");

const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>daemonStartup</key>
	<string>login</string>
	<key>lockedSettings</key>
	<array>
		<string>mode</string>
	</array>
	<key>network</key>
	<dict>
		<key>allowPublicRegistries</key>
		<false/>
		<key>proxyMode</key>
		<string>explicit</string>
		<key>proxyUrl</key>
		<string>https://proxy.example.com:8443</string>
	</dict>
	<key>requiredHarnesses</key>
	<array>
		<string>claude-code</string>
	</array>
	<key>schemaVersion</key>
	<string>hol-guard-mdm-policy.v1</string>
	<key>settings</key>
	<dict>
		<key>mode</key>
		<string>enforce</string>
		<key>nested</key>
		<dict>
			<key>actions</key>
			<dict>
				<key>shell</key>
				<string>block</string>
			</dict>
		</dict>
		<key>ratio</key>
		<real>0.5</real>
		<key>retries</key>
		<integer>3</integer>
		<key>sync</key>
		<false/>
	</dict>
</dict>
</plist>
"#;

fn document() -> Value {
    json!({
        "schemaVersion": "hol-guard-mdm-policy.v1",
        "daemonStartup": "login",
        "lockedSettings": ["mode"],
        "requiredHarnesses": ["claude-code"],
        "network": {
            "proxyMode": "explicit",
            "proxyUrl": "https://proxy.example.com:8443",
            "allowPublicRegistries": false,
        },
        "settings": {
            "mode": "enforce",
            "sync": false,
            "retries": 3,
            "ratio": 0.5,
            "nested": {"actions": {"shell": "block"}},
        },
    })
}

#[test]
fn the_binary_profile_reads_as_the_policy_document() {
    assert_eq!(parse_plist(BINARY).expect("binary plist"), document());
}

#[test]
fn the_xml_profile_reads_as_the_same_document() {
    assert_eq!(
        parse_plist(XML.as_bytes()).expect("xml plist"),
        document(),
        "both serialisations are the same policy"
    );
}

#[test]
fn a_value_no_policy_can_carry_is_refused_rather_than_guessed() {
    // Python turns these into `bytes` and `datetime`, which the typed fields
    // reject and the canonical hash cannot serialise.
    for (fragment, expected) in [
        (
            "<data>aGk=</data>",
            "managed policy plist holds binary data",
        ),
        (
            "<date>2026-10-16T00:00:00Z</date>",
            "managed policy plist holds a date",
        ),
    ] {
        let document =
            format!("<plist version=\"1.0\"><dict><key>settings</key>{fragment}</dict></plist>");
        assert_eq!(
            parse_plist(document.as_bytes()).expect_err("refused"),
            expected
        );
    }
}

#[test]
fn a_document_that_is_not_a_plist_is_not_read_as_one() {
    for (bytes, expected) in [
        (
            b"{\"schemaVersion\": \"x\"}".to_vec(),
            "managed policy is not a valid plist",
        ),
        (
            b"<other><dict/></other>".to_vec(),
            "managed policy is not a plist document",
        ),
        (
            b"<plist version=\"1.0\"></plist>".to_vec(),
            "managed policy plist is empty",
        ),
        (
            b"<plist version=\"1.0\"><dict/><dict/></plist>".to_vec(),
            "managed policy plist has more than one value",
        ),
        (
            b"<plist version=\"1.0\"><dict><string>v</string></dict></plist>".to_vec(),
            "managed policy plist has a value without a key",
        ),
        (
            b"<plist version=\"1.0\"><dict><key>k</key></dict></plist>".to_vec(),
            "managed policy plist has a key without a value",
        ),
    ] {
        assert_eq!(
            parse_plist(&bytes).expect_err("refused"),
            expected,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[test]
fn a_truncated_binary_plist_is_refused_before_it_is_indexed() {
    // Too short to hold a trailer at all.
    assert_eq!(
        parse_plist(&BINARY[..30]).expect_err("refused"),
        "managed policy is not a valid plist"
    );

    let mut torn = BINARY.to_vec();
    // The object-table offset is the last eight bytes of the trailer.
    let table = torn.len() - 8;
    torn[table..].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        parse_plist(&torn).expect_err("refused"),
        "managed policy plist has an unreadable object table"
    );
}

#[test]
fn nesting_past_the_bound_is_refused() {
    let depth = MAX_DEPTH + 2;
    let mut document = String::from("<plist version=\"1.0\">");
    document.push_str(&"<array>".repeat(depth));
    document.push_str("<string>deep</string>");
    document.push_str(&"</array>".repeat(depth));
    document.push_str("</plist>");
    assert_eq!(
        parse_plist(document.as_bytes()).expect_err("refused"),
        "managed policy plist nests too deeply"
    );
}
