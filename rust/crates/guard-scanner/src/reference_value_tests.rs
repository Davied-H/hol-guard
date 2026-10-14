use super::is_reference;
use crate::scan_text;
use guard_rules::MAX_SCAN_BYTES;

/// A literal credential value, assembled at run time so the repository holds
/// no secret-shaped text.
fn literal() -> String {
    ["hunter2", "-production", "-value"].concat()
}

fn key_literal() -> String {
    ["key_", "a1b2c3d4", "e5f6g7h8", "i9j0"].concat()
}

fn credential_assignment(text: &str) -> bool {
    scan_text(text, true, true, MAX_SCAN_BYTES, None)
        .matches
        .iter()
        .any(|matched| matched.classifier == "credential-assignment")
}

fn reference(value: &str) -> bool {
    is_reference(&format!("token={value}"), "")
}

#[test]
fn references_carry_no_secret() {
    for value in [
        "process.env.ANALYTICS_API_KEY;",
        "process.env[",
        "import.meta.env.VITE_API_KEY",
        "os.environ[",
        "os.getenv(",
        "env::var(",
        "string",
        "string;",
        "String>",
        "$GITHUB_TOKEN",
        "${NPM_TOKEN",
        "${NPM_TOKEN}",
        "${GITHUB_TOKEN:-}",
        "${DEPLOY_TOKEN:-0}",
        "$2",
        "-",
        "-0",
        "sys.argv[2]",
        "process.argv[1]",
        "\"$2\"",
        "\"${GITHUB_TOKEN:-}\"",
        "\"$GITHUB_TOKEN\"",
        "key_...",
        "...",
        "...]",
        "sk-ant-…",
        "<your-token>",
        "\"<your-token>\"",
        "'key_...'",
    ] {
        assert!(reference(value), "{value:?}");
    }
    let key = key_literal();
    let appended = format!("process.env.API_KEY||{key}");
    let ellipsis = format!("{key}...");
    for value in [
        key.as_str(),
        appended.as_str(),
        "processXenv.API_KEY",
        "stringly-typed-secret",
        ellipsis.as_str(),
        "$(gh",
        "${TOKEN:-key_a1b2c3d4}",
        "${TOKEN:=0}",
        "$12",
        "-1234",
        "-a1b2c3",
        "sys.argv[2]+key",
        "<a1b2 c3d4>",
    ] {
        assert!(!reference(value), "{value:?}");
    }
}

#[test]
fn quoted_values_are_literals_not_references() {
    for value in [
        "\"$uperSecret99\"",
        "'$Secr3tPass'",
        "\"process.env.API_KEY\"",
        "'string'",
        "'$GITHUB_TOKEN'",
    ] {
        assert!(!reference(value), "{value:?}");
    }
    assert!(credential_assignment("password = \"$uperSecret99\""));
    assert!(credential_assignment("password = '$Secr3tPass'"));
}

#[test]
fn dotenv_values_that_start_with_a_dollar_stay_literals() {
    assert!(credential_assignment("DB_PASSWORD=$Pa55word\n"));
    assert!(credential_assignment("API_TOKEN=$uperSecret99\n"));
    assert!(!credential_assignment("export API_TOKEN=$CI_API_TOKEN\n"));
    assert!(!credential_assignment("NPM_TOKEN=${NPM_TOKEN}\n"));
}

#[test]
fn literals_after_a_reference_on_the_same_line_still_match() {
    let secret = literal();
    for text in [
        format!("API_KEY: str = \"{secret}\""),
        format!("const apiKey: string = \"{secret}\";"),
        format!("api_key: SecretStr = \"{secret}\""),
        format!("function client(apiKey: string = '{secret}') {{}}"),
        format!("TOKEN = os.getenv(\"TOKEN\", \"{secret}\")"),
        format!("auth_token = os.environ.get(\"AUTH_TOKEN\") or \"{secret}\""),
        format!("api_key = os.environ[\"API_KEY\"] if prod else \"{secret}\""),
        format!("const API_KEY = process.env.API_KEY || \"{secret}\";"),
        format!("const API_KEY = process.env.API_KEY ?? `{secret}`;"),
        format!("let token = std::env::var(\"TOKEN\").unwrap_or(\"{secret}\".into());"),
    ] {
        assert!(credential_assignment(&text), "{text:?}");
    }
}

#[test]
fn references_without_a_hidden_literal_stay_allowed() {
    let other = literal();
    for text in [
        "api_key: str = os.environ[\"API_KEY\"]".to_string(),
        "TOKEN = os.getenv(\"TOKEN\", \"\")".to_string(),
        "const apiKey: string = process.env.API_KEY ?? \"\";".to_string(),
        "const API_KEY = process.env.API_KEY;".to_string(),
        format!("def client(api_key: str, model: str = \"{other}\"):"),
        format!("function client(apiKey: string) {{ return \"{other}\"; }}"),
        format!("const token = process.env.TOKEN; const label = \"{other}\";"),
    ] {
        assert!(!credential_assignment(&text), "{text:?}");
    }
}

#[test]
fn client_configuration_source_is_not_a_credential() {
    let source = "/**\n *   ANALYTICS_API_KEY=key_... ANALYTICS_PROJECT_ID=1 \\\n *   \
        DATABASE_URL=postgres://... [ANALYTICS_API_KEY=...] \\\n */\n\
        const PERSONAL_API_KEY = process.env.ANALYTICS_API_KEY;\n\
        function client(\n  apiKey: string,\n  token: string | undefined,\n) {}\n\
        export API_TOKEN=$CI_API_TOKEN\n\
        rotate() {\n  local new_password=\"$2\"\n  \
        if [ -z \"${GITHUB_TOKEN:-}\" ]; then return; fi\n}\n\
        new_password = sys.argv[2]\n";
    assert!(!credential_assignment(source));
}

#[test]
fn literal_credentials_beside_references_still_match() {
    let key = key_literal();
    let secret = literal();
    for text in [
        format!(
            "const PERSONAL_API_KEY = process.env.ANALYTICS_API_KEY;\nconst token = \"{key}\";"
        ),
        format!("apiKey: string,\npassword = {secret}"),
        format!("API_KEY={key}"),
    ] {
        assert!(credential_assignment(&text), "{text:?}");
    }
}
