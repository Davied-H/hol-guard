//! Assignment values that name where a credential comes from, not the credential.
//!
//! Source files read keys from the environment (`process.env.API_KEY`),
//! declare their types (`apiKey: string`) and document the variables they
//! need (`API_KEY=key_...`, `TOKEN=<your-token>`). Each shape matches the
//! credential assignment rule, but none carries secret material, so reading
//! ordinary source that configures a client stopped agents mid-task.

use regex::Regex;
use std::sync::LazyLock;

static REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // Environment lookups, with only identifier, index and call syntax
        // after them, so an appended literal is not hidden behind one.
        r"^(?:(?:process\.env|import\.meta\.env|Bun\.env|os\.environ)(?:\.[A-Za-z_][A-Za-z0-9_]*|\[)?",
        r"|(?:os\.getenv|os\.environ\.get|Deno\.env\.get|(?:std::)?env::var)\()",
        r"[A-Za-z0-9_\[\]()]*;?$",
        // Type annotations.
        r"|^(?:string|number|boolean|bigint|unknown|any|never|null|undefined|str|bytes|bool|None|String|SecretStr)(?:\[\])?[;)>|]?$",
        // Shell variable references.
        r"|^\$\{?[A-Za-z_][A-Za-z0-9_]*$",
        // Documentation placeholders: a short visible prefix and an ellipsis,
        // or a bracketed name.
        r"|^[A-Za-z0-9_-]{0,12}(?:\.\.\.|…)[\])>;]*$",
        r"|^<[A-Za-z0-9_.-]{1,64}>[;)]*$",
    ))
    .expect("credential reference rule must compile")
});

/// Whether an assignment value is a reference or placeholder, not a credential.
pub(crate) fn is_reference(value: &str) -> bool {
    REFERENCE.is_match(value)
}

#[cfg(test)]
mod tests {
    use super::is_reference;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn credential_assignment(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
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
            "key_...",
            "...",
            "...]",
            "sk-ant-…",
            "<your-token>",
        ] {
            assert!(is_reference(value), "{value:?}");
        }
        for value in [
            "key_a1b2c3d4e5f6g7h8i9j0",
            "process.env.API_KEY||sk_live_value",
            "processXenv.API_KEY",
            "stringly-typed-secret",
            "key_a1b2c3d4e5f6g7h8i9j0...",
            "$(gh",
            "<a1b2 c3d4>",
        ] {
            assert!(!is_reference(value), "{value:?}");
        }
    }

    #[test]
    fn client_configuration_source_is_not_a_credential() {
        let source = "/**\n *   ANALYTICS_API_KEY=key_... ANALYTICS_PROJECT_ID=1 \\\n *   \
            DATABASE_URL=postgres://... [ANALYTICS_API_KEY=...] \\\n */\n\
            const PERSONAL_API_KEY = process.env.ANALYTICS_API_KEY;\n\
            function client(\n  apiKey: string,\n  token: string | undefined,\n) {}\n\
            export API_TOKEN=$CI_API_TOKEN\n";
        assert!(!credential_assignment(source));
    }

    #[test]
    fn literal_credentials_beside_references_still_match() {
        for text in [
            "const PERSONAL_API_KEY = process.env.ANALYTICS_API_KEY;\nconst token = \"key_a1b2c3d4e5f6g7h8\";",
            "apiKey: string,\npassword = hunter2-production-value",
            "API_KEY=key_a1b2c3d4e5f6g7h8i9j0",
        ] {
            assert!(credential_assignment(text), "{text:?}");
        }
    }
}
