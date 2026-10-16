//! Which hidden paths hold credentials.
//!
//! A read of a hidden path used to be reviewed whatever it named, so listing
//! `~/.claude/skills` or reading an editor's settings asked for approval as
//! often as reading `~/.aws/credentials`. The leading dot says the directory is
//! out of the way, not that it holds a secret: the stores worth a prompt are a
//! known set, and everything else under a dot is ordinary configuration.
//!
//! A read is not an exfiltration by itself. What leaves the machine is still
//! judged where it leaves, so this list names the files whose contents are a
//! credential, and the directories that exist to hold them.

/// Path components that name a credential store outright.
const CREDENTIAL_PARTS: &[&str] = &[
    ".1password",
    ".authinfo",
    ".aws",
    ".azure",
    ".boto",
    ".chef",
    ".docker",
    ".git-credentials",
    ".gnupg",
    ".gpg",
    ".hol-guard",
    ".kube",
    ".msmtprc",
    ".mozilla",
    ".my.cnf",
    ".netrc",
    ".npmrc",
    ".op",
    ".password-store",
    ".pgpass",
    ".pypirc",
    ".s3cfg",
    ".ssh",
    ".terraform.d",
    ".thunderbird",
    ".vault-token",
    "auth.json",
    "gcloud",
    "keychains",
    "keyrings",
];

/// Component prefixes: `.env.local` and `credentials.toml` are the same store
/// as `.env` and `credentials`.
const CREDENTIAL_PREFIXES: &[&str] = &[
    ".env",
    "credentials",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
];

/// Suffixes of files whose contents are a key.
const CREDENTIAL_SUFFIXES: &[&str] = &[
    ".asc",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
    ".ppk",
];

/// Directory pairs where the parent alone is ordinary: `~/.config` holds an
/// editor's settings next to a token for the GitHub CLI.
const CREDENTIAL_PAIRS: &[&str] = &[
    ".config/doctl",
    ".config/gcloud",
    ".config/gh",
    ".config/hub",
    ".config/op",
    ".git/config",
    ".local/share/keyrings",
    "library/keychains",
];

/// A component read without the shell punctuation that can ride along with
/// it: `~/.ssh)` closes a substitution and still names the same directory.
fn bare(part: &str) -> &str {
    part.trim_matches(|character: char| {
        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-')
    })
}

/// Whether this already-lowered path component names a credential store.
pub fn credential_store_part(raw: &str) -> bool {
    let part = bare(raw);
    CREDENTIAL_PARTS.contains(&part)
        || CREDENTIAL_PREFIXES
            .iter()
            .any(|prefix| part == *prefix || part.starts_with(&format!("{prefix}.")))
        || CREDENTIAL_SUFFIXES
            .iter()
            .any(|suffix| part.ends_with(suffix))
}

/// Whether these already-lowered path components reach a credential store,
/// either by naming one or by walking into one of the stores that share a
/// directory with ordinary configuration.
pub fn credential_store_path(parts: &[String]) -> bool {
    if parts.iter().any(|part| credential_store_part(part)) {
        return true;
    }
    let joined = parts
        .iter()
        .map(|part| bare(part))
        .collect::<Vec<&str>>()
        .join("/");
    CREDENTIAL_PAIRS.iter().any(|pair| {
        joined == *pair
            || joined.starts_with(&format!("{pair}/"))
            || joined.contains(&format!("/{pair}/"))
            || joined.ends_with(&format!("/{pair}"))
    })
}
