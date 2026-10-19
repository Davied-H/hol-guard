//! Login and token code that lives in a directory named for it.
//!
//! `src/lib/auth`, `app/api/auth` and `packages/auth` hold a project's own
//! sign-in code, not stored credentials. The credential-path screen treats a
//! bare `auth` or `token` directory as a store, which is right for a file
//! under a home directory and wrong for a repository: reading the directory,
//! its `README.md` or its `package.json` was held for review.
//!
//! The exemption is narrow. It applies to a read, below a repository root,
//! of a directory listing (names only) or of a document or package manifest.
//! Every other screen still runs on the real path, and everything else under
//! such a directory (data files, extensionless files, anything a sibling
//! screen already refuses) keeps its review. Source files never needed it.

use std::path::{Component, Path, PathBuf};

/// Directory names that name a feature when they sit inside a repository.
const FEATURE_DIRECTORIES: [&str; 3] = ["auth", "authorization", "token"];

/// Documents and manifests that describe code and hold no stored value.
const DOCUMENT_EXTENSIONS: [&str; 3] = ["md", "mdx", "rst"];
const MANIFEST_NAMES: [&str; 2] = ["package.json", "tsconfig.json"];

const MAX_ANCESTORS: usize = 64;

/// True when the only reason `canonical` reads as credential-named is a
/// feature directory below a repository root, and what is read is a directory
/// or a document. The caller still applies every other path screen.
pub(super) fn feature_only_credential_name(canonical: &Path, home_dir: Option<&str>) -> bool {
    let is_directory = canonical.is_dir();
    if !is_directory && !document_or_manifest(canonical) {
        return false;
    }
    let Some(repository) = repository_root(canonical) else {
        return false;
    };
    // A dotfiles repository makes the home directory itself a work tree.
    let home = home_dir.and_then(|home| std::fs::canonicalize(home).ok());
    if home.is_some_and(|home| home == repository) {
        return false;
    }
    let Ok(relative) = canonical.strip_prefix(&repository) else {
        return false;
    };
    let parts: Vec<Component<'_>> = relative.components().collect();
    let mut neutral = repository.clone();
    let mut renamed = false;
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return false;
        };
        let Some(name) = name.to_str() else {
            return false;
        };
        let is_last = index + 1 == parts.len();
        let feature = FEATURE_DIRECTORIES.contains(&name.to_ascii_lowercase().as_str());
        if feature && (!is_last || is_directory) {
            renamed = true;
            neutral.push("feature");
        } else {
            neutral.push(name);
        }
    }
    renamed && !guard_secure_fs::credential_named_path(&neutral)
}

fn document_or_manifest(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    MANIFEST_NAMES.contains(&name.as_str())
        || Path::new(&name)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| DOCUMENT_EXTENSIONS.contains(&extension))
}

fn repository_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .take(MAX_ANCESTORS)
        .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
        .map(Path::to_path_buf)
}

#[cfg(all(test, unix))]
mod tests {
    use super::feature_only_credential_name;
    use std::path::{Path, PathBuf};

    struct Repository {
        root: PathBuf,
    }

    impl Drop for Repository {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn repository(name: &str, files: &[&str]) -> Repository {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/feature-directory-fixtures")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        for file in files {
            let target = root.join(file);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, "x\n").unwrap();
        }
        Repository { root }
    }

    fn exempt(repository: &Repository, relative: &str) -> bool {
        feature_only_credential_name(&repository.root.join(relative), None)
    }

    #[test]
    fn feature_directories_and_their_documents_are_not_credential_stores() {
        let repo = repository(
            "feature",
            &[
                "src/lib/auth/session.ts",
                "src/lib/auth/README.md",
                "packages/auth/package.json",
                "app/api/auth/email/login/route.ts",
                "src/lib/token/issue.ts",
            ],
        );
        for relative in [
            "src/lib/auth",
            "src/lib/auth/README.md",
            "packages/auth",
            "packages/auth/package.json",
            "app/api/auth",
            "app/api/auth/email",
            "app/api/auth/email/login",
            "src/lib/token",
        ] {
            assert!(exempt(&repo, relative), "{relative}");
        }
    }

    #[test]
    fn data_files_stores_and_other_folders_keep_their_review() {
        let repo = repository(
            "kept",
            &[
                "src/lib/auth/config.json",
                "src/lib/auth/session",
                "src/lib/auth/credentials.json",
                "src/lib/auth/oauth_tokens/session.json",
                "src/lib/secrets/store.md",
                "config/prod-secrets/notes.md",
                "playwright/.auth/user.json",
                "src/lib/plain/README.md",
            ],
        );
        for relative in [
            // Data and extensionless files under a feature directory.
            "src/lib/auth/config.json",
            "src/lib/auth/session",
            "src/lib/auth/credentials.json",
            // A store inside or beside it.
            "src/lib/auth/oauth_tokens",
            "src/lib/auth/oauth_tokens/session.json",
            "src/lib/secrets",
            "src/lib/secrets/store.md",
            "config/prod-secrets/notes.md",
            "playwright/.auth",
            "playwright/.auth/user.json",
            // Nothing named for a feature: the screen has nothing to relax.
            "src/lib/plain/README.md",
        ] {
            assert!(!exempt(&repo, relative), "{relative}");
        }
    }

    #[test]
    fn a_folder_that_is_not_a_repository_keeps_its_review() {
        // Outside this checkout, so no `.git` sits above it.
        let root = std::env::temp_dir().join(format!("hg-feature-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("auth")).unwrap();
        std::fs::write(root.join("auth/README.md"), "x\n").unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let verdicts = [
            feature_only_credential_name(&root.join("auth"), None),
            feature_only_credential_name(&root.join("auth/README.md"), None),
        ];
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(verdicts, [false, false]);
    }

    #[test]
    fn a_home_directory_that_is_a_work_tree_keeps_its_review() {
        let repo = repository("home", &["auth/README.md"]);
        let home = repo.root.to_str();
        assert!(!feature_only_credential_name(&repo.root.join("auth"), home));
        assert!(!feature_only_credential_name(
            &repo.root.join("auth/README.md"),
            home
        ));
    }
}
