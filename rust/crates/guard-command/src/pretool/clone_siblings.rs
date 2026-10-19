//! Whether two checkouts are clones of one repository. A `git clone` of a
//! local checkout records that checkout's path as its origin, and a second
//! clone of a hosted repository records the same URL, so the remote URLs the
//! two configurations name show the relationship without running Git.

use std::path::Path;

/// `first` and `second` are canonical work tree roots of different checkouts
/// with plain, readable configurations, and either names the other as a
/// remote or both name one remote URL.
pub(super) fn related_clones(first: &Path, second: &Path) -> bool {
    if first == second {
        return false;
    }
    let (Some(first_urls), Some(second_urls)) = (
        super::workspace_git_config::remote_urls(first),
        super::workspace_git_config::remote_urls(second),
    ) else {
        return false;
    };
    first_urls.iter().any(|url| names_checkout(url, second))
        || second_urls.iter().any(|url| names_checkout(url, first))
        || first_urls
            .iter()
            .any(|url| !url.is_empty() && second_urls.contains(url))
}

/// A remote URL that is the absolute path of the checkout at `root`, or of
/// its `.git` directory.
fn names_checkout(url: &str, root: &Path) -> bool {
    let path = url.strip_prefix("file://").unwrap_or(url);
    if !path.starts_with('/') {
        return false;
    }
    std::fs::canonicalize(path.trim_end_matches('/'))
        .is_ok_and(|named| named == root || named == root.join(".git"))
}
