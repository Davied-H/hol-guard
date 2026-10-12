//! Names-only listing of the Oh My Pi agent home (`~/.agent`).
use super::tree::{expanded_operand, walk, HAZARDS};
use super::ReadContext;

/// Oh My Pi keeps user skills and session artifacts under `~/.agent`, and
/// agents list that root to find them. A listing prints entry names, never
/// contents, so `ls ~/.agent` and `ls -R ~/.agent` are allowed when the
/// operand names exactly the verified home's `.agent` directory and that
/// directory is real (not a link). A recursive listing still walks every
/// descendant under the same screens as any other `ls -R`. Content searches
/// do not use this proof, so `grep -r` rooted there still asks.
pub(in crate::pretool) fn agent_home_listing_root(
    value: &str,
    context: ReadContext<'_>,
    recursive: bool,
) -> bool {
    if !value.starts_with(['/', '~'])
        || value.len() > 4096
        || value.contains(HAZARDS)
        || value.contains(['*', '?', '[', ']', '{', '}'])
        || value.split('/').any(|part| part == "..")
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let Some(agent) = context
        .home_dir
        .and_then(|home| std::fs::canonicalize(home).ok())
        .map(|home| home.join(".agent"))
    else {
        return false;
    };
    let Some(root) = expanded_operand(value, context) else {
        return false;
    };
    std::fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.is_dir())
        && std::fs::canonicalize(&root).is_ok_and(|canonical| canonical == agent)
        && (!recursive || walk(root, &[], &[], false))
}
