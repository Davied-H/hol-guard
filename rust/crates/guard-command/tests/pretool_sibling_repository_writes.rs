#![cfg(unix)]

//! A session started in a folder above its checkouts, or beside the one it
//! edits, still writes that repository through the shell the way a file-edit
//! tool does: `cat /tmp/x.ts > <clone>/src/lib/y.ts`, an append, a quoted
//! heredoc, or a staging copy followed by a write. Hooks, settings,
//! credential files, links and executables keep their review, and so does any
//! folder that is not a repository. Instruction files are judged as they are
//! inside a repository.

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::git_helper_fixture::{self as fixture, evaluate_pre_tool_envelope_with_context};

struct Layout {
    root: PathBuf,
    home: PathBuf,
    /// The session folder: a plain directory above the checkouts.
    session: PathBuf,
    clone: PathBuf,
    notes: PathBuf,
    scratch: PathBuf,
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn layout(name: &str) -> Layout {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/omp-redirect-fixtures")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let home = fixture::canonical_spelling(&root).join("home");
    let session = home.join("work");
    let clone = home.join("acme-app-clone");
    let notes = home.join("plain-notes");
    for directory in [
        session.clone(),
        notes.clone(),
        clone.join("src/lib"),
        clone.join("src/api/login"),
        clone.join("scripts"),
        clone.join(".git/hooks"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(clone.join("src/lib/auth.ts"), "export const auth = 1;\n").unwrap();
    std::fs::write(clone.join(".env"), "SESSION_KEY=synthetic\n").unwrap();
    std::fs::write(clone.join("AGENTS.md"), "rules\n").unwrap();
    std::fs::write(clone.join(".git/config"), "[core]\n").unwrap();
    std::fs::write(clone.join("scripts/run.sh"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        clone.join("scripts/run.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::write(notes.join("a.md"), "notes\n").unwrap();
    std::fs::write(home.join(".zshrc"), "export PATH\n").unwrap();
    symlink(home.join(".zshrc"), clone.join("src/lib/link.ts")).unwrap();
    symlink(&notes, clone.join("linked")).unwrap();
    let scratch = PathBuf::from(format!("/tmp/hg-redirect-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(scratch.join("x.ts"), "export const x = 1;\n").unwrap();
    std::fs::write(scratch.join("a.ts"), "export const a = 1;\n").unwrap();
    Layout {
        root,
        home,
        session,
        clone,
        notes,
        scratch,
    }
}

fn permitted(layout: &Layout, cwd: &Path, command: &str) -> bool {
    let evaluate = |harness| {
        let result = evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            layout.home.to_str(),
            cwd.to_str(),
        );
        result.decision == "allow" && matches!(result.minimum_action.as_str(), "allow" | "warn")
    };
    let omp = evaluate("omp");
    assert_eq!(omp, evaluate("zcode"), "host policy drift: {command}");
    omp
}

#[test]
fn redirects_into_a_sibling_clone_are_the_edits_a_file_tool_makes() {
    let layout = layout("allowed");
    let (clone, scratch) = (layout.clone.display(), layout.scratch.display());
    for command in [
        format!("cat {scratch}/x.ts > {clone}/src/lib/y.ts"),
        format!("cat {scratch}/x.ts > {clone}/src/api/login/route.ts"),
        format!("cat {scratch}/x.ts > {clone}/src/lib/auth.ts"),
        format!("cat {scratch}/x.ts >> {clone}/src/lib/auth.ts"),
        format!("cat {scratch}/x.ts >> {clone}/src/lib/y.ts"),
        format!("cat > {clone}/notes.md <<'EOF'\n# Pending\n- a\nEOF"),
        format!("cat > {clone}/.pending-edits.md <<'EOF'\n# Pending\n- a\nEOF"),
        format!("cat >> {clone}/notes.md <<'EOF'\n- b\nEOF"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {clone}/src/lib/y.ts"),
        format!(
            "cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts >> {clone}/src/lib/auth.ts"
        ),
    ] {
        assert!(permitted(&layout, &layout.session, &command), "{command}");
    }
}

#[test]
fn a_staging_copy_before_a_write_is_allowed_in_an_ordinary_session_folder_too() {
    let layout = layout("ordinary");
    let scratch = layout.scratch.display();
    for command in [
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > src/lib/y.ts"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts >> src/lib/auth.ts"),
        format!("ls src && cat {scratch}/x.ts > src/lib/y.ts"),
        format!("cat {scratch}/x.ts > src/lib/y.ts"),
    ] {
        assert!(permitted(&layout, &layout.clone, &command), "{command}");
    }
}

#[test]
fn protected_targets_links_and_other_folders_keep_their_review() {
    let layout = layout("reviewed");
    let (clone, scratch) = (layout.clone.display(), layout.scratch.display());
    let (home, notes) = (layout.home.display(), layout.notes.display());
    let mut wrongly_allowed = Vec::new();
    for command in [
        // Git control files, hooks, dotenv and harness settings.
        format!("cat {scratch}/x.ts > {clone}/.git/config"),
        format!("cat {scratch}/x.ts >> {clone}/.git/hooks/pre-commit"),
        format!("cat {scratch}/x.ts >> {clone}/.env"),
        format!("cat {scratch}/x.ts > {clone}/.husky/pre-commit"),
        format!("cat {scratch}/x.ts > {clone}/.claude/settings.json"),
        // Existing programs are not truncated, and links are not followed.
        format!("cat {scratch}/x.ts > {clone}/scripts/run.sh"),
        format!("cat {scratch}/x.ts > {clone}/src/lib/link.ts"),
        format!("cat {scratch}/x.ts > {clone}/linked/a.md"),
        // A folder that is not a repository, the home itself and its dotfiles.
        format!("cat {scratch}/x.ts > {notes}/a.md"),
        format!("cat {scratch}/x.ts > {notes}/b.md"),
        format!("cat {scratch}/x.ts > {home}/notes.md"),
        format!("cat {scratch}/x.ts >> {home}/.zshrc"),
        // The same boundaries hold for heredocs.
        format!("cat > {clone}/.git/hooks/pre-commit <<'EOF'\nexit 0\nEOF"),
        format!("cat > {clone}/.env <<'EOF'\nX=1\nEOF"),
        format!("cat > {notes}/b.md <<'EOF'\nx\nEOF"),
        format!("cat > {home}/.zshrc <<'EOF'\nexport X=1\nEOF"),
        format!("cat > {clone}/src/lib/link.ts <<'EOF'\nx\nEOF"),
        // A staging chain keeps every one of them, and any step that could
        // change directory or create a link first.
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {clone}/.git/hooks/pre-commit"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {home}/.zshrc"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {clone}/.env"),
        format!("cp {scratch}/a.ts {scratch}/b.ts && cat {scratch}/a.ts > {notes}/b.md"),
        format!("ln -s {home}/.zshrc {clone}/src/lib/l.ts && cat {scratch}/a.ts > {clone}/src/lib/l.ts"),
    ] {
        if permitted(&layout, &layout.session, &command) {
            wrongly_allowed.push(command);
        }
    }
    assert!(wrongly_allowed.is_empty(), "{wrongly_allowed:#?}");
}

#[test]
fn instruction_file_heredocs_are_not_held_where_redirects_are_not() {
    // The same write as the redirect form: a repository session runs the
    // heredoc inside its sandbox, and a session folder has no sandbox around
    // the clone, so the target checks stand in for it.
    let layout = layout("instruction-heredoc");
    let clone = layout.clone.display();
    let command = format!("cat > {clone}/AGENTS.md <<'EOF'\nmore rules\nEOF");
    assert!(permitted(&layout, &layout.session, &command), "{command}");
}

#[test]
fn instruction_file_redirects_are_judged_as_from_inside_the_repository() {
    // A plain redirect into an instruction file is a warning in a repository
    // session; the session folder must not read it any looser or any tighter.
    let layout = layout("instructions");
    let (clone, scratch) = (layout.clone.display(), layout.scratch.display());
    for (outside, inside) in [
        (
            format!("cat {scratch}/x.ts >> {clone}/AGENTS.md"),
            format!("cat {scratch}/x.ts >> AGENTS.md"),
        ),
        (
            format!("cat {scratch}/x.ts > {clone}/AGENTS.md"),
            format!("cat {scratch}/x.ts > AGENTS.md"),
        ),
    ] {
        assert_eq!(
            permitted(&layout, &layout.session, &outside),
            permitted(&layout, &layout.clone, &inside),
            "{outside}"
        );
    }
}
