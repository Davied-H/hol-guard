#![cfg(unix)]

//! Searches of framework route paths, which are spelled with brackets.
//!
//! `app/blog/[slug]/page.tsx` is one file in a Next.js application, and the
//! bracket class matches no entry, so the shell hands `rg` the word as typed.
//! Such a search is screened as the path it names; a class that could match
//! something else, or a route holding a secret, keeps its review.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture() -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rg-literal-route")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let app = home.join("portal");
    std::fs::create_dir_all(app.join(".git")).unwrap();
    for file in [
        "app/blog/[slug]/page.tsx",
        "app/blog/[slug]/opengraph-image.tsx",
        "app/[locale]/layout.tsx",
        "app/dashboard/page.tsx",
        "src/main.ts",
    ] {
        write(app.join(file), "export default function Page() {}\n");
    }
    // A route that keeps a local environment file beside its component.
    write(app.join("app/admin/[id]/page.tsx"), "export default 1;\n");
    write(app.join("app/admin/[id]/.env"), "TOKEN=fixture\n");
    write(app.join(".gitignore"), ".env\n");
    Fixture { root, home }
}

fn check(f: &Fixture, command: &str, want_allow: bool) {
    let cwd = f.home.join("portal");
    let result: PreToolResultV1 = evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        f.home.to_str(),
        cwd.to_str(),
    );
    assert_eq!(
        result.minimum_action,
        if want_allow { "allow" } else { "review" },
        "{command}: {} {}",
        result.minimum_action,
        result.reason_code
    );
}

#[test]
fn searches_of_bracketed_route_paths_are_allowed() {
    let f = fixture();
    for command in [
        // A home-rooted route is the spelling an agent working from a
        // multi-repository parent types, and the screens it has to clear.
        "rg -n useRouter ~/portal/app/blog/[slug]/page.tsx",
        "rg -n useRouter ~/portal/app/blog/[slug]",
        "rg -ln export ~/portal/app/[locale]",
        "rg -n export ~/portal/app/[locale]/layout.tsx ~/portal/app/blog/[slug]/page.tsx",
        // The cwd-relative spellings of the same searches.
        "rg -n useRouter app/blog/[slug]/page.tsx",
        "rg -n export app/[locale] src",
    ] {
        check(&f, command, true);
    }
}

#[test]
fn bracketed_searches_that_could_reach_more_keep_their_review() {
    let f = fixture();
    for command in [
        // The route keeps an environment file, so the tree below it is not
        // ordinary and the walk gives no proof.
        "rg -n TOKEN ~/portal/app/admin/[id]",
        // A negated class is this matcher's own refusal, not a literal name.
        "rg -n export ~/portal/app/[!x]",
        // Nothing is there to screen, so there is no proof to give.
        "rg -n export ~/portal/app/blog/[missing]/page.tsx",
        // A class that can match a leading dot would name a hidden entry
        // under `dotglob`.
        "rg -n export ~/portal/app/[,-0]",
        // A parent component leaves the tree whose rules were inspected.
        "rg -n export ../portal/app/[locale]",
    ] {
        check(&f, command, false);
    }
}
