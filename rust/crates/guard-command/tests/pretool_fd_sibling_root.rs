//! `fd` rooted in a neighbouring repository: `fd -e tsx . ~/Code/org/service-api`.
//! `fd` prints names, skips hidden entries and honours the repository's ignore
//! rules, which is the walk an `rg` root already proves, so the two roots get
//! the same decision. A tree that could name a credential, or one reached
//! through a link out of the repository, keeps its review.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn a_names_only_search_of_a_sibling_repository_is_allowed() {
    let layout = layout("fd-sibling-root");
    let sibling = layout.org.join("service-api");
    write(sibling.join("app/badge/page.tsx"), "export const x = 1;\n");
    write(sibling.join("tests/journey/runner.spec.ts"), "fixture\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "fd . ~/Code/org/service-api",
        "fd -e tsx . ~/Code/org/service-api",
        "fd runner ~/Code/org/service-api/tests",
        "fd --max-depth 2 . ~/Code/org/service-api/app",
        "fd . ../service-api",
        "fd . ~/Code/org/service-api | head -20",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn a_sibling_tree_that_could_name_a_secret_is_reviewed() {
    let layout = layout("fd-sibling-secret");
    let sibling = layout.org.join("service-api");
    write(sibling.join("config/service.pem"), "SYNTHETIC KEY\n");
    write(layout.home.join(".ssh/id_rsa"), "fixture\n");
    std::os::unix::fs::symlink(layout.home.join(".ssh"), sibling.join("keys")).unwrap();
    let cwd = layout.org.join("app-portal");
    for command in [
        "fd . ~/Code/org/service-api/config",
        "fd . ~/Code/org/service-api/keys",
        // A hidden directory of the home directory is no repository's tree.
        "fd . ~/.ssh",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
}

#[test]
fn an_option_that_widens_the_listing_keeps_its_review() {
    let layout = layout("fd-sibling-widening");
    write(
        layout.org.join("service-api/app/badge/page.tsx"),
        "export const x = 1;\n",
    );
    let cwd = layout.org.join("app-portal");
    for command in [
        // `--hidden` prints the entries the walk proves nothing about.
        "fd --hidden . ~/Code/org/service-api",
        // `--follow` leaves the tree the walk measured.
        "fd --follow . ~/Code/org/service-api",
        // `--exec` runs a program per match rather than printing a name.
        "fd . ~/Code/org/service-api --exec cat {}",
        // `--no-ignore` searches what the repository's ignore rules exclude.
        "fd --no-ignore . ~/Code/org/service-api",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
}
