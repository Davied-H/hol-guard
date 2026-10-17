//! A sibling repository named one file at a time: `rg PATTERN
//! ~/Code/org/service-api/src/main.rs`, and the same spelling for a file that
//! is not there. `rg` opens a named file whatever the ignore rules say and
//! prints an error for a missing one, so both answers rest on the path's own
//! components rather than on a walk. Hidden, credential and linked-away
//! spellings keep their review.
#![cfg(unix)]

use crate::pretool_home_layout_reads::{assert_decision, layout, write};

#[test]
fn naming_a_file_in_a_sibling_repository_is_allowed() {
    let layout = layout("rg-sibling-named-file");
    let sibling = layout.org.join("service-api");
    write(
        sibling.join("src/journey/runner.ts"),
        "export const x = 1;\n",
    );
    write(
        sibling.join(".github/workflows/release.yml"),
        "name: release\n",
    );
    write(sibling.join("dist/bundle.js"), "// fixture\n");
    write(sibling.join(".gitignore"), "dist/\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ~/Code/org/service-api/src/main.rs",
        "rg -n export ~/Code/org/service-api/src/journey/runner.ts",
        "rg -n release ~/Code/org/service-api/.github/workflows/release.yml",
        // `rg` searches a named file even where the walk would prune it.
        "rg -n fixture ~/Code/org/service-api/dist/bundle.js",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn naming_a_missing_file_in_a_sibling_repository_is_allowed() {
    let layout = layout("rg-sibling-missing-file");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ~/Code/org/service-api/src/lib.rs",
        "rg -n fixture ~/Code/org/service-api/src/journey/runner.ts | head -6",
        "rg -n fixture ~/Code/org/service-api/src/main.rs ~/Code/org/service-api/src/lib.rs",
    ] {
        assert_decision(&cwd, &layout.home, command, true);
    }
}

#[test]
fn a_named_path_that_could_reach_a_secret_is_reviewed() {
    let layout = layout("rg-sibling-named-secret");
    let sibling = layout.org.join("service-api");
    write(sibling.join(".env"), "TOKEN=fixture\n");
    write(sibling.join("src/credentials.json"), "{}\n");
    write(sibling.join("src/server.pem"), "fixture\n");
    write(sibling.join(".secrets/notes.md"), "fixture\n");
    std::os::unix::fs::symlink(layout.home.join(".ssh"), sibling.join("src/keys")).unwrap();
    write(layout.home.join(".ssh/id_rsa"), "fixture\n");
    let cwd = layout.org.join("app-portal");
    for command in [
        "rg -n fixture ~/Code/org/service-api/.env",
        "rg -n fixture ~/Code/org/service-api/src/credentials.json",
        "rg -n fixture ~/Code/org/service-api/src/server.pem",
        "rg -n fixture ~/Code/org/service-api/.secrets/notes.md",
        "rg -n fixture ~/Code/org/service-api/.git/config",
        "rg -n fixture ~/Code/org/service-api/src/keys/id_rsa",
        // A missing name is screened the same way the file would be.
        "rg -n fixture ~/Code/org/service-api/src/.env.local",
        "rg -n fixture ~/Code/org/service-api/src/secrets/prod.pem",
        // Nothing below home that is not a repository gets this route.
        "rg -n fixture ~/Code/org/notes/todo.md",
    ] {
        assert_decision(&cwd, &layout.home, command, false);
    }
}
