use super::*;

fn target_names(command: &str) -> Vec<String> {
    let intent = parse_package_intent(command, None, None, None, None)
        .expect("the install must produce a package intent");
    intent
        .targets
        .into_iter()
        .map(|target| target.package_name.expect("a named package"))
        .collect()
}

#[test]
fn bun_value_options_do_not_become_package_targets() {
    for options in [
        "--cwd /tmp/project/dashboard",
        "--cwd=/tmp/project/dashboard",
        "--cache-dir /tmp/bun-cache",
        "-c bunfig.toml",
        "--config bunfig.toml",
        "--backend copyfile",
        "--omit dev",
        "--linker isolated",
        "-F app",
        "--filter app",
    ] {
        let command = format!("bun add {options} evil-pkg");
        assert_eq!(target_names(&command), ["evil-pkg"], "{command}");
    }
}

#[test]
fn a_bun_lockfile_install_in_another_directory_names_no_package() {
    // #4808: the directory after --cwd was reviewed as `<dir>@latest`.
    for command in [
        "bun install --cwd /tmp/project/dashboard --frozen-lockfile --ignore-scripts",
        "bun install --frozen-lockfile --cwd /tmp/project/dashboard",
    ] {
        assert!(target_names(command).is_empty(), "{command}");
    }
}

#[test]
fn yarn_cwd_after_the_subcommand_is_a_directory() {
    assert_eq!(
        target_names("yarn add --cwd /tmp/project evil-pkg"),
        ["evil-pkg"]
    );
}

#[test]
fn managers_without_a_cwd_value_still_review_the_next_word() {
    // npm does not read `--cwd`'s next token as its value, so skipping it
    // would let a package go unevaluated.
    assert_eq!(target_names("npm install --cwd evil-pkg"), ["evil-pkg"]);
}
