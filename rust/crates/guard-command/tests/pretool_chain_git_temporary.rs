#![cfg(unix)]

//! A chain may save a Git object read in a temporary file and inspect it in
//! the same command: `git -C app show <rev>:src/a.ts > /tmp/a.ts && wc -l /tmp/a.ts`.
//! Git object reads change no directory, rename nothing and create no link, so
//! they may share a chain with that file. `stat` may take an output format.
//! Working-tree Git commands, execution sinks, `cd`, hidden and credential
//! paths keep their review.

use crate::pretool_home_layout_reads::{assert_decision, layout};
use std::path::PathBuf;

struct Temporary(PathBuf);

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temporary(name: &str) -> Temporary {
    let path = PathBuf::from(format!(
        "/tmp/hg-git-chain-{name}-{}.ts",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    Temporary(path)
}

#[test]
fn git_object_reads_share_a_chain_with_their_temporary_file() {
    let layout = layout("git-temporary");
    let staged = temporary("allowed");
    let file = staged.0.display();
    for command in [
        format!("git -C app-portal show HEAD:src/main.rs > {file} && wc -l {file}"),
        format!("git -C app-portal show HEAD:src/main.rs > {file}; wc -l {file}"),
        format!("git -C app-portal log --oneline -3 > {file} && head -2 {file}"),
        format!("git -C app-portal ls-files > {file} && wc -l {file}"),
        format!(
            "git -C app-portal show HEAD:src/main.rs > {file} && grep -n main {file} | head -5"
        ),
    ] {
        assert_decision(&layout.org, &layout.home, &command, true);
    }
    std::fs::write(&staged.0, "fn main() {}\n").unwrap();
    for command in [
        format!("stat -f \"%N %Sm\" {file}; file {file}"),
        format!("stat -f \"%N %Sm\" {file}"),
        format!("stat -c '%n %s' {file}"),
        "stat -f '%N %z' app-portal/src/main.rs".to_owned(),
        "stat -x app-portal/src/main.rs".to_owned(),
    ] {
        assert_decision(&layout.org, &layout.home, &command, true);
    }
}

#[test]
fn temporary_git_chains_keep_working_tree_sink_and_path_boundaries() {
    let layout = layout("git-temporary-reviewed");
    let staged = temporary("reviewed");
    let file = staged.0.display();
    std::fs::create_dir_all(layout.home.join(".ssh")).unwrap();
    std::fs::write(layout.home.join(".ssh/id_rsa"), "synthetic key\n").unwrap();
    std::fs::write(layout.org.join("app-portal/.env"), "TOKEN=synthetic\n").unwrap();
    let home = layout.home.display();
    for command in [
        // Working-tree Git commands and a write flag stay out of the chain.
        format!("git -C app-portal status --short > {file}; cat {file}"),
        format!("git -C app-portal checkout -b other > {file}; cat {file}"),
        format!("git -C app-portal diff --output={file}.out > {file}; wc -l {file}"),
        // The saved text reaches an execution sink, or the chain re-anchors.
        format!("git -C app-portal show HEAD:src/main.rs > {file} && sh {file}"),
        format!("git -C app-portal show HEAD:src/main.rs > {file} && cat {file} | sh"),
        format!(
            "git -C app-portal show HEAD:src/main.rs > {file} && cd app-portal && cp {file} b.rs"
        ),
        format!("git -C app-portal show HEAD:src/main.rs > {home}/.zshrc && wc -l {home}/.zshrc"),
        // Credential, hidden and unproven stat operands.
        format!("stat -f '%N %Sm' {home}/.ssh/id_rsa"),
        "stat -f '%N %Sm' ~/.ssh/id_rsa".to_owned(),
        "stat -f '%N' app-portal/.env".to_owned(),
        format!("stat -f '%N' {home}/.ssh"),
        "stat -f".to_owned(),
        "stat -f '%N'".to_owned(),
        "stat --file-system app-portal/src/main.rs".to_owned(),
        "stat -f '%N' $(cat app-portal/src/main.rs)".to_owned(),
    ] {
        assert_decision(&layout.org, &layout.home, &command, false);
    }
}
