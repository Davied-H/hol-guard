use super::*;
use std::os::unix::fs::PermissionsExt;

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Layout {
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    workspace: PathBuf,
}

impl Layout {
    fn new(tag: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("guard-grant-{tag}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let home = root.join("home");
        let bin = home.join("tools/bin");
        let workspace = root.join("work");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let program = bin.join("lanectl");
        std::fs::write(&program, "#!/bin/sh\necho ok\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            root,
            home,
            bin,
            workspace,
        }
    }

    fn search_path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.bin.display())
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn grant(capabilities: &[&str]) -> GrantInput {
    GrantInput {
        identity_hash: HASH.to_owned(),
        name: "lanectl".to_owned(),
        capabilities: capabilities.iter().map(|name| (*name).to_owned()).collect(),
    }
}

fn base_plan() -> Value {
    json!({
        "profile_version": "workspace-contained-v1",
        "exec_roots": [],
        "sandbox_path": "/usr/bin:/bin",
        "read_only_roots": [],
        "grant_identity_hash": null,
        "capabilities": [],
    })
}

fn widened(layout: &Layout, grant: &GrantInput, platform: &str) -> Result<Value, String> {
    let mut plan = base_plan();
    widen(
        &mut plan,
        grant,
        "lanectl",
        &layout.search_path(),
        Some(&layout.home),
        &layout.workspace,
        platform,
    )
    .map(|()| plan)
    .map_err(|error| format!("{error:?}"))
}

#[test]
fn capability_names_must_be_known_sorted_and_distinct() {
    let names = |items: &[&str]| {
        items
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<_>>()
    };
    assert!(grant_capabilities(&names(&[])).is_some());
    assert!(grant_capabilities(&names(&GRANT_CAPABILITIES)).is_some());
    for refused in [
        names(&["network"]),
        names(&["state-dir-write", "state-dir-read"]),
        names(&["loopback-network", "loopback-network"]),
    ] {
        assert!(grant_capabilities(&refused).is_none(), "{refused:?}");
    }
}

#[test]
fn the_plan_runs_the_granted_program_and_its_interpreter() {
    let layout = Layout::new("exec");
    let plan = widened(
        &layout,
        &grant(&["loopback-network", "state-dir-read"]),
        "darwin",
    )
    .unwrap();
    assert_eq!(plan["profile_version"], GRANT_PROFILE);
    assert_eq!(plan["grant_identity_hash"], HASH);
    assert_eq!(
        plan["capabilities"],
        json!(["loopback-network", "state-dir-read"])
    );
    let exec_roots = plan["exec_roots"].as_array().unwrap();
    assert!(exec_roots.contains(&json!(layout.bin)), "{plan}");
    assert!(
        exec_roots.contains(&json!("/bin")),
        "the interpreter's directory: {plan}"
    );
    let sandbox_path = plan["sandbox_path"].as_str().unwrap();
    assert!(
        sandbox_path.starts_with(&format!("{}:", layout.bin.display())),
        "the session found it first: {sandbox_path}"
    );
    assert_eq!(
        plan["read_only_roots"],
        json!([layout.home.join(".lanectl")])
    );
}

#[test]
fn linux_keeps_every_capability_denied() {
    let layout = Layout::new("linux");
    let plan = widened(&layout, &grant(&GRANT_CAPABILITIES), "linux").unwrap();
    assert_eq!(plan["capabilities"], json!([]));
    assert_eq!(plan["read_only_roots"], json!([]));
    assert!(plan["exec_roots"]
        .as_array()
        .unwrap()
        .contains(&json!(layout.bin)));
}

#[test]
fn an_invalid_grant_or_unlocatable_program_is_refused() {
    let layout = Layout::new("refused");
    assert!(widened(&layout, &grant(&["network"]), "darwin").is_err());
    let mut short = grant(&[]);
    short.identity_hash = "abc".to_owned();
    assert!(widened(&layout, &short, "darwin").is_err());
    let mut plan = base_plan();
    assert!(widen(
        &mut plan,
        &grant(&[]),
        "missing-cli",
        &layout.search_path(),
        Some(&layout.home),
        &layout.workspace,
        "darwin",
    )
    .is_err());
    // A shared directory name grants no state, though the network grant holds.
    let mut shared = grant(&["state-dir-read"]);
    shared.name = "ssh".to_owned();
    assert!(widened(&layout, &shared, "darwin").is_err());
    shared.capabilities = vec!["loopback-network".to_owned()];
    assert!(widened(&layout, &shared, "darwin").is_ok());
}

#[test]
fn the_state_directory_is_a_plain_name_inside_home() {
    let layout = Layout::new("state");
    assert_eq!(
        state_dir("lanectl", &layout.home),
        Some(layout.home.join(".lanectl"))
    );
    for name in [
        "", "x", "Lanectl", "lane.ctl", "../x", "lane/ctl", "ssh", "aws", "config",
    ] {
        assert_eq!(state_dir(name, &layout.home), None, "{name}");
    }
    assert_eq!(state_dir("lanectl", Path::new("relative")), None);
    // A link in place of the directory is never followed.
    std::os::unix::fs::symlink(&layout.workspace, layout.home.join(".linked")).unwrap();
    assert_eq!(state_dir("linked", &layout.home), None);
}

#[test]
fn profile_rules_accept_only_the_state_directory_of_a_state_grant() {
    let layout = Layout::new("rules");
    let state = layout.home.join(".lanectl");
    let caps = |items: &[&str]| {
        items
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<_>>()
    };
    let rules = super::rules(
        &caps(&["state-dir-write"]),
        std::slice::from_ref(&state),
        Some(&layout.home),
    )
    .unwrap();
    assert_eq!(rules.reads, vec![state.clone()]);
    assert_eq!(rules.writes, vec![state.clone()]);
    assert!(rules.network.is_empty());
    let read = super::rules(
        &caps(&["state-dir-read"]),
        std::slice::from_ref(&state),
        Some(&layout.home),
    )
    .unwrap();
    assert!(read.writes.is_empty());
    for (capabilities, roots) in [
        (caps(&[]), vec![state.clone()]),
        (caps(&["state-dir-read"]), vec![layout.home.clone()]),
        (
            caps(&["state-dir-read"]),
            vec![layout.home.join(".other"), state.clone()],
        ),
        (
            caps(&["state-dir-read"]),
            vec![layout.workspace.join(".lanectl")],
        ),
        (caps(&["network"]), vec![]),
    ] {
        assert!(
            super::rules(&capabilities, &roots, Some(&layout.home)).is_err(),
            "{capabilities:?} {roots:?}"
        );
    }
    let loopback = super::rules(&caps(&["loopback-network"]), &[], Some(&layout.home)).unwrap();
    assert_eq!(loopback.network, loopback_any_port());
}
