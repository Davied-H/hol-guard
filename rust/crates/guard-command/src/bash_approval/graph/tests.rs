use std::time::Duration;

use super::*;

const SCRIPT: &str =
    include_str!("../../../../../../tests/fixtures/script_approvals/maintenance.sh");
const HELPER: &str =
    include_str!("../../../../../../tests/fixtures/script_approvals/fixture-registry");

struct FixtureResolver;

impl Resolver for FixtureResolver {
    fn resolve(&self, argv: &[String]) -> std::result::Result<Executable, &'static str> {
        let command = argv[0].as_str();
        match command {
            "fixture-registry" => Ok(Executable::Bash(Code {
                original_path: "/fixtures/fixture-registry".into(),
                resolved_path: "/fixtures/fixture-registry".into(),
                source: HELPER.into(),
            })),
            "sort" | "head" => Ok(Executable::Native {
                resolved_path: format!("/usr/bin/{command}"),
                content_sha256: "1".repeat(64),
            }),
            "rm" => Ok(Executable::Native {
                resolved_path: "/bin/rm".into(),
                content_sha256: "2".repeat(64),
            }),
            _ => Err("bash_helper_unresolved"),
        }
    }
}

fn graph(mode: &str) -> Graph {
    build(
        Code {
            original_path: "/fixtures/maintenance.sh".into(),
            resolved_path: "/fixtures/maintenance.sh".into(),
            source: SCRIPT.into(),
        },
        &["/fixtures/maintenance.sh".into(), mode.into()],
        &BTreeMap::from([("HOME".into(), "/isolated/home".into())]),
        &FixtureResolver,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap()
}

#[test]
fn graph_includes_helper_bytes_and_every_reachable_parent_and_child() {
    let dry = graph("dry");
    let delete = graph("delete");
    assert_eq!(dry.code.len(), 2);
    assert_eq!(
        dry.code[0].content_sha256,
        hex::encode(Sha256::digest(HELPER))
    );
    assert_eq!(dry.native_images.len(), 2);
    assert!(!dry.native_images.contains_key("/bin/rm"));
    assert!(delete.native_images.contains_key("/bin/rm"));
    assert_eq!(
        dry.invocations
            .iter()
            .filter(|call| call.operation.argv[0] == "fixture-registry")
            .count(),
        4
    );
    assert_eq!(
        dry.invocations
            .iter()
            .filter(|call| call.operation.argv[0] == "printf")
            .count(),
        4
    );
    assert_eq!(dry.writes.len(), 5);
    assert!(dry
        .frozen_source
        .contains("/bin/bash --noprofile --norc -c"));
    assert_eq!(
        dry.source_for_launch().unwrap_err().reason,
        "bash_output_handles_required"
    );
}

#[test]
fn output_rendering_requires_a_complete_contiguous_descriptor_table() {
    let entry = || Code {
        original_path: "/entry".into(),
        resolved_path: "/entry".into(),
        source: ": > '/reports/result'\nprintf x >> '/reports/result'".into(),
    };
    let run = |fds: &BTreeMap<String, u32>| {
        build_with_outputs(
            entry(),
            &["/entry".into()],
            &BTreeMap::new(),
            &FixtureResolver,
            Instant::now() + Duration::from_secs(1),
            fds,
        )
    };
    assert_eq!(
        run(&BTreeMap::new()).unwrap_err().reason,
        "bash_output_handle_missing"
    );
    assert_eq!(
        run(&BTreeMap::from([("/reports/result".into(), 69)]))
            .unwrap_err()
            .reason,
        "bash_output_descriptor_bounds"
    );
    let graph = run(&BTreeMap::from([("/reports/result".into(), 6)])).unwrap();
    assert_eq!(graph.source_for_launch().unwrap(), ": >&6\nprintf x >&6");
}

#[cfg(target_os = "macos")]
#[path = "kernel_tests.rs"]
mod kernel;

#[test]
fn recursive_or_unresolved_helpers_never_return_a_partial_graph() {
    struct Recursive;
    impl Resolver for Recursive {
        fn resolve(&self, _: &[String]) -> std::result::Result<Executable, &'static str> {
            Ok(Executable::Bash(Code {
                original_path: "/cycle".into(),
                resolved_path: "/cycle".into(),
                source: "cycle".into(),
            }))
        }
    }
    let source = Code {
        original_path: "/entry".into(),
        resolved_path: "/entry".into(),
        source: "cycle".into(),
    };
    let result = build(
        source,
        &["/entry".into()],
        &BTreeMap::new(),
        &Recursive,
        Instant::now() + Duration::from_secs(1),
    );
    assert_eq!(result.unwrap_err().reason, "bash_helper_cycle");
    let source = Code {
        original_path: "/entry".into(),
        resolved_path: "/entry".into(),
        source: "unknown".into(),
    };
    assert_eq!(
        build(
            source,
            &["/entry".into()],
            &BTreeMap::new(),
            &FixtureResolver,
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap_err()
        .reason,
        "bash_helper_unresolved"
    );
}

#[cfg(unix)]
#[test]
fn frozen_dry_graph_runs_without_opening_mutable_entry_or_helper_paths() {
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "guard-frozen-bash-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let graph = graph("dry");
    let result = Command::new("/bin/bash")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            &graph.frozen_source,
            "/fixtures/maintenance.sh",
            "dry",
        ])
        .env_clear()
        .env("HOME", &root)
        .env("PATH", "/unavailable")
        .current_dir(&root)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read_to_string(root.join("maintenance-report.tsv")).unwrap(), "alpha/current\nalpha/obsolete\nalpha\tlocal metadata\nbeta/current\nbeta/obsolete\nbeta\tlocal metadata\n");
    std::fs::remove_dir_all(root).unwrap();
}
