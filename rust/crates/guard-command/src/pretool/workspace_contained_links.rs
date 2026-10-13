//! Preserve linked-destination refusals when trying broader containment.

use std::path::{Path, PathBuf};

#[cfg(unix)]
fn linked_file(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.nlink() != 1)
}

#[cfg(not(unix))]
fn linked_file(_path: &Path) -> bool {
    // Workspace containment is not admitted on non-Unix platforms.
    false
}

fn target(value: &str, workspace: &Path) -> PathBuf {
    workspace.join(value)
}

pub(super) fn mutates_linked_destination(
    name: &str,
    arguments: &[String],
    workspace: &Path,
) -> bool {
    match (name, arguments) {
        ("cp", [source, destination]) | ("cp", [_, source, destination])
            if arguments.len() == 2 || arguments.first().is_some_and(|value| value == "--") =>
        {
            let mut destination = target(destination, workspace);
            if destination.is_dir() {
                let Some(basename) = Path::new(source).file_name() else {
                    return true;
                };
                destination = destination.join(basename);
            }
            linked_file(&destination)
        }
        ("touch", [destination]) => linked_file(&target(destination, workspace)),
        ("touch", [separator, destination]) if separator == "--" => {
            linked_file(&target(destination, workspace))
        }
        _ => false,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    struct Workspace(PathBuf);

    impl Drop for Workspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn linked_destinations_are_refused_but_sources_and_plain_writes_stay_available() {
        let root = Workspace(std::env::temp_dir().join(format!(
            "guard-linked-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )));
        std::fs::create_dir(&root.0).unwrap();
        let workspace = root.0.as_path();
        std::fs::write(workspace.join("protected"), b"sentinel").unwrap();
        std::fs::hard_link(workspace.join("protected"), workspace.join("linked")).unwrap();
        std::fs::write(workspace.join("source"), b"ordinary").unwrap();
        for (name, args, expected) in [
            ("cp", vec!["source", "linked"], true),
            ("cp", vec!["--", "source", "linked"], true),
            ("touch", vec!["linked"], true),
            ("touch", vec!["--", "linked"], true),
            ("cp", vec!["linked", "new"], false),
            ("touch", vec!["new"], false),
            ("echo", vec!["linked"], false),
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(mutates_linked_destination(name, &args, workspace), expected);
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: format!("{name} {}", args.join(" ")),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .unwrap();
            assert_eq!(
                super::super::command_shape(&model, workspace, None).is_none(),
                expected,
            );
        }
    }
}
