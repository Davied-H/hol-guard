//! Preserve linked-destination refusals when trying broader containment.

use std::path::{Path, PathBuf};

#[cfg(unix)]
fn linked_file(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // A symlink may resolve to a protected inode. Metadata errors other
    // than absence cannot establish a safe destination.
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => true,
        Ok(metadata) => metadata.is_file() && metadata.nlink() != 1,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

#[cfg(not(unix))]
fn linked_file(_path: &Path) -> bool {
    // Workspace containment is not admitted on non-Unix platforms.
    false
}

fn target(value: &str, workspace: &Path) -> PathBuf {
    workspace.join(value)
}

fn expanded_operand(value: &str) -> bool {
    value
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '$' | '\u{60}' | '{' | '}'))
}

fn plain_operand(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.starts_with('~')
        && !expanded_operand(value)
}

/// True means containment must decline. Unsupported forms of cp/touch must
/// fail closed: flags, multiple destinations, and shell expansions can make
/// a protected hard-linked inode the write target.
pub(super) fn mutates_linked_destination(
    name: &str,
    arguments: &[String],
    workspace: &Path,
) -> bool {
    match name {
        "cp" => {
            let operands = match arguments {
                [source, destination] if plain_operand(source) && plain_operand(destination) => {
                    Some((source.as_str(), destination.as_str()))
                }
                [separator, source, destination]
                    if separator == "--" && !source.is_empty() && !destination.is_empty() =>
                {
                    Some((source.as_str(), destination.as_str()))
                }
                _ => None,
            };
            let Some((source, destination)) = operands else {
                return true;
            };
            // Even after the option separator, require concrete operands.
            if expanded_operand(source) || expanded_operand(destination) {
                return true;
            }
            let mut destination = target(destination, workspace);
            if destination.is_dir() {
                let Some(basename) = Path::new(source).file_name() else {
                    return true;
                };
                destination = destination.join(basename);
            }
            linked_file(&destination)
        }
        "touch" => {
            let destination = match arguments {
                [destination] if plain_operand(destination) => destination,
                [separator, destination] if separator == "--" && !destination.is_empty() => {
                    destination
                }
                _ => return true,
            };
            if expanded_operand(destination) {
                return true;
            }
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
            ("cp", vec!["-f", "source", "linked"], true),
            ("cp", vec!["-p", "source", "linked"], true),
            ("cp", vec!["source", "new", "sub"], true),
            ("cp", vec!["source", "linked*"], true),
            ("touch", vec!["-c", "linked"], true),
            ("touch", vec!["-m", "linked"], true),
            ("touch", vec!["linked", "new"], true),
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

    #[test]
    fn directory_changes_cannot_hide_a_linked_destination() {
        let root = Workspace(std::env::temp_dir().join(format!(
            "guard-linked-cwd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )));
        let workspace = root.0.as_path();
        std::fs::create_dir_all(workspace.join("sub")).unwrap();
        std::fs::write(workspace.join("protected"), b"sentinel").unwrap();
        std::fs::hard_link(workspace.join("protected"), workspace.join("sub/linked")).unwrap();
        for command in [
            "cd sub && cp source linked",
            "pushd sub && touch linked",
            "cd sub && cp -f source linked",
            "cd sub && touch -m linked",
            "cd sub && touch new",
        ] {
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: command.to_owned(),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .unwrap();
            assert!(
                super::super::command_shape(&model, workspace, None).is_none(),
                "{command} must not bypass destination checks"
            );
        }
    }
}
