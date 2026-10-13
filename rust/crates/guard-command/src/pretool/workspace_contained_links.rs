//! Preserve linked-destination refusals when trying broader containment.

use crate::CanonicalCommandV1;
use std::path::Path;

#[path = "workspace_contained_cwd.rs"]
mod cwd;

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

pub(super) fn unbounded_linked_writes(model: &CanonicalCommandV1, workspace: &Path) -> bool {
    if !model.segments.iter().any(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(|name| matches!(super::super::executable_basename(name), "cp" | "touch"))
    }) {
        return false;
    }
    let Some(locations) = cwd::locations(model, workspace) else {
        return true;
    };
    model
        .segments
        .iter()
        .zip(locations)
        .any(|(segment, locations)| {
            let name = super::super::executable_basename(
                segment.executable.as_deref().unwrap_or_default(),
            );
            locations
                .iter()
                .any(|cwd| mutates_linked_destination(name, &segment.arguments, cwd))
        })
}

fn mutates_linked_destination(name: &str, arguments: &[String], workspace: &Path) -> bool {
    match name {
        "cp" => copy_targets(arguments, workspace).unwrap_or(true),
        "touch" => touch_targets(arguments)
            .map(|targets| {
                targets
                    .iter()
                    .any(|target| linked_file(&workspace.join(target)))
            })
            .unwrap_or(true),
        _ => false,
    }
}

fn touch_targets(arguments: &[String]) -> Option<Vec<&str>> {
    let mut targets = Vec::new();
    let mut options = true;
    let mut args = arguments.iter();
    while let Some(arg) = args.next() {
        if options && arg == "--" {
            options = false;
            continue;
        }
        if options && arg.starts_with('-') {
            match arg.as_str() {
                "-d" | "-t" | "-r" | "--date" | "--reference" | "--time" => {
                    args.next()?;
                }
                "--no-create" | "--no-dereference" => {}
                value
                    if value.starts_with("--date=")
                        || value.starts_with("--reference=")
                        || value.starts_with("--time=") => {}
                value
                    if value.starts_with('-')
                        && !value.starts_with("--")
                        && value.len() > 1
                        && value[1..].chars().all(|c| "amch".contains(c)) => {}
                _ => return None,
            }
        } else {
            targets.push(arg.as_str());
        }
    }
    (!targets.is_empty()).then_some(targets)
}

fn copy_targets(arguments: &[String], workspace: &Path) -> Option<bool> {
    let mut paths = Vec::new();
    let mut target_directory = None;
    let mut recursive = false;
    let mut no_target_directory = false;
    let mut options = true;
    let mut args = arguments.iter();
    while let Some(arg) = args.next() {
        if options && arg == "--" {
            options = false;
            continue;
        }
        if options && arg.starts_with('-') {
            match arg.as_str() {
                "-t" | "--target-directory" => {
                    target_directory = Some(args.next()?.as_str());
                }
                "-S" | "--suffix" => {
                    args.next()?;
                }
                "-T" | "--no-target-directory" => no_target_directory = true,
                "--recursive" | "--archive" => recursive = true,
                "--force"
                | "--interactive"
                | "--no-clobber"
                | "--preserve"
                | "--verbose"
                | "--dereference"
                | "--no-dereference"
                | "--remove-destination" => {}
                value if value.starts_with("--target-directory=") => {
                    target_directory = Some(value.strip_prefix("--target-directory=")?);
                }
                value if value.starts_with("--preserve=") || value.starts_with("--suffix=") => {}
                value
                    if value.starts_with('-')
                        && !value.starts_with("--")
                        && value.len() > 1
                        && value[1..].chars().all(|c| "afHiLnPpRrvXbuc".contains(c)) =>
                {
                    recursive |= value[1..].chars().any(|c| "aRr".contains(c));
                }
                _ => return None,
            }
        } else {
            paths.push(arg.as_str());
        }
    }
    let destination = if let Some(directory) = target_directory {
        if no_target_directory {
            return None;
        }
        workspace.join(directory)
    } else {
        workspace.join(paths.pop()?)
    };
    if paths.is_empty() {
        return None;
    }
    let directory = target_directory.is_some() || (!no_target_directory && destination.is_dir());
    let mut remaining = 4096;
    for source in paths {
        let source_path = workspace.join(source);
        let target = if directory {
            destination.join(source_path.file_name()?)
        } else {
            destination.clone()
        };
        if linked_copy_tree(&source_path, &target, recursive, &mut remaining)? {
            return Some(true);
        }
    }
    Some(false)
}

fn linked_copy_tree(
    source: &Path,
    destination: &Path,
    recursive: bool,
    remaining: &mut usize,
) -> Option<bool> {
    if linked_file(destination) {
        return Some(true);
    }
    if !recursive || !source.is_dir() || !destination.exists() {
        return Some(false);
    }
    if source.symlink_metadata().ok()?.file_type().is_symlink() {
        return None;
    }
    for child in std::fs::read_dir(source).ok()? {
        *remaining = remaining.checked_sub(1)?;
        let child = child.ok()?;
        if linked_copy_tree(
            &child.path(),
            &destination.join(child.file_name()),
            true,
            remaining,
        )? {
            return Some(true);
        }
    }
    Some(false)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Workspace(PathBuf);

    impl Drop for Workspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn linked_destinations_are_refused_but_sources_and_plain_writes_stay_available() {
        let mut root = Workspace(std::env::temp_dir().join(format!(
            "guard-linked-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )));
        std::fs::create_dir(&root.0).unwrap();
        root.0 = root.0.canonicalize().unwrap();
        let workspace = root.0.as_path();
        std::fs::write(workspace.join("protected"), b"sentinel").unwrap();
        std::fs::hard_link(workspace.join("protected"), workspace.join("linked")).unwrap();
        std::fs::write(workspace.join("source"), b"ordinary").unwrap();
        std::fs::write(workspace.join("second"), b"ordinary").unwrap();
        std::fs::create_dir(workspace.join("destination")).unwrap();
        std::fs::hard_link(
            workspace.join("protected"),
            workspace.join("destination/source"),
        )
        .unwrap();
        for (name, args, expected) in [
            ("cp", vec!["source", "linked"], true),
            ("cp", vec!["--", "source", "linked"], true),
            ("touch", vec!["linked"], true),
            ("touch", vec!["--", "linked"], true),
            ("cp", vec!["-fp", "source", "linked"], true),
            ("cp", vec!["--force", "source", "linked"], true),
            ("cp", vec!["source", "second", "destination"], true),
            ("cp", vec!["-t", "destination", "source"], true),
            ("touch", vec!["-cm", "linked"], true),
            ("touch", vec!["source", "linked"], true),
            ("cp", vec!["--unknown", "source", "new"], true),
            ("cp", vec!["linked", "new"], false),
            ("cp", vec!["-fp", "source", "new"], false),
            ("touch", vec!["new"], false),
            ("touch", vec!["-m", "new"], false),
            ("touch", vec!["-r", "linked", "source"], false),
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
        std::fs::create_dir(workspace.join("sub")).unwrap();
        std::fs::write(workspace.join("sub/source"), b"ordinary").unwrap();
        std::fs::hard_link(workspace.join("protected"), workspace.join("sub/linked")).unwrap();
        std::fs::create_dir_all(workspace.join("tree/nested")).unwrap();
        std::fs::write(workspace.join("tree/nested/file"), b"ordinary").unwrap();
        std::fs::create_dir_all(workspace.join("destination/tree/nested")).unwrap();
        std::fs::hard_link(
            workspace.join("protected"),
            workspace.join("destination/tree/nested/file"),
        )
        .unwrap();
        for (command, refused) in [
            ("cd sub && cp -f source linked", true),
            ("cd sub && touch -m linked", true),
            ("cd sub && cp -fp source new", false),
            ("cd sub && touch -m new", false),
            ("false && cd sub && true; touch linked", true),
            ("cd sub | touch linked", true),
            ("cp -R tree destination", true),
            ("cp -R tree new-directory", false),
        ] {
            let model = crate::parse_command(&crate::CommandModelRequestV1 {
                command: command.into(),
                dialect: "posix".into(),
                transport: "shell_string".into(),
                extraction_provenance: "pre-tool-generic".into(),
            })
            .unwrap();
            assert_eq!(
                super::super::command_shape(&model, workspace, None).is_none(),
                refused,
                "{command}"
            );
        }
    }
}
