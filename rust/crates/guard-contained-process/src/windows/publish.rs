//! Publishes a build run's declared output directories from the private
//! snapshot back to the live workspace.
//!
//! The container has exited by the time this runs, and only the declared
//! workspace-relative directories are written. The live side is reached
//! through handle-bound directories, so a link swapped into the path is
//! refused, not followed. The staged side is copied only as plain
//! directories and regular files; any link or other reparse point in it
//! fails the publish. A name the snapshot withheld is neither written nor
//! removed.
use super::readonly::BuildRun;
use crate::bound_fs::{self, identity, Directory};
use std::ffi::OsString;
use std::fs::Metadata;
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::Path;

const REPARSE_POINT: u32 = 0x400;
/// One replaced or removed live file; built assets are far smaller.
const LIVE_FILE_LIMIT: usize = 256 * 1024 * 1024;

struct Budget {
    entries: usize,
    bytes: usize,
}

struct Publish<'a> {
    live: &'a Directory,
    staged: &'a Directory,
    withhold: &'a dyn Fn(&Path) -> bool,
    max_entries: usize,
    max_bytes: usize,
    budget: Budget,
}

pub(super) fn publish_outputs(
    workspace: &Path,
    snapshot: &Path,
    build: &BuildRun<'_>,
    withhold: &dyn Fn(&Path) -> bool,
) -> io::Result<()> {
    let live = Directory::open(workspace)?;
    let staged = Directory::open(snapshot)?;
    let mut publish = Publish {
        live: &live,
        staged: &staged,
        withhold,
        max_entries: build.max_output_entries,
        max_bytes: build.max_output_bytes,
        budget: Budget {
            entries: 0,
            bytes: 0,
        },
    };
    for output in build.outputs {
        bound_fs::relative_components(output)?;
        if withhold(output) {
            return Err(bound_fs::changed());
        }
        let metadata = match staged.metadata(output) {
            Ok(metadata) => metadata,
            // The build wrote nothing there; the live directory is left as is.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if linked(&metadata) || !metadata.is_dir() {
            return Err(bound_fs::changed());
        }
        live.mkdir_all(output)?;
        publish.sync(output)?;
    }
    Ok(())
}

fn linked(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0
}

fn missing(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
}

impl Publish<'_> {
    /// Makes the live directory at `relative` hold what the staged one holds.
    fn sync(&mut self, relative: &Path) -> io::Result<()> {
        let remaining = self.max_entries.saturating_sub(self.budget.entries);
        let staged: Vec<OsString> = self.staged.entries(relative, remaining)?;
        let live: Vec<OsString> = self.live.entries(relative, self.max_entries)?;
        for name in live.iter().filter(|name| !staged.contains(name)) {
            let child = relative.join(name);
            if !(self.withhold)(&child) {
                self.remove(&child)?;
            }
        }
        for name in staged {
            let child = relative.join(&name);
            if (self.withhold)(&child) {
                continue;
            }
            self.budget.entries += 1;
            if self.budget.entries > self.max_entries {
                return Err(exceeded());
            }
            let metadata = self.staged.metadata(&child)?;
            if linked(&metadata) {
                return Err(bound_fs::changed());
            }
            if metadata.is_dir() {
                match self.live.metadata(&child) {
                    Ok(current) if current.is_dir() && !linked(&current) => {}
                    Ok(_) => {
                        self.remove(&child)?;
                        self.live.mkdir_all(&child)?;
                    }
                    Err(error) if missing(&error) => self.live.mkdir_all(&child)?,
                    Err(error) => return Err(error),
                }
                self.sync(&child)?;
            } else if metadata.is_file() {
                self.write(&child)?;
            } else {
                return Err(bound_fs::changed());
            }
        }
        Ok(())
    }

    fn write(&mut self, relative: &Path) -> io::Result<()> {
        let remaining = self.max_bytes.saturating_sub(self.budget.bytes);
        let file = self.staged.read(relative, remaining)?;
        self.budget.bytes += file.bytes.len();
        match self.live.metadata(relative) {
            Ok(current) if current.is_file() && !linked(&current) => {
                let current = self.live.read(relative, LIVE_FILE_LIMIT)?;
                if current.digest != file.digest {
                    self.live.atomic_replace(
                        relative,
                        Some((&current.identity, &current.digest)),
                        &file.bytes,
                    )?;
                }
                Ok(())
            }
            Ok(_) => {
                self.remove(relative)?;
                self.live.create(relative, &file.bytes, false)
            }
            Err(error) if missing(&error) => self.live.create(relative, &file.bytes, false),
            Err(error) => Err(error),
        }
    }

    /// Removes one live entry the build no longer produces. A live link is
    /// refused rather than removed, since its target is outside this tree.
    fn remove(&self, relative: &Path) -> io::Result<()> {
        let metadata = self.live.metadata(relative)?;
        if linked(&metadata) {
            return Err(bound_fs::changed());
        }
        if metadata.is_dir() {
            let directory = self.live.directory(relative)?;
            let expected = identity(directory.handle())?;
            directory.remove_tree()?;
            drop(directory);
            self.live.atomic_remove_directory(relative, &expected)
        } else {
            let file = self.live.read(relative, LIVE_FILE_LIMIT)?;
            self.live
                .atomic_remove(relative, (&file.identity, &file.digest))
        }
    }
}

fn exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "build output budget exceeded")
}
