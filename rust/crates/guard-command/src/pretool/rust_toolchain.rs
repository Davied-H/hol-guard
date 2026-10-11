//! Version queries for `cargo` and `rustc` through the rustup proxy.
//!
//! A lone `--version` or `-V` prints a banner and exits, but the rustup proxy
//! that usually stands in for `cargo` and `rustc` first picks a toolchain. It
//! reads the nearest `rust-toolchain` or `rust-toolchain.toml` in the working
//! directory or one of its ancestors. A `path` entry there makes the proxy run
//! that directory's binary, which the workspace controls. A channel name only
//! selects an official toolchain, which rustup downloads and verifies itself.
//!
//! The probe is admitted when no toolchain file is found, or when the nearest
//! one names a plain channel and nothing else that can select a binary. Any
//! file that cannot be read or parsed, is a symlink, or is unusually large
//! keeps the normal review path.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

const TOOLCHAIN_FILES: [&str; 2] = ["rust-toolchain", "rust-toolchain.toml"];
const MAX_TOOLCHAIN_FILE_BYTES: u64 = 4096;
const TOOLCHAIN_KEYS: [&str; 4] = ["channel", "components", "targets", "profile"];

pub(super) fn safe_version_probe(arguments: &[String], context: super::PathContext<'_>) -> bool {
    if !matches!(arguments, [flag] if matches!(flag.as_str(), "--version" | "-V")) {
        return false;
    }
    let Some(cwd) = context.cwd.map(Path::new) else {
        return false;
    };
    if !cwd.is_absolute() {
        return false;
    }
    // rustup searches the physical working directory, so a symlinked path
    // must not hide a toolchain file above its target.
    let Ok(physical) = fs::canonicalize(cwd) else {
        return false;
    };
    ancestors_inert(cwd) && ancestors_inert(&physical)
}

fn ancestors_inert(cwd: &Path) -> bool {
    for directory in cwd.ancestors() {
        match nearest_toolchain(directory) {
            Lookup::Absent => continue,
            Lookup::Inert => return true,
            Lookup::Unsafe => return false,
        }
    }
    true
}

enum Lookup {
    Absent,
    Inert,
    Unsafe,
}

fn nearest_toolchain(directory: &Path) -> Lookup {
    let mut found = false;
    for name in TOOLCHAIN_FILES {
        let path = directory.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return Lookup::Unsafe,
        };
        if !metadata.is_file() || metadata.len() > MAX_TOOLCHAIN_FILE_BYTES {
            return Lookup::Unsafe;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            return Lookup::Unsafe;
        };
        if !inert_toolchain(&contents) {
            return Lookup::Unsafe;
        }
        found = true;
    }
    if found {
        Lookup::Inert
    } else {
        Lookup::Absent
    }
}

fn inert_toolchain(contents: &str) -> bool {
    let trimmed = contents.trim();
    if !trimmed.contains(['\n', '=', '[']) {
        return plain_channel(trimmed);
    }
    let Ok(document) = trimmed.parse::<toml::Table>() else {
        return false;
    };
    let mut entries = document.iter();
    let Some(("toolchain", toml::Value::Table(toolchain))) =
        entries.next().map(|(key, value)| (key.as_str(), value))
    else {
        return false;
    };
    entries.next().is_none()
        && toolchain
            .keys()
            .all(|key| TOOLCHAIN_KEYS.contains(&key.as_str()))
        && toolchain
            .get("channel")
            .is_some_and(|channel| channel.as_str().is_some_and(plain_channel))
}

fn plain_channel(channel: &str) -> bool {
    !channel.is_empty()
        && channel.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

#[cfg(test)]
mod tests {
    use super::inert_toolchain;

    #[test]
    fn admits_plain_channels_only() {
        for contents in [
            "stable",
            "1.85.0\n",
            "nightly-2025-01-01",
            "[toolchain]\nchannel = \"1.85.0\"\n",
            "[toolchain]\nchannel = \"stable\"\ncomponents = [\"clippy\", \"rustfmt\"]\nprofile = \"minimal\"\n",
        ] {
            assert!(inert_toolchain(contents), "{contents}");
        }
        for contents in [
            "",
            "../toolchain",
            "/opt/toolchain",
            "C:\\toolchain",
            "[toolchain]\npath = \"/opt/toolchain\"\n",
            "[toolchain]\nchannel = \"stable\"\npath = \"tools\"\n",
            "[toolchain]\nchannel = \"../tools\"\n",
            "[toolchain]\ncomponents = [\"clippy\"]\n",
            "[toolchain]\nchannel = \"stable\"\n[other]\nkey = 1\n",
            "path = \"/opt/toolchain\"\n",
            "[toolchain\n",
        ] {
            assert!(!inert_toolchain(contents), "{contents}");
        }
    }
}
