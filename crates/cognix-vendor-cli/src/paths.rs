//! Filesystem and path helpers shared by the CLI.
//!
//! All writes that replace existing repository metadata go through
//! [`atomic_write`] so an interrupted process cannot leave a truncated JSON
//! document behind.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Join a path to the current directory and normalize `.`/`..` lexically.
///
/// The function intentionally does not require the path to exist.
pub fn absolute_path(path: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("reading current directory")?
            .join(path)
    };
    Ok(lexical_normalize(&joined))
}

/// Resolve a path that may be relative to `base`.
pub fn resolve_against(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        lexical_normalize(path)
    } else {
        lexical_normalize(&base.join(path))
    }
}

/// Remove `.` and resolve `..` components without touching the filesystem.
pub fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let popped = result.pop();
                if !popped {
                    result.push("..");
                }
            }
            Component::Prefix(prefix) => result.push(prefix.as_os_str()),
            Component::RootDir => result.push(Component::RootDir.as_os_str()),
            Component::Normal(part) => result.push(part),
        }
    }
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

/// Compute a relative path from `base` to `target`.
///
/// Both paths are normalized first. If the paths do not share a prefix (for
/// example, different Windows drives), the normalized target is returned.
pub fn relative_to(base: &Path, target: &Path) -> PathBuf {
    let base = lexical_normalize(base);
    let target = lexical_normalize(target);
    let base_components: Vec<Component<'_>> = base.components().collect();
    let target_components: Vec<Component<'_>> = target.components().collect();

    let common = base_components
        .iter()
        .zip(target_components.iter())
        .take_while(|(left, right)| left == right)
        .count();

    if common == 0 && (base.is_absolute() || target.is_absolute()) {
        return target;
    }

    let mut result = PathBuf::new();
    for _ in common..base_components.len() {
        result.push("..");
    }
    for component in &target_components[common..] {
        result.push(component.as_os_str());
    }
    if result.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        result
    }
}

/// Returns true when `child` is inside `parent` (or equal to it).
pub fn is_within(child: &Path, parent: &Path) -> bool {
    let child = lexical_normalize(child);
    let parent = lexical_normalize(parent);
    child == parent || child.starts_with(&parent)
}

/// Returns true when a path is a safe, non-empty relative path with only
/// normal components. Used when reading paths from Cargo checksum manifests.
pub fn is_safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Atomically replace a file with `contents`.
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("creating directory {}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cognix-vendor");
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{counter}", std::process::id()));

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .with_context(|| format!("creating temporary file {}", temp_path.display()))?;
        file.write_all(contents)
            .with_context(|| format!("writing temporary file {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("flushing temporary file {}", temp_path.display()))?;
    }

    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("replacing {}", path.display()))?;
    }

    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "renaming {} to {} (remove the destination if it is locked)",
            temp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

/// Serialize a value as pretty JSON with a trailing newline and write it
/// atomically.
pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("serializing JSON for {}", path.display()))?;
    bytes.push(b'\n');
    atomic_write(path, &bytes)
}

/// Read and parse a JSON document with path context.
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing JSON in {}", path.display()))
}

/// SHA-256 of a file, formatted as lower-case hex.
pub fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// SHA-256 of a byte slice, formatted as lower-case hex.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Current UNIX timestamp in seconds.
pub fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the UNIX epoch")?
        .as_secs())
}

/// Locate the Cargo binary, honoring `CARGO` set by Cargo itself when this
/// program is invoked through `cargo run`.
pub fn cargo_program() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn unique_suffix() -> String {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}.{counter}", std::process::id())
}

/// Create a unique sibling path. The path itself is not created.
pub fn sibling_temp_path(base: &Path, label: &str) -> Result<PathBuf> {
    let parent = base
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = base
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vendor");
    Ok(parent.join(format!(".{name}.{label}.{}", unique_suffix())))
}

/// Format a byte count for terminal output.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn normalizes_dot_and_parent_components() {
        assert_eq!(
            lexical_normalize(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
        assert_eq!(lexical_normalize(Path::new("a/../..")), PathBuf::from(".."));
    }

    #[test]
    fn computes_relative_paths() {
        assert_eq!(
            relative_to(Path::new("/repo/.cargo"), Path::new("/repo/vendor")),
            PathBuf::from("../vendor")
        );
        assert_eq!(
            relative_to(Path::new("/repo"), Path::new("/repo")),
            PathBuf::from(".")
        );
        assert_eq!(
            relative_to(Path::new("/repo"), Path::new("/other/vendor")),
            PathBuf::from("../other/vendor")
        );
    }

    #[test]
    fn rejects_unsafe_relative_paths() {
        assert!(is_safe_relative(Path::new("src/lib.rs")));
        assert!(!is_safe_relative(Path::new("../lib.rs")));
        assert!(!is_safe_relative(Path::new("/etc/passwd")));
        assert!(!is_safe_relative(Path::new("")));
    }

    #[test]
    fn atomic_write_replaces_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested/value.json");
        atomic_write(&path, b"one").expect("first write");
        atomic_write(&path, b"two").expect("second write");
        assert_eq!(fs::read(&path).expect("read"), b"two");
        let leftovers = fs::read_dir(path.parent().expect("parent"))
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn detects_containment() {
        assert!(is_within(Path::new("/repo/vendor/a"), Path::new("/repo")));
        assert!(!is_within(Path::new("/repo2"), Path::new("/repo")));
    }
}
