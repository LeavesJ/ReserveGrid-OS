//! Atomic TOML configuration read/write utilities.
//!
//! Services use these helpers to persist operator-driven config changes
//! from the dashboard UI. Writes use atomic rename to prevent corruption
//! on crash or concurrent access.

use std::fs;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

/// Errors that can occur when reading or writing config TOML files.
#[derive(Debug, Error)]
pub enum ConfigIoError {
    #[error("failed to read config from {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to parse TOML from {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },

    #[error("failed to serialize config to TOML: {source}")]
    Serialize { source: toml::ser::Error },

    #[error("failed to write config to {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to rename temp file to {path}: {source}")]
    Rename {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to create backup at {path}: {source}")]
    Backup {
        path: String,
        source: std::io::Error,
    },
}

/// Read and deserialize a TOML config file.
pub fn read_toml<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigIoError> {
    let contents = fs::read_to_string(path).map_err(|e| ConfigIoError::Read {
        path: path.display().to_string(),
        source: e,
    })?;
    toml::from_str(&contents).map_err(|e| ConfigIoError::Parse {
        path: path.display().to_string(),
        source: e,
    })
}

/// Atomically write a serializable value as pretty-printed TOML.
///
/// The write sequence is:
/// 1. Serialize value to TOML string
/// 2. Write to `{path}.tmp`
/// 3. If the original file exists, copy it to `{path}.bak`
/// 4. Rename `{path}.tmp` to `{path}` (atomic on POSIX)
///
/// On failure the original file is untouched (the tmp file may remain).
pub fn atomic_write_toml<T: Serialize>(path: &Path, value: &T) -> Result<(), ConfigIoError> {
    let toml_text =
        toml::to_string_pretty(value).map_err(|e| ConfigIoError::Serialize { source: e })?;

    let tmp_path = path.with_extension("toml.tmp");
    fs::write(&tmp_path, toml_text.as_bytes()).map_err(|e| ConfigIoError::Write {
        path: tmp_path.display().to_string(),
        source: e,
    })?;

    // Best-effort backup of the original file before overwrite.
    if path.exists() {
        let bak_path = path.with_extension("toml.bak");
        if let Err(e) = fs::copy(path, &bak_path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to create config backup; proceeding with save"
            );
        }
    }

    fs::rename(&tmp_path, path).map_err(|e| ConfigIoError::Rename {
        path: path.display().to_string(),
        source: e,
    })?;

    tracing::info!(path = %path.display(), "config saved to disk");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestConfig {
        name: String,
        value: u32,
    }

    #[test]
    fn round_trip_write_read() {
        let dir = std::env::temp_dir().join("rg_config_io_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test.toml");

        let cfg = TestConfig {
            name: "hello".into(),
            value: 42,
        };

        atomic_write_toml(&path, &cfg).expect("write should succeed");
        let loaded: TestConfig = read_toml(&path).expect("read should succeed");
        assert_eq!(cfg, loaded);

        // Verify backup was not created (no pre-existing file on first write
        // actually there IS a file now since we wrote it; write again to test backup)
        atomic_write_toml(&path, &cfg).expect("second write should succeed");
        let bak_path = path.with_extension("toml.bak");
        assert!(
            bak_path.exists(),
            "backup file should exist after second write"
        );

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_nonexistent_returns_error() {
        let path = PathBuf::from("/tmp/rg_nonexistent_config_io_test.toml");
        let result: Result<TestConfig, _> = read_toml(&path);
        assert!(result.is_err());
    }
}
