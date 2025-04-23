//! Sysctl handling

use std::{any::type_name, fs, path::PathBuf, str::FromStr};

use anyhow::Context as _;

/// State of system sysctl knobs
pub(crate) struct State {
    pub kernel_unprivileged_userns_clone: bool,
}

impl State {
    /// Fetch current state
    pub(crate) fn fetch() -> anyhow::Result<Self> {
        Ok(Self {
            kernel_unprivileged_userns_clone: Self::read_bool("kernel/unprivileged_userns_clone")?,
        })
    }

    /// Generate synthetic "all is supported" state
    pub(crate) fn all() -> Self {
        Self {
            kernel_unprivileged_userns_clone: true,
        }
    }

    /// Generate synthetic "none is supported" state
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self {
            kernel_unprivileged_userns_clone: false,
        }
    }

    fn read<T>(key: &str) -> anyhow::Result<T>
    where
        T: FromStr,
    {
        let path: PathBuf = ["/proc/sys", key].iter().collect();
        let val_str = fs::read_to_string(&path)
            .map(|s| s.trim_end().to_owned())
            .with_context(|| format!("Failed to read {path:?}"))?;
        val_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Failed to parse {:?} into {}", val_str, type_name::<T>()))
    }

    fn read_bool(key: &str) -> anyhow::Result<bool> {
        Ok(Self::read::<u8>(key)? != 0)
    }
}
