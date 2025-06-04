//! Sysctl handling

use std::{any::type_name, fs, io, path::PathBuf, str::FromStr};

use anyhow::Context as _;

/// State of system sysctl knobs
pub(crate) struct State {
    pub kernel_unprivileged_userns_clone: bool,
}

impl State {
    /// Fetch current state
    pub(crate) fn fetch() -> anyhow::Result<Self> {
        Ok(Self {
            kernel_unprivileged_userns_clone: match Self::read_bool(
                "kernel/unprivileged_userns_clone",
            ) {
                Ok(v) => v,
                Err(err)
                    if err
                        .root_cause()
                        .downcast_ref::<io::Error>()
                        .is_some_and(|ioerr| ioerr.kind() == io::ErrorKind::NotFound) =>
                {
                    // This sysctl comes from a patch commonly applied by Linux distros, but may not be here
                    // In this case the vanilla behavior is to allow unprivileged user namespaces
                    true
                }
                Err(err) => return Err(err),
            },
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
