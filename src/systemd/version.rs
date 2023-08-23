//! Systemd & kernel version

use std::fmt;
use std::process::Command;
use std::str;

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub struct SystemdVersion {
    pub major: u16,
    pub minor: u16,
}

impl SystemdVersion {
    pub fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub fn local_system() -> anyhow::Result<Self> {
        let output = Command::new("systemctl").arg("--version").output()?;
        if !output.status.success() {
            anyhow::bail!("systemctl invocation failed with code {:?}", output.status);
        }
        let (major, rest) = str::from_utf8(&output.stdout)?
            .split_once('(')
            .ok_or_else(|| anyhow::anyhow!("Unable to get systemd major version"))?
            .1
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("Unable to get systemd minor version"))?;
        let minor = rest
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>();
        Ok(Self {
            major: major.parse()?,
            minor: minor.parse()?,
        })
    }
}

impl fmt::Display for SystemdVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub struct KernelVersion {
    major: u16,
    minor: u16,
    release: u16,
}

impl KernelVersion {
    pub fn new(major: u16, minor: u16, release: u16) -> Self {
        Self {
            major,
            minor,
            release,
        }
    }

    pub fn local_system() -> anyhow::Result<Self> {
        let output = Command::new("uname").arg("-r").output()?;
        if !output.status.success() {
            anyhow::bail!("uname invocation failed with code {:?}", output.status);
        }
        let tokens: Vec<_> = str::from_utf8(&output.stdout)?.splitn(3, '.').collect();
        let release = tokens
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("Unable to get kernel release version"))?
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>();
        Ok(Self {
            major: tokens
                .first()
                .ok_or_else(|| anyhow::anyhow!("Unable to get kernel major version"))?
                .parse()?,
            minor: tokens
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("Unable to get kernel minor version"))?
                .parse()?,
            release: release.parse()?,
        })
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.release)
    }
}
