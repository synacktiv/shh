//! Systemd & kernel version

use std::fmt;
use std::io::BufRead;
use std::process::Command;
use std::str;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
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
        let line = output
            .stdout
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Unable to get systemd version"))??;
        Self::parse_version_line(&line)
    }

    fn parse_version_line(s: &str) -> anyhow::Result<Self> {
        let version = s
            .split_once('(')
            .ok_or_else(|| anyhow::anyhow!("Unable to parse systemd version"))?
            .1
            .split_once(')')
            .ok_or_else(|| anyhow::anyhow!("Unable to parse systemd version"))?
            .0;
        let major_str = version
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>();
        let major = major_str.parse()?;
        let minor = if let Some('.') = version.chars().nth(major_str.len()) {
            // Actual minor version
            version
                .chars()
                .skip(major_str.len() + 1)
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()?
        } else {
            // RC or distro suffix
            0
        };
        Ok(Self { major, minor })
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

#[cfg(test)]
mod tests {
    use crate::systemd::SystemdVersion;

    #[test]
    fn test_parse_version() {
        assert_eq!(
            SystemdVersion::parse_version_line("systemd 254 (254.1)").unwrap(),
            SystemdVersion::new(254, 1)
        );
        assert_eq!(
            SystemdVersion::parse_version_line("systemd 255 (255~rc3-2)").unwrap(),
            SystemdVersion::new(255, 0)
        );
    }
}
