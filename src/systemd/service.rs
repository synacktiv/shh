//! Systemd service actions

use std::{
    env, fmt,
    fs::{self, File},
    io::{self, BufRead as _, BufReader, BufWriter, Write},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use itertools::Itertools as _;
use rand::Rng as _;

use crate::{
    cl::HardeningOptions,
    systemd::{END_OPTION_OUTPUT_SNIPPET, START_OPTION_OUTPUT_SNIPPET, options::OptionWithValue},
};

use super::InstanceKind;

pub(crate) struct Service {
    name: String,
    arg: Option<String>,
    instance: InstanceKind,
}

const PROFILING_FRAGMENT_NAME: &str = "profile";
const HARDENING_FRAGMENT_NAME: &str = "harden";
/// Command line prefix for `ExecStartXxx`= that bypasses all hardening options
/// See <https://www.freedesktop.org/software/systemd/man/255/systemd.service.html#Command%20lines>
const PRIVILEGED_PREFIX: &str = "+";

/// Systemd "exposure level", to rate service security.
/// The lower, the better
pub(crate) struct ExposureLevel(u8);

impl TryFrom<f64> for ExposureLevel {
    type Error = anyhow::Error;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        const RANGE: RangeInclusive<f64> = 0.0..=10.0;
        anyhow::ensure!(
            RANGE.contains(&value),
            "Value not in range [{:.1}; {:.1}]",
            RANGE.start(),
            RANGE.end()
        );
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Ok(Self((value * 10.0) as u8))
    }
}

impl fmt::Display for ExposureLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.1}", f64::from(self.0) / 10.0)
    }
}

pub(crate) struct JournalCursor(String);

impl JournalCursor {
    pub(crate) fn current() -> anyhow::Result<Self> {
        let tmp_file = tempfile::NamedTempFile::new()?;
        // Note: user instances use the same cursor
        let status = Command::new("journalctl")
            .args([
                "-n",
                "0",
                "--cursor-file",
                tmp_file
                    .path()
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid temporary filepath"))?,
            ])
            .status()?;
        if !status.success() {
            anyhow::bail!("journalctl failed: {status}");
        }
        let val = fs::read_to_string(tmp_file.path())?;
        Ok(Self(val))
    }
}

impl AsRef<str> for JournalCursor {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl Service {
    pub(crate) fn new(unit: &str, instance: InstanceKind) -> anyhow::Result<Self> {
        const UNSUPPORTED_UNIT_SUFFIXS: [&str; 10] = [
            ".socket",
            ".device",
            ".mount",
            ".automount",
            ".swap",
            ".target",
            ".path",
            ".timer",
            ".slice",
            ".scope",
        ];
        if let Some(suffix) = UNSUPPORTED_UNIT_SUFFIXS.iter().find(|s| unit.ends_with(*s)) {
            let type_ = suffix.split_at(1).1;
            anyhow::bail!("Unit type {type_:?} is not supported");
        }
        let unit = unit.strip_suffix(".service").unwrap_or(unit);
        if let Some((name, arg)) = unit.split_once('@') {
            Ok(Self {
                name: name.to_owned(),
                arg: Some(arg.to_owned()),
                instance,
            })
        } else {
            Ok(Self {
                name: unit.to_owned(),
                arg: None,
                instance,
            })
        }
    }

    fn unit_name(&self) -> String {
        format!(
            "{}{}.service",
            &self.name,
            if let Some(arg) = self.arg.as_ref() {
                format!("@{arg}")
            } else {
                String::new()
            }
        )
    }

    /// Get systemd "exposure level" for the service (0-100).
    /// 100 means extremely exposed (no hardening), 0 means so sandboxed it can't do much.
    /// Although this is a very crude heuristic, below 40-50 is generally good.
    pub(crate) fn get_exposure_level(&self) -> anyhow::Result<ExposureLevel> {
        let mut cmd = Command::new("systemd-analyze");
        cmd.arg("security");
        if matches!(self.instance, InstanceKind::User) {
            cmd.arg("--user");
        }
        let output = cmd
            .arg(self.unit_name())
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()?;
        if !output.status.success() {
            anyhow::bail!("systemd-analyze failed: {}", output.status);
        }
        let last_line = output
            .stdout
            .lines()
            .map_while(Result::ok)
            .last()
            .context("Failed to read systemd-analyze output")?;
        let val_f = last_line
            .rsplit(' ')
            .nth(2)
            .and_then(|v| v.parse::<f64>().ok())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse exposure level"))?;
        val_f.try_into()
    }

    pub(crate) fn add_profile_fragment(
        &self,
        hardening_opts: &HardeningOptions,
    ) -> anyhow::Result<()> {
        // Check first if our fragment does not yet exist
        let fragment_path = self.fragment_path(PROFILING_FRAGMENT_NAME, false);
        anyhow::ensure!(
            !fragment_path.is_file(),
            "Fragment config already exists at {fragment_path:?}"
        );
        let harden_fragment_path = self.fragment_path(HARDENING_FRAGMENT_NAME, true);
        anyhow::ensure!(
            !harden_fragment_path.is_file(),
            "Hardening config already exists at {harden_fragment_path:?} and may conflict with profiling"
        );

        let config_paths_bufs = self.config_paths()?;
        let config_paths = config_paths_bufs
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        log::info!("Located unit config file(s): {config_paths:?}");

        // Write new fragment
        #[expect(clippy::unwrap_used)] // fragment_path guarantees by construction we have a parent
        fs::create_dir_all(fragment_path.parent().unwrap())?;
        let mut fragment_file = BufWriter::new(File::create(&fragment_path)?);
        Self::write_fragment_header(&mut fragment_file)?;
        writeln!(fragment_file, "[Service]")?;
        // writeln!(fragment_file, "AmbientCapabilities=CAP_SYS_PTRACE")?;
        if Self::config_vals("Type", &config_paths)?
            .last()
            .is_some_and(|v| v.starts_with("notify"))
        {
            // needed because strace becomes the main process
            writeln!(fragment_file, "NotifyAccess=all")?;
        }
        writeln!(fragment_file, "Environment=RUST_BACKTRACE=1")?;
        if !Self::config_vals("SystemCallFilter", &config_paths)?.is_empty() {
            // Allow ptracing, only if a syscall filter is already in place, otherwise it becomes a whitelist
            writeln!(fragment_file, "SystemCallFilter=@debug")?;
        }
        // strace may slow down enough to risk reaching some service timeouts
        writeln!(fragment_file, "TimeoutStartSec=infinity")?;
        writeln!(fragment_file, "KillMode=control-group")?;
        writeln!(fragment_file, "StandardOutput=journal")?;

        // Profile data dir
        // %t maps to /run for system instances or $XDG_RUNTIME_DIR (usually /run/user/[UID]) for user instance
        let mut rng = rand::rng();
        let profile_data_dir = PathBuf::from(format!(
            "%t/{}-profile-data_{:08x}",
            env!("CARGO_BIN_NAME"),
            rng.random::<u32>()
        ));
        #[expect(clippy::unwrap_used)]
        writeln!(
            fragment_file,
            "RuntimeDirectory={}",
            profile_data_dir.file_name().unwrap().to_str().unwrap()
        )?;

        let shh_bin = env::current_exe()?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Unable to decode current executable path"))?
            .to_owned();

        // Wrap ExecStartXxx directives
        let mut exec_start_idx = 1;
        let mut profile_data_paths = Vec::new();
        for exec_start_opt in ["ExecStartPre", "ExecStart", "ExecStartPost"] {
            let exec_start_cmds = Self::config_vals(exec_start_opt, &config_paths)?;
            if !exec_start_cmds.is_empty() {
                writeln!(fragment_file, "{exec_start_opt}=")?;
            }
            for cmd in exec_start_cmds {
                if cmd.starts_with(PRIVILEGED_PREFIX) {
                    // TODO handle other special prefixes?
                    // Write command unchanged
                    writeln!(fragment_file, "{exec_start_opt}={cmd}")?;
                } else {
                    let profile_data_path = profile_data_dir.join(format!("{exec_start_idx:03}"));
                    exec_start_idx += 1;
                    #[expect(clippy::unwrap_used)]
                    writeln!(
                        fragment_file,
                        "{}={} run {} -p {} -- {}",
                        exec_start_opt,
                        shh_bin,
                        self.instance
                            .to_cmd_args()
                            .into_iter()
                            .chain(hardening_opts.to_cmd_args())
                            .collect::<Vec<_>>()
                            .join(" "),
                        profile_data_path.to_str().unwrap(),
                        cmd
                    )?;
                    profile_data_paths.push(profile_data_path);
                }
            }
        }

        // Add invocation that merges previous profiles
        #[expect(clippy::unwrap_used)]
        writeln!(
            fragment_file,
            "ExecStopPost={} merge-profile-data {} {}",
            shh_bin,
            self.instance
                .to_cmd_args()
                .into_iter()
                .chain(hardening_opts.to_cmd_args())
                .collect::<Vec<_>>()
                .join(" "),
            profile_data_paths
                .iter()
                .map(|p| p.to_str().unwrap())
                .join(" ")
        )?;

        log::info!("Config fragment written in {fragment_path:?}");
        Ok(())
    }

    pub(crate) fn remove_profile_fragment(&self) -> anyhow::Result<()> {
        let fragment_path = self.fragment_path(PROFILING_FRAGMENT_NAME, false);
        fs::remove_file(&fragment_path)?;
        log::info!("{fragment_path:?} removed");
        // let mut parent_dir = fragment_path;
        // while let Some(parent_dir) = parent_dir.parent() {
        //     if fs::remove_dir(parent_dir).is_err() {
        //         // Likely directory not empty
        //         break;
        //     }
        //     log::info!("{parent_dir:?} removed");
        // }
        Ok(())
    }

    pub(crate) fn remove_hardening_fragment(&self) -> anyhow::Result<()> {
        let fragment_path = self.fragment_path(HARDENING_FRAGMENT_NAME, true);
        fs::remove_file(&fragment_path)?;
        log::info!("{fragment_path:?} removed");
        Ok(())
    }

    pub(crate) fn add_hardening_fragment(
        &self,
        opts: Vec<OptionWithValue<String>>,
    ) -> anyhow::Result<PathBuf> {
        let fragment_path = self.fragment_path(HARDENING_FRAGMENT_NAME, true);
        #[expect(clippy::unwrap_used)]
        fs::create_dir_all(fragment_path.parent().unwrap())?;

        let mut fragment_file = BufWriter::new(File::create(&fragment_path)?);
        Self::write_fragment_header(&mut fragment_file)?;
        writeln!(fragment_file, "[Service]")?;
        for opt in opts {
            writeln!(fragment_file, "{opt}")?;
        }

        log::info!("Config fragment written in {fragment_path:?}");
        Ok(fragment_path)
    }

    fn write_fragment_header<W: Write>(writer: &mut W) -> io::Result<()> {
        writeln!(
            writer,
            "# This file has been autogenerated by {} v{}",
            env!("CARGO_BIN_NAME"),
            env!("CARGO_PKG_VERSION"),
        )
    }

    pub(crate) fn reload_unit_config(&self) -> anyhow::Result<()> {
        let mut cmd = Command::new("systemctl");
        if matches!(self.instance, InstanceKind::User) {
            cmd.arg("--user");
        }
        let status = cmd.arg("daemon-reload").status()?;
        if !status.success() {
            anyhow::bail!("systemctl failed: {status}");
        }
        Ok(())
    }

    pub(crate) fn action(&self, verb: &str, block: bool) -> anyhow::Result<()> {
        let unit_name = self.unit_name();
        log::info!("{verb} {unit_name}");
        let mut cmd = vec![verb];
        if matches!(self.instance, InstanceKind::User) {
            cmd.push("--user");
        }
        if !block {
            cmd.push("--no-block");
        }
        cmd.push(&unit_name);
        let status = Command::new("systemctl").args(cmd).status()?;
        if !status.success() {
            anyhow::bail!("systemctl failed: {status}");
        }
        Ok(())
    }

    pub(crate) fn profiling_result_retry(
        &self,
        cursor: &JournalCursor,
    ) -> anyhow::Result<Vec<OptionWithValue<String>>> {
        // DefaultTimeoutStopSec is typically 90s and services can dynamically extend it
        // See https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#TimeoutStopSec=
        const PROFILING_RESULT_TIMEOUT: Duration = Duration::from_secs(90);
        const PROFILING_RESULT_USLEEP: Duration = Duration::from_millis(300);
        const PROFILING_RESULT_WARN_DELAY: Duration = Duration::from_secs(3);
        // For user units, sometimes journalctl does not have the logs yet, so retry with a delay
        let time_start = Instant::now();
        let mut slow_result_warned = false;
        loop {
            match self.profiling_result(cursor) {
                Ok(opts) => return Ok(opts),
                Err(err) => {
                    let now = Instant::now();
                    let waited = now.saturating_duration_since(time_start);
                    if waited > PROFILING_RESULT_TIMEOUT {
                        return Err(err.context("Timeout waiting for profiling result"));
                    } else if !slow_result_warned && (waited > PROFILING_RESULT_WARN_DELAY) {
                        log::warn!(
                            "Profiling result is not available after {}s ({}), this can be caused by slow service shutdown. Will retry and wait up to {}s",
                            PROFILING_RESULT_WARN_DELAY.as_secs(),
                            err,
                            PROFILING_RESULT_TIMEOUT.as_secs()
                        );
                        slow_result_warned = true;
                    }
                }
            }
            sleep(PROFILING_RESULT_USLEEP);
        }
    }

    fn profiling_result(
        &self,
        cursor: &JournalCursor,
    ) -> anyhow::Result<Vec<OptionWithValue<String>>> {
        // Start journalctl process
        let mut cmd = Command::new("journalctl");
        if matches!(self.instance, InstanceKind::User) {
            cmd.arg("--user");
        }
        let mut child = cmd
            .args([
                "-r",
                "-o",
                "cat",
                "--output-fields=MESSAGE",
                "--no-tail",
                "--after-cursor",
                cursor.as_ref(),
                "-u",
                &self.unit_name(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("LANG", "C")
            .spawn()?;

        // Parse its output
        #[expect(clippy::unwrap_used)]
        let reader = BufReader::new(child.stdout.take().unwrap());
        let snippet_lines: Vec<_> = reader
            .lines()
            // Stream lines but bubble up errors
            .skip_while(|r| {
                r.as_ref()
                    .map(|l| l != END_OPTION_OUTPUT_SNIPPET)
                    .unwrap_or(false)
            })
            .take_while_inclusive(|r| {
                r.as_ref()
                    .map(|l| l != START_OPTION_OUTPUT_SNIPPET)
                    .unwrap_or(true)
            })
            .collect::<Result<_, _>>()?;
        if (snippet_lines.len() < 2)
            || (snippet_lines
                .last()
                .ok_or_else(|| anyhow::anyhow!("Unable to get profiling result lines"))?
                != START_OPTION_OUTPUT_SNIPPET)
        {
            anyhow::bail!("Unable to get profiling result snippet");
        }
        // The output with '-r' flag is in reverse chronological order
        // (to get the end as fast as possible), so reverse it, after we have
        // removed marker lines
        #[expect(clippy::indexing_slicing)]
        let opts = snippet_lines[1..snippet_lines.len() - 1]
            .iter()
            .rev()
            .map(|l| l.parse::<OptionWithValue<String>>())
            .collect::<anyhow::Result<_>>()?;

        // Stop journalctl
        child.kill()?;
        child.wait()?;

        Ok(opts)
    }

    fn config_vals(key: &str, config_paths: &[&Path]) -> anyhow::Result<Vec<String>> {
        // Note: we could use 'systemctl show -p xxx' but its output is different from config
        // files, and we would need to interpret it anyway
        let mut vals = Vec::new();
        for config_path in config_paths {
            let config_file = BufReader::new(File::open(config_path)?);
            let prefix = format!("{key}=");
            let mut file_vals = vec![];
            let mut lines = config_file.lines();
            while let Some(line) = lines.next() {
                let line = line?;
                if line.starts_with(&prefix) {
                    let val = if line.ends_with('\\') {
                        let mut val = line
                            .split_once('=')
                            .ok_or_else(|| anyhow::anyhow!("Unable to parse service option line"))?
                            .1
                            .trim()
                            .to_owned();
                        // Remove trailing '\'
                        val.pop();
                        // Append next lines
                        loop {
                            let next_line = lines
                                .next()
                                .ok_or_else(|| anyhow::anyhow!("Unexpected end of file"))??;
                            val = format!("{} {}", val, next_line.trim_start());
                            if next_line.ends_with('\\') {
                                // Remove trailing '\'
                                val.pop();
                            } else {
                                break;
                            }
                        }
                        val
                    } else {
                        line.split_once('=')
                            .ok_or_else(|| anyhow::anyhow!("Unable to parse service option line"))?
                            .1
                            .trim()
                            .to_owned()
                    };
                    file_vals.push(val);
                }
            }
            // Handles lines that reset previously set options
            if let Some((last, _)) = file_vals
                .split_inclusive(String::is_empty)
                .rev()
                .take(2)
                .collect_tuple()
            {
                file_vals = last.to_vec();
                vals.clear();
            }
            vals.extend(file_vals);
        }
        Ok(vals)
    }

    fn config_paths(&self) -> anyhow::Result<Vec<PathBuf>> {
        let mut cmd = Command::new("systemctl");
        if matches!(self.instance, InstanceKind::User) {
            cmd.arg("--user");
        }
        let output = cmd
            .args(["status", "-n", "0", &self.unit_name()])
            .env("LANG", "C")
            .output()?;
        let mut paths = Vec::new();
        let mut drop_in_dir = None;
        for line in output.stdout.lines() {
            let line = line?;
            let line = line.trim_start();
            if line.starts_with("Loaded:") {
                // Main unit file
                anyhow::ensure!(paths.is_empty());
                let path = line
                    .split_once('(')
                    .ok_or_else(|| anyhow::anyhow!("Failed to locate main unit file"))?
                    .1
                    .split_once(';')
                    .ok_or_else(|| anyhow::anyhow!("Failed to locate main unit file"))?
                    .0;
                paths.push(PathBuf::from(path));
            } else if line.starts_with("Drop-In:") {
                // Drop in base dir
                anyhow::ensure!(paths.len() == 1);
                anyhow::ensure!(drop_in_dir.is_none());
                let dir = line
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("Failed to locate unit config fragment dir"))?
                    .1
                    .trim_start();
                drop_in_dir = Some(PathBuf::from(dir));
            } else if let Some(dir) = drop_in_dir.as_ref() {
                if line.contains(':') {
                    // Not a path, next key: val line
                    break;
                } else if line.starts_with('/') {
                    // New base dir
                    drop_in_dir = Some(PathBuf::from(line));
                } else {
                    for filename in line.trim().chars().skip(2).collect::<String>().split(", ") {
                        let path = dir.join(filename);
                        paths.push(path);
                    }
                }
            }
        }
        Ok(paths)
    }

    fn fragment_path(&self, name: &str, persistent: bool) -> PathBuf {
        // https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#System%20Unit%20Search%20Path
        let base_dir = if persistent {
            let etc = "/etc";
            match self.instance {
                InstanceKind::System => etc.to_owned(),
                InstanceKind::User => {
                    // Use /etc if we can, which affects all user instances, otherwise use per user XDG dir
                    let aflags = nix::unistd::AccessFlags::R_OK
                        .union(nix::unistd::AccessFlags::W_OK)
                        .union(nix::unistd::AccessFlags::X_OK);
                    if nix::unistd::access(etc, aflags).is_ok() {
                        etc.to_owned()
                    } else {
                        #[expect(clippy::unwrap_used)]
                        env::var_os("XDG_CONFIG_DIR")
                            .or_else(|| {
                                env::var_os("HOME").map(|h| {
                                    PathBuf::from(h).join(".config").as_os_str().to_owned()
                                })
                            })
                            .and_then(|p| p.to_str().map(ToOwned::to_owned))
                            .unwrap()
                    }
                }
            }
        } else {
            match self.instance {
                InstanceKind::System => "/run".to_owned(),
                InstanceKind::User => env::var_os("XDG_RUNTIME_DIR")
                    .and_then(|p| p.to_str().map(ToOwned::to_owned))
                    .unwrap_or_else(|| format!("/run/user/{}", nix::unistd::getuid().as_raw())),
            }
        };
        [
            &base_dir,
            "systemd",
            &self.instance.to_string(),
            &format!(
                "{}{}.service.d",
                self.name,
                if self.arg.is_some() { "@" } else { "" }
            ),
            &format!("zz_{}-{}.conf", env!("CARGO_BIN_NAME"), name),
        ]
        .iter()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_vals() {
        let _ = simple_logger::SimpleLogger::new().init();

        let mut cfg_file1 = tempfile::NamedTempFile::new().unwrap();
        let mut cfg_file2 = tempfile::NamedTempFile::new().unwrap();
        let mut cfg_file3 = tempfile::NamedTempFile::new().unwrap();

        writeln!(cfg_file1, "blah=a").unwrap();
        writeln!(cfg_file1, "blah=b").unwrap();
        writeln!(cfg_file2, "blah=").unwrap();
        writeln!(cfg_file2, "blah=c").unwrap();
        writeln!(cfg_file2, "blih=e").unwrap();
        writeln!(cfg_file2, "bloh=f").unwrap();
        writeln!(cfg_file3, "blah=d").unwrap();

        assert_eq!(
            Service::config_vals(
                "blah",
                &[cfg_file1.path(), cfg_file2.path(), cfg_file3.path()]
            )
            .unwrap(),
            vec!["c", "d"]
        );
    }

    #[test]
    fn test_config_val_multiline() {
        let _ = simple_logger::SimpleLogger::new().init();

        let mut cfg_file = tempfile::NamedTempFile::new().unwrap();

        writeln!(
            cfg_file,
            r#"ExecStartPre=/bin/sh -c "[ ! -e /usr/bin/galera_recovery ] && VAR= || \
VAR=`cd /usr/bin/..; /usr/bin/galera_recovery`; [ $? -eq 0 ] \
&& systemctl set-environment _WSREP_START_POSITION=$VAR || exit 1""#
        )
        .unwrap();

        assert_eq!(
            Service::config_vals("ExecStartPre", &[cfg_file.path()]).unwrap(),
            vec![
                r#"/bin/sh -c "[ ! -e /usr/bin/galera_recovery ] && VAR= ||  VAR=`cd /usr/bin/..; /usr/bin/galera_recovery`; [ $? -eq 0 ]  && systemctl set-environment _WSREP_START_POSITION=$VAR || exit 1""#
            ]
        );
    }
}
