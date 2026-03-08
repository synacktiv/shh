//! Systemd unit log handling via `journalctl`

use std::{
    fs,
    io::BufRead as _,
    process,
    process::{Command, Stdio},
};

use anyhow::Context as _;

use crate::systemd::{
    InstanceKind, Service, end_option_output_line, options::OptionWithValue, service::InvocationId,
    start_option_output_line,
};

pub(crate) struct JournalCursor(String);

#[derive(Debug, strum::Display)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) enum IncompleteOutputKind {
    #[strum(to_string = "Missing start marker")]
    MissingStartMarker,
    #[strum(to_string = "Missing stop marker")]
    MissingStopMarker,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum ProfilingLogError {
    #[error("Incomplete output: {kind}. Current logs:\n{logs}")]
    Incomplete {
        kind: IncompleteOutputKind,
        logs: String,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

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
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        anyhow::ensure!(status.success(), "journalctl failed: {status}");
        let val = fs::read_to_string(tmp_file.path())?;
        Ok(Self(val))
    }

    pub(crate) fn profiling_result(
        &self,
        service: &Service,
        invocation: &InvocationId,
    ) -> Result<Vec<OptionWithValue<String>>, ProfilingLogError> {
        // Start journalctl process
        let mut cmd = Command::new("journalctl");
        if matches!(service.instance, InstanceKind::User) {
            cmd.arg("--user");
        }
        let output = cmd
            .args([
                "-o",
                "cat",
                "--output-fields=MESSAGE",
                "--no-tail",
                "--after-cursor",
                self.as_ref(),
                "-u",
                &service.unit_name(),
                // Filter to only stdout/stderr from the service process,
                // excluding systemd's own messages about the unit (e.g. "Deactivated successfully.")
                "_TRANSPORT=stdout",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("LANG", "C")
            .output()
            .context("Failed to start journalctl")?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("journalctl failed: {}", output.status).into());
        }

        // Parse its output
        let snippet_lines = Self::parse_profiling_result(invocation, &output)?;

        let opts = snippet_lines
            .iter()
            .map(|l| l.parse::<OptionWithValue<String>>())
            .collect::<anyhow::Result<_>>()?;

        Ok(opts)
    }

    fn parse_profiling_result(
        invocation: &InvocationId,
        output: &process::Output,
    ) -> Result<Vec<String>, ProfilingLogError> {
        let start_marker = start_option_output_line(Some(invocation));
        let end_marker = end_option_output_line(Some(invocation));
        let mut has_start_marker = false;
        let mut has_end_marker = false;
        let snippet_lines: Vec<_> = output
            .stdout
            .lines()
            // Filter out delimiting lines while letting errors bubble up
            .skip_while(|r| r.as_ref().is_ok_and(|l| l != &start_marker))
            .inspect(|_| {
                has_start_marker = true;
            })
            .skip(1)
            .inspect(|r| {
                if r.as_ref().is_ok_and(|l| l == &end_marker) {
                    has_end_marker = true;
                }
            })
            .take_while(|r| r.as_ref().map_or(true, |l| l != &end_marker))
            .collect::<Result<_, _>>()
            .context("Failed to read journactl output")?;
        if !has_start_marker {
            return Err(ProfilingLogError::Incomplete {
                kind: IncompleteOutputKind::MissingStartMarker,
                logs: String::from_utf8_lossy(&output.stdout).into_owned(),
            });
        }
        if !has_end_marker {
            return Err(ProfilingLogError::Incomplete {
                kind: IncompleteOutputKind::MissingStopMarker,
                logs: String::from_utf8_lossy(&output.stdout).into_owned(),
            });
        }
        Ok(snippet_lines)
    }
}

impl AsRef<str> for JournalCursor {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
impl Eq for ProfilingLogError {}

#[cfg(test)]
impl PartialEq for ProfilingLogError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Incomplete { kind: k1, logs: l1 }, Self::Incomplete { kind: k2, logs: l2 }) => {
                k1 == k2 && l1 == l2
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::process::ExitStatusExt as _,
        process::{ExitStatus, Output},
    };

    use super::*;

    fn make_invocation() -> InvocationId {
        "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8".parse().unwrap()
    }

    fn make_output(stdout: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn parse_valid_single_option() {
        let invocation = make_invocation();
        let start = start_option_output_line(Some(&invocation));
        let end = end_option_output_line(Some(&invocation));
        let stdout = format!("{start}\nProtectHome=yes\n{end}\n");
        let output = make_output(&stdout);

        let result = JournalCursor::parse_profiling_result(&invocation, &output).unwrap();
        assert_eq!(result, vec!["ProtectHome=yes"]);
    }

    #[test]
    fn parse_valid_multiple_options() {
        let invocation = make_invocation();
        let start = start_option_output_line(Some(&invocation));
        let end = end_option_output_line(Some(&invocation));
        let stdout =
            format!("{start}\nProtectHome=yes\nProtectSystem=strict\nNoNewPrivileges=yes\n{end}\n");
        let output = make_output(&stdout);

        let result = JournalCursor::parse_profiling_result(&invocation, &output).unwrap();
        assert_eq!(
            result,
            vec![
                "ProtectHome=yes",
                "ProtectSystem=strict",
                "NoNewPrivileges=yes"
            ]
        );
    }

    #[test]
    fn parse_empty_options() {
        let invocation = make_invocation();
        let start = start_option_output_line(Some(&invocation));
        let end = end_option_output_line(Some(&invocation));
        let stdout = format!("{start}\n{end}\n");
        let output = make_output(&stdout);

        let result = JournalCursor::parse_profiling_result(&invocation, &output).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_missing_start_marker() {
        let invocation = make_invocation();
        let end = end_option_output_line(Some(&invocation));
        let stdout = format!("some random log\n{end}\n");
        let output = make_output(&stdout);

        let err = JournalCursor::parse_profiling_result(&invocation, &output).unwrap_err();
        assert_eq!(
            err,
            ProfilingLogError::Incomplete {
                kind: IncompleteOutputKind::MissingStartMarker,
                logs: stdout,
            }
        );
    }

    #[test]
    fn parse_missing_end_marker() {
        let invocation = make_invocation();
        let start = start_option_output_line(Some(&invocation));
        let stdout = format!("{start}\nProtectHome=yes\n");
        let output = make_output(&stdout);

        let err = JournalCursor::parse_profiling_result(&invocation, &output).unwrap_err();
        assert_eq!(
            err,
            ProfilingLogError::Incomplete {
                kind: IncompleteOutputKind::MissingStopMarker,
                logs: stdout,
            }
        );
    }

    #[test]
    fn parse_missing_both_markers() {
        let invocation = make_invocation();
        let stdout = "some random log line\nanother line\n";
        let output = make_output(stdout);

        let err = JournalCursor::parse_profiling_result(&invocation, &output).unwrap_err();
        assert_eq!(
            err,
            ProfilingLogError::Incomplete {
                kind: IncompleteOutputKind::MissingStartMarker,
                logs: stdout.to_owned(),
            }
        );
    }

    #[test]
    fn parse_empty_stdout() {
        let invocation = make_invocation();
        let output = make_output("");

        let err = JournalCursor::parse_profiling_result(&invocation, &output).unwrap_err();
        assert_eq!(
            err,
            ProfilingLogError::Incomplete {
                kind: IncompleteOutputKind::MissingStartMarker,
                logs: String::new(),
            }
        );
    }

    #[test]
    fn parse_ignores_lines_before_start_marker() {
        let invocation = make_invocation();
        let start = start_option_output_line(Some(&invocation));
        let end = end_option_output_line(Some(&invocation));
        let stdout =
            format!("Started service foo\nSome log line\n{start}\nProtectHome=yes\n{end}\n");
        let output = make_output(&stdout);

        let result = JournalCursor::parse_profiling_result(&invocation, &output).unwrap();
        assert_eq!(result, vec!["ProtectHome=yes"]);
    }

    #[test]
    fn parse_ignores_lines_after_end_marker() {
        let invocation = make_invocation();
        let start = start_option_output_line(Some(&invocation));
        let end = end_option_output_line(Some(&invocation));
        let stdout = format!("{start}\nProtectHome=yes\n{end}\nStopped service foo\nMore logs\n");
        let output = make_output(&stdout);

        let result = JournalCursor::parse_profiling_result(&invocation, &output).unwrap();
        assert_eq!(result, vec!["ProtectHome=yes"]);
    }

    #[test]
    fn parse_with_surrounding_log_lines() {
        let invocation = make_invocation();
        let start = start_option_output_line(Some(&invocation));
        let end = end_option_output_line(Some(&invocation));
        let stdout = format!(
            "Started service\nLog before\n{start}\nProtectHome=yes\nNoNewPrivileges=yes\n{end}\nStopped service\nLog after\n"
        );
        let output = make_output(&stdout);

        let result = JournalCursor::parse_profiling_result(&invocation, &output).unwrap();
        assert_eq!(result, vec!["ProtectHome=yes", "NoNewPrivileges=yes"]);
    }

    #[test]
    fn parse_wrong_invocation_id_missing_start() {
        let invocation = make_invocation();
        let other_invocation: InvocationId = "00000000000000000000000000000001".parse().unwrap();
        let start = start_option_output_line(Some(&other_invocation));
        let end = end_option_output_line(Some(&other_invocation));
        let stdout = format!("{start}\nProtectHome=yes\n{end}\n");
        let output = make_output(&stdout);

        // Markers with a different invocation ID are not recognized
        let err = JournalCursor::parse_profiling_result(&invocation, &output).unwrap_err();
        assert_eq!(
            err,
            ProfilingLogError::Incomplete {
                kind: IncompleteOutputKind::MissingStartMarker,
                logs: stdout,
            }
        );
    }

    #[test]
    fn parse_error_logs_contain_stdout() {
        let invocation = make_invocation();
        let stdout = "line one\nline two\n";
        let output = make_output(stdout);

        let err = JournalCursor::parse_profiling_result(&invocation, &output).unwrap_err();
        assert_eq!(
            err,
            ProfilingLogError::Incomplete {
                kind: IncompleteOutputKind::MissingStartMarker,
                logs: stdout.to_owned(),
            }
        );
    }

    #[test]
    fn parse_start_marker_without_end_preserves_lines() {
        let invocation = make_invocation();
        let start = start_option_output_line(Some(&invocation));
        let stdout = format!("{start}\nOptionA=val\nOptionB=val\n");
        let output = make_output(&stdout);

        let err = JournalCursor::parse_profiling_result(&invocation, &output).unwrap_err();
        assert_eq!(
            err,
            ProfilingLogError::Incomplete {
                kind: IncompleteOutputKind::MissingStopMarker,
                logs: stdout,
            }
        );
    }
}
