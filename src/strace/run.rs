//! Strace invocation code

use std::{
    env,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use anyhow::Context as _;

use crate::strace::{STRACE_BIN, parser::LogParser};

pub(crate) struct Strace {
    /// Strace process
    process: Child,
    /// Pipe dir
    pipe_dir: PathBuf,
    /// Temp dir for pipe location
    _tmp_pipe_dir: Option<tempfile::TempDir>,
    /// Strace log mirror path
    log_path: Option<PathBuf>,
}

impl Strace {
    pub(crate) fn run(command: &[&str], log_path: Option<PathBuf>) -> anyhow::Result<Self> {
        // Use runtime directory or a temp dir for named pipe
        let (pipe_dir, tmp_dir) = env::var_os("RUNTIME_DIRECTORY")
            .and_then(|rd| env::split_paths(&rd).last())
            .map_or_else(
                || -> anyhow::Result<_> {
                    let tmp_dir =
                        tempfile::tempdir().context("Failed to create temporary directory")?;
                    Ok((tmp_dir.path().to_owned(), Some(tmp_dir)))
                },
                |d| Ok((d, None)),
            )?;

        // Create named pipe
        let pipe_path = Self::pipe_path(&pipe_dir);
        #[expect(clippy::unwrap_used)]
        nix::unistd::mkfifo(&pipe_path, nix::sys::stat::Mode::from_bits(0o600).unwrap())
            .with_context(|| format!("Failed to create named pipe in {pipe_path:?}"))?;

        // Start process
        // TODO setuid/setgid execution will be broken unless strace runs as root
        let child = Command::new(STRACE_BIN)
            .args([
                "--daemonize=grandchild",
                "--relative-timestamps",
                "--follow-forks",
                "--status=successful,failed",
                "--strings-in-hex=all",
                // Despite this, some structs are still truncated
                "-e",
                "abbrev=none",
                // "-e",
                // "read=all",
                // "-e",
                // "write=all",
                "-e",
                "decode-fds=path",
                "--output-append-mode",
                "-o",
                #[expect(clippy::unwrap_used)]
                pipe_path.to_str().unwrap(),
                "--",
            ])
            .args(command)
            .env("LANG", "C") // avoids locale side effects
            .stdin(Stdio::null())
            .spawn()
            .context("Failed to start strace")?;

        Ok(Self {
            process: child,
            pipe_dir,
            _tmp_pipe_dir: tmp_dir,
            log_path,
        })
    }

    fn pipe_path(dir: &Path) -> PathBuf {
        dir.join("strace.pipe")
    }

    pub(crate) fn log_lines(&self) -> anyhow::Result<LogParser> {
        let pipe_path = Self::pipe_path(&self.pipe_dir);
        let reader = BufReader::new(File::open(pipe_path)?);
        LogParser::new(Box::new(reader), self.log_path.as_deref())
    }
}

impl Drop for Strace {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
