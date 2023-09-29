//! Strace invocation code

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use crate::strace::parser::LogParser;

pub struct Strace {
    /// Strace process
    process: Child,
    /// Temp dir for pipe location
    pipe_dir: tempfile::TempDir,
}

impl Strace {
    pub fn run(command: &[&str]) -> anyhow::Result<Self> {
        // Create named pipe
        let pipe_dir = tempfile::tempdir()?;
        let pipe_path = Self::pipe_path(&pipe_dir);
        nix::unistd::mkfifo(&pipe_path, nix::sys::stat::Mode::from_bits(0o600).unwrap())?;

        // Start process
        // TODO setuid/setgid execution will be broken unless strace runs as root
        let child = Command::new("strace")
            .args([
                "--daemonize=grandchild",
                "--relative-timestamps",
                "--follow-forks",
                // TODO APPROXIMATION this can make us miss interesting stuff like open with O_EXCL|O_CREAT which
                // returns -1 because file exists
                "--successful-only",
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
                pipe_path.to_str().unwrap(),
                "--",
            ])
            .args(command)
            .env("LANG", "C") // avoids locale side effects
            .stdin(Stdio::null())
            .spawn()?;

        Ok(Self {
            process: child,
            pipe_dir,
        })
    }

    fn pipe_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("strace.pipe")
    }

    pub fn log_lines(&self) -> anyhow::Result<LogParser> {
        let pipe_path = Self::pipe_path(&self.pipe_dir);
        let reader = BufReader::new(File::open(pipe_path)?);
        LogParser::new(Box::new(reader))
    }
}

impl Drop for Strace {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
