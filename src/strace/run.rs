//! Strace invocation code

use std::{
    env,
    fs::File,
    io::{self, BufReader},
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use anyhow::Context as _;

use crate::strace::{STRACE_BIN, parser::LogParser};

pub(crate) struct Strace {
    /// Strace process
    process: Child,
    /// Pipe path
    pipe_path: tempfile::NamedTempFile<()>,
    /// Strace log mirror path
    log_path: Option<PathBuf>,
}

impl Strace {
    pub(crate) fn run(command: &[&str], log_path: Option<PathBuf>) -> anyhow::Result<Self> {
        // Create named pipe in runtime directory or a temp dir
        let mut pipe_path_builder = tempfile::Builder::new();
        pipe_path_builder.prefix("strace_").suffix(".pipe");
        let pipe_path = if let Some(runtime_dir) =
            env::var_os("RUNTIME_DIRECTORY").and_then(|rd| env::split_paths(&rd).last())
        {
            pipe_path_builder.make_in(runtime_dir, Self::make_pipe)
        } else {
            pipe_path_builder.make(Self::make_pipe)
        }
        .context("Failed to create strace named pipe")?;

        // Start process
        // TODO setuid/setgid execution will be broken unless strace runs as root
        let child = Command::new(STRACE_BIN)
            .process_group(0) // set dedicated process group for easy signal handling, without affecting the shh process
            .args([
                "--daemonize=grandchild",
                "--kill-on-exit",
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
                pipe_path.path().to_str().unwrap(),
                "--",
            ])
            .args(command)
            .env("LANG", "C") // avoids locale side effects
            .stdin(Stdio::null())
            .spawn()
            .context("Failed to start strace")?;

        Ok(Self {
            process: child,
            pipe_path,
            log_path,
        })
    }

    fn make_pipe(path: &Path) -> io::Result<()> {
        #[expect(clippy::unwrap_used)]
        nix::unistd::mkfifo(path, nix::sys::stat::Mode::from_bits(0o600).unwrap())
            .map_err(Into::into)
    }

    pub(crate) fn stop(&self) {
        // Strace runs with `--deamonize=grandchild`, so will become child of the init process.
        // Consequently, the pid we have is already gone, but because we have started it with a unique process group,
        // we can still reliably kill strace.
        // Strace also runs with `--kill-on-exit` so the subtree will be reliably killed even if the tracee created
        // another process group (sshd does this).
        #[expect(clippy::cast_possible_wrap)]
        let pgid = nix::unistd::Pid::from_raw(-(self.process.id() as i32));
        // Ignore errors because it may have already naturally stopped
        let _ = nix::sys::signal::kill(pgid, nix::sys::signal::Signal::SIGKILL);
    }

    pub(crate) fn log_lines(&self) -> anyhow::Result<LogParser> {
        let reader = BufReader::new(File::open(self.pipe_path.path())?);
        LogParser::new(Box::new(reader), self.log_path.as_deref())
    }
}

impl Drop for Strace {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
