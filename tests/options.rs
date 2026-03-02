//! Integration tests for generated options

#[cfg(test)]
#[cfg(feature = "test-env-vm")]
mod tests {
    use std::{
        env,
        io::BufRead as _,
        process::{Command, Stdio},
    };

    use insta::assert_snapshot;

    fn shh_run_options(to_run: &[&str]) -> String {
        const START_OPTION_OUTPUT_SNIPPET_PREFIX: &str =
            "-------- Start of suggested service options ";
        const END_OPTION_OUTPUT_SNIPPET_PREFIX: &str = "-------- End of suggested service options ";
        let bin =
            env::var("CARGO_BIN_EXE_shh").unwrap_or_else(|_| env!("CARGO_BIN_EXE_shh").to_owned());
        let mut cmd = Command::new(bin);
        let output = cmd
            .args(["run", "--"])
            .args(to_run)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success());
        let mut has_end_marker = false;
        let opts: Vec<_> = output
            .stdout
            .lines()
            // Filter out delimiting lines while letting errors bubble up
            .skip_while(|r| {
                r.as_ref()
                    .is_ok_and(|l| !l.starts_with(START_OPTION_OUTPUT_SNIPPET_PREFIX))
            })
            .skip(1)
            .inspect(|r| {
                if r.as_ref()
                    .is_ok_and(|l| l.starts_with(END_OPTION_OUTPUT_SNIPPET_PREFIX))
                {
                    has_end_marker = true;
                }
            })
            .take_while(|r| {
                r.as_ref()
                    .map_or(true, |l| !l.starts_with(END_OPTION_OUTPUT_SNIPPET_PREFIX))
            })
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(has_end_marker);
        opts.join("\n")
    }

    #[test]
    fn run_true() {
        assert_snapshot!(shh_run_options(&["true"]));
    }

    #[test]
    fn run_write_dev_null() {
        assert_snapshot!(shh_run_options(&["sh", "-c", ": > /dev/null"]));
    }

    #[test]
    fn run_ls_dev() {
        assert_snapshot!(shh_run_options(&["ls", "/dev"]));
    }

    #[test]
    fn run_ls_proc() {
        assert_snapshot!(shh_run_options(&["busybox", "ls", "/proc/1/"]));
        assert_snapshot!(shh_run_options(&["cat", "/proc/cpuinfo"]));
    }

    #[test]
    fn run_read_kallsyms() {
        assert_snapshot!(shh_run_options(&["head", "/proc/kallsyms"]));
    }

    #[test]
    fn run_ls_modules() {
        assert_snapshot!(shh_run_options(&["ls", "/usr/lib/modules/"]));
    }

    #[test]
    fn run_dmesg() {
        assert_snapshot!(shh_run_options(&["dmesg"]));
    }

    #[test]
    fn run_systemctl() {
        assert_snapshot!(shh_run_options(&["systemctl", "--user"]));
    }

    #[test]
    fn run_ss() {
        assert_snapshot!(shh_run_options(&["ss", "-l"]));
    }

    #[test]
    fn run_mmap_wx() {
        assert_snapshot!(shh_run_options(&[
            "python3",
            "-c",
            "import mmap; mmap.mmap(-1, 4096, prot=mmap.PROT_WRITE|mmap.PROT_EXEC)"
        ]));
        assert_snapshot!(shh_run_options(&[
            "python3",
            "-c",
            "import mmap; mmap.mmap(-1, 4096, prot=mmap.PROT_WRITE)"
        ]));
    }

    #[test]
    fn run_sched_realtime() {
        assert_snapshot!(shh_run_options(&[
            "python3",
            "-c",
            "import os; os.sched_setscheduler(0, os.SCHED_RR, os.sched_param(os.sched_get_priority_min(os.SCHED_RR)))"
        ]));
        assert_snapshot!(shh_run_options(&[
            "python3",
            "-c",
            "import os; os.sched_setscheduler(0, os.SCHED_IDLE, os.sched_param(0))"
        ]));
    }

    #[test]
    fn run_bind() {
        assert_snapshot!(shh_run_options(&[
            "python3",
            "-c",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind((\"127.0.0.1\", 1234))"
        ]));
        assert_snapshot!(shh_run_options(&[
            "python3",
            "-c",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind((\"127.0.0.1\", 1234))"
        ]));
    }

    #[test]
    fn run_sock_packet() {
        assert_snapshot!(shh_run_options(&[
            "python3",
            "-c",
            "import socket; socket.socket(socket.AF_NETLINK, socket.SOCK_RAW)"
        ]));
        assert_snapshot!(shh_run_options(&[
            "python3",
            "-c",
            "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)"
        ]));
    }

    #[test]
    fn run_syslog() {
        assert_snapshot!(shh_run_options(&["dmesg", "-S"]));
    }

    #[test]
    fn run_mknod() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let pipe_path = tmp_dir.path().join("pipe");
        assert_snapshot!(shh_run_options(&[
            "mknod",
            pipe_path.as_os_str().to_str().unwrap(),
            "p"
        ]));
        let dev_path = tmp_dir.path().join("dev");
        assert_snapshot!(shh_run_options(&[
            "mknod",
            dev_path.as_os_str().to_str().unwrap(),
            "b",
            "255",
            "255"
        ]));
    }

    #[test]
    fn run_ping_4() {
        assert_snapshot!(shh_run_options(&["ping", "-4", "-c", "1", "127.0.0.1"]));
    }

    #[test]
    fn run_ping_6() {
        assert_snapshot!(shh_run_options(&["ping", "-6", "-c", "1", "::1"]));
    }

    #[test]
    fn run_gimp() {
        assert_snapshot!(shh_run_options(&[
            "su", "testuser", "xvfb-run", "gimp", "--quit"
        ]));
    }
}
