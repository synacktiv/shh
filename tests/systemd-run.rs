//! These tests run generated options with systemd-run to ensure they are valid
//! and allow the program to execute normally

#[cfg(test)]
#[cfg(feature = "test-env-vm")]
mod tests {
    use std::{
        env,
        fs::{self, Permissions},
        io::{BufRead as _, Write as _},
        iter,
        net::{TcpListener, UdpSocket},
        os::unix::{
            self,
            fs::{FileTypeExt as _, PermissionsExt as _},
            net::{UnixDatagram, UnixListener},
        },
        path::Path,
        process,
        sync::{LazyLock, mpsc},
        thread,
        time::Duration,
    };

    use assert_cmd::{
        Command,
        assert::{Assert, OutputAssertExt as _},
    };
    use nix::{sys::stat, unistd};
    use predicates::prelude::predicate;

    static ALL_SHH_RUN_OPTS: LazyLock<Vec<Vec<&'static str>>> = LazyLock::new(all_shh_run_opts);
    const KERNEL_LOG_REGEX: &str = r"\[\ *[0-9]+\.[0-9]+\] ";
    /// Interval between writes of a file watched by the service
    const WRITE_INTERVAL: Duration = Duration::from_millis(100);
    /// Python script attempting to create an entry, existing or not
    const CREATE_ENTRY_SCRIPT: &str = "
import ctypes, os, stat, sys

# Values from <fcntl.h>, <stdio.h> and x86_64 <sys/syscall.h>
AT_FDCWD = -100
RENAME_NOREPLACE = 1
SYS_mknod = 133

kind, path, src, held = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)


def check(ret):
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), path)


if kind in ('link', 'rename'):
    open(src, 'w').close()
try:
    if kind in ('open', 'open-replace'):
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
    elif kind in ('mkdir', 'mkdir-p'):
        os.mkdir(path)
    elif kind == 'symlink':
        os.symlink('/dev/null', path)
    elif kind == 'link':
        os.link(src, path)
    elif kind == 'rename':
        check(libc.renameat2(AT_FDCWD, src.encode(), AT_FDCWD, path.encode(), RENAME_NOREPLACE))
    elif kind == 'mknod':
        # mknod syscall on x86_64, glibc's mkfifo calls mknodat
        check(libc.syscall(SYS_mknod, path.encode(), stat.S_IFIFO | 0o644, 0))
    elif kind == 'mkfifo':
        os.mkfifo(path)
    else:
        raise ValueError(kind)
except FileExistsError:
    if kind == 'open-replace':
        os.unlink(path)
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
else:
    # A held entry the service creates is one it does not see
    if held == 'held':
        sys.exit(1)
if kind == 'mkdir-p':
    open(os.path.join(path, 'file'), 'w').close()
";

    /// Python script making a syscall of a given kind on a path
    const PATH_SYSCALL_SCRIPT: &str = include_str!("path_syscall.py");

    /// Python script opening a path with `openat2` and a resolve flag, from a given working directory, after
    /// writing given files
    const OPENAT2_RESOLVE_SCRIPT: &str = "
import ctypes, os, struct, sys

# Values from <fcntl.h>, <linux/openat2.h> and x86_64 <sys/syscall.h>
AT_FDCWD = -100
RESOLVE_FLAGS = {'RESOLVE_NO_XDEV': 0x01, 'RESOLVE_IN_ROOT': 0x10}
SYS_openat2 = 437

resolve, cwd, path, *written = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
for written_path in written:
    open(written_path, 'w').close()
os.chdir(cwd)
# struct open_how: flags, mode, resolve
how = struct.pack('QQQ', os.O_RDONLY, 0, RESOLVE_FLAGS[resolve])
if libc.syscall(SYS_openat2, AT_FDCWD, path.encode(), how, ctypes.c_size_t(len(how))) < 0:
    err = ctypes.get_errno()
    raise OSError(err, os.strerror(err), path)
";

    /// Build the command making a syscall of a given kind on a path
    fn path_syscall_cmd<'a>(kind: &'a str, path: &'a Path) -> [&'a str; 5] {
        [
            "python3",
            "-c",
            PATH_SYSCALL_SCRIPT,
            kind,
            path.to_str().unwrap(),
        ]
    }

    /// C program making a syscall of a given kind on a path through the 32-bit x86 ABI
    const SYSCALL_32BIT_SRC: &str = include_str!("syscall_32bit.c");

    /// C program attaching a shared memory segment with execute permission
    const SHMAT_EXEC_SRC: &str = include_str!("shmat_exec.c");

    /// C program sending or receiving UDP datagrams through `sendmmsg` or `recvmmsg`
    const MMSG_UDP_SRC: &str = include_str!("mmsg_udp.c");

    /// C program receiving a UDP datagram through a call naming no sender
    const RECV_UNNAMED_PEER_SRC: &str = include_str!("recv_unnamed_peer.c");

    /// Path of the tested `shh` binary
    fn shh_bin() -> String {
        env::var("CARGO_BIN_EXE_shh").unwrap_or_else(|_| env!("CARGO_BIN_EXE_shh").to_owned())
    }

    /// Parse the systemd options suggested by `shh`, from an output holding nothing else
    fn suggested_options(stdout: &[u8]) -> Vec<String> {
        const START_MARKER: &str = "-------- Start of suggested service options ";
        const END_MARKER: &str = "-------- End of suggested service options ";
        let mut lines = str::from_utf8(stdout).unwrap().lines();
        assert!(lines.next().unwrap().starts_with(START_MARKER));
        assert!(lines.next_back().unwrap().starts_with(END_MARKER));
        lines.map(str::to_owned).collect()
    }

    /// Profile a command once with `shh run`, and generate systemd options from its profile with each `shh` option
    /// set, logging the set as its options are taken
    fn generate_options(
        cmd: &[&str],
        shh_opts_sets: &[Vec<&'static str>],
    ) -> impl Iterator<Item = Vec<String>> {
        let bin = shh_bin();
        let profile_dir = tempfile::tempdir().unwrap();
        let profile = profile_dir.path().join("profile");
        Command::new(&bin)
            .arg("run")
            .arg("-p")
            .arg(&profile)
            .arg("--")
            .args(cmd)
            .unwrap();
        let merged_profile = profile_dir.path().join("merged");
        let all_sd_opts: Vec<_> = shh_opts_sets
            .iter()
            .map(|shh_opts| {
                // Preserve the original profile for subsequent option sets
                fs::copy(&profile, &merged_profile).unwrap();
                let output = Command::new(&bin)
                    .arg("merge-profile-data")
                    .args(shh_opts)
                    .arg(&merged_profile)
                    .unwrap();
                let opts = suggested_options(&output.stdout);
                output.assert().success();
                opts
            })
            .collect();
        iter::zip(shh_opts_sets, all_sd_opts).map(|(shh_opts, sd_opts)| {
            eprintln!("shh run option: {}", shh_opts.join(" "));
            sd_opts
        })
    }

    /// Run systemd-run for given command, with options
    fn systemd_run(cmd: &[&str], sd_opts: &[String], user: bool) -> Assert {
        let mut sd_cmd = vec!["systemd-run".to_owned()];
        if user {
            sd_cmd.extend([
                "--user".to_owned(),
                "-M".to_owned(),
                format!("{}@.host", env::var("TEST_USER").unwrap()),
            ]);
        }
        sd_cmd.extend(["-P", "-G", "--wait"].into_iter().map(ToOwned::to_owned));
        for sd_opt in sd_opts {
            // Some options are supported in systemd unit files but not by systemd-run, work around that
            let sd_opt = match sd_opt.as_str() {
                // https://github.com/systemd/systemd/issues/36222#issuecomment-2623967515
                "PrivateTmp=disconnected" => "PrivateTmpEx=disconnected",
                "RestrictAddressFamilies=none" => "RestrictAddressFamilies=",
                s => s,
            };
            sd_cmd.extend(["-p", sd_opt].into_iter().map(ToOwned::to_owned));
        }
        sd_cmd.extend(
            ["-p", "Environment=LANG=C", "--"]
                .into_iter()
                .map(ToOwned::to_owned),
        );
        sd_cmd.extend(cmd.iter().map(|s| (*s).to_owned()));
        eprintln!(
            "{}",
            shlex::try_join(sd_cmd.iter().map(AsRef::as_ref)).unwrap()
        );
        let assrt = Command::new(&sd_cmd[0])
            .args(&sd_cmd[1..])
            .unwrap()
            .assert();
        // eprintln!("{}", String::from_utf8_lossy(&assrt.get_output().stdout));
        // eprintln!("{}", String::from_utf8_lossy(&assrt.get_output().stderr));
        assrt.success()
    }

    /// Generate all combinations of `shh run` args to test
    fn all_shh_run_opts() -> Vec<Vec<&'static str>> {
        let args_mode = vec![vec!["-m", "generic"], vec![], vec!["-m", "aggressive"]];
        let args_fs = vec![
            vec![],
            vec!["-w"],
            vec!["-w", "--merge-paths-threshold", "1"],
            vec!["-w", "--merge-paths-threshold", "2"],
            vec!["-w", "--merge-paths-threshold", "10"],
            vec!["-w", "--merge-paths-threshold", "100"],
        ];
        let args_fw = vec![vec![], vec!["-f"]];
        let mut combinations = Vec::with_capacity(args_mode.len() * args_fs.len() * args_fw.len());
        for arg_mode in &args_mode {
            for arg_fs in &args_fs {
                for arg_fw in &args_fw {
                    if arg_mode.get(1).is_some_and(|m| *m == "generic")
                        && (!arg_fs.is_empty() || !arg_fw.is_empty())
                    {
                        // Generic mode is incompatible with those
                        continue;
                    }
                    let mut args = Vec::with_capacity(arg_mode.len() + arg_fs.len() + arg_fw.len());
                    args.extend(arg_mode);
                    args.extend(arg_fs);
                    args.extend(arg_fw);
                    combinations.push(args);
                }
            }
        }
        combinations
    }

    /// Build every `shh run` option set for a system or user service
    fn shh_run_opts(user: bool) -> Vec<Vec<&'static str>> {
        ALL_SHH_RUN_OPTS
            .iter()
            .map(|shh_opts| {
                let mut shh_opts = shh_opts.clone();
                if user {
                    shh_opts.extend(["-i", "user"]);
                }
                shh_opts
            })
            .collect()
    }

    /// Build every `shh run` option set for a 32-bit program
    fn shh_run_opts_32bit() -> Vec<Vec<&'static str>> {
        ALL_SHH_RUN_OPTS
            .iter()
            // SystemCallArchitectures=native kills 32-bit programs
            .filter(|shh_opts| !shh_opts.contains(&"aggressive"))
            .cloned()
            .collect()
    }

    /// Profile a command, and run it with the options generated for every `shh run` option set as a system or
    /// user service
    fn profile_and_run(cmd: &[&str], user: bool) {
        for sd_opts in generate_options(cmd, &shh_run_opts(user)) {
            let _ = systemd_run(cmd, &sd_opts, user);
        }
    }

    /// Send UDP datagrams from 127.0.0.2 to a free port of 127.0.0.1 every `WRITE_INTERVAL`, until the returned
    /// sender is dropped
    fn send_udp_to_free_port() -> (u16, mpsc::Sender<()>) {
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let socket = UdpSocket::bind("127.0.0.2:0").unwrap();
        let (stop, stopped) = mpsc::channel();
        thread::spawn(move || {
            while stopped.recv_timeout(WRITE_INTERVAL) == Err(mpsc::RecvTimeoutError::Timeout) {
                socket.send_to(b"x", ("127.0.0.1", port)).unwrap();
            }
        });
        (port, stop)
    }

    /// Send 1024 UDP datagrams from 127.0.0.2 then one from 127.0.0.3 to a free port of 127.0.0.1, each time
    /// 127.0.0.4 receives a datagram on that port
    #[expect(clippy::infinite_loop)]
    fn send_udp_batches_to_free_port() -> u16 {
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let ready = UdpSocket::bind(("127.0.0.4", port)).unwrap();
        let [first, last] =
            ["127.0.0.2", "127.0.0.3"].map(|addr| UdpSocket::bind((addr, 0)).unwrap());
        thread::spawn(move || {
            loop {
                ready.recv(&mut [0]).unwrap();
                for i in 1..=1024 {
                    first.send_to(b"x", ("127.0.0.1", port)).unwrap();
                    // Keeps the receive queue below half its default size
                    while i % 10 == 0 && udp_rx_queue(port) > 100_000 {
                        thread::sleep(Duration::from_millis(1));
                    }
                }
                last.send_to(b"x", ("127.0.0.1", port)).unwrap();
            }
        });
        port
    }

    /// Size of the receive queue of the UDP socket bound to a port of 127.0.0.1, in bytes
    fn udp_rx_queue(port: u16) -> usize {
        let local_address = format!("0100007F:{port:04X}");
        let sockets = fs::read_to_string("/proc/net/udp").unwrap();
        let socket = sockets
            .lines()
            .find(|line| line.split_whitespace().nth(1) == Some(local_address.as_str()))
            .unwrap();
        let (_, rx_queue) = socket
            .split_whitespace()
            .nth(4)
            .unwrap()
            .split_once(':')
            .unwrap();
        usize::from_str_radix(rx_queue, 16).unwrap()
    }

    /// Compile a C program from its source
    fn compile_c(src: &str, gcc_args: &[&str], output: &Path) {
        Command::new("gcc")
            .args(gcc_args)
            .args(["-x", "c", "-o"])
            .arg(output)
            .arg("-")
            .write_stdin(src)
            .unwrap();
    }

    /// Create an entry of a type: `file`, `dir`, `fifo`, or `symlink` to `/dev/null`
    fn create_entry(type_: &str, path: &Path) {
        match type_ {
            "file" => fs::write(path, "").unwrap(),
            "dir" => fs::create_dir(path).unwrap(),
            "fifo" => unistd::mkfifo(path, stat::Mode::from_bits(0o666).unwrap()).unwrap(),
            "symlink" => unix::fs::symlink("/dev/null", path).unwrap(),
            _ => unreachable!(),
        }
    }

    /// Remove an entry, a directory or not
    fn remove_entry(path: &Path) {
        if fs::symlink_metadata(path).unwrap().is_dir() {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    }

    /// Profile a command creating paths, and run it as a system service with the options generated for every
    /// `shh run` option set, removing the paths after each step
    fn profile_and_run_creating_paths<P>(cmd: &[&str], paths: &[P])
    where
        P: AsRef<Path>,
    {
        let all_sd_opts = generate_options(cmd, &ALL_SHH_RUN_OPTS);
        for path in paths {
            fs::remove_file(path).unwrap();
        }
        for sd_opts in all_sd_opts {
            let _ = systemd_run(cmd, &sd_opts, false);
            for path in paths {
                fs::remove_file(path).unwrap();
            }
        }
    }

    /// Parse the major and minor numbers of a version, like `6.12.48+deb13-amd64`
    fn major_minor(version: &str) -> (u32, u32) {
        let mut numbers = version.split('.').map(|n| n.parse().unwrap());
        (numbers.next().unwrap(), numbers.next().unwrap())
    }

    /// Read the major and minor version of the running kernel
    fn kernel_version() -> (u32, u32) {
        major_minor(&fs::read_to_string("/proc/sys/kernel/osrelease").unwrap())
    }

    /// Read the major and minor version of strace
    fn strace_version() -> (u32, u32) {
        let output = Command::new("strace").arg("-V").unwrap();
        // Like `strace -- version 6.13`
        let first_line = output.stdout.lines().next().unwrap().unwrap();
        major_minor(first_line.rsplit(' ').next().unwrap())
    }

    #[test]
    fn run_matches_merge_profile_data() {
        // Generate options with `shh run` directly, as when merging profile data, for option sets covering every
        // option kind
        let cmd = ["true"];
        let shh_opts_sets = [
            vec!["-m", "generic"],
            vec!["-m", "aggressive", "-w", "-f"],
            vec!["-m", "aggressive", "-w", "-f", "-i", "user"],
        ];
        for (shh_opts, merged_sd_opts) in
            iter::zip(&shh_opts_sets, generate_options(&cmd, &shh_opts_sets))
        {
            let output = Command::new(shh_bin())
                .arg("run")
                .args(shh_opts)
                .arg("--")
                .args(cmd)
                .unwrap();
            assert_eq!(suggested_options(&output.stdout), merged_sd_opts);
        }
    }

    #[test]
    fn systemd_run_true() {
        let cmd = ["true"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_write_dev_null() {
        let cmd = ["sh", "-c", ": > /dev/null"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_touch_dev_null() {
        let cmd = ["touch", "/dev/null"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_write_dev_kmsg() {
        // Only root can open /dev/kmsg for writing
        let cmd = [
            "python3",
            "-c",
            "import os; os.close(os.open('/dev/kmsg', os.O_WRONLY))",
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_ls_dev() {
        let cmd = ["ls", "/dev/"];
        for user in [false, true] {
            for sd_opts in generate_options(&cmd, &shh_run_opts(user)) {
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains("char"))
                    .stdout(predicate::str::contains("log"));
            }
        }
    }

    #[test]
    fn systemd_run_ls_proc() {
        let cmd = ["ls", "/proc/1"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_read_kallsyms() {
        let cmd = ["head", "/proc/kallsyms"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_ls_modules() {
        let cmd = ["ls", "/usr/lib/modules/"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_dmesg() {
        let cmd = ["dmesg"];
        for sd_opts in generate_options(&cmd, &ALL_SHH_RUN_OPTS) {
            let asrt = systemd_run(&cmd, &sd_opts, false);
            asrt.stdout(predicate::str::is_match(KERNEL_LOG_REGEX).unwrap());
        }
    }

    #[test]
    fn systemd_run_systemctl() {
        let cmd = ["systemctl"];
        for user in [false, true] {
            let shh_opts_sets: Vec<_> = shh_run_opts(user)
                .into_iter()
                // This one breaks systemctl under load,
                // due to divergent code path that makes us deny `@io-event`
                .filter(|shh_opts| !shh_opts.contains(&"aggressive"))
                .collect();
            for sd_opts in generate_options(&cmd, &shh_opts_sets) {
                let _ = systemd_run(&cmd, &sd_opts, user);
            }
        }
    }

    #[test]
    fn systemd_run_ss() {
        let cmd = ["ss", "-l"];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_mmap_wx() {
        let cmd = [
            "python3",
            "-c",
            "import mmap; mmap.mmap(-1, 4096, prot=mmap.PROT_WRITE|mmap.PROT_EXEC)",
        ];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_sched_realtime() {
        let cmd = [
            "python3",
            "-c",
            "import os; os.sched_setscheduler(0, os.SCHED_RR, os.sched_param(os.sched_get_priority_min(os.SCHED_RR)))",
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_bind() {
        let cmd = [
            "python3",
            "-c",
            "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind((\"127.0.0.1\", 1234))",
        ];
        for user in [false, true] {
            profile_and_run(&cmd, user);
        }
    }

    #[test]
    fn systemd_run_bind_unix() {
        // Bind a Unix socket, a write to its directory, that clients outside the service reach
        for dir in ["/var/lib", "/tmp"] {
            let path = format!("{dir}/shh-test-{id}.sock", id = rand::random::<u16>());
            let code = format!("import socket; socket.socket(socket.AF_UNIX).bind({path:?})");
            let cmd = ["python3", "-c", &code];
            let _ = fs::remove_file(&path);
            profile_and_run_creating_paths(&cmd, &[&path]);
        }
    }

    #[test]
    fn systemd_run_uds_through_symlink() {
        // Connect to a Unix socket in /tmp through a symlink in /var/lib, a read of the symlink and of the
        // socket, then bind one in /tmp through a symlink in /var/lib to its directory, a write to that directory
        let sock_dir = tempfile::tempdir_in("/tmp").unwrap();
        let link_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let sock = sock_dir.path().join("sock");
        let _listener = UnixListener::bind(&sock).unwrap();
        let sock_link = link_dir.path().join("sock");
        unix::fs::symlink(&sock, &sock_link).unwrap();
        let connect_cmd = [
            "python3",
            "-c",
            "import socket, sys; socket.socket(socket.AF_UNIX).connect(sys.argv[1])",
            sock_link.to_str().unwrap(),
        ];
        profile_and_run(&connect_cmd, false);
        let dir_link = link_dir.path().join("dir");
        unix::fs::symlink(sock_dir.path(), &dir_link).unwrap();
        let bound = dir_link.join("new");
        let bind_cmd = [
            "python3",
            "-c",
            "import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])",
            bound.to_str().unwrap(),
        ];
        profile_and_run_creating_paths(&bind_cmd, &[sock_dir.path().join("new")]);
    }

    #[test]
    fn systemd_run_sendmsg_udp() {
        // Send a UDP datagram to an address given only to sendmsg
        let cmd = [
            "python3",
            "-c",
            "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendmsg([b'x'], [], 0, ('127.0.0.1', 9))",
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_recvmsg_udp() {
        // Receive a UDP datagram from an address returned only by recvmsg
        let (port, _sending) = send_udp_to_free_port();
        let cmd = [
            "python3",
            "-c",
            "import socket, sys; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', int(sys.argv[1]))); s.settimeout(10); s.recvmsg(1)",
            &port.to_string(),
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_mmsg_udp() {
        // Send a UDP datagram to an address given only to sendmmsg, and receive one from an address returned only
        // by recvmmsg, which 32-bit x86 programs call as recvmmsg_time64
        let bin_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let bin = bin_dir.path().join("mmsg_udp");
        let bin_32bit = bin_dir.path().join("mmsg_udp_32bit");
        compile_c(MMSG_UDP_SRC, &[], &bin);
        compile_c(MMSG_UDP_SRC, &["-m32"], &bin_32bit);
        let shh_opts_sets_32bit = shh_run_opts_32bit();
        let (recv_port, _sending) = send_udp_to_free_port();
        let recv_port = recv_port.to_string();
        for (program, kind, port, shh_opts_sets) in [
            (&bin, "sendmmsg", "9", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "recvmmsg", &recv_port, ALL_SHH_RUN_OPTS.as_slice()),
            (&bin_32bit, "recvmmsg", &recv_port, &shh_opts_sets_32bit),
        ] {
            let cmd = [program.to_str().unwrap(), kind, port, "1"];
            for sd_opts in generate_options(&cmd, shh_opts_sets) {
                let _ = systemd_run(&cmd, &sd_opts, false);
            }
        }
    }

    #[test]
    fn systemd_run_mmsg_udp_truncated() {
        // Pass sendmmsg and recvmmsg more messages than strace prints of an mmsghdr array, the last one received
        // from an address no printed message names
        let bin_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let bin = bin_dir.path().join("mmsg_udp");
        compile_c(MMSG_UDP_SRC, &[], &bin);
        let recv_port = send_udp_batches_to_free_port().to_string();
        for (kind, port) in [("sendmmsg", "9"), ("recvmmsg", recv_port.as_str())] {
            profile_and_run(&[bin.to_str().unwrap(), kind, port, "1025"], false);
        }
    }

    #[test]
    fn systemd_run_recv_unnamed_peer() {
        // Receive a UDP datagram from 127.0.0.2 through calls naming no sender, on a socket bound to 127.0.0.1, which
        // 32-bit x86 programs call as recvmmsg_time64 and sendfile64
        let bin_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let bin = bin_dir.path().join("recv_unnamed_peer");
        let bin_32bit = bin_dir.path().join("recv_unnamed_peer_32bit");
        compile_c(RECV_UNNAMED_PEER_SRC, &[], &bin);
        compile_c(
            RECV_UNNAMED_PEER_SRC,
            &["-m32", "-D_FILE_OFFSET_BITS=64"],
            &bin_32bit,
        );
        let shh_opts_sets_32bit = shh_run_opts_32bit();
        let (port, _sending) = send_udp_to_free_port();
        let port = port.to_string();
        for (program, call, shh_opts_sets) in [
            (&bin, "recvfrom", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "recvfrom-empty-addr", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "recvfrom-short-addr", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "recvmsg", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "recvmmsg", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "read", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "readv", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "preadv2", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "splice", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin, "sendfile", ALL_SHH_RUN_OPTS.as_slice()),
            (&bin_32bit, "recvmmsg", &shh_opts_sets_32bit),
            (&bin_32bit, "sendfile", &shh_opts_sets_32bit),
        ] {
            let cmd = [program.to_str().unwrap(), call, &port];
            for sd_opts in generate_options(&cmd, shh_opts_sets) {
                let _ = systemd_run(&cmd, &sd_opts, false);
            }
        }
    }

    #[test]
    fn systemd_run_sendmsg_unix() {
        // Send a datagram to a Unix socket in /tmp named only to sendmsg
        let sock_dir = tempfile::tempdir_in("/tmp").unwrap();
        let sock = sock_dir.path().join("sock");
        let receiver = UnixDatagram::bind(&sock).unwrap();
        // Empties the bounded socket queue, until an empty datagram
        let draining = thread::spawn(move || while receiver.recv(&mut [0]).unwrap() > 0 {});
        let cmd = [
            "python3",
            "-c",
            "import socket, sys; socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM).sendmsg([b'x'], [], 0, sys.argv[1])",
            sock.to_str().unwrap(),
        ];
        profile_and_run(&cmd, false);
        UnixDatagram::unbound()
            .unwrap()
            .send_to(&[], &sock)
            .unwrap();
        draining.join().unwrap();
    }

    #[test]
    fn systemd_run_sock_packet() {
        let cmd = [
            "python3",
            "-c",
            "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)",
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_syslog() {
        let cmd = ["dmesg", "-S"];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_mknod() {
        let tmp_dir = tempfile::tempdir().unwrap();

        let pipe_path = tmp_dir.path().join("pipe");
        let cmd_pipe = ["mknod", pipe_path.as_os_str().to_str().unwrap(), "p"];
        let all_pipe_sd_opts = generate_options(&cmd_pipe, &ALL_SHH_RUN_OPTS);
        let _ = fs::remove_file(&pipe_path);
        for mut sd_opts in all_pipe_sd_opts {
            sd_opts.push(format!("BindPaths={}", tmp_dir.path().to_str().unwrap()));
            if let Some(inaccessible_path_opt) = sd_opts
                .iter_mut()
                .find(|o| o.starts_with("InaccessiblePaths="))
            {
                *inaccessible_path_opt = inaccessible_path_opt
                    .split(' ')
                    .filter(|e| e.strip_prefix('-').unwrap_or(e) != "/tmp")
                    .collect::<Vec<_>>()
                    .join(" ");
            }

            let _ = systemd_run(&cmd_pipe, &sd_opts, false);
            assert!(fs::metadata(&pipe_path).unwrap().file_type().is_fifo());
            fs::remove_file(&pipe_path).unwrap();
        }

        let dev_path = tmp_dir.path().join("dev");
        let cmd_dev = [
            "mknod",
            dev_path.as_os_str().to_str().unwrap(),
            "b",
            "255",
            "255",
        ];
        let all_dev_sd_opts = generate_options(&cmd_dev, &ALL_SHH_RUN_OPTS);
        let _ = fs::remove_file(&dev_path);
        for mut sd_opts in all_dev_sd_opts {
            sd_opts.push(format!("BindPaths={}", tmp_dir.path().to_str().unwrap()));
            if let Some(inaccessible_path_opt) = sd_opts
                .iter_mut()
                .find(|o| o.starts_with("InaccessiblePaths="))
            {
                *inaccessible_path_opt = inaccessible_path_opt
                    .split(' ')
                    .filter(|e| e.strip_prefix('-').unwrap_or(e) != "/tmp")
                    .collect::<Vec<_>>()
                    .join(" ");
            }

            let _ = systemd_run(&cmd_dev, &sd_opts, false);
            assert!(
                fs::metadata(&dev_path)
                    .unwrap()
                    .file_type()
                    .is_block_device()
            );
            fs::remove_file(&dev_path).unwrap();
        }
    }

    #[test]
    fn systemd_run_script() {
        let mut script = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o755))
            .tempfile()
            .unwrap();
        script
            .write_all("#!/usr/bin/env sh\necho 'from a script'".as_bytes())
            .unwrap();
        let script_path = script.into_temp_path();
        let cmd = [script_path.to_str().unwrap()];
        for user in [false, true] {
            for sd_opts in generate_options(&cmd, &shh_run_opts(user)) {
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains("from a script"));
            }
        }
    }

    #[test]
    fn systemd_run_curl() {
        let cmd = ["curl", "-k", "https://example.com"];
        for user in [false, true] {
            for sd_opts in generate_options(&cmd, &shh_run_opts(user)) {
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains("<html"));
            }
        }
    }

    #[test]
    fn systemd_run_ping_4() {
        let cmd = ["ping", "-c", "1", "-4", "127.0.0.1"];
        for user in [false, true] {
            for sd_opts in generate_options(&cmd, &shh_run_opts(user)) {
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains(
                "127.0.0.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss",
            ));
            }
        }
    }

    #[test]
    fn systemd_run_ping_6() {
        let cmd = ["ping", "-c", "1", "-6", "::1"];
        for user in [false, true] {
            for sd_opts in generate_options(&cmd, &shh_run_opts(user)) {
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains(
                    "::1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss",
                ));
            }
        }
    }

    fn del_netns(ns: &str) {
        let mut cmd = process::Command::new("ip");
        cmd.args(["netns", "del", ns]);
        assert!(cmd.status().unwrap().success());
        assert!(!fs::exists(format!("/run/netns/{ns}")).unwrap());
    }

    #[test]
    fn systemd_netns_create() {
        let ns = format!("t{}", rand::random::<u16>());
        let cmd = ["ip", "netns", "add", &ns];
        let all_sd_opts = generate_options(&cmd, &ALL_SHH_RUN_OPTS);
        assert!(fs::exists(format!("/run/netns/{ns}")).unwrap());
        del_netns(&ns);
        for sd_opts in all_sd_opts {
            let _ = systemd_run(&cmd, &sd_opts, false);
            assert!(fs::exists(format!("/run/netns/{ns}")).unwrap());
            del_netns(&ns);
        }
    }

    /// Profile and run a command sending a signal to its child as a system and user service, checking the child's
    /// return code
    fn kill_child(sig: &str, rc: &str) {
        let code = format!(
            "import signal, subprocess; p = subprocess.Popen((\"sleep\", \"0.5s\")); p.send_signal(signal.SIG{sig}); p.wait(); print(f\"rc={{p.returncode}}\")",
        );
        let cmd = ["python3", "-c", &code];
        for user in [false, true] {
            for sd_opts in generate_options(&cmd, &shh_run_opts(user)) {
                let asrt = systemd_run(&cmd, &sd_opts, user);
                asrt.stdout(predicate::str::contains(rc));
            }
        }
    }

    #[test]
    fn systemd_kill_sigurg() {
        kill_child("URG", "0");
    }

    #[test]
    fn systemd_kill_sigkill() {
        kill_child("KILL", "-9");
    }

    #[test]
    fn systemd_run_ptrace_attach() {
        // Attach to and detach from a different user's process, requiring CAP_SYS_PTRACE
        let script = r#"
import ctypes, os, subprocess, sys

# Request values from <sys/ptrace.h>
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

libc = ctypes.CDLL("libc.so.6", use_errno=True)

def ptrace(request, pid):
    if libc.ptrace(request, pid, None, None) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

# Oldest process of the user, kept running by lingering in the test environment
target_pid = int(subprocess.check_output(["pgrep", "--oldest", "--euid", sys.argv[1]]))
ptrace(PTRACE_ATTACH, target_pid)
# Attaching stops the target, it must be waited for before it can be detached
os.waitpid(target_pid, 0)
ptrace(PTRACE_DETACH, target_pid)
"#;
        let user = env::var("TEST_USER").unwrap();
        let cmd = ["python3", "-c", script, &user];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_wake_lock() {
        // Take and release a wake lock, requiring CAP_BLOCK_SUSPEND
        if !fs::exists("/sys/power/wake_lock").unwrap() {
            eprintln!("Kernel built without CONFIG_PM_WAKELOCKS, skipping");
            return;
        }
        let cmd = [
            "sh",
            "-c",
            "echo shh-test > /sys/power/wake_lock && echo shh-test > /sys/power/wake_unlock",
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_rm() {
        // Remove a pre-existing file, a write to its directory
        let path = format!("/var/lib/shh-test-{}", rand::random::<u16>());
        let cmd = ["rm", &path];
        fs::write(&path, "").unwrap();
        for sd_opts in generate_options(&cmd, &ALL_SHH_RUN_OPTS) {
            fs::write(&path, "").unwrap();
            let _ = systemd_run(&cmd, &sd_opts, false);
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn systemd_run_creat() {
        // Create a file with the creat syscall, a write to its directory
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let path = dir.path().join("file");
        let cmd = [
            "python3",
            "-c",
            "import ctypes, sys; sys.exit(ctypes.CDLL(None).creat(sys.argv[1].encode(), 0o644) < 0)",
            path.to_str().unwrap(),
        ];
        profile_and_run_creating_paths(&cmd, &[&path]);
    }

    #[test]
    fn systemd_run_openat2() {
        // Create a file with the openat2 syscall, a write to its directory
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let path = dir.path().join("file");
        profile_and_run_creating_paths(&path_syscall_cmd("openat2", &path), &[&path]);
    }

    #[test]
    fn systemd_run_openat2_in_root() {
        // Open a file through a symlink of a root directory in /var/lib, the working directory, which the walk
        // reads
        let root = tempfile::tempdir_in("/var/lib").unwrap();
        fs::create_dir_all(root.path().join("usr/lib")).unwrap();
        create_entry("file", &root.path().join("usr/lib/file"));
        unix::fs::symlink("usr/lib", root.path().join("lib")).unwrap();
        let cmd = [
            "python3",
            "-c",
            OPENAT2_RESOLVE_SCRIPT,
            "RESOLVE_IN_ROOT",
            root.path().to_str().unwrap(),
            "/lib/file",
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_openat2_no_xdev() {
        // Open a pre-existing file in /var/lib, /home or /etc from the root directory, or under /proc/sys from
        // /proc, a walk crossing no mount of the profiling environment
        let var_lib_file = tempfile::NamedTempFile::new_in("/var/lib").unwrap();
        let var_lib_path = var_lib_file.path().to_str().unwrap();
        let home_file = tempfile::NamedTempFile::new_in("/home").unwrap();
        let etc_file = tempfile::NamedTempFile::new_in("/etc").unwrap();
        for (cwd, path, written) in [
            ("/", var_lib_path, &[][..]),
            ("/", home_file.path().to_str().unwrap(), &[]),
            // A write in /var/lib leaves ProtectSystem=full, which binds /etc onto itself
            ("/", etc_file.path().to_str().unwrap(), &[var_lib_path]),
            ("/proc", "sys/kernel/hostname", &[]),
        ] {
            let mut cmd = vec![
                "python3",
                "-c",
                OPENAT2_RESOLVE_SCRIPT,
                "RESOLVE_NO_XDEV",
                cwd,
                path,
            ];
            cmd.extend_from_slice(written);
            profile_and_run(&cmd, false);
        }
    }

    #[test]
    fn systemd_run_symlinked_efi() {
        // Write to a file in /var/lib, the target of a symlinked /efi, which ProtectSystem mounts at that target
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        unix::fs::symlink(dir.path(), "/efi").unwrap();
        let path = dir.path().join("file");
        profile_and_run(&["touch", path.to_str().unwrap()], false);
        fs::remove_file("/efi").unwrap();
    }

    #[test]
    fn systemd_run_create_in_home() {
        // Write to /home or /root themselves, which ProtectHome=tmpfs mounts read only
        for dir in ["/home", "/root"] {
            let path = format!("{dir}/shh-test-{id}", id = rand::random::<u16>());
            profile_and_run_creating_paths(&["touch", &path], &[&path]);
        }
        profile_and_run(&["touch", "/home"], false);
        // Read a file in /home, which ProtectHome=read-only shows
        let home_file = tempfile::NamedTempFile::new_in("/home").unwrap();
        let cmd = ["cat", home_file.path().to_str().unwrap()];
        for sd_opts in generate_options(&cmd, &ALL_SHH_RUN_OPTS) {
            assert!(sd_opts.contains(&"ProtectHome=read-only".to_owned()));
            let _ = systemd_run(&cmd, &sd_opts, false);
        }
    }

    #[test]
    fn systemd_run_tmpfile() {
        // Open an unnamed temporary file, a write to its directory, on the tmpfs of the test environment
        let dir = tempfile::tempdir_in("/mnt/tmp").unwrap();
        let cmd = [
            "python3",
            "-c",
            "import os, sys; os.open(sys.argv[1], os.O_TMPFILE | os.O_RDWR)",
            dir.path().to_str().unwrap(),
        ];
        profile_and_run(&cmd, false);
    }

    #[test]
    fn systemd_run_symlink() {
        // Create a symlink, a write to its directory
        let temp_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let path = temp_dir.path().join("link");
        let cmd = ["ln", "-s", "/dev/null", path.to_str().unwrap()];
        profile_and_run_creating_paths(&cmd, &[&path]);
    }

    #[test]
    fn systemd_run_mkfifo_through_symlink() {
        // Create a FIFO in /var/lib through a symlink in /tmp, a read of the symlink and a write to the directory
        // of its target
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let link_dir = tempfile::tempdir_in("/tmp").unwrap();
        let link = link_dir.path().join("link");
        unix::fs::symlink(dir.path(), &link).unwrap();
        let path = link.join("fifo");
        let cmd = ["mkfifo", path.to_str().unwrap()];
        profile_and_run_creating_paths(&cmd, &[dir.path().join("fifo")]);
    }

    #[test]
    fn systemd_run_create_through_dotdot() {
        // Create symlinks through paths containing `..`, including symlink targets, reading the exited directory
        // and writing to the resolved destination directory
        let target_dir = tempfile::tempdir_in("/tmp").unwrap();
        let inner_dir = target_dir.path().join("inner");
        fs::create_dir(&inner_dir).unwrap();
        fs::create_dir(target_dir.path().join("x")).unwrap();
        let link_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let link = link_dir.path().join("link");
        unix::fs::symlink(&inner_dir, &link).unwrap();
        let link_dotdot = link_dir.path().join("dotdot");
        unix::fs::symlink("link/../x", &link_dotdot).unwrap();
        for (path, created) in [
            (inner_dir.join("../x/new"), target_dir.path().join("x/new")),
            (link.join("../new"), target_dir.path().join("new")),
            (link_dotdot.join("new"), target_dir.path().join("x/new")),
        ] {
            let cmd = ["ln", "-s", "/dev/null", path.to_str().unwrap()];
            profile_and_run_creating_paths(&cmd, &[&created]);
        }
    }

    #[test]
    fn systemd_run_create_through_nested_symlink_target() {
        // Create a symlink in /tmp through a symlink in /var/lib whose relative target starts with another
        // symlink, reads of both symlinks and a write to the directory of the final target
        let cache_dir = tempfile::tempdir_in("/tmp").unwrap();
        let subdir = cache_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        let link_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let public = link_dir.path().join("public");
        unix::fs::symlink("bridge/subdir", &public).unwrap();
        unix::fs::symlink(cache_dir.path(), link_dir.path().join("bridge")).unwrap();
        let path = public.join("new");
        let cmd = ["ln", "-s", "/dev/null", path.to_str().unwrap()];
        profile_and_run_creating_paths(&cmd, &[subdir.join("new")]);
    }

    #[test]
    fn systemd_run_rename_through_nested_symlink_target() {
        // Rename a pre-existing file in /var/lib through a symlink whose target starts with another symlink, to
        // a directory on the same mount as the final source directory, through Python as `mv` falls back to
        // copying when the directories are on different mounts
        let tree = tempfile::tempdir_in("/var/lib").unwrap();
        let src_dir = tree.path().join("src");
        let dst_dir = tree.path().join("dst");
        fs::create_dir_all(src_dir.join("sub")).unwrap();
        fs::create_dir(&dst_dir).unwrap();
        let bridge = dst_dir.join("bridge");
        unix::fs::symlink(bridge.join("sub"), dst_dir.join("alias")).unwrap();
        unix::fs::symlink(&src_dir, &bridge).unwrap();
        let src = src_dir.join("sub/file");
        let src_alias = dst_dir.join("alias/file");
        let dst = dst_dir.join("new");
        let cmd = [
            "python3",
            "-c",
            "import os, sys; os.rename(sys.argv[1], sys.argv[2])",
            src_alias.to_str().unwrap(),
            dst.to_str().unwrap(),
        ];
        fs::write(&src, "").unwrap();
        for sd_opts in generate_options(&cmd, &ALL_SHH_RUN_OPTS) {
            fs::rename(&dst, &src).unwrap();
            let _ = systemd_run(&cmd, &sd_opts, false);
        }
        fs::remove_file(&dst).unwrap();
    }

    #[test]
    fn systemd_run_ln_hard() {
        // Hard link a pre-existing file, a read of the source, both directly in /tmp
        let src = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        let dst = src.path().with_extension("dst");
        let cmd = ["ln", src.path().to_str().unwrap(), dst.to_str().unwrap()];
        profile_and_run_creating_paths(&cmd, &[&dst]);
    }

    #[test]
    fn systemd_run_link_rename_across_mounts() {
        // Hard link a pre-existing /etc file into /var/lib, and rename a file created in /var/tmp into /var/lib,
        // through Python as `mv` falls back to copying when the directories are on different mounts
        let src = tempfile::NamedTempFile::new_in("/etc").unwrap();
        let dst_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let link = dst_dir.path().join("link");
        let created = format!("/var/tmp/shh-test-{}", rand::random::<u16>());
        let renamed = dst_dir.path().join("renamed");
        let cmd = [
            "python3",
            "-c",
            "import os, sys; os.link(sys.argv[1], sys.argv[2]); open(sys.argv[3], 'w').close(); os.rename(sys.argv[3], sys.argv[4])",
            src.path().to_str().unwrap(),
            link.to_str().unwrap(),
            &created,
            renamed.to_str().unwrap(),
        ];
        profile_and_run_creating_paths(&cmd, &[&link, &renamed]);
    }

    #[test]
    fn systemd_run_mv_symlink() {
        // Rename a pre-existing symlink over another in /var/lib, a write to their directory, not to the
        // directory of their target
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let target_dir = dir.path().join("releases");
        let target = target_dir.join("target");
        let src = dir.path().join("new");
        let dst = dir.path().join("cur");
        fs::create_dir(&target_dir).unwrap();
        fs::write(&target, "").unwrap();
        unix::fs::symlink(&target, &dst).unwrap();
        let cmd = ["mv", "-T", src.to_str().unwrap(), dst.to_str().unwrap()];
        unix::fs::symlink(&target, &src).unwrap();
        for sd_opts in generate_options(&cmd, &ALL_SHH_RUN_OPTS) {
            unix::fs::symlink(&target, &src).unwrap();
            let _ = systemd_run(&cmd, &sd_opts, false);
        }
    }

    #[test]
    fn systemd_run_replace_executed_file() {
        // Run a pre-existing script in /var/lib, and replace, remove or move it or its directory, writes to
        // directories whose entries the service must not see as mount points, or holding them
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let tool_dir = dir.path().join("tools");
        let tool = tool_dir.join("tool");
        let new = tool_dir.join("new");
        let staging_dir = dir.path().join("staging");
        let old_dir = dir.path().join("old");
        let setup = || {
            for bin_dir in [&tool_dir, &staging_dir] {
                fs::create_dir_all(bin_dir).unwrap();
                let bin = bin_dir.join("tool");
                fs::write(&bin, "#!/bin/sh\n").unwrap();
                fs::set_permissions(&bin, Permissions::from_mode(0o755)).unwrap();
            }
            fs::write(&new, "").unwrap();
            if old_dir.exists() {
                fs::remove_dir_all(&old_dir).unwrap();
            }
        };
        let [tool_dir, tool, new, staging_dir, old_dir] =
            [&tool_dir, &tool, &new, &staging_dir, &old_dir].map(|p| p.to_str().unwrap());
        for script in [
            format!("{tool} && mv {new} {tool}"),
            format!("{tool} && rm {tool}"),
            format!("{tool} && rm -r {tool_dir}"),
            format!("{tool} && mv {tool_dir} {old_dir} && rm {old_dir}/tool"),
            format!(
                "mv {tool_dir} {old_dir} && mv {staging_dir} {tool_dir} && {tool} && rm -r {old_dir}"
            ),
        ] {
            let cmd = ["sh", "-c", &script];
            setup();
            for sd_opts in generate_options(&cmd, &ALL_SHH_RUN_OPTS) {
                setup();
                let _ = systemd_run(&cmd, &sd_opts, false);
            }
        }
    }

    #[test]
    fn systemd_run_rename_exchange() {
        // Exchange two pre-existing files in /tmp, a write to their directory
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        fs::write(&a, "").unwrap();
        fs::write(&b, "").unwrap();
        let cmd = [
            "mv",
            "--exchange",
            "-T",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
        ];
        profile_and_run(&cmd, false);
    }

    /// Profile and run commands creating an entry of each kind over a held one of a type, as a system service
    fn create_held(type_: &str, kinds: &[&str]) {
        // Create an entry held directly in /tmp, which the service must see; link and rename sources are created
        // by the command
        for kind in kinds {
            let path = format!("/tmp/shh-test-{id}", id = rand::random::<u16>());
            let src = format!("{path}.src");
            create_entry(type_, Path::new(&path));
            let cmd = [
                "python3",
                "-c",
                CREATE_ENTRY_SCRIPT,
                kind,
                &path,
                &src,
                "held",
            ];
            let all_sd_opts = generate_options(&cmd, &ALL_SHH_RUN_OPTS);
            let _ = fs::remove_file(&src);
            for sd_opts in all_sd_opts {
                let _ = systemd_run(&cmd, &sd_opts, false);
                let _ = fs::remove_file(&src);
            }
            remove_entry(Path::new(&path));
        }
    }

    #[test]
    fn systemd_run_create_held_file() {
        create_held("file", &["open", "link", "rename", "open-replace"]);
    }

    #[test]
    fn systemd_run_create_held_dir() {
        create_held("dir", &["mkdir", "mkdir-p"]);
    }

    #[test]
    fn systemd_run_create_held_symlink() {
        create_held("symlink", &["symlink"]);
    }

    #[test]
    fn systemd_run_create_held_fifo() {
        create_held("fifo", &["mknod", "mkfifo"]);
    }

    /// Profile and run commands creating an entry of each kind where one of a type is held during profiling only,
    /// as a system service
    fn create_held_then_free(type_: &str, kinds: &[&str]) {
        // Create an entry in /var/lib held during profiling only, a write to its directory; link and rename
        // sources are created by the command in another directory
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        let src_dir = dir.path().join("src");
        let dst_dir = dir.path().join("dst");
        fs::create_dir(&src_dir).unwrap();
        fs::create_dir(&dst_dir).unwrap();
        let src = src_dir.join("file");
        let path = dst_dir.join("entry");
        for kind in kinds {
            let cmd = [
                "python3",
                "-c",
                CREATE_ENTRY_SCRIPT,
                kind,
                path.to_str().unwrap(),
                src.to_str().unwrap(),
                "free",
            ];
            create_entry(type_, &path);
            let all_sd_opts = generate_options(&cmd, &ALL_SHH_RUN_OPTS);
            remove_entry(&path);
            let _ = fs::remove_file(&src);
            for sd_opts in all_sd_opts {
                let _ = systemd_run(&cmd, &sd_opts, false);
                // Created by the service
                remove_entry(&path);
                let _ = fs::remove_file(&src);
            }
        }
    }

    #[test]
    fn systemd_run_create_held_then_free_file() {
        create_held_then_free("file", &["open", "link", "rename"]);
    }

    #[test]
    fn systemd_run_create_held_then_free_symlink() {
        create_held_then_free("symlink", &["open", "symlink"]);
    }

    #[test]
    fn systemd_run_create_held_then_free_dir() {
        create_held_then_free("dir", &["mkdir"]);
    }

    #[test]
    fn systemd_run_create_held_then_free_fifo() {
        create_held_then_free("fifo", &["mknod", "mkfifo"]);
    }

    /// Profile and run commands failing on an entry held at a path, as a system service
    fn fail_on_held_entry(path: &Path) {
        // Fail on an entry held during profiling and the run, which the service must see: a non-empty directory to
        // remove or to rename an empty one onto, or a socket path to bind, directly in /tmp or in /var/lib
        // Python script expecting to fail on an existing entry
        let script = "
import errno, os, socket, sys

kind, path, src = sys.argv[1:]
expected = errno.EADDRINUSE if kind == 'bind' else errno.ENOTEMPTY
try:
    if kind == 'rmdir':
        os.rmdir(path)
    elif kind == 'rename':
        os.rename(src, path)
    elif kind == 'bind':
        socket.socket(socket.AF_UNIX).bind(path)
    else:
        raise ValueError(kind)
except OSError as e:
    if e.errno != expected:
        raise
else:
    sys.exit(1)
";
        let src = path.with_extension("src");
        for kind in ["rmdir", "rename", "bind"] {
            if kind == "bind" {
                UnixListener::bind(path).unwrap();
            } else {
                create_entry("dir", path);
                create_entry("file", &path.join("file"));
            }
            if kind == "rename" {
                create_entry("dir", &src);
            }
            let cmd = [
                "python3",
                "-c",
                script,
                kind,
                path.to_str().unwrap(),
                src.to_str().unwrap(),
            ];
            for sd_opts in generate_options(&cmd, &ALL_SHH_RUN_OPTS) {
                let _ = systemd_run(&cmd, &sd_opts, false);
            }
            remove_entry(path);
            if kind == "rename" {
                remove_entry(&src);
            }
        }
    }

    #[test]
    fn systemd_run_fail_on_held_entry_tmp() {
        let tmp_name = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        fail_on_held_entry(&tmp_name.path().with_extension("entry"));
    }

    #[test]
    fn systemd_run_fail_on_held_entry_var_lib() {
        let var_lib_dir = tempfile::tempdir_in("/var/lib").unwrap();
        fail_on_held_entry(&var_lib_dir.path().join("entry"));
    }

    #[test]
    fn systemd_run_remove_absent() {
        // Remove an absent entry, or rename one across two directories, in /var/lib, which the service must see
        // absent rather than on a read-only mount
        // Python script expecting to fail on an absent entry
        let script = "
import os, sys

kind, path, dst = sys.argv[1:]
try:
    if kind == 'unlink':
        os.unlink(path)
    elif kind == 'rmdir':
        os.rmdir(path)
    elif kind == 'rename':
        os.rename(path, dst)
    else:
        raise ValueError(kind)
except FileNotFoundError:
    pass
else:
    sys.exit(1)
";
        let var_lib_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let src_dir = var_lib_dir.path().join("src");
        let dst_dir = var_lib_dir.path().join("dst");
        create_entry("dir", &src_dir);
        create_entry("dir", &dst_dir);
        let absent = var_lib_dir.path().join("absent");
        let src = src_dir.join("absent");
        let dst = dst_dir.join("new");
        for (kind, path) in [("unlink", &absent), ("rmdir", &absent), ("rename", &src)] {
            let cmd = [
                "python3",
                "-c",
                script,
                kind,
                path.to_str().unwrap(),
                dst.to_str().unwrap(),
            ];
            profile_and_run(&cmd, false);
        }
    }

    #[test]
    fn systemd_run_absent_xattr() {
        // Remove or replace an absent attribute of a file in /var/lib, which the service must see absent rather
        // than on a read-only mount
        // Python script expecting to fail on an absent attribute
        let script = "
import errno, os, sys

kind, path = sys.argv[1:]
try:
    if kind == 'removexattr':
        os.removexattr(path, 'user.absent')
    elif kind == 'setxattr':
        os.setxattr(path, 'user.absent', b'', os.XATTR_REPLACE)
    else:
        raise ValueError(kind)
except OSError as e:
    if e.errno != errno.ENODATA:
        raise
else:
    sys.exit(1)
";
        let file = tempfile::NamedTempFile::new_in("/var/lib").unwrap();
        for kind in ["removexattr", "setxattr"] {
            let cmd = ["python3", "-c", script, kind, file.path().to_str().unwrap()];
            profile_and_run(&cmd, false);
        }
    }

    #[test]
    fn systemd_run_xattrat() {
        // Set an attribute, and remove an absent one, of a file in /var/lib, with the syscalls taking a directory
        // descriptor
        if kernel_version() < (6, 13) {
            eprintln!("Kernel without setxattrat and removexattrat, skipping");
            return;
        }
        let file = tempfile::NamedTempFile::new_in("/var/lib").unwrap();
        for kind in ["setxattrat", "removexattrat"] {
            profile_and_run(&path_syscall_cmd(kind, file.path()), false);
        }
    }

    #[test]
    fn systemd_run_file_setattr() {
        // Set the attributes of a file in /var/lib to their current, zero, values
        // Decoded by strace from 6.17
        if kernel_version() < (6, 17) || strace_version() < (6, 17) {
            eprintln!("Kernel or strace without file_setattr, skipping");
            return;
        }
        let file = tempfile::NamedTempFile::new_in("/var/lib").unwrap();
        profile_and_run(&path_syscall_cmd("file_setattr", file.path()), false);
    }

    #[test]
    fn systemd_run_fd_write() {
        // Change the metadata of a file opened read-only, on the tmpfs of the test environment
        let file = tempfile::NamedTempFile::new_in("/mnt/tmp").unwrap();
        for kind in [
            "fchmod",
            "fchown",
            "fremovexattr",
            "fsetxattr",
            "ioctl-fssetxattr",
            "ioctl-setflags",
        ] {
            profile_and_run(&path_syscall_cmd(kind, file.path()), false);
        }
    }

    /// Profile and run commands making a syscall of each kind on the `file` or `link` entry of a directory, as a
    /// system service
    fn read_path(cases: &[(&str, &str)]) {
        // Query a file in /var/lib, or a symlink to it, with a single syscall
        let dir = tempfile::tempdir_in("/var/lib").unwrap();
        create_entry("file", &dir.path().join("file"));
        unix::fs::symlink("file", dir.path().join("link")).unwrap();
        for &(kind, entry) in cases {
            let supported = match kind {
                "getxattrat" | "listxattrat" => kernel_version() >= (6, 13),
                // Decoded by strace from 6.17
                "file_getattr" => kernel_version() >= (6, 17) && strace_version() >= (6, 17),
                _ => true,
            };
            if !supported {
                eprintln!("Kernel or strace without {kind}, skipping");
                continue;
            }
            profile_and_run(&path_syscall_cmd(kind, &dir.path().join(entry)), false);
        }
    }

    #[test]
    fn systemd_run_read_path_access() {
        read_path(&[
            ("access", "file"),
            ("faccessat", "file"),
            ("faccessat2", "file"),
        ]);
    }

    #[test]
    fn systemd_run_read_path_xattr() {
        read_path(&[
            ("getxattr", "file"),
            ("getxattrat", "file"),
            ("lgetxattr", "link"),
            ("listxattr", "file"),
            ("listxattrat", "file"),
            ("llistxattr", "link"),
        ]);
    }

    #[test]
    fn systemd_run_read_path_readlink() {
        read_path(&[
            ("readlink", "link"),
            ("readlink-file", "file"),
            ("readlinkat", "link"),
        ]);
    }

    #[test]
    fn systemd_run_read_path_metadata() {
        read_path(&[
            ("file_getattr", "file"),
            ("name_to_handle_at", "file"),
            ("name_to_handle_at-size", "file"),
            ("statfs", "file"),
            ("statx", "file"),
        ]);
    }

    #[test]
    fn systemd_run_read_path_watch() {
        read_path(&[("fanotify_mark", "file"), ("inotify_add_watch", "file")]);
    }

    #[test]
    fn systemd_run_32bit_abi() {
        // 32-bit x86 programs making one syscall named differently from its x86_64 call: writes on the tmpfs of
        // the test environment, reads on a pre-existing file hidden by PrivateTmp=, in the /tmp tmpfs for an
        // inode number fitting in the 16 bits of oldstat
        let bin_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let bin = bin_dir.path().join("syscall_32bit");
        compile_c(SYSCALL_32BIT_SRC, &["-m32"], &bin);
        let written = tempfile::NamedTempFile::new_in("/mnt/tmp").unwrap();
        let read = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        let shh_opts_sets = shh_run_opts_32bit();
        for (kind, path) in [
            ("chown32", written.path()),
            ("fchown32", written.path()),
            ("ioctl-setflags32", written.path()),
            ("lchown32", written.path()),
            ("truncate64", written.path()),
            ("utimensat_time64", written.path()),
            ("fstatat64", read.path()),
            ("lstat64", read.path()),
            ("oldlstat", read.path()),
            ("oldstat", read.path()),
            ("stat64", read.path()),
            ("statfs64", read.path()),
        ] {
            let cmd = [bin.to_str().unwrap(), kind, path.to_str().unwrap()];
            for sd_opts in generate_options(&cmd, &shh_opts_sets) {
                let _ = systemd_run(&cmd, &sd_opts, false);
            }
        }
    }

    #[test]
    fn systemd_run_fanotify_mount_mark() {
        // Watch the mount of a file in /var/lib written outside the service, seen only through the host's
        // mounts
        let file = tempfile::NamedTempFile::new_in("/var/lib").unwrap();
        let path = file.path().to_owned();
        // Stops once the file is removed
        thread::spawn(move || {
            while let Ok(mut f) = fs::OpenOptions::new().append(true).open(&path) {
                f.write_all(b"x").unwrap();
                thread::sleep(WRITE_INTERVAL);
            }
        });
        profile_and_run(&path_syscall_cmd("fanotify_mark-mount", file.path()), false);
    }

    #[test]
    fn systemd_run_bind_port_in_use() {
        // Bind a port held during profiling and the run, which the service must see in use
        let script = "
import errno, socket, sys

try:
    socket.socket().bind(('127.0.0.1', int(sys.argv[1])))
except OSError as e:
    if e.errno != errno.EADDRINUSE:
        raise
else:
    sys.exit(1)
";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let cmd = ["python3", "-c", script, &port];
        for sd_opts in generate_options(&cmd, &ALL_SHH_RUN_OPTS) {
            let _ = systemd_run(&cmd, &sd_opts, false);
        }
    }

    #[test]
    fn systemd_run_cp_tmp() {
        // Copy a pre-existing file, a read of the source and a creation, both directly in /tmp
        let src = tempfile::NamedTempFile::new_in("/tmp").unwrap();
        let dst = src.path().with_extension("dst");
        let cmd = ["cp", src.path().to_str().unwrap(), dst.to_str().unwrap()];
        profile_and_run_creating_paths(&cmd, &[&dst]);
    }

    #[test]
    fn systemd_run_write_tmp_dirs() {
        // Create a file in each of several pre-existing directories directly in /tmp, /tmp itself is not written
        let dirs: Vec<_> = iter::repeat_with(|| tempfile::tempdir_in("/tmp").unwrap())
            .take(6)
            .collect();
        let mut cmd = vec![
            "sh",
            "-c",
            r#"for d in "$@"; do echo x > "$d/f" || exit 1; done"#,
            "sh",
        ];
        cmd.extend(dirs.iter().map(|d| d.path().to_str().unwrap()));
        let files: Vec<_> = dirs.iter().map(|d| d.path().join("f")).collect();
        profile_and_run_creating_paths(&cmd, &files);
    }

    #[test]
    fn systemd_run_write_listed_dir_subdirs() {
        // List a directory, then create a file in each of its pre-existing subdirectories; there are more of
        // them than the largest merge threshold of `all_shh_run_opts`, so that merging the writable exceptions
        // would put them onto the read-only directory
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let files: Vec<_> = (0..101)
            .map(|i| {
                let subdir = dir.path().join(i.to_string());
                fs::create_dir(&subdir).unwrap();
                subdir.join("f")
            })
            .collect();
        let cmd = [
            "sh",
            "-c",
            r#"ls "$1" > /dev/null && for d in "$1"/*; do echo x > "$d/f" || exit 1; done"#,
            "sh",
            dir.path().to_str().unwrap(),
        ];
        profile_and_run_creating_paths(&cmd, &files);
    }

    #[test]
    fn systemd_run_timerfd_alarm() {
        // Create a timerfd on clock 8, CLOCK_REALTIME_ALARM, which Python's time module lacks; a user service
        // lacks the capability it needs
        profile_and_run(&["python3", "-c", "import os; os.timerfd_create(8)"], false);
    }

    #[test]
    fn systemd_run_timer_cpu_clock() {
        // Create a timer on the CPU clock of the thread, a dynamic clock
        let script = "
import ctypes, threading, time

libc = ctypes.CDLL(None, use_errno=True)
clock = time.pthread_getcpuclockid(threading.get_ident())
if libc.timer_create(clock, None, ctypes.byref(ctypes.c_void_p())) != 0:
    raise OSError(ctypes.get_errno(), 'timer_create')
";
        profile_and_run(&["python3", "-c", script], false);
    }

    #[test]
    fn systemd_run_shmat_exec() {
        // A C program, since Python's ctypes maps writable and executable memory on import
        let bin_dir = tempfile::tempdir_in("/var/lib").unwrap();
        let bin = bin_dir.path().join("shmat_exec");
        compile_c(SHMAT_EXEC_SRC, &[], &bin);
        profile_and_run(&[bin.to_str().unwrap()], false);
    }
}
