//! Strace output parser

use std::{
    fs::File,
    io::{self, BufRead, BufWriter, Write as _},
    path::Path,
};

use crate::strace::Syscall;

mod combinator;
use combinator::parse_line;
use nix::libc::pid_t;

use super::{Expression, IntegerExpression};

pub(crate) struct LogParser {
    reader: Box<dyn BufRead>,
    log: Option<BufWriter<File>>,
    buf: String,
    unfinished_syscalls: Vec<SyscallStart>,
}

impl LogParser {
    pub(crate) fn new(reader: Box<dyn BufRead>, log_path: Option<&Path>) -> anyhow::Result<Self> {
        let log = log_path
            .map(|p| -> io::Result<_> {
                let file = File::options().create(true).append(true).open(p)?;
                Ok(BufWriter::with_capacity(64 * 1024, file))
            })
            .transpose()?;
        Ok(Self {
            reader,
            log,
            buf: String::new(),
            unfinished_syscalls: Vec::new(),
        })
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
enum ParseResult {
    /// This line was ignored
    /// (strace sometimes outputs complete garbage like '1008333      0.000045 ???( <unfinished ...>')
    IgnoredLine,
    /// This line describes an unfinished syscall
    SyscallStart(SyscallStart),
    /// This line describes a previously unfinished syscall that is now finished
    SyscallEnd(SyscallEnd),
    /// This line describes a complete syscall
    Syscall(Syscall),
}

/// A syscall started that did not yet return
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct SyscallStart {
    pub pid: pid_t,
    pub rel_ts: f64,
    pub name: String,
    pub args: Vec<Expression>,
}

impl SyscallStart {
    /// Merge syscall start and end to build a complete syscall invocation description
    pub(crate) fn end(self, end: &SyscallEnd) -> Syscall {
        debug_assert_eq!(self.pid, end.pid);
        debug_assert_eq!(self.name, end.name);
        Syscall {
            pid: self.pid,
            rel_ts: end.rel_ts,
            name: self.name,
            args: self.args,
            ret_val: end.ret_val.clone(),
        }
    }
}

/// A syscall that ended
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct SyscallEnd {
    pub pid: pid_t,
    pub rel_ts: f64,
    pub name: String,
    pub ret_val: IntegerExpression,
}

impl Iterator for LogParser {
    type Item = anyhow::Result<Syscall>;

    /// Parse strace output lines and yield syscalls
    /// Ignore invalid lines, but bubble up errors if the parsing matches and we fail subsequent parsing
    fn next(&mut self) -> Option<Self::Item> {
        let sc = loop {
            self.buf.clear();
            let line = match self.reader.read_line(&mut self.buf) {
                Ok(0) => return None, // EOF
                Ok(_) => self.buf.trim_end(),
                Err(e) => return Some(Err(anyhow::Error::new(e).context("Failed to read line"))),
            };

            if line.ends_with(" +++") || line.ends_with(" ---") {
                // Process exited, or signal received, not a syscall
                continue;
            }

            if let Some(log) = self.log.as_mut() {
                if let Err(e) = writeln!(log, "{line}") {
                    return Some(Err(e.into()));
                }
            }

            match parse_line(line) {
                Ok(ParseResult::Syscall(sc)) => {
                    log::trace!("Parsed line: {line:?}");
                    if sc.is_successful_or_pending() {
                        break sc;
                    }
                }
                Ok(ParseResult::SyscallStart(sc)) => {
                    self.unfinished_syscalls.push(sc);
                }
                Ok(ParseResult::SyscallEnd(sc_end)) => {
                    if let Some(unfinished_index) = self
                        .unfinished_syscalls
                        .iter()
                        .position(|sc| (sc.name == sc_end.name) && (sc.pid == sc_end.pid))
                    {
                        let sc_start = self.unfinished_syscalls.swap_remove(unfinished_index); // I fucking love Rust <3
                        break sc_start.end(&sc_end);
                    }
                    log::warn!("Unable to find first part of syscall");
                }
                Ok(ParseResult::IgnoredLine) => {
                    log::warn!("Ignored line: {line:?}");
                }
                Err(e) => {
                    // Unfortunately, some versions of strace output inconsistent line format,
                    // so we have to ignore some parsing errors
                    // log::error!("Failed to parse line: {line:?}");
                    // return Some(Err(e));
                    log::warn!("Failed to parse line ({e}): {line:?}");
                }
            }
        };
        Some(Ok(sc))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use pretty_assertions::assert_eq;

    use super::*;

    macro_rules! assert_snapshot {
        ($e:expr) => {
            insta::with_settings!({sort_maps => true}, {
                insta::assert_ron_snapshot!($e);
            });
        };
    }

    #[test]
    fn test_mmap() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "382944      0.000054 mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f52a332e000",
            ).unwrap()
        );

        assert_snapshot!(
            parse_line(
                "601646      0.000011 mmap(0x7f2fce8dc000, 1396736, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x26000) = 0x7f2fce8dc000",
            ).unwrap()
        );
    }

    #[test]
    fn test_access() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "382944      0.000036 access(\"\\x2f\\x65\\x74\\x63\\x2f\\x6c\\x64\\x2e\\x73\\x6f\\x2e\\x70\\x72\\x65\\x6c\\x6f\\x61\\x64\", R_OK) = -1 ENOENT (No such file or directory)",
            ).unwrap()
        );
    }

    #[test]
    fn test_rt_sigaction() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "720313      0.000064 rt_sigaction(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7f6da716c510}, NULL, 8) = 0",
            ).unwrap()
        );
    }

    #[test]
    fn test_rt_sigprocmask() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line("440663      0.002174 rt_sigprocmask(SIG_SETMASK, [], ~[KILL STOP RTMIN RT_1], 8) = 0").unwrap()
        );
    }

    #[test]
    fn test_newfstatat() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "772627      0.000010 newfstatat(AT_FDCWD, \"\\x2f\\x61\\x2f\\x70\\x61\\x74\\x68\", {st_dev=makedev(0xfd, 0x1), st_ino=26427782, st_mode=S_IFDIR|0755, st_nlink=2, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=112, st_size=53248, st_atime=1689948680 /* 2023-07-21T16:11:20.028467954+0200 */, st_atime_nsec=28467954, st_mtime=1692975712 /* 2023-08-25T17:01:52.252908565+0200 */, st_mtime_nsec=252908565, st_ctime=1692975712 /* 2023-08-25T17:01:52.252908565+0200 */, st_ctime_nsec=252908565}, 0) = 0",
            ).unwrap()
        );
    }

    #[test]
    fn test_getrandom() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "815537      0.000017 getrandom(\"\\x42\\x18\\x81\\x90\\x40\\x63\\x1a\\x2c\", 8, GRND_NONBLOCK) = 8",
            ).unwrap()
        );
    }

    #[test]
    fn test_fstatfs() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "244841      0.000033 fstatfs(6, {f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=231830864, f_bfree=38594207, f_bavail=26799417, f_files=58957824, f_ffree=54942232, f_fsid={val=[0x511787a8, 0x92a74a52]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOATIME}) = 0",
            ).unwrap()
        );

        assert_snapshot!(
            parse_line(
                "895683      0.000028 fstatfs(3, {f_type=PROC_SUPER_MAGIC, f_bsize=4096, f_blocks=0, f_bfree=0, f_bavail=0, f_files=0, f_ffree=0, f_fsid={val=[0, 0]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NODEV|ST_NOEXEC|ST_RELATIME}) = 0",
            ).unwrap()
        );
    }

    #[test]
    fn test_open_relative() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "998518      0.000033 openat(AT_FDCWD<\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x64\\x65\\x2f\\x73\\x72\\x63\\x2f\\x73\\x68\\x68>, \"\\x2e\\x2e\", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3<\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x64\\x65\\x2f\\x73\\x72\\x63>",
            ).unwrap()
        );
    }

    #[test]
    fn test_truncated() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "28707      0.000194 sendto(15<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x35\\x34\\x31\\x38\\x32\\x31\\x33\\x5d>, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1694010548, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20",
            ).unwrap()
        );

        assert_snapshot!(
            parse_line("215947      0.000022 read(3, \"\\x12\\xef\"..., 832) = 832",).unwrap()
        );
    }

    #[test]
    fn test_invalid() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Bogus output ('{{', note the missing field name) that strace 5.10 can generate
        let res = parse_line(
            "57652      0.000071 sendto(19<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x38\\x34\\x38\\x36\\x39\\x32\\x5d>, {{len=20, type=0x16 /* NLMSG_??? */, flags=NLM_F_REQUEST|0x300, seq=1697715709, pid=0}, \"\\x00\\x00\\x00\\x00\"}, 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20",
        );
        assert_eq!(res.unwrap(), ParseResult::IgnoredLine);
    }

    #[test]
    fn test_bind() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "688129      0.000023 bind(4<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x34\\x31\\x38\\x34\\x35\\x32\\x32\\x5d>, {sa_family=AF_UNIX, sun_path=@\"\\x62\\x31\\x39\\x33\\x64\\x30\\x62\\x30\\x63\\x63\\x64\\x37\\x30\\x35\\x66\\x39\\x2f\\x62\\x75\\x73\\x2f\\x73\\x79\\x73\\x74\\x65\\x6d\\x63\\x74\\x6c\\x2f\"}, 34) = 0",
            ).unwrap()
        );

        assert_snapshot!(
            parse_line(
                "132360      0.000022 bind(6<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x38\\x31\\x35\\x36\\x39\\x33\\x5d>, {sa_family=AF_INET, sin_port=htons(8025), sin_addr=inet_addr(\"\\x31\\x32\\x37\\x2e\\x30\\x2e\\x30\\x2e\\x31\")}, 16) = 0",
            ).unwrap()
        );
    }

    #[test]
    fn test_multiplication() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "85195      0.000038 prlimit64(0, RLIMIT_NOFILE, {rlim_cur=512*1024, rlim_max=512*1024}, NULL) = 0",
            ).unwrap()
        );
    }

    #[test]
    fn test_epoll() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "114586      0.000075 epoll_ctl(3<\\x61\\x6e\\x6f\\x6e\\x5f\\x69\\x6e\\x6f\\x64\\x65\\x3a\\x5b\\x65\\x76\\x65\\x6e\\x74\\x70\\x6f\\x6c\\x6c\\x5d>, EPOLL_CTL_ADD, 4<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x37\\x33\\x31\\x35\\x39\\x38\\x5d>, {events=EPOLLIN, data={u32=4, u64=4}}) = 0",
            ).unwrap()
        );

        assert_snapshot!(
            parse_line(
                "3487       0.000130 epoll_pwait(4<\\x61\\x6e\\x6f\\x6e\\x5f\\x69\\x6e\\x6f\\x64\\x65\\x3a\\x5b\\x65\\x76\\x65\\x6e\\x74\\x70\\x6f\\x6c\\x6c\\x5d>, [{events=EPOLLOUT, data={u32=833093633, u64=9163493471957811201}}, {events=EPOLLOUT, data={u32=800587777, u64=9163493471925305345}}], 128, 0, NULL, 0) = 2",
            ).unwrap()
        );
    }

    #[test]
    fn test_interleave() {
        let _ = simple_logger::SimpleLogger::new().init();

        let lines = Cursor::new(
            "1       0.000001 select(4, [3], NULL, NULL, NULL <unfinished ...>
2       0.000002 clock_gettime(CLOCK_REALTIME, {tv_sec=1130322148, tv_nsec=3977000}) = 0
1       0.000003 <... select resumed> )      = 1 (in [3])"
                .as_bytes()
                .to_vec(),
        );
        let parser = LogParser::new(Box::new(lines), None).unwrap();
        let syscalls: Vec<Syscall> = parser.into_iter().collect::<Result<_, _>>().unwrap();

        assert_snapshot!(syscalls);
    }

    #[test]
    fn test_getpid() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(parse_line("641342      0.000022 getpid()           = 641314").unwrap());
    }

    #[test]
    fn test_close() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line("246722      0.000003 close(39<\\x2f\\x6d\\x65\\x6d\\x66\\x64\\x3a\\x6d\\x6f\\x7a\\x69\\x6c\\x6c\\x61\\x2d\\x69\\x70\\x63>(deleted)) = 0").unwrap()
        );
    }

    #[test]
    fn test_sched_getaffinity() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line("231196      0.000017 sched_getaffinity(0, 512, [0 1 2 3 4 5 6 7]) = 8",)
                .unwrap()
        );
    }

    #[test]
    fn test_execve() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line("1234      0.000000 execve(\"\\x12\", [\"\\x34\"], [\"\\x56\"]) = 0",)
                .unwrap()
        );
    }

    #[test]
    fn test_ioctl() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line("34274      0.000058 ioctl(1<\\x2f\\x64\\x65\\x76\\x2f\\x70\\x74\\x73\\x2f\\x30>, TCSETSW, {c_iflag=ICRNL|IXON|IUTF8, c_oflag=NL0|CR0|TAB0|BS0|VT0|FF0|OPOST|ONLCR, c_cflag=B38400|CS8|CREAD, c_lflag=ISIG|ICANON|ECHO|ECHOE|ECHOK|IEXTEN|ECHOCTL|ECHOKE, c_line=N_TTY, c_cc=[[VINTR]=0x3, [VQUIT]=0x1c, [VERASE]=0x7f, [VKILL]=0x15, [VEOF]=0x4, [VTIME]=0, [VMIN]=0x1, [VSWTC]=0, [VSTART]=0x11, [VSTOP]=0x13, [VSUSP]=0x1a, [VEOL]=0, [VREPRINT]=0x12, [VDISCARD]=0xf, [VWERASE]=0x17, [VLNEXT]=0x16, [VEOL2]=0, [17]=0, [18]=0]}) = 0",)
                .unwrap()
        );
    }

    #[test]
    fn test_in_out_args() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "664767      0.000014 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f3b7c000990, parent_tid=0x7f3b7c000990, exit_signal=0, stack=0x7f3b7b800000, stack_size=0x7ff880, tls=0x7f3b7c0006c0} => {parent_tid=[664773]}, 88) = 664773",
            )
            .unwrap()
        );

        assert_snapshot!(
            parse_line(
                "237494      0.000026 getpeername(3, {sa_family=AF_UNIX, sun_path=@\"\\x6e\\x6f\\x70\\x65\"}, [124 => 20]) = 0",
            )
            .unwrap()
        );

        // Note: not a real strace line
        assert_snapshot!(
            parse_line(
                "176051      0.000020 recvmsg(3, {msg_namelen=128 => 16, msg_controllen=56, msg_flags=0}, 0) = 64"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_named_args() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "714433      0.000035 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3f3c2f5090) = 714434",
            )
            .unwrap()
        );
    }

    #[test]
    fn test_bitshift() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "794046      0.000024 capset({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=1<<CAP_SYS_CHROOT, permitted=1<<CAP_SYS_CHROOT, inheritable=0}) = 0",
            )
            .unwrap()
        );
    }

    #[test]
    fn test_macro_addr_arg() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_snapshot!(
            parse_line(
                "813299      0.000023 connect(93, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, \"\\x12\\x34\", &sin6_addr), sin6_scope_id=0}, 28) = 0",
            )
            .unwrap()
        );
    }

    #[test]
    fn test_wait() {
        let _ = simple_logger::SimpleLogger::new().init();
        assert_snapshot!(
            parse_line(
                "30192      0.000010 wait4(30247, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 30247",
            )
            .unwrap()
        );
    }

    #[test]
    fn test_ret_code() {
        let _ = simple_logger::SimpleLogger::new().init();
        assert_snapshot!(
            parse_line(
                r#"39270      0.000020 connect(11<\x73\x6f\x63\x6b\x65\x74\x3a\x5b\x32\x31\x34\x31\x30\x37\x5d>, {sa_family=AF_INET, sin_port=htons(4321), sin_addr=inet_addr("\x31\x2e\x32\x2e\x33\x2e\x34")}, 16) = -1 EINPROGRESS (Operation now in progress)"#,
            )
            .unwrap()
        );
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchs {
    extern crate test;

    use std::io::BufReader;

    use test::Bencher;

    use super::*;

    #[bench]
    fn bench_parse_line(b: &mut Bencher) {
        let log_path = Path::new("strace.log");
        if !log_path.is_file() {
            return;
        }
        let log_lines: Vec<_> = BufReader::new(File::open(log_path).unwrap())
            .lines()
            .take(5000)
            .collect::<Result<_, _>>()
            .unwrap();

        b.iter(|| {
            log_lines.iter().map(|l| parse_line(&l)).for_each(drop);
        });
    }
}
