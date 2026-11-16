//! Process syscall handlers

use std::{
    any::{type_name, type_name_of_val},
    borrow::ToOwned,
    fs::{self, File},
    io::{BufRead as _, BufReader, Read},
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use goblin::elf;
use itertools::Itertools as _;
use nix::{
    libc::{PIDFD_SIGNAL_PROCESS_GROUP, pid_t, uid_t},
    unistd,
};

use super::{
    ExtractArg as _, FdOrPath, HandlerError, SyscallHandler, path_arg, pidfd_pid,
    walk::{resolve_path, traverse_path},
};
use crate::{
    strace::{Expression, IntegerExpression, IntegerExpressionValue, NamedSymbol, Syscall},
    summarize::{ProgramState, action::ProgramAction},
};

/// Handler for chdir-like syscalls
pub(crate) struct ChdirHandler {
    pub path: FdOrPath<usize>,
}

impl SyscallHandler for ChdirHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        if !sc.is_successful() {
            return Ok(());
        }
        let dir = self.path.extract(sc)?.resolve(state.cur_dir.as_ref())?;
        if let Some(mut dir) = dir {
            traverse_path(&mut dir, true, actions);
            debug_assert!(dir.is_absolute());
            state.cur_dir = dir;
        }
        Ok(())
    }
}

/// Handler for clone/clone3 syscalls
pub(crate) struct Clone3Handler {
    pub args: usize,
}

impl SyscallHandler for Clone3Handler {
    fn handle(
        &self,
        sc: &Syscall,
        _actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let child_pid = match &sc.ret_val {
            Some(rv) => rv.value().ok_or_else(|| err_value!(sc.ret_val, i64))?,
            None => return Ok(()),
        };
        if child_pid <= 0 {
            return Ok(());
        }
        let child_pid = TryInto::<pid_t>::try_into(child_pid)
            .map_err(|_| err_value!(child_pid, i64 => pid_t))?;

        let clone_args = self.args.extract(sc)?;
        let members = unpack_expr!(clone_args, Expression::Struct(members) => members);
        let flags_expr = unpack_struct_member!(members, "flags");
        let flags = unpack_expr!(
            flags_expr,
            Expression::Integer(IntegerExpression { value: flags, .. }) => flags
        );
        let share_fd_table = flags.is_flag_set("CLONE_FILES");
        state
            .proc_fd
            .add_child_proc(sc.pid, child_pid, share_fd_table);
        Ok(())
    }
}

/// Handler for fork/vfork syscalls
pub(crate) struct ForkHandler;

impl SyscallHandler for ForkHandler {
    fn handle(
        &self,
        sc: &Syscall,
        _actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let child_pid = match &sc.ret_val {
            Some(rv) => rv.value().ok_or_else(|| err_value!(sc.ret_val, i64))?,
            None => return Ok(()),
        };
        if child_pid <= 0 {
            return Ok(());
        }
        let child_pid = TryInto::<pid_t>::try_into(child_pid)
            .map_err(|_| err_value!(child_pid, i64 => pid_t))?;

        state.proc_fd.add_child_proc(sc.pid, child_pid, false);
        Ok(())
    }
}

/// Handler for unshare syscall
pub(crate) struct UnshareHandler {
    pub flags: usize,
}

impl SyscallHandler for UnshareHandler {
    fn handle(
        &self,
        sc: &Syscall,
        _actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        if !sc.is_successful() {
            return Ok(());
        }
        let flags = self.flags.extract(sc)?;
        let flags = unpack_expr!(
            flags,
            Expression::Integer(IntegerExpression { value: flags, .. }) => flags
        );
        if flags.is_flag_set("CLONE_FILES") {
            state.proc_fd.split_fd_table(sc.pid);
        }
        Ok(())
    }
}

/// Handler for exec-like syscalls
pub(crate) struct ExecHandler {
    pub relfd: Option<usize>,
    pub path: usize,
}

impl SyscallHandler for ExecHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let relfd = self.relfd.extract(sc)?;
        let path_expr = self.path.extract(sc)?;

        let mut next_path = resolve_path(path_arg(path_expr)?, relfd, state.cur_dir.as_ref());
        while let Some(mut cur_path) = next_path {
            traverse_path(&mut cur_path, true, actions);
            actions.push(ProgramAction::Exec(cur_path.clone()));
            next_path =
                read_elf_interpreter(&cur_path).or_else(|| read_shebang_interpreter(&cur_path));
        }
        Ok(())
    }
}

/// Handler for syscalls sending a signal to a process or thread ID
pub(crate) struct KillHandler {
    pub pid: usize,
    pub sig: usize,
}

impl SyscallHandler for KillHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let pid = self.pid.extract(sc)?;
        let sig = self.sig.extract(sc)?;

        let pid_val = unpack_expr!(
            pid,
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::Literal(pid_val),
                ..
            }) => pid_val
        );
        let pid_val = pid_t::try_from(*pid_val).map_err(|_| err_value!(*pid_val, i64 => pid_t))?;
        if kill_other(sc.pid, pid_val, sig)? {
            actions.push(ProgramAction::KillOther);
        }
        Ok(())
    }
}

/// Handler for `pidfd_send_signal` syscall
pub(crate) struct PidfdSendSignalHandler {
    pub pidfd: usize,
    pub sig: usize,
    pub flags: usize,
}

impl SyscallHandler for PidfdSendSignalHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let pidfd = self.pidfd.extract(sc)?;
        let sig = self.sig.extract(sc)?;
        let flags = unpack_expr!(
            self.flags.extract(sc)?,
            Expression::Integer(IntegerExpression { value, .. }) => value
        );

        // The process group the process leads is signaled instead
        let pid = if flags.is_flag_set("PIDFD_SIGNAL_PROCESS_GROUP")
            || flags
                .value()
                .is_some_and(|v| v & i64::from(PIDFD_SIGNAL_PROCESS_GROUP) != 0)
        {
            None
        } else {
            pidfd_pid(pidfd)?
        };
        if pid.map_or(Ok(true), |pid| kill_other(sc.pid, pid, sig))? {
            actions.push(ProgramAction::KillOther);
        }
        Ok(())
    }
}

/// Check whether a signal sent to a process ID may reach a process its sender has no evident permission to signal
fn kill_other(sender: pid_t, target: pid_t, sig: &Expression) -> Result<bool, HandlerError> {
    let sig_name = match sig {
        Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(sig_name)),
            ..
        }) => Some(sig_name),
        Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(0),
            ..
        }) => None,
        _ => {
            return Err(err_expr_type!(sig));
        }
    };
    // https://man7.org/linux/man-pages/man2/kill.2.html
    if target > 0 {
        let session_id = |pid| unistd::getsid(Some(unistd::Pid::from_raw(pid)));
        if sig_name.is_some_and(|s| s == "SIGCONT")
            && session_id(target).is_ok_and(|sid| session_id(sender) == Ok(sid))
        {
            return Ok(false);
        }
        // Note: for signals that terminate the target process, most of the time we will
        // fail to parse target UIDs here because it is already dead,
        // which will lead to "under" hardening
        if let Ok(target_uids) = process_uids(target)
            && let Ok(sender_uids) = process_uids(sender)
            && [sender_uids.real, sender_uids.effective]
                .iter()
                .any(|uid| [target_uids.real, target_uids.saved].contains(uid))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Handler for `sched_setscheduler` syscall
pub(crate) struct SetSchedulerHandler {
    pub policy: usize,
}

impl SyscallHandler for SetSchedulerHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        const RT_SCHEDULERS: [&str; 2] = ["SCHED_FIFO", "SCHED_RR"];
        let policy = self.policy.extract(sc)?;
        let policy_val = unpack_expr!(
            policy,
            Expression::Integer(IntegerExpression {
                value: policy_val,
                ..
            }) => policy_val
        );
        if RT_SCHEDULERS.iter().any(|s| policy_val.is_flag_set(s)) {
            actions.push(ProgramAction::SetRealtimeScheduler);
        }
        Ok(())
    }
}

/// Parse ELF and return interpreter path if we can
fn read_elf_interpreter(path: &Path) -> Option<PathBuf> {
    // TODO Find a way to parse only the first few pages
    let buf = fs::read(path).ok()?;
    let elf = elf::Elf::parse(&buf).ok()?;
    elf.interpreter.map(PathBuf::from)
}

/// Parse shebang and return interpreter path if we can
fn read_shebang_interpreter(path: &Path) -> Option<PathBuf> {
    let mut file = BufReader::new(File::open(path).ok()?);
    let mut line = String::new();
    file.read_line(&mut line).ok()?;
    line.strip_prefix("#!")
        .and_then(shlex::split)
        .and_then(|a| a.first().cloned())
        .map(PathBuf::from)
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct ProcessUids {
    real: uid_t,
    effective: uid_t,
    saved: uid_t,
    _fs: uid_t,
}

/// Get process Uid
/// See <https://man7.org/linux/man-pages/man5/proc_pid_status.5.html>
fn process_uids(pid: pid_t) -> anyhow::Result<ProcessUids> {
    let path: PathBuf = ["/proc", pid.to_string().as_str(), "status"]
        .iter()
        .collect();
    let file = File::open(&path).with_context(|| format!("Failed to open {path:?}"))?;
    read_process_uids(file)
}

fn read_process_uids<R>(reader: R) -> anyhow::Result<ProcessUids>
where
    R: Read,
{
    let reader = BufReader::new(reader);
    let (real, effective, saved, fs) = reader
        .lines()
        .map_while(Result::ok)
        .find_map(|l| l.strip_prefix("Uid:").map(ToOwned::to_owned))
        .ok_or_else(|| anyhow::anyhow!("Failed to parse process status file"))?
        .split_ascii_whitespace()
        .map(str::parse::<uid_t>)
        .collect_tuple()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse process status file UID line"))?;
    Ok(ProcessUids {
        real: real.context("Failed to parse process real UID")?,
        effective: effective.context("Failed to parse process effective UID")?,
        saved: saved.context("Failed to parse process saved UID")?,
        _fs: fs.context("Failed to parse process FS UID")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summarize::{
        handlers::tests::{
            buf_expr, fd_expr, int_literal, make_syscall, named_symbol, summarize_syscall,
        },
        program_state,
    };

    /// Process ID above the kernel's `PID_MAX_LIMIT`, of no process
    const NO_SUCH_PID: i64 = 4_194_305;

    /// Build a successful syscall made by the test process
    fn own_syscall(name: &str, args: Vec<Expression>) -> Syscall {
        let mut sc = make_syscall(name, args, 0);
        sc.pid = unistd::getpid().as_raw();
        sc
    }

    /// Build the argument lists of every signal sending syscall but `kill`, targeting a thread, and a process if
    /// the syscall takes both
    fn signal_args(process: i64, thread: i64) -> [(&'static str, Vec<Expression>); 5] {
        [
            ("tkill", vec![int_literal(thread), int_literal(0)]),
            (
                "tgkill",
                vec![
                    int_literal(process),
                    int_literal(thread),
                    named_symbol("SIGTERM"),
                ],
            ),
            ("rt_sigqueueinfo", vec![int_literal(thread), int_literal(0)]),
            (
                "rt_tgsigqueueinfo",
                vec![int_literal(process), int_literal(thread), int_literal(0)],
            ),
            (
                "pidfd_send_signal",
                vec![
                    fd_expr(3, format!("pid:{thread}")),
                    int_literal(0),
                    named_symbol("NULL"),
                    int_literal(0),
                ],
            ),
        ]
    }

    #[test]
    fn read_process_uids_works() {
        let data = "Name:	bat
Umask:	0022
State:	R (running)
Tgid:	144479
Ngid:	0
Pid:	144479
PPid:	2725
TracerPid:	0
Uid:	1001	1002	1003	1004
Gid:	1000	1000	1000	1000
FDSize:	64
Groups:	50 964 968 998 1000
NStgid:	144479
NSpid:	144479
NSpgid:	144479
NSsid:	2725
Kthread:	0
VmPeak:	  151444 kB
VmSize:	   86016 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	    7468 kB
VmRSS:	    7468 kB
RssAnon:	    1288 kB
RssFile:	    6180 kB
RssShmem:	       0 kB
VmData:	    2620 kB
VmStk:	     144 kB
VmExe:	    2784 kB
VmLib:	    8388 kB
VmPTE:	      84 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
CoreDumping:	0
THP_enabled:	1
untag_mask:	0xffffffffffffffff
Threads:	2
SigQ:	2/256555
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000000001000
SigCgt:	0000000100000440
CapInh:	0000000800000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	0
Seccomp_filters:	0
Speculation_Store_Bypass:	thread vulnerable
SpeculationIndirectBranch:	conditional enabled
Cpus_allowed:	ffffffff
Cpus_allowed_list:	0-31
Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:	0
voluntary_ctxt_switches:	0
nonvoluntary_ctxt_switches:	1
x86_Thread_features:
x86_Thread_features_locked:
".as_bytes();
        assert_eq!(
            read_process_uids(data).unwrap(),
            ProcessUids {
                real: 1001,
                effective: 1002,
                saved: 1003,
                _fs: 1004
            }
        );
    }

    #[test]
    fn chdir_handler_with_path() {
        let handler = ChdirHandler {
            path: FdOrPath::Path(0),
        };
        let sc = make_syscall("chdir", vec![buf_expr(b"/tmp")], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(state.cur_dir.to_str(), Some("/tmp"));
        assert!(actions.is_empty());
    }

    #[test]
    fn chdir_handler_wrong_arg_type() {
        let handler = ChdirHandler {
            path: FdOrPath::Path(0),
        };
        let sc = make_syscall("chdir", vec![int_literal(42)], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ExpressionTypeMismatch { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn chdir_handler_missing_arg() {
        let handler = ChdirHandler {
            path: FdOrPath::Path(0),
        };
        let sc = make_syscall("chdir", vec![], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::SyscalllArgIndexOutOfBounds { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn sched_setscheduler_handler_fifo() {
        let handler = SetSchedulerHandler { policy: 1 };
        let sc = make_syscall(
            "sched_setscheduler",
            vec![int_literal(0), named_symbol("SCHED_FIFO")],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::SetRealtimeScheduler]);
    }

    #[test]
    fn sched_setscheduler_handler_rr() {
        let handler = SetSchedulerHandler { policy: 1 };
        let sc = make_syscall(
            "sched_setscheduler",
            vec![int_literal(0), named_symbol("SCHED_RR")],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::SetRealtimeScheduler]);
    }

    #[test]
    fn sched_setscheduler_handler_other() {
        let handler = SetSchedulerHandler { policy: 1 };
        let sc = make_syscall(
            "sched_setscheduler",
            vec![int_literal(0), named_symbol("SCHED_OTHER")],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn sched_setscheduler_handler_wrong_type() {
        let handler = SetSchedulerHandler { policy: 1 };
        let sc = make_syscall(
            "sched_setscheduler",
            vec![int_literal(0), buf_expr(b"invalid")],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ExpressionTypeMismatch { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn signal_own_process() {
        let own = i64::from(unistd::getpid().as_raw());
        for (name, args) in signal_args(own, own) {
            assert_eq!(
                summarize_syscall(own_syscall(name, args)),
                vec![ProgramAction::Syscalls([name.into()].into())]
            );
        }
    }

    #[test]
    fn signal_unknown_thread_kill_other() {
        let own = i64::from(unistd::getpid().as_raw());
        for (name, args) in signal_args(own, NO_SUCH_PID) {
            assert_eq!(
                summarize_syscall(own_syscall(name, args)),
                vec![
                    ProgramAction::KillOther,
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }

    #[test]
    fn pidfd_signal_unknown_target_kill_other() {
        let own = format!("pid:{}", unistd::getpid());
        for (pidfd, flags) in [
            // Process outside the tracer's PID namespace
            (fd_expr(3, "anon_inode:[pidfd]"), int_literal(0)),
            // PIDFD_SELF_THREAD
            (int_literal(-10000), int_literal(0)),
            (fd_expr(3, &own), named_symbol("PIDFD_SIGNAL_PROCESS_GROUP")),
            // PIDFD_SIGNAL_PROCESS_GROUP, undecoded by strace < 6.9
            (fd_expr(3, &own), int_literal(4)),
        ] {
            assert_eq!(
                summarize_syscall(own_syscall(
                    "pidfd_send_signal",
                    vec![pidfd, int_literal(0), named_symbol("NULL"), flags],
                )),
                vec![
                    ProgramAction::KillOther,
                    ProgramAction::Syscalls(["pidfd_send_signal".into()].into()),
                ]
            );
        }
    }

    #[test]
    fn pidfd_signal_own_thread_scopes() {
        let own = format!("pid:{}", unistd::getpid());
        for flags in [
            named_symbol("PIDFD_SIGNAL_THREAD"),
            named_symbol("PIDFD_SIGNAL_THREAD_GROUP"),
            int_literal(1),
            int_literal(2),
        ] {
            assert_eq!(
                summarize_syscall(own_syscall(
                    "pidfd_send_signal",
                    vec![
                        fd_expr(3, &own),
                        int_literal(0),
                        named_symbol("NULL"),
                        flags
                    ],
                )),
                vec![ProgramAction::Syscalls(["pidfd_send_signal".into()].into())]
            );
        }
    }

    #[test]
    fn kill_handler_wrong_pid_type() {
        let handler = KillHandler { pid: 0, sig: 1 };
        let sc = make_syscall(
            "kill",
            vec![buf_expr(b"invalid"), named_symbol("SIGTERM")],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::ExpressionTypeMismatch { .. })
        ));
        assert!(actions.is_empty());
    }
}
