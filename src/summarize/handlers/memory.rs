//! Memory mapping syscall handlers

use super::{ExtractArg as _, HandlerError, SyscallHandler, fd_fs::fd_path};
use crate::{
    strace::{Expression, IntegerExpression, Syscall},
    summarize::{ProgramState, action::ProgramAction},
};

/// Handler for `memfd_create` syscall
pub(crate) struct MemfdCreateHandler {
    pub flags: usize,
}

impl SyscallHandler for MemfdCreateHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let flags = self.flags.extract(sc)?;

        let flags = unpack_expr!(
            flags,
            Expression::Integer(IntegerExpression { value: flags, .. }) => flags
        );
        if flags.is_flag_set("MFD_HUGETLB") {
            actions.push(ProgramAction::HugePageMemoryMapping);
        }
        Ok(())
    }
}

/// Handler for mmap-like syscalls
pub(crate) struct MmapHandler {
    pub prot: usize,
    pub flags: Option<usize>,
    pub fd: Option<usize>,
}

impl SyscallHandler for MmapHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let prot = self.prot.extract(sc)?;
        let flags = self.flags.extract(sc)?;
        let fd = self.fd.extract(sc)?;

        let prot_val = unpack_expr!(
            prot,
            Expression::Integer(IntegerExpression {
                value: prot_val,
                ..
            }) => prot_val
        );
        if let Some(flags) = flags {
            let flags = unpack_expr!(
                flags,
                Expression::Integer(IntegerExpression { value: flags, .. }) => flags
            );
            if flags.is_flag_set("MAP_HUGETLB") {
                actions.push(ProgramAction::HugePageMemoryMapping);
            }
            if flags.is_flag_set("MAP_LOCKED") {
                actions.push(ProgramAction::LockMemoryMapping);
            }
        }
        if prot_val.is_flag_set("PROT_EXEC") {
            if let Some(path) = fd.and_then(|fd| fd_path(fd, actions, &state.cur_dir)) {
                actions.push(ProgramAction::Exec(path));
            }
            if sc.name.ends_with("mprotect") || prot_val.is_flag_set("PROT_WRITE") {
                actions.push(ProgramAction::WriteExecuteMemoryMapping);
            }
        }
        Ok(())
    }
}

/// Handler for `shmat` syscall
pub(crate) struct ShmAtHandler {
    pub flags: usize,
}

impl SyscallHandler for ShmAtHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let flags = self.flags.extract(sc)?;

        let flags = unpack_expr!(
            flags,
            Expression::Integer(IntegerExpression { value: flags, .. }) => flags
        );
        if flags.is_flag_set("SHM_EXEC") {
            actions.push(ProgramAction::WriteExecuteMemoryMapping);
        }
        Ok(())
    }
}

/// Handler for `shmctl` syscall
pub(crate) struct ShmCtlHandler {
    pub op: usize,
}

impl SyscallHandler for ShmCtlHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let op = self.op.extract(sc)?;

        let op = unpack_expr!(
            op,
            Expression::Integer(IntegerExpression { value: op, .. }) => op
        );
        if op.is_flag_set("SHM_LOCK") || op.is_flag_set("SHM_UNLOCK") {
            actions.push(ProgramAction::LockMemoryMapping);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summarize::{
        handlers::tests::{
            binary_or_flags, buf_expr, int_literal, make_syscall, named_symbol, summarize_syscall,
        },
        program_state,
    };

    #[test]
    fn memfd_create_handler_with_hugetlb() {
        let handler = MemfdCreateHandler { flags: 1 };
        let sc = make_syscall(
            "memfd_create",
            vec![buf_expr(b"test"), named_symbol("MFD_HUGETLB")],
            3,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::HugePageMemoryMapping]);
    }

    #[test]
    fn memfd_create_handler_without_hugetlb() {
        let handler = MemfdCreateHandler { flags: 1 };
        let sc = make_syscall(
            "memfd_create",
            vec![buf_expr(b"test"), named_symbol("MFD_CLOEXEC")],
            3,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn memfd_create_handler_wrong_flags_index() {
        let handler = MemfdCreateHandler { flags: 5 }; // Wrong index
        let sc = make_syscall("memfd_create", vec![buf_expr(b"test"), int_literal(4)], 3);
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
    fn memfd_create_handler_missing_flags() {
        let handler = MemfdCreateHandler { flags: 1 };
        let sc = make_syscall("memfd_create", vec![buf_expr(b"test")], 3);
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
    fn mmap_handler_exec_only_prot() {
        let handler = MmapHandler {
            prot: 0,
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![named_symbol("PROT_EXEC"), int_literal(0), int_literal(4096)],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn mmap_handler_exec_write_prot() {
        let handler = MmapHandler {
            prot: 0,
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                binary_or_flags(&["PROT_EXEC", "PROT_WRITE"]),
                int_literal(0),
                int_literal(4096),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::WriteExecuteMemoryMapping]);
    }

    #[test]
    fn mmap_handler_hugetlb_flag() {
        let handler = MmapHandler {
            prot: 0,
            flags: Some(3),
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                named_symbol("PROT_READ"),
                int_literal(0),
                int_literal(4096),
                binary_or_flags(&["MAP_HUGETLB"]),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::HugePageMemoryMapping]);
    }

    #[test]
    fn mmap_handler_exec_hugetlb_flag() {
        let handler = MmapHandler {
            prot: 0,
            flags: Some(3),
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                binary_or_flags(&["PROT_EXEC", "PROT_WRITE"]),
                int_literal(0),
                int_literal(4096),
                binary_or_flags(&["MAP_HUGETLB"]),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(
            actions,
            vec![
                ProgramAction::HugePageMemoryMapping,
                ProgramAction::WriteExecuteMemoryMapping
            ]
        );
    }

    #[test]
    fn mmap_handler_locked_flag() {
        let handler = MmapHandler {
            prot: 0,
            flags: Some(3),
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                named_symbol("PROT_READ"),
                int_literal(0),
                int_literal(4096),
                binary_or_flags(&["MAP_LOCKED"]),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::LockMemoryMapping]);
    }

    #[test]
    fn mmap_handler_wrong_prot_index() {
        let handler = MmapHandler {
            prot: 5, // Wrong index
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![int_literal(0), int_literal(4096), named_symbol("PROT_READ")],
            0,
        );
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
    fn mmap_handler_wrong_flags_type() {
        let handler = MmapHandler {
            prot: 0,
            flags: Some(3),
            fd: None,
        };
        let sc = make_syscall(
            "mmap",
            vec![
                named_symbol("PROT_READ"),
                int_literal(0),
                int_literal(4096),
                buf_expr(b"invalid"),
            ],
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
    fn mprotect_handler_write() {
        let handler = MmapHandler {
            prot: 0,
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mprotect",
            vec![
                binary_or_flags(&["PROT_WRITE"]),
                int_literal(0x1000),
                int_literal(4096),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn mprotect_handler_exec_write() {
        let handler = MmapHandler {
            prot: 0,
            flags: None,
            fd: None,
        };
        let sc = make_syscall(
            "mprotect",
            vec![
                binary_or_flags(&["PROT_EXEC", "PROT_WRITE"]),
                int_literal(0x1000),
                int_literal(4096),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::WriteExecuteMemoryMapping]);
    }

    #[test]
    fn shmctl_handler_shm_lock() {
        let handler = ShmCtlHandler { op: 1 };
        let sc = make_syscall("shmctl", vec![int_literal(1), named_symbol("SHM_LOCK")], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::LockMemoryMapping]);
    }

    #[test]
    fn shmctl_handler_shm_unlock() {
        let handler = ShmCtlHandler { op: 1 };
        let sc = make_syscall(
            "shmctl",
            vec![int_literal(1), named_symbol("SHM_UNLOCK")],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::LockMemoryMapping]);
    }

    #[test]
    fn shmctl_handler_no_lock() {
        let handler = ShmCtlHandler { op: 1 };
        let sc = make_syscall("shmctl", vec![int_literal(1), named_symbol("SHM_STAT")], 0);
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert!(actions.is_empty());
    }

    #[test]
    fn shmctl_handler_wrong_type() {
        let handler = ShmCtlHandler { op: 1 };
        let sc = make_syscall("shmctl", vec![int_literal(1), buf_expr(b"invalid")], 0);
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
    fn shmat_exec() {
        let _ = simple_logger::SimpleLogger::new().init();

        for (flags, mut expected) in [
            (int_literal(0), vec![]),
            (named_symbol("SHM_RDONLY"), vec![]),
            (
                named_symbol("SHM_EXEC"),
                vec![ProgramAction::WriteExecuteMemoryMapping],
            ),
            (
                binary_or_flags(&["SHM_RDONLY", "SHM_EXEC"]),
                vec![ProgramAction::WriteExecuteMemoryMapping],
            ),
        ] {
            expected.push(ProgramAction::Syscalls(["shmat".into()].into()));
            assert_eq!(
                summarize_syscall(make_syscall(
                    "shmat",
                    vec![int_literal(3), named_symbol("NULL"), flags],
                    0x7f00_0000_0000,
                )),
                expected
            );
        }
    }
}
