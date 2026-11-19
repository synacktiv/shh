//! Timer and suspend wakeup syscall handlers

use super::{ExtractArg as _, HandlerError, SyscallHandler};
use crate::{
    strace::{Expression, IntegerExpression, IntegerExpressionValue, NamedSymbol, Syscall},
    summarize::{ProgramState, action::ProgramAction},
};

/// Handler for `epoll_ctl` syscall
pub(crate) struct EpollCtlHandler {
    pub op: usize,
    pub event: usize,
}

impl SyscallHandler for EpollCtlHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        let op = self.op.extract(sc)?;
        let event = self.event.extract(sc)?;

        let op_name = unpack_expr!(
            op,
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(op_name)),
                ..
            }) => op_name
        );

        if op_name == "EPOLL_CTL_ADD" {
            let evt_struct = unpack_expr!(event, Expression::Struct(evt_struct) => evt_struct);
            let evt_member = unpack_struct_member!(evt_struct, "events");
            let evt_flags = unpack_expr!(evt_member, Expression::Integer(ie) => ie);
            if evt_flags.value.is_flag_set("EPOLLWAKEUP") {
                actions.push(ProgramAction::Wakeup);
            }
        }
        Ok(())
    }
}

/// Handler for timer creation and sleep syscalls
pub(crate) struct TimerHandler {
    pub clockid: usize,
}

impl SyscallHandler for TimerHandler {
    fn handle(
        &self,
        sc: &Syscall,
        actions: &mut Vec<ProgramAction>,
        _state: &mut ProgramState,
    ) -> Result<(), HandlerError> {
        const PRIVILEGED_CLOCK_NAMES: [&str; 2] = ["CLOCK_REALTIME_ALARM", "CLOCK_BOOTTIME_ALARM"];
        // Dynamic clocks, like CPU clocks, are integer literals
        let clockid = unpack_expr!(
            self.clockid.extract(sc)?,
            Expression::Integer(IntegerExpression { value, .. }) => value
        );
        if clockid.is_any_flag_set(&PRIVILEGED_CLOCK_NAMES) {
            actions.push(ProgramAction::SetAlarm);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::summarize::{
        handlers::tests::{int_literal, make_syscall, named_symbol, summarize_syscall},
        program_state,
    };

    #[test]
    fn epoll_ctl_handler_add_with_wakeup() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([(
            "events".to_owned(),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::BinaryOr(vec![IntegerExpressionValue::NamedSymbol(
                    NamedSymbol::Unambiguous("EPOLLWAKEUP".to_owned()),
                )]),
                metadata: None,
            }),
        )]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_ADD"),
                int_literal(10),
                Expression::Struct(event_struct),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(result.is_ok());
        assert_eq!(actions, vec![ProgramAction::Wakeup]);
    }

    #[test]
    fn epoll_ctl_handler_add_without_wakeup() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([(
            "events".to_owned(),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                    "EPOLLIN".to_owned(),
                )),
                metadata: None,
            }),
        )]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_ADD"),
                int_literal(10),
                Expression::Struct(event_struct),
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
    fn epoll_ctl_handler_del_no_wakeup() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([(
            "events".to_owned(),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                    "EPOLLWAKEUP".to_owned(),
                )),
                metadata: None,
            }),
        )]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_DEL"),
                int_literal(10),
                Expression::Struct(event_struct),
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
    fn epoll_ctl_handler_missing_events_field() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_ADD"),
                int_literal(10),
                Expression::Struct(event_struct),
            ],
            0,
        );
        let mut actions = vec![];
        let mut state = program_state();

        let result = handler.handle(&sc, &mut actions, &mut state);
        assert!(matches!(
            result,
            Err(HandlerError::MissingStructMember { .. })
        ));
        assert!(actions.is_empty());
    }

    #[test]
    fn epoll_ctl_handler_wrong_op_type() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let event_struct = HashMap::from([(
            "events".to_owned(),
            Expression::Integer(IntegerExpression {
                value: IntegerExpressionValue::NamedSymbol(NamedSymbol::Unambiguous(
                    "EPOLLIN".to_owned(),
                )),
                metadata: None,
            }),
        )]);
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                int_literal(1),
                int_literal(10),
                Expression::Struct(event_struct),
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
    fn epoll_ctl_handler_wrong_event_type() {
        let handler = EpollCtlHandler { op: 1, event: 3 };
        let sc = make_syscall(
            "epoll_ctl",
            vec![
                int_literal(5),
                named_symbol("EPOLL_CTL_ADD"),
                int_literal(10),
                int_literal(999),
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
    fn timer_handler_clocks() {
        for (clock, expected) in [
            (named_symbol("CLOCK_MONOTONIC"), vec![]),
            (named_symbol("CLOCK_REALTIME"), vec![]),
            (
                named_symbol("CLOCK_REALTIME_ALARM"),
                vec![ProgramAction::SetAlarm],
            ),
            (
                named_symbol("CLOCK_BOOTTIME_ALARM"),
                vec![ProgramAction::SetAlarm],
            ),
            // MAKE_THREAD_CPUCLOCK(3264, CPUCLOCK_SCHED)
            (int_literal(-26114), vec![]),
        ] {
            let sc = make_syscall("timer_create", vec![clock, int_literal(0)], 0);
            let mut actions = vec![];
            TimerHandler { clockid: 0 }
                .handle(&sc, &mut actions, &mut program_state())
                .unwrap();
            assert_eq!(actions, expected);
        }
    }

    #[test]
    fn alarm_clock_timers_set_alarm() {
        let _ = simple_logger::SimpleLogger::new().init();

        for name in [
            "clock_nanosleep",
            "clock_nanosleep_time64",
            "timerfd_create",
        ] {
            assert_eq!(
                summarize_syscall(make_syscall(
                    name,
                    vec![named_symbol("CLOCK_REALTIME_ALARM"), int_literal(0)],
                    0,
                )),
                vec![
                    ProgramAction::SetAlarm,
                    ProgramAction::Syscalls([name.into()].into()),
                ]
            );
        }
    }
}
