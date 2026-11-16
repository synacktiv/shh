//! Summarize program syscalls into higher level action

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use anyhow::Context as _;

use crate::strace::{SyscallItem, SyscallName};

mod action;
mod fd;
mod handlers;
mod syscall_map;

pub(crate) use action::{NetworkActivity, NetworkActivityKind, ProgramAction, SetSpecifier};
use fd::ProcessFdTracker;
pub(crate) use handlers::{PathWalk, traverse_path_within};
use syscall_map::SYSCALL_MAP;

/// Information that persists between syscalls and that we need to handle
/// Obviously, keeping this to a minimum is a goal
#[derive(Debug)]
pub(crate) struct ProgramState {
    /// Process fd-table topology and shared socket state
    proc_fd: ProcessFdTracker,
    /// Current working directory
    cur_dir: PathBuf,
    /// System default for `IPV6_V6ONLY` (from net.ipv6.bindv6only sysctl)
    bindv6only_default: bool,
}

impl ProgramState {
    pub(crate) fn new<P>(cur_dir: P, bindv6only_default: bool) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            proc_fd: ProcessFdTracker::default(),
            cur_dir: cur_dir.into(),
            bindv6only_default,
        }
    }
}

/// Returns the set of syscall names that have handlers
pub(crate) fn handled_syscall_names() -> HashSet<&'static str> {
    SYSCALL_MAP.keys().copied().collect()
}

pub(crate) fn summarize<I>(
    syscalls: I,
    env_paths: &[PathBuf],
    mut program_state: ProgramState,
) -> anyhow::Result<Vec<ProgramAction>>
where
    I: IntoIterator<Item = anyhow::Result<SyscallItem>>,
{
    let mut actions = Vec::new();
    let mut stats: HashMap<SyscallName, u64> = HashMap::new();
    for item in syscalls {
        let item = item?;
        match item {
            SyscallItem::NameOnly(name) => {
                stats.entry(name).and_modify(|c| *c += 1).or_insert(1);
            }
            SyscallItem::Complete(syscall) => {
                log::trace!("{syscall:?}");
                stats
                    .entry(syscall.name.clone())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
                let name = syscall.name.as_str();

                if let Some(handler) = SYSCALL_MAP.get(name) {
                    handler
                        .handle(syscall.as_ref(), &mut actions, &mut program_state)
                        .with_context(|| format!("Failed to summarize syscall {syscall:?}"))?;
                }
            }
        }
    }

    // Almost free optimization
    actions.dedup();

    // Create single action with all syscalls for efficient handling of seccomp filters
    actions.push(ProgramAction::Syscalls(stats.keys().cloned().collect()));

    // Directories in PATH env var need to be accessible, otherwise systemd errors
    actions.extend(env_paths.iter().cloned().map(ProgramAction::Read));

    // Report stats
    if log::log_enabled!(log::Level::Debug) {
        let mut syscall_names = stats.keys().collect::<Vec<_>>();
        syscall_names.sort_unstable();
        for syscall_name in syscall_names {
            #[expect(clippy::unwrap_used)]
            let count = stats.get(syscall_name).unwrap();
            log::debug!("{:24} {: >12}", format!("{syscall_name}:"), count);
        }
    }

    Ok(actions)
}

#[cfg(test)]
pub(crate) fn program_state() -> ProgramState {
    ProgramState::new("/", false)
}
