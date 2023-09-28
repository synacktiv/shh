//! Command line tests

use std::env;

use nix::unistd::Uid;

use assert_cmd::{assert::OutputAssertExt, Command};
use predicates::prelude::*;

//
// Important: these tests have expectations strongly linked to the the environment they run on.
// For example binary may run lib from ${RUSTUP_HOME}/toolchains/stable-x86_64-unknown-linux-gnu/lib/
// Hence, they are not truly portabe, and are conditionnaly enabled using feature flags or runtime
// tests.
//

#[test]
fn run_true() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "true"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains(
            if Uid::effective().is_root() {
                "ProtectHome=tmpfs\n"
            } else {
                "ProtectHome=read-only\n"
            }
        ).count(1))
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            predicate::str::contains("PrivateTmp=true\n").count(0)
        } else {
            predicate::str::contains("PrivateTmp=true\n").count(1)
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1));
}

#[test]
fn run_write_dev_null() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "sh", "-c", ": > /dev/null"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains(
            if Uid::effective().is_root() && !env::current_exe().unwrap().starts_with("/home") {
                "ProtectHome=tmpfs\n"
            } else {
                "ProtectHome=read-only\n"
            }
        ).count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            predicate::str::contains("PrivateTmp=true\n").count(0)
        } else {
            predicate::str::contains("PrivateTmp=true\n").count(1)
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1));
}

#[test]
fn run_ls_dev() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "ls", "/dev"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains(
            if Uid::effective().is_root() {
                "ProtectHome=tmpfs\n"
            } else {
                "ProtectHome=read-only\n"
            }
        ).count(1))
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp")  {
            predicate::str::contains("PrivateTmp=true\n").count(0)
        } else {
            predicate::str::contains("PrivateTmp=true\n").count(1)
        })
        .stdout(predicate::str::contains("PrivateDevices=").not())
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1));
}

#[test]
fn run_ls_proc() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "ls", "/proc/1/"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains(
            if Uid::effective().is_root() {
                "ProtectHome=tmpfs\n"
            } else {
                "ProtectHome=read-only\n"
            }
        ).count(1))
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            predicate::str::contains("PrivateTmp=true\n").count(0)
        } else {
            predicate::str::contains("PrivateTmp=true\n").count(1)
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=").not())
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1));
}

#[test]
fn run_read_kallsyms() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "head", "/proc/kallsyms"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains(
            if Uid::effective().is_root() {
                "ProtectHome=tmpfs\n"
            } else {
                "ProtectHome=read-only\n"
            }
        ).count(1))
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            predicate::str::contains("PrivateTmp=true\n").count(0)
        } else {
            predicate::str::contains("PrivateTmp=true\n").count(1)
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=").not())
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1));
}

#[test]
fn run_ls_modules() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "ls", "/usr/lib/modules/"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains(
            if Uid::effective().is_root() {
                "ProtectHome=tmpfs\n"
            } else {
                "ProtectHome=read-only\n"
            }
        ).count(1))
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            predicate::str::contains("PrivateTmp=true\n").count(0)
        } else {
            predicate::str::contains("PrivateTmp=true\n").count(1)
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=").not())
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1));
}

#[test]
#[cfg_attr(not(feature = "as-root"), ignore)]
fn run_dmesg() {
    assert!(Uid::effective().is_root());
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "dmesg"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("ProtectHome=tmpfs\n").count(1))
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=").not())
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=").not())
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1));
}

#[test]
#[cfg_attr(feature = "as-root", ignore)]
fn run_systemctl() {
    assert!(!Uid::effective().is_root());
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "systemctl", "--user"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("ProtectHome=read-only\n").count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            predicate::str::contains("PrivateTmp=true\n").count(0)
        } else {
            predicate::str::contains("PrivateTmp=true\n").count(1)
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_UNIX\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicates::boolean::OrPredicate::new(
            predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1),
            predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1),
        ));
}

#[test]
fn run_ss() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "ss", "-l"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains(
            if Uid::effective().is_root() {
                "ProtectHome=tmpfs\n"
            } else {
                "ProtectHome=read-only\n"
            }
        ).count(1))
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            predicate::str::contains("PrivateTmp=true\n").count(0)
        } else {
            predicate::str::contains("PrivateTmp=true\n").count(1)
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=").not())
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_NETLINK AF_UNIX\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1));
}

#[test]
fn run_mmap_wx() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "python3", "-c", "import mmap, os, tempfile; f = tempfile.NamedTemporaryFile(\"wb\"); f.write(os.urandom(16)); f.flush(); mmap.mmap(f.file.fileno(), 0, prot=mmap.PROT_WRITE|mmap.PROT_EXEC)"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=full\n").count(1))
        .stdout(predicate::str::contains("ProtectHome=read-only\n").count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            predicate::str::contains("PrivateTmp=true\n").count(0)
        } else {
            predicate::str::contains("PrivateTmp=true\n").count(1)
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=\n").not())
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1));
}
