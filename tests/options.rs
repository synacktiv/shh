//! Integration tests for generated options

#![expect(clippy::ignore_without_reason, clippy::tests_outside_test_module)]

use std::env;

use assert_cmd::{Command, assert::OutputAssertExt as _};
use nix::unistd::Uid;
use predicates::{BoxPredicate, prelude::*};

//
// Important: these tests have expectations strongly linked to the the environment they run on.
// For example binary may run lib from ${RUSTUP_HOME}/toolchains/stable-x86_64-unknown-linux-gnu/lib/
// Hence, they are not truly portabe, and are conditionnaly enabled using feature flags or runtime
// tests.
//

#[test]
fn run_true() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "true"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if Uid::effective().is_root() {
            BoxPredicate::new(predicate::str::contains("ProtectHome=true\n").count(1))
        } else {
            BoxPredicate::new(predicate::str::contains("ProtectHome=").not())
        })
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
fn run_write_dev_null() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "sh", "-c", ": > /dev/null"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
fn run_ls_dev() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "ls", "/dev"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if Uid::effective().is_root() {
            BoxPredicate::new(predicate::str::contains("ProtectHome=true\n").count(1))
        } else {
            BoxPredicate::new(predicate::str::contains("ProtectHome=").not())
        })
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=").not())
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
fn run_ls_proc() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "busybox", "ls", "/proc/1/"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if Uid::effective().is_root() {
            BoxPredicate::new(predicate::str::contains("ProtectHome=true\n").count(1))
        } else {
            BoxPredicate::new(predicate::str::contains("ProtectHome=").not())
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=").not())
        .stdout(predicate::str::contains("ProcSubset=pid\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "cat", "/proc/cpuinfo"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if Uid::effective().is_root() {
            BoxPredicate::new(predicate::str::contains("ProtectHome=true\n").count(1))
        } else {
            BoxPredicate::new(predicate::str::contains("ProtectHome=").not())
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=true\n").not())
        .stdout(predicate::str::contains("ProcSubset=").not())
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
fn run_read_kallsyms() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "head", "/proc/kallsyms"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if Uid::effective().is_root() {
            BoxPredicate::new(predicate::str::contains("ProtectHome=true\n").count(1))
        } else {
            BoxPredicate::new(predicate::str::contains("ProtectHome=").not())
        })
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=").not())
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
fn run_ls_modules() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "ls", "/usr/lib/modules/"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if Uid::effective().is_root() {
            BoxPredicate::new(predicate::str::contains("ProtectHome=true\n").count(1))
        } else {
            BoxPredicate::new(predicate::str::contains("ProtectHome=").not())
        })
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=").not())
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn run_dmesg() {
    assert!(Uid::effective().is_root());

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "dmesg"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("ProtectHome=true\n").count(1))
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        .stdout(predicate::str::contains("PrivateDevices=").not())
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=").not())
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_WAKE_ALARM\n").count(1));
}

#[test]
#[cfg_attr(feature = "int-tests-as-root", ignore)]
fn run_systemctl() {
    assert!(!Uid::effective().is_root());

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "systemctl", "--user"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("ProtectHome=").not())
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_UNIX\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicates::boolean::OrPredicate::new(
            predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1),
            predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1),
        ))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
fn run_ss() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "ss", "-l"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if Uid::effective().is_root() {
            BoxPredicate::new(predicate::str::contains("ProtectHome=true\n").count(1))
        } else {
            BoxPredicate::new(predicate::str::contains("ProtectHome=").not())
        })
        .stdout(if !Uid::effective().is_root() && env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=").not())
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_NETLINK AF_UNIX\n").count(1).or(predicate::str::contains("RestrictAddressFamilies=AF_NETLINK\n").count(1)))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
fn run_mmap_wx() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "python3", "-c", "import mmap; mmap.mmap(-1, 4096, prot=mmap.PROT_WRITE|mmap.PROT_EXEC)"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=\n").not())
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "python3", "-c", "import mmap; mmap.mmap(-1, 4096, prot=mmap.PROT_WRITE)"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn run_sched_realtime() {
    assert!(Uid::effective().is_root());

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "python3", "-c", "import os; os.sched_setscheduler(0, os.SCHED_RR, os.sched_param(os.sched_get_priority_min(os.SCHED_RR)))"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=").not())
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "python3", "-c", "import os; os.sched_setscheduler(0, os.SCHED_IDLE, os.sched_param(0))"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
fn run_bind() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "python3", "-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind((\"127.0.0.1\", 1234))"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=\n").not())
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_INET\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").not())
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "-f", "--", "python3", "-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind((\"127.0.0.1\", 1234))"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=\n").not())
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_INET\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindAllow=ipv4:tcp:1234\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true\n").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn run_sock_packet() {
    assert!(Uid::effective().is_root());

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "python3", "-c", "import socket; socket.socket(socket.AF_NETLINK, socket.SOCK_RAW)"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_NETLINK\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "python3", "-c", "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(if env::current_exe().unwrap().starts_with("/tmp") {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=").not())
        } else {
            BoxPredicate::new(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        })
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_PACKET\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn run_syslog() {
    assert!(Uid::effective().is_root());

    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "dmesg", "-S"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("ProtectHome=true\n").count(1))
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=").not())
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_WAKE_ALARM\n").count(1));
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn run_mknod() {
    assert!(Uid::effective().is_root());

    let tmp_dir = tempfile::tempdir().unwrap();

    let pipe_path = tmp_dir.path().join("pipe");
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "mknod", pipe_path.as_os_str().to_str().unwrap(), "p"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("ProtectHome=true\n").count(1))
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_MKNOD CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));

    let dev_path = tmp_dir.path().join("dev");
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "--", "mknod", dev_path.as_os_str().to_str().unwrap(), "b", "255", "255"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("ProtectHome=true\n").count(1))
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1).or(predicate::str::contains("PrivateTmp=disconnected\n").count(1)))
        .stdout(predicate::str::contains("PrivateDevices=").not())
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("MemoryDenyWriteExecute=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("LockPersonality=true\n").count(1))
        .stdout(predicate::str::contains("RestrictRealtime=true").count(1))
        .stdout(predicate::str::contains("ProtectClock=true\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio:EPERM @chown:EPERM @clock:EPERM @cpu-emulation:EPERM @debug:EPERM @io-event:EPERM @ipc:EPERM @keyring:EPERM @memlock:EPERM @module:EPERM @mount:EPERM @network-io:EPERM @obsolete:EPERM @pkey:EPERM @privileged:EPERM @process:EPERM @raw-io:EPERM @reboot:EPERM @resources:EPERM @sandbox:EPERM @setuid:EPERM @signal:EPERM @swap:EPERM @sync:EPERM @timer:EPERM\n").count(1))
        .stdout(predicate::str::contains("CapabilityBoundingSet=~CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN CAP_IPC_LOCK CAP_KILL CAP_NET_RAW CAP_PERFMON CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_NICE CAP_SYS_PACCT CAP_SYS_PTRACE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_WAKE_ALARM\n").count(1));
}

#[test]
fn run_ping_4() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "-f", "--", "ping", "-4", "-c", "1", "127.0.0.1"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_INET\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("IPAddressDeny=any\n").count(1))
        .stdout(predicate::str::contains("IPAddressAllow=127.0.0.1\n").count(1));
}

#[test]
fn run_ping_6() {
    Command::cargo_bin("shh")
        .unwrap()
        .args(["run", "-f", "--", "ping", "-6", "-c", "1", "::1"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("PrivateMounts=true\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_INET6\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv4:udp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:tcp\n").count(1))
        .stdout(predicate::str::contains("SocketBindDeny=ipv6:udp\n").count(1))
        .stdout(predicate::str::contains("IPAddressDeny=any\n").count(1))
        .stdout(predicate::str::contains("IPAddressAllow=::1\n").count(1));
}
