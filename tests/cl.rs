//! Command line tests

use assert_cmd::{assert::OutputAssertExt, Command};
use predicates::prelude::*;

//
// Important: these tests assume they are run from a dir under /home, so we don't test for ProtectHome=xxx
// option values, because they are affected by that.
// See test_resolve_protect_home for unit test covering that option.
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
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @io-event @ipc @keyring @memlock @module @mount @network-io @obsolete @pkey @privileged @process @raw-io @reboot @resources @sandbox @setuid @signal @swap @sync @timer\n").count(1));
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
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @io-event @ipc @keyring @memlock @module @mount @network-io @obsolete @pkey @privileged @process @raw-io @reboot @resources @sandbox @setuid @swap @sync @timer\n").count(1));
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
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=").not())
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @io-event @ipc @keyring @memlock @module @mount @network-io @obsolete @pkey @privileged @process @raw-io @reboot @resources @sandbox @setuid @signal @swap @sync @timer\n").count(1));
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
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=").not())
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @io-event @ipc @keyring @memlock @module @mount @network-io @obsolete @pkey @privileged @process @raw-io @reboot @resources @sandbox @setuid @signal @swap @sync @timer\n").count(1));
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
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=").not())
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @io-event @ipc @keyring @memlock @module @mount @network-io @obsolete @pkey @privileged @process @raw-io @reboot @resources @sandbox @setuid @signal @swap @sync @timer\n").count(1));
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
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=").not())
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @io-event @ipc @keyring @memlock @module @mount @network-io @obsolete @pkey @privileged @process @raw-io @reboot @resources @sandbox @setuid @signal @swap @sync @timer\n").count(1));
}

#[test]
#[ignore] // needs to be run as root
fn run_dmesg() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "dmesg"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=").not())
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=").not())
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=none\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @io-event @ipc @keyring @memlock @module @mount @network-io @obsolete @pkey @privileged @process @raw-io @reboot @resources @sandbox @setuid @signal @swap @sync @timer\n").count(1));
}

#[test]
fn run_systemctl() {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .args(["run", "--", "systemctl", "--user"])
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("ProtectSystem=strict\n").count(1))
        .stdout(predicate::str::contains("ProtectHome=read-only\n").count(1))
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=ptraceable\n").count(1))
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_UNIX\n").count(1))
        .stdout(predicates::boolean::OrPredicate::new(
            predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @ipc @keyring @memlock @module @mount @obsolete @pkey @privileged @raw-io @reboot @resources @sandbox @setuid @swap @sync @timer\n").count(1),
            predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @io-event @ipc @keyring @memlock @module @mount @obsolete @pkey @privileged @raw-io @reboot @resources @sandbox @setuid @swap @sync @timer\n").count(1),
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
        .stdout(predicate::str::contains("PrivateTmp=true\n").count(1))
        .stdout(predicate::str::contains("PrivateDevices=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelTunables=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelModules=true\n").count(1))
        .stdout(predicate::str::contains("ProtectKernelLogs=true\n").count(1))
        .stdout(predicate::str::contains("ProtectControlGroups=true\n").count(1))
        .stdout(predicate::str::contains("ProtectProc=").not())
        .stdout(predicate::str::contains("RestrictAddressFamilies=AF_NETLINK AF_UNIX\n").count(1))
        .stdout(predicate::str::contains("SystemCallFilter=~@aio @chown @clock @cpu-emulation @debug @io-event @ipc @keyring @memlock @module @mount @obsolete @pkey @privileged @raw-io @reboot @resources @sandbox @setuid @signal @swap @sync @timer\n").count(1));
}
