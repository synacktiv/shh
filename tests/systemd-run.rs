//! These tests run generated options with systemd-run to ensure they are valid
//! and allow the program to execute normally

#![expect(
    clippy::ignore_without_reason,
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::unwrap_used
)]

use std::{
    env,
    fs::{self, Permissions},
    io::{BufRead as _, Write as _},
    os::unix::fs::{FileTypeExt as _, PermissionsExt as _},
    process,
    sync::LazyLock,
};

use assert_cmd::{
    Command,
    assert::{Assert, OutputAssertExt as _},
};
use predicates::prelude::predicate;

static ALL_SHH_RUN_OPTS: LazyLock<Vec<Vec<&'static str>>> = LazyLock::new(all_shh_run_opts);
const KERNEL_LOG_REGEX: &str = r"\[\ *[0-9]+\.[0-9]+\] ";

const SYSTEMD_RUN_USER: &[bool] = if cfg!(feature = "int-tests-sd-user") {
    &[false, true]
} else {
    &[false]
};

/// Run `shh run` for a given command, and return generated systemd options
fn generate_options(cmd: &[&str], run_opts: &[&str]) -> Vec<String> {
    const START_OPTION_OUTPUT_SNIPPET: &str =
        "-------- Start of suggested service options --------";
    const END_OPTION_OUTPUT_SNIPPET: &str = "-------- End of suggested service options --------";
    let output = Command::cargo_bin("shh")
        .unwrap()
        .arg("run")
        .args(run_opts)
        .arg("--")
        .args(cmd)
        .unwrap();
    let opts = output
        .stdout
        .clone()
        .lines()
        // Filter out delimiting lines while letting errors bubble up
        .skip_while(|r| {
            r.as_ref()
                .is_ok_and(|l| !l.starts_with(START_OPTION_OUTPUT_SNIPPET))
        })
        .skip(1)
        .take_while(|r| {
            r.as_ref().is_err()
                || r.as_ref()
                    .is_ok_and(|l| !l.starts_with(END_OPTION_OUTPUT_SNIPPET))
        })
        .collect::<Result<_, _>>()
        .unwrap();
    output.assert().success();
    opts
}

/// Run systemd-run for given command, with options
fn systemd_run(cmd: &[&str], sd_opts: &[String], user: bool) -> Assert {
    // TODO why do we need sudo to get output, even when already running as root through sudo wrapper?
    let mut sd_cmd = vec!["sudo".to_owned(), "systemd-run".to_owned()];
    if user {
        sd_cmd.extend([
            "--user".to_owned(),
            "-M".to_owned(),
            format!("{}@.host", env::var("SUDO_USER").unwrap()),
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
    #[expect(clippy::indexing_slicing)]
    Command::new(&sd_cmd[0])
        .args(sd_cmd)
        .unwrap()
        .assert()
        .success()
}

/// Generate all combinations of `shh run` args to test
fn all_shh_run_opts() -> Vec<Vec<&'static str>> {
    let args_mode = vec![vec![], vec!["-m", "aggressive"]];
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

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_true() {
    let cmd = ["true"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, *user);
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_write_dev_null() {
    let cmd = ["sh", "-c", ": > /dev/null"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, *user);
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_ls_dev() {
    let cmd = ["ls", "/dev/"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let asrt = systemd_run(&cmd, &sd_opts, *user);
            asrt.stdout(predicate::str::contains("block"))
                .stdout(predicate::str::contains("char"))
                .stdout(predicate::str::contains("log"));
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_ls_proc() {
    let cmd = ["ls", "/proc/1"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, *user);
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_read_kallsyms() {
    let cmd = ["head", "/proc/kallsyms"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, *user);
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_ls_modules() {
    let cmd = ["ls", "/usr/lib/modules/"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, *user);
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_dmesg() {
    let cmd = ["dmesg"];
    for shh_opts in &*ALL_SHH_RUN_OPTS {
        eprintln!("shh run option: {}", shh_opts.join(" "));
        let sd_opts = generate_options(&cmd, shh_opts);
        let asrt = systemd_run(&cmd, &sd_opts, false);
        asrt.stdout(predicate::str::is_match(KERNEL_LOG_REGEX).unwrap());
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_systemctl() {
    let cmd = ["systemctl"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, *user);
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_ss() {
    let cmd = ["ss", "-l"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, *user);
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_mmap_wx() {
    let cmd = [
        "python3",
        "-c",
        "import mmap; mmap.mmap(-1, 4096, prot=mmap.PROT_WRITE|mmap.PROT_EXEC)",
    ];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, *user);
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_sched_realtime() {
    let cmd = [
        "python3",
        "-c",
        "import os; os.sched_setscheduler(0, os.SCHED_RR, os.sched_param(os.sched_get_priority_min(os.SCHED_RR)))",
    ];
    for shh_opts in &*ALL_SHH_RUN_OPTS {
        eprintln!("shh run option: {}", shh_opts.join(" "));
        let sd_opts = generate_options(&cmd, shh_opts);
        let _ = systemd_run(&cmd, &sd_opts, false);
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_bind() {
    let cmd = [
        "python3",
        "-c",
        "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind((\"127.0.0.1\", 1234))",
    ];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let _ = systemd_run(&cmd, &sd_opts, *user);
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_sock_packet() {
    let cmd = [
        "python3",
        "-c",
        "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)",
    ];
    for shh_opts in &*ALL_SHH_RUN_OPTS {
        eprintln!("shh run option: {}", shh_opts.join(" "));
        let sd_opts = generate_options(&cmd, shh_opts);
        let _ = systemd_run(&cmd, &sd_opts, false);
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_syslog() {
    let cmd = ["dmesg", "-S"];
    for shh_opts in &*ALL_SHH_RUN_OPTS {
        eprintln!("shh run option: {}", shh_opts.join(" "));
        let sd_opts = generate_options(&cmd, shh_opts);
        let _ = systemd_run(&cmd, &sd_opts, false);
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_mknod() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let pipe_path = tmp_dir.path().join("pipe");
    let cmd = ["mknod", pipe_path.as_os_str().to_str().unwrap(), "p"];
    for shh_opts in &*ALL_SHH_RUN_OPTS {
        eprintln!("shh run option: {}", shh_opts.join(" "));
        let mut sd_opts = generate_options(&cmd, shh_opts);
        let _ = fs::remove_file(&pipe_path);

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

        let _ = systemd_run(&cmd, &sd_opts, false);
        assert!(fs::metadata(&pipe_path).unwrap().file_type().is_fifo());
        fs::remove_file(&pipe_path).unwrap();
    }

    let dev_path = tmp_dir.path().join("dev");
    let cmd = [
        "mknod",
        dev_path.as_os_str().to_str().unwrap(),
        "b",
        "255",
        "255",
    ];
    for shh_opts in &*ALL_SHH_RUN_OPTS {
        eprintln!("shh run option: {}", shh_opts.join(" "));
        let mut sd_opts = generate_options(&cmd, shh_opts);
        let _ = fs::remove_file(&dev_path);

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

        let _ = systemd_run(&cmd, &sd_opts, false);
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
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
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
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let asrt = systemd_run(&cmd, &sd_opts, *user);
            asrt.stdout(predicate::str::contains("from a script"));
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_curl() {
    let cmd = ["curl", "https://example.com"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let asrt = systemd_run(&cmd, &sd_opts, *user);
            asrt.stdout(predicate::str::contains("<html>"));
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_ping_4() {
    let cmd = ["ping", "-c", "1", "-4", "127.0.0.1"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let asrt = systemd_run(&cmd, &sd_opts, *user);
            asrt.stdout(predicate::str::contains(
                "127.0.0.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss",
            ));
        }
    }
}

#[test]
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_run_ping_6() {
    let cmd = ["ping", "-c", "1", "-6", "::1"];
    for user in SYSTEMD_RUN_USER {
        for shh_opts in &*ALL_SHH_RUN_OPTS {
            let mut shh_opts = shh_opts.clone();
            if *user {
                shh_opts.extend(["-i", "user"]);
            }
            eprintln!("shh run option: {}", shh_opts.join(" "));
            let sd_opts = generate_options(&cmd, &shh_opts);
            let asrt = systemd_run(&cmd, &sd_opts, *user);
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
#[cfg_attr(not(feature = "int-tests-as-root"), ignore)]
fn systemd_netns_create() {
    let ns = format!("t{}", rand::random::<u16>());
    let cmd = ["ip", "netns", "add", &ns];
    for shh_opts in &*ALL_SHH_RUN_OPTS {
        eprintln!("shh run option: {}", shh_opts.join(" "));
        let sd_opts = generate_options(&cmd, shh_opts);
        assert!(fs::exists(format!("/run/netns/{ns}")).unwrap());
        del_netns(&ns);
        let _ = systemd_run(&cmd, &sd_opts, false);
        assert!(fs::exists(format!("/run/netns/{ns}")).unwrap());
        del_netns(&ns);
    }
}
