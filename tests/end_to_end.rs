//! End to end tests for the service hardening workflow

#[cfg(test)]
#[cfg(feature = "test-env-vm")]
mod tests {
    use std::{env, fs, process::Command, sync::LazyLock, time::Duration};

    use backon::{BlockingRetryable as _, ConstantBuilder};

    static ALL_SHH_RUN_OPTS: LazyLock<Vec<Vec<&'static str>>> = LazyLock::new(all_shh_run_opts);

    const HARDENING_FRAGMENT_PATH: &str = "/etc/systemd/system/caddy.service.d/zz_shh-harden.conf";

    fn shh_bin() -> String {
        env::var("CARGO_BIN_EXE_shh").unwrap_or_else(|_| env!("CARGO_BIN_EXE_shh").to_owned())
    }

    /// Generate all combinations of `shh` hardening args to test
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

    /// Generic function to check hardening workflow for a service
    fn harden_service<F>(service_name: &str, checker: F)
    where
        F: Fn(),
    {
        let bin = shh_bin();

        for shh_opts in &*ALL_SHH_RUN_OPTS {
            eprintln!("shh service option: {}", shh_opts.join(" "));

            // Start service
            let mut status = Command::new("systemctl")
                .args(["start", service_name])
                .status()
                .unwrap();
            assert!(status.success());

            // Pre check
            checker();

            // Start profiling
            status = Command::new(&bin)
                .args(["service", "start-profile", service_name])
                .args(shh_opts)
                .status()
                .unwrap();
            assert!(status.success());

            // Profiling check
            checker();

            // Finish profiling with auto-apply
            status = Command::new(&bin)
                .args(["service", "finish-profile", service_name, "-a"])
                .status()
                .unwrap();
            assert!(status.success());
            eprintln!("{}", fs::read_to_string(HARDENING_FRAGMENT_PATH).unwrap());

            // Log service status for diagnostics
            let journalctl_output = Command::new("journalctl")
                .args(["-u", service_name, "--no-pager", "-n", "50"])
                .output()
                .unwrap();
            eprintln!(
                "journalctl -u {service_name}:\n{}",
                String::from_utf8_lossy(&journalctl_output.stdout)
            );
            let systemctl_output = Command::new("systemctl")
                .args(["status", service_name])
                .output()
                .unwrap();
            eprintln!(
                "systemctl status {service_name}:\n{}",
                String::from_utf8_lossy(&systemctl_output.stdout)
            );

            // Post hardening check
            checker();

            // Reset service
            status = Command::new(&bin)
                .args(["service", "reset", "caddy"])
                .status()
                .unwrap();
            assert!(status.success());

            // Verify hardening fragment is removed
            assert!(!fs::exists(HARDENING_FRAGMENT_PATH).unwrap(),);
        }
    }

    #[test]
    fn harden_caddy() {
        fn checker() {
            let response = (|| ureq::get("http://127.0.0.1/").call())
                .retry(
                    ConstantBuilder::new()
                        .with_delay(Duration::from_millis(500))
                        .with_max_times(10),
                )
                .when(|e| {
                    matches!(
                        e,
                        ureq::Error::Io(io_err) if io_err.kind() == std::io::ErrorKind::ConnectionRefused
                    )
                })
                .call()
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
            let html = response.into_body().read_to_string().unwrap();
            assert!(html.contains("<html"));
        }
        harden_service("caddy", checker);
    }
}
