//! Systemd Hardening Helper

#![cfg_attr(all(feature = "nightly", test), feature(test))]

use std::{
    fs::{self, File},
    thread,
};

use anyhow::Context;
use clap::Parser;

mod cl;
mod strace;
mod summarize;
mod systemd;

fn sd_options(
    sd_version: &systemd::SystemdVersion,
    kernel_version: &systemd::KernelVersion,
    mode: &cl::HardeningMode,
) -> anyhow::Result<Vec<systemd::OptionDescription>> {
    let sd_opts = systemd::build_options(sd_version, kernel_version, mode);
    log::info!(
        "Enabled support for systemd options: {}",
        sd_opts
            .iter()
            .map(|o| o.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(sd_opts)
}

fn main() -> anyhow::Result<()> {
    // Init logger
    simple_logger::SimpleLogger::new()
        .with_level(if cfg!(debug_assertions) {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .env()
        .init()
        .context("Failed to setup logger")?;

    // Get versions
    let sd_version = systemd::SystemdVersion::local_system()?;
    let kernel_version = systemd::KernelVersion::local_system()?;
    let strace_version = strace::StraceVersion::local_system()?;
    log::info!("Detected versions: Systemd {sd_version}, Linux kernel {kernel_version}, strace {strace_version}");
    if strace_version < strace::StraceVersion::new(6, 4) {
        log::warn!("Strace version >=6.4 is strongly recommended, if you experience strace output parsing errors, please consider upgrading");
    }

    // Parse cl args
    let args = cl::Args::parse();

    // Handle CL args
    match args.action {
        cl::Action::Run {
            command,
            mode,
            profile_data_path,
        } => {
            // Build supported systemd options
            let sd_opts = sd_options(&sd_version, &kernel_version, &mode)?;

            // Run strace
            let cmd = command.iter().map(|a| &**a).collect::<Vec<&str>>();
            let st = strace::Strace::run(&cmd)?;

            // Start signal handling thread
            let mut signals = signal_hook::iterator::Signals::new([
                signal_hook::consts::signal::SIGINT,
                signal_hook::consts::signal::SIGQUIT,
                signal_hook::consts::signal::SIGTERM,
            ])?;
            thread::spawn(move || {
                for sig in signals.forever() {
                    // The strace, and its watched child processes already get the signal, so the iterator will stop naturally
                    log::info!("Got signal {sig:?}, ignoring");
                }
            });

            // Summarize actions
            let logs = st.log_lines()?;
            let actions = summarize::summarize(logs)?;
            log::debug!("{actions:?}");

            if let Some(profile_data_path) = profile_data_path {
                // Dump profile data
                log::info!("Writing profile data into {profile_data_path:?}...");
                let file = File::create(profile_data_path)?;
                bincode::serialize_into(file, &actions)?;
            } else {
                // Resolve
                let resolved_opts = systemd::resolve(&sd_opts, &actions)?;

                // Report
                systemd::report_options(resolved_opts);
            }
        }
        cl::Action::MergeProfileData { mode, paths } => {
            // Build supported systemd options
            let sd_opts = sd_options(&sd_version, &kernel_version, &mode)?;

            // Load and merge profile data
            let mut actions: Vec<summarize::ProgramAction> = Vec::new();
            for path in &paths {
                let file = File::open(path)?;
                let mut profile_actions: Vec<summarize::ProgramAction> =
                    bincode::deserialize_from(file)?;
                actions.append(&mut profile_actions);
            }
            log::debug!("{actions:?}");

            // Resolve
            let resolved_opts = systemd::resolve(&sd_opts, &actions)?;

            // Report
            systemd::report_options(resolved_opts);

            // Remove profile data files
            for path in paths {
                fs::remove_file(path)?;
            }
        }
        cl::Action::Service(cl::ServiceAction::StartProfile {
            service,
            mode,
            no_restart,
        }) => {
            let service = systemd::Service::new(&service);
            service.add_profile_fragment(&mode)?;
            if !no_restart {
                service.reload_unit_config()?;
                service.action("restart", false)?;
            } else {
                log::warn!("Profiling config will only be applied when systemd config is reloaded, and service restarted");
            }
        }
        cl::Action::Service(cl::ServiceAction::FinishProfile {
            service,
            apply,
            no_restart,
        }) => {
            let service = systemd::Service::new(&service);
            service.action("stop", true)?;
            service.remove_profile_fragment()?;
            let resolved_opts = service.profiling_result()?;
            log::info!(
                "Resolved systemd options: {}",
                resolved_opts
                    .iter()
                    .map(|o| format!("{o}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if apply && !resolved_opts.is_empty() {
                service.add_hardening_fragment(resolved_opts)?;
            }
            service.reload_unit_config()?;
            if !no_restart {
                service.action("start", false)?;
            }
        }
        cl::Action::Service(cl::ServiceAction::Reset { service }) => {
            let service = systemd::Service::new(&service);
            let _ = service.remove_profile_fragment();
            let _ = service.remove_hardening_fragment();
            service.reload_unit_config()?;
            service.action("try-restart", false)?;
        }
    }

    Ok(())
}
