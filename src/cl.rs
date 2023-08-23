//! Command line interface

use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, clap::Subcommand)]
pub enum Action {
    /// Run a program to profile its behavior
    Run {
        /// The command line to run
        command: Vec<String>,
    },
    /// Act on a systemd service unit
    #[clap(subcommand)]
    Service(ServiceAction),
}

#[derive(Debug, clap::Subcommand)]
pub enum ServiceAction {
    /// Add fragment config to service to profile its behavior
    StartProfile {
        /// Service unit name
        service: String,
        /// Disable immediate service restart
        #[arg(short, long, default_value_t = false)]
        no_restart: bool,
    },
    /// Get profiling result and remove fragment config from service
    FinishProfile {
        /// Service unit name
        service: String,
        /// Automatically apply hardening config
        #[arg(short, long, default_value_t = false)]
        apply: bool,
        /// Disable immediate service restart
        #[arg(short, long, default_value_t = false)]
        no_restart: bool,
    },
    /// Remove profiling and/or hardening config fragments, and restart service to restore its initial state
    Reset {
        /// Service unit name
        service: String,
    },
}
