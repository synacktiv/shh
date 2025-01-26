//! Systemd code

mod options;
mod resolver;
mod service;
mod version;

pub(crate) use options::{
    build_options, OptionDescription, OptionValue, SocketFamily, SocketProtocol,
};
pub(crate) use resolver::resolve;
pub(crate) use service::Service;
pub(crate) use version::{KernelVersion, SystemdVersion};

const START_OPTION_OUTPUT_SNIPPET: &str = "-------- Start of suggested service options --------";
const END_OPTION_OUTPUT_SNIPPET: &str = "-------- End of suggested service options --------";

pub(crate) fn report_options(opts: Vec<options::OptionWithValue<&'static str>>) {
    // Report (not through logging facility because we may need to parse it back from service logs)
    println!("{START_OPTION_OUTPUT_SNIPPET}");
    for opt in opts {
        println!("{opt}");
    }
    println!("{END_OPTION_OUTPUT_SNIPPET}");
}
