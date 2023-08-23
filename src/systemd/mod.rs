//! Systemd code

mod options;
mod resolver;
mod service;
mod version;

pub use options::build_options;
pub use resolver::resolve;
pub use service::Service;
pub use version::{KernelVersion, SystemdVersion};

const START_OPTION_OUTPUT_SNIPPET: &str = "-------- Start of suggested service options --------";
const END_OPTION_OUTPUT_SNIPPET: &str = "-------- End of suggested service options --------";

pub fn report_options(opts: Vec<options::OptionWithValue>) {
    // Report (not through logging facility because we may need to parse it back from service logs)
    println!("{}", START_OPTION_OUTPUT_SNIPPET);
    for opt in opts {
        println!("{opt}");
    }
    println!("{}", END_OPTION_OUTPUT_SNIPPET);
}
