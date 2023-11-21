# SHH (Systemd Hardening Helper)

Automatic [systemd](https://systemd.io/) service hardening guided by [strace](https://strace.io/) profiling.

See [this article](https://www.synacktiv.com/publications/systemd-hardening-made-easy-with-shh) for an introduction.

## Installation

### From source

You need a Rust build environment for example from [rustup](https://rustup.rs/).

```
cargo build --release
install -Dm 755 -t /usr/local/bin target/release/shh
```

### Debian

See [GitHub releases](https://github.com/synacktiv/shh/releases) for Debian packages built for each tagged version.

## Usage

To harden a system unit named `SERVICE.service`:

1. Start service profiling: `shh service start-profile SERVICE`. The service will be restarted with strace profiling.
2. Use the service normally for a while, trying to cover as much features and use cases as possible.
3. Run `shh service finish-profile SERVICE -a`. The service will be restarted with a hardened configuration built from previous runtime profiling, to allow it to run safely as was observed during the profiling period, and to deny other dangerous system actions.

Run `shh -h` for full command line reference, or append `-h` to a subcommand to get help.

Services running in per-user instances of the service manager (controlled via `systemctl --user ...`) are **not** supported.

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0-standalone.html)
