# AGENTS.md

## Build & Test Commands

- Build: `cargo build` (release: `cargo build --release`)
- Check/Lint: `cargo clippy` (pedantic + restriction lints enabled)
- Format: `cargo fmt`
- Test: `cargo test`
- Single test: `cargo test <test_name>` (e.g., `cargo test run_true`)
- Integration tests as root: `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' cargo test --features int-tests-as-root --test '*'`

## Architecture

- **shh**: CLI tool for automatic systemd service hardening via strace profiling
- `src/main.rs`: Entry point, CLI handling
- `src/strace/`: Strace output parsing (nom-based parsers)
- `src/systemd/`: Systemd option generation and service management
- `src/summarize/`: Profiling data summarization
- `tests/`: Integration tests using `assert_cmd` and `insta` snapshots

## Code Style

- Rust 2024 edition, MSRV 1.85
- Strict Clippy: pedantic + many restriction lints (see `[lints.clippy]` in Cargo.toml)
- No `unwrap`/`expect`/`panic` in non-test code; use `anyhow` for errors
- Use `thiserror` for custom error types
- Group std imports first, then external crates, then local modules
- Prefer `log` macros for logging; no `dbg!` or `todo!`
