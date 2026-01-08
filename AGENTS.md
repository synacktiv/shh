# AGENTS.md - SHH (Systemd Hardening Helper)

## Commands

- Build: `cargo build`
- Check/lint: `cargo clippy`
- Test all: `cargo test`
- Single test: `cargo test <test_name>` (e.g., `cargo test run_gimp`)
- Integration tests require features: `--features int-tests-as-root`, `int-tests-gimp`, `int-tests-sd-user`

## Architecture

Rust CLI tool (`shh`) for automatic systemd service hardening via strace profiling.

- `src/main.rs` - Entry point, CLI handling
- `src/cl.rs` - Command line argument definitions (clap)
- `src/strace/` - Strace output parsing (nom parser)
- `src/summarize/` - Profiling data summarization
- `src/systemd/` - Systemd option generation
- `src/sysctl.rs` - Sysctl state handling
- `tests/` - Integration tests (profile.rs, options.rs, systemd-run.rs)

## Code Style

- Rust 2024 edition, MSRV 1.85
- Strict clippy::pedantic + many restriction lints (see Cargo.toml [lints.clippy])
- No `unwrap()`/`expect()`/`panic!()` in non-test code; use `anyhow::Result`
- Max 250 lines per function; document public items with `/// doc comments`
- Use `thiserror` for custom errors; prefer explicit error handling over `.unwrap()`
