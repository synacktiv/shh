# AGENTS.md

## Build & Test Commands

- Build: `cargo build` (release: `cargo build --release`)
- Check/Lint: `cargo clippy` (pedantic + restriction lints enabled)
- Format: `cargo fmt --all`
- Test: `cargo test`
- Single test: `cargo test <test_name>`

## Architecture

- **shh**: CLI tool for automatic systemd service hardening via strace profiling
- `src/main.rs`: Entry point, CLI handling
- `src/strace/`: Strace output parsing (nom-based parsers)
- `src/systemd/`: Systemd option generation and service management
- `src/summarize/`: Profiling data summarization
- `tests/`: Integration tests using `assert_cmd` and `insta` snapshots

## Code Style

- Rust 2024 edition, MSRV 1.87
- Strict Clippy: pedantic + many restriction lints (see `[lints.clippy]` in Cargo.toml)
- No `unwrap`/`expect`/`panic` in non-test code; use `anyhow` for errors
- Use `thiserror` for custom error types
- Group std imports first, then external crates, then local modules
- Prefer `log` macros for logging; no `dbg!` or `todo!`
- Prefer `default-features = false` for dependencies.
- In tests: use `use super::*;` to import from the parent module
- In tests: prefer `unwrap()` over `expect()` for conciseness
- In tests: do not add custom messages to `assert!`/`assert_eq!`/`assert_ne!` — the test name is sufficient
- When moving or refactoring code, never remove comment lines — preserve all comments and move them along with the code they document

## Version control

- This repository uses the jujutsu VCS. **Never use any `jj` command that modifies the repository**.
- You can also use read-only git commands for inspecting repository state. **Never use any git command that modifies the repository**.
