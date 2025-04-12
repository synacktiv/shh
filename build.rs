//! Build script to generate syscall map

#![expect(clippy::unwrap_used)]

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::BufRead as _,
    path::Path,
    process::{Command, Stdio},
};

use const_gen::{CompileConst as _, const_declaration};

fn is_syscall_line(l: &str) -> bool {
    l.starts_with("    ") && !l.starts_with("    # ")
}

/// Ignored classes it would make no sense to backlist
const IGNORED_CLASSES: [&str; 3] = ["default", "known", "system-service"];

fn main() {
    // Run systemd-analyze to get syscall list & groups
    let output = Command::new("systemd-analyze")
        .arg("syscall-filter")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());

    // Parse output
    let mut classes: HashMap<String, HashSet<String>> = HashMap::new();
    let mut lines: Box<dyn Iterator<Item = String>> =
        Box::new(output.stdout.lines().map(Result::unwrap));
    loop {
        // Get class name
        lines = Box::new(lines.skip_while(|l| !l.starts_with('@')));
        let Some(class_name) = lines
            .next()
            .and_then(|g| g.strip_prefix('@').map(ToOwned::to_owned))
        else {
            break;
        };
        if IGNORED_CLASSES.contains(&class_name.as_str()) {
            continue;
        }

        // Get syscalls names
        lines = Box::new(lines.skip_while(|l| !is_syscall_line(l)));
        let mut group_syscalls = HashSet::new();
        for line in lines.by_ref() {
            if is_syscall_line(&line) {
                group_syscalls.insert(line.trim_start().to_owned());
            } else {
                break;
            }
        }
        classes.insert(class_name, group_syscalls);
    }

    // Write generated code
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("systemd_syscall_groups.rs");
    let const_declarations = const_declaration!(SYSCALL_CLASSES = classes);
    fs::write(&dest_path, const_declarations).unwrap();
}
