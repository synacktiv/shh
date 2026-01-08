//! Integration tests that ensure we successfully profile complex executions
//! We only check it returns successfully, which covers both strace output parsing
//! and the summary that follows

#![expect(clippy::tests_outside_test_module)]

use assert_cmd::{assert::OutputAssertExt as _, cargo::cargo_bin_cmd};
use predicates::prelude::predicate;

#[test]
#[cfg_attr(
    not(feature = "int-tests-gimp"),
    ignore = "int-tests-gimp feature not enabled"
)]

fn run_gimp() {

    cargo_bin_cmd!("shh")
        .args(["run", "--", "xvfb-run", "timeout", "10", "gimp"])
        .unwrap()
        .assert()
        .success()
        .stdout(
            predicate::str::contains("-------- Start of suggested service options --------\n")
                .count(1),
        )
        .stdout(
            predicate::str::contains("-------- End of suggested service options --------\n")
                .count(1),
        );
}
