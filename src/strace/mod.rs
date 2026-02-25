//! Strace related code

use std::{collections::HashMap, fmt, io::BufRead as _, process::Command, str};

mod parser;
mod run;

use nix::libc::pid_t;
pub(crate) use run::Strace;

const STRACE_BIN: &str = if let Some(p) = option_env!("SHH_STRACE_BIN_PATH") {
    p
} else {
    "strace"
};

pub(crate) type SyscallName = ecow::EcoString;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct Syscall {
    pub pid: pid_t,
    pub rel_ts: f64,
    pub name: SyscallName,
    pub args: Vec<Expression>,
    pub ret_val: IntegerExpression,
}

impl Syscall {
    pub(crate) fn is_successful_or_pending(&self) -> bool {
        // Strace `--successful-only` argument can make us miss interesting stuff,
        // so identify "successful" syscalls with our own logic

        /// Errors codes considered as "successful"
        /// They are 2 cases in which we allow this:
        /// - The code means "pending", and the operation can be waited for with another syscall,
        ///   for example `connect` can return `EINPROGRESS` "error", and successful connect completion
        ///   can then be waited for with `epoll`
        /// - The operation is idempotent, and the code means "already done", for example `open`
        ///   with `O_EXCL|O_CREAT` flags that returns EEXIST error
        const SUCCESSFUL_ERRNO_VALUES: [&str; 4] =
            ["EAGAIN", "EEXIST", "EINPROGRESS", "EWOULDBLOCK"];

        self.ret_val.value().is_some_and(|v| v != -1)
            || self
                .ret_val
                .metadata
                .as_ref()
                .and_then(|m| str::from_utf8(m).ok())
                .is_some_and(|m| SUCCESSFUL_ERRNO_VALUES.iter().any(|e| m.starts_with(e)))
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) enum BufferType {
    AbstractPath,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct IntegerExpression {
    pub value: IntegerExpressionValue,
    pub metadata: Option<Vec<u8>>,
}

impl IntegerExpression {
    pub(crate) fn value(&self) -> Option<i64> {
        self.value.value()
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct BufferExpression {
    pub value: Vec<u8>,
    pub type_: BufferType,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) enum Expression {
    Buffer(BufferExpression),
    MacAddress([u8; 6]),
    Integer(IntegerExpression),
    Struct(HashMap<String, Expression>),
    // The strace syntax can be ambiguous between array and set (ie sigset_t in sigprocmask),
    // so store both in this, and let the summary interpret
    Collection {
        complement: bool,
        // First element of tuple is index if explicitly set
        values: Vec<(Option<IntegerExpression>, Expression)>,
    },
    // Only used for strace pseudo macro invocations, see `test_macro_addr_arg` for an example
    DestinationAddress(String),
}

impl Expression {
    pub(crate) fn metadata(&self) -> Option<&[u8]> {
        match self {
            Self::Integer(IntegerExpression { metadata, .. }) => metadata.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) enum IntegerExpressionValue {
    BinaryOr(Vec<IntegerExpressionValue>),
    BooleanAnd(Vec<IntegerExpressionValue>),
    Equality(Vec<IntegerExpressionValue>),
    LeftBitShift {
        bits: Box<IntegerExpressionValue>,
        shift: Box<IntegerExpressionValue>,
    },
    Literal(i64),
    Macro {
        name: String,
        args: Vec<Expression>,
    },
    Multiplication(Vec<IntegerExpressionValue>),
    NamedSymbol(String),
    Substraction(Vec<IntegerExpressionValue>),
}

impl IntegerExpressionValue {
    pub(crate) fn is_flag_set(&self, flag: &str) -> bool {
        match self {
            IntegerExpressionValue::NamedSymbol(v) => flag == v,
            IntegerExpressionValue::BinaryOr(ces) => ces.iter().any(|ce| ce.is_flag_set(flag)),
            _ => false, // if it was a flag field, strace would have decoded it with named consts
        }
    }

    pub(crate) fn flags(&self) -> Vec<String> {
        match self {
            IntegerExpressionValue::NamedSymbol(v) => vec![v.clone()],
            IntegerExpressionValue::BinaryOr(vs) => {
                vs.iter().flat_map(IntegerExpressionValue::flags).collect()
            }
            _ => vec![],
        }
    }

    pub(crate) fn value(&self) -> Option<i64> {
        match self {
            IntegerExpressionValue::BinaryOr(values) => values
                .iter()
                .map(Self::value)
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .reduce(|a, b| a | b),
            IntegerExpressionValue::BooleanAnd(values) => values
                .iter()
                .map(Self::value)
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .reduce(|a, b| i64::from((a != 0) && (b != 0))),
            IntegerExpressionValue::Equality(values) => values
                .iter()
                .map(Self::value)
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .reduce(|a, b| i64::from(a == b)),
            IntegerExpressionValue::LeftBitShift { bits, shift } => {
                Some(bits.value()? << shift.value()?)
            }
            IntegerExpressionValue::Literal(v) => Some(*v),
            IntegerExpressionValue::NamedSymbol(_) | IntegerExpressionValue::Macro { .. } => None,
            IntegerExpressionValue::Multiplication(values) => values
                .iter()
                .map(Self::value)
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .reduce(|a, b| a * b),
            IntegerExpressionValue::Substraction(values) => values
                .iter()
                .map(Self::value)
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .reduce(|a, b| a - b),
        }
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct StraceVersion {
    pub major: u16,
    pub minor: u16,
}

impl StraceVersion {
    pub(crate) fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub(crate) fn local_system() -> anyhow::Result<Self> {
        let output = Command::new(STRACE_BIN).arg("--version").output()?;
        anyhow::ensure!(
            output.status.success(),
            "strace invocation failed with code {:?}",
            output.status
        );
        let version_line = output
            .stdout
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Unable to get strace version"))??;
        let (major, minor) = version_line
            .rsplit_once(' ')
            .ok_or_else(|| anyhow::anyhow!("Unable to get strace version"))?
            .1
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("Unable to get strace version"))?;
        Ok(Self {
            major: major.parse()?,
            minor: minor.parse()?,
        })
    }
}

impl fmt::Display for StraceVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[cfg(all(feature = "nightly", test))]
#[expect(clippy::tests_outside_test_module)]
mod benchs {
    extern crate test;

    use std::{collections::HashMap, hash::Hash, ops::Deref};

    use test::Bencher;

    /// 32 most common syscall names from a 180MB gimp startup strace log
    const SC_NAMES: [&str; 32] = [
        "sched_yield",
        "futex",
        "read",
        "mmap",
        "openat",
        "close",
        "recvmsg",
        "fstat",
        "mprotect",
        "newfstatat",
        "rt_sigprocmask",
        "ppoll",
        "write",
        "poll",
        "epoll_ctl",
        "munmap",
        "access",
        "prctl",
        "statx",
        "set_robust_list",
        "rseq",
        "brk",
        "clone3",
        "madvise",
        "lseek",
        "fcntl",
        "writev",
        "rt_sigaction",
        "readlink",
        "recvfrom",
        "timerfd_settime",
        "epoll_pwait",
    ];

    /// Generic benchmark exercising Syscall.name field operations
    /// (creation, clone, comparison, `HashMap` keying)
    /// as done in the summarize path
    fn bench_syscall_name<S>(b: &mut Bencher)
    where
        S: Clone + Eq + Hash + Deref<Target = str> + for<'a> From<&'a str>,
    {
        b.iter(|| {
            // Simulate what summarize() does: create names, clone into HashMap, compare
            let mut stats: HashMap<S, u64> = HashMap::new();
            for _ in 0..1000 {
                for sc_name in &SC_NAMES {
                    // Simulate parser creating the name (From<&str>)
                    let sc_name: S = test::black_box(*sc_name).into();

                    // Simulate HashMap entry (clone + hash + eq)
                    stats
                        .entry(sc_name.clone())
                        .and_modify(|c| *c += 1)
                        .or_insert(1);

                    // Simulate handler lookup (deref + eq)
                    let _ = test::black_box(&*sc_name == "connect");

                    // Simulate ends_with check (like mprotect handler)
                    let _ = test::black_box(sc_name.ends_with("mprotect"));

                    // Simulate sc_name clone into action (like handlers do)
                    let _cloned = test::black_box(sc_name.clone());
                }
            }
            test::black_box(&stats);
        });
    }

    #[bench]
    fn bench_syscall_name_std_string(b: &mut Bencher) {
        bench_syscall_name::<String>(b);
    }

    #[bench]
    fn bench_syscall_name_compact_str(b: &mut Bencher) {
        bench_syscall_name::<compact_str::CompactString>(b);
    }

    #[bench]
    fn bench_syscall_name_smol_str(b: &mut Bencher) {
        bench_syscall_name::<smol_str::SmolStr>(b);
    }

    #[bench]
    fn bench_syscall_name_ecow(b: &mut Bencher) {
        bench_syscall_name::<ecow::EcoString>(b);
    }

    /// Representative integer values from strace output that fit in i64:
    /// - small return values (0, -1, 3)
    /// - errno-like negative values (-11, -38)
    /// - medium values (flags, modes: 0o100644, 0x80000)
    /// - large pointer-like values from mmap (0x7f2fce8dc000)
    /// - `i64::MAX`
    const INT_VALUES: [i64; 14] = [
        0,
        -1,
        1,
        3,
        -11,
        -38,
        0o10_0644,
        0x80000,
        4096,
        0x7fff,
        0x0010_0000,
        0x7f2f_ce8d_c000,
        0x7f2b_44c3_31a8_0001, // large epoll data
        i64::MAX,
    ];

    /// Benchmark integer literal operations using i128:
    /// (creation, clone, comparison, arithmetic, conversion)
    /// as done in the parsing and summarize paths
    #[bench]
    fn bench_int_literal_i128(b: &mut Bencher) {
        let values: Vec<i128> = INT_VALUES.iter().map(|v| i128::from(*v)).collect();
        b.iter(|| {
            for _ in 0..1000 {
                for val in &values {
                    let v = test::black_box(*val);
                    let v2 = test::black_box(v);

                    // Comparison with -1 (is_successful_or_pending)
                    let _ = test::black_box(v != -1);
                    // Comparison with 0 (BooleanAnd logic)
                    let _ = test::black_box(v != 0);
                    // Bitwise OR (BinaryOr variant)
                    let _ = test::black_box(v | v2);
                    // Subtraction (Substraction variant)
                    let _ = test::black_box(v - v2);
                    // Multiplication (Multiplication variant)
                    let _ = test::black_box(v * v2);
                    // Conversion (as done in handlers via try_from)
                    let _ = test::black_box(i32::try_from(v));
                    let _ = test::black_box(u16::try_from(v));
                }
            }
        });
    }

    /// Benchmark integer literal operations using i64
    #[bench]
    fn bench_int_literal_i64(b: &mut Bencher) {
        let values: Vec<i64> = INT_VALUES.to_vec();
        b.iter(|| {
            for _ in 0..1000 {
                for val in &values {
                    let v = test::black_box(*val);
                    let v2 = test::black_box(v);

                    // Comparison with -1 (is_successful_or_pending)
                    let _ = test::black_box(v != -1);
                    // Comparison with 0 (BooleanAnd logic)
                    let _ = test::black_box(v != 0);
                    // Bitwise OR (BinaryOr variant)
                    let _ = test::black_box(v | v2);
                    // Subtraction (Substraction variant)
                    let _ = test::black_box(v - v2);
                    // Multiplication (Multiplication variant)
                    let _ = test::black_box(v * v2);
                    // Conversion (as done in handlers via try_from)
                    let _ = test::black_box(i32::try_from(v));
                    let _ = test::black_box(u16::try_from(v));
                }
            }
        });
    }
}
