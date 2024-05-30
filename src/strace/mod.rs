//! Strace related code

use std::{collections::HashMap, fmt, io::BufRead, process::Command, str};

mod parser;
mod run;

pub use run::Strace;

#[derive(Debug, Clone, PartialEq)]
pub struct Syscall {
    pub pid: u32,
    pub rel_ts: f64,
    pub name: String,
    pub args: Vec<Expression>,
    pub ret_val: SyscallRetVal,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BufferType {
    AbstractPath,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntegerExpression {
    pub value: IntegerExpressionValue,
    pub metadata: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BufferExpression {
    pub value: Vec<u8>,
    pub type_: BufferType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    Buffer(BufferExpression),
    Integer(IntegerExpression),
    Struct(HashMap<String, Expression>),
    // The strace syntax can be ambiguous between array and set (ie sigset_t in sigprocmask),
    // so store both in this, and let the summary interpret
    Collection {
        complement: bool,
        values: Vec<Expression>,
    },
    Macro {
        name: String,
        args: Vec<Expression>,
    },
    // Only used for strace pseudo macro invocations, see `test_macro_addr_arg` for an example
    DestinationAddress(String),
}

impl Expression {
    pub fn metadata(&self) -> Option<&[u8]> {
        match self {
            Self::Integer(IntegerExpression { metadata, .. }) => metadata.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IntegerExpressionValue {
    BinaryOr(Vec<IntegerExpressionValue>),
    Multiplication(Vec<IntegerExpressionValue>),
    LeftBitShift {
        bits: Box<IntegerExpressionValue>,
        shift: Box<IntegerExpressionValue>,
    },
    NamedConst(String),
    Literal(i128), // allows holding both signed and unsigned 64 bit integers
}

impl IntegerExpressionValue {
    pub fn is_flag_set(&self, flag: &str) -> bool {
        match self {
            IntegerExpressionValue::NamedConst(v) => flag == v,
            IntegerExpressionValue::BinaryOr(ces) => ces.iter().any(|ce| ce.is_flag_set(flag)),
            _ => false, // if it was a flag field, strace would have decoded it with named consts
        }
    }

    pub fn flags(&self) -> Vec<String> {
        match self {
            IntegerExpressionValue::NamedConst(v) => vec![v.clone()],
            IntegerExpressionValue::BinaryOr(vs) => vs.iter().flat_map(|v| v.flags()).collect(),
            _ => vec![],
        }
    }
}

pub type SyscallRetVal = i128; // allows holding both signed and unsigned 64 bit integers

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub struct StraceVersion {
    pub major: u16,
    pub minor: u16,
}

impl StraceVersion {
    pub fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub fn local_system() -> anyhow::Result<Self> {
        let output = Command::new("strace").arg("--version").output()?;
        if !output.status.success() {
            anyhow::bail!("strace invocation failed with code {:?}", output.status);
        }
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
