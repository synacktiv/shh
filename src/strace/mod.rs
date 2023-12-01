//! Strace related code

use std::collections::HashMap;
use std::fmt;
use std::io::BufRead;
use std::process::Command;
use std::str;

mod parser;
mod run;

pub use run::Strace;

#[derive(Debug, Clone, PartialEq)]
pub struct Syscall {
    pub pid: u32,
    pub rel_ts: f64,
    pub name: String,
    pub args: Vec<SyscallArg>,
    pub ret_val: SyscallRetVal,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BufferType {
    AbstractPath,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyscallArg {
    Buffer {
        value: Vec<u8>,
        type_: BufferType,
    },
    Integer {
        value: IntegerExpression,
        metadata: Option<Vec<u8>>,
    },
    Struct(HashMap<String, SyscallArg>),
    Array(Vec<SyscallArg>),
    Macro {
        name: String,
        args: Vec<SyscallArg>,
    },
}

impl SyscallArg {
    pub fn metadata(&self) -> Option<&[u8]> {
        match self {
            Self::Integer { metadata, .. } => metadata.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IntegerExpression {
    BinaryNot(Box<IntegerExpression>),
    BinaryOr(Vec<IntegerExpression>),
    Multiplication(Vec<IntegerExpression>),
    LeftBitShift {
        bits: Box<IntegerExpression>,
        shift: Box<IntegerExpression>,
    },
    NamedConst(String),
    Literal(i128), // allows holding both signed and unsigned 64 bit integers
}

impl IntegerExpression {
    pub fn is_flag_set(&self, flag: &str) -> bool {
        match self {
            IntegerExpression::NamedConst(v) => flag == v,
            IntegerExpression::BinaryOr(ces) => ces.iter().any(|ce| ce.is_flag_set(flag)),
            IntegerExpression::BinaryNot(ce) => !ce.is_flag_set(flag),
            _ => false, // if it was a flag field, strace would have decoded it with named consts
        }
    }

    pub fn flags(&self) -> Vec<String> {
        match self {
            IntegerExpression::NamedConst(v) => vec![v.clone()],
            IntegerExpression::BinaryOr(vs) => vs.iter().flat_map(|v| v.flags()).collect(),
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
