//! Strace related code

use std::collections::HashMap;

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
