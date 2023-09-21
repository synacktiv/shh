//! Strace output parser

use std::collections::HashMap;
use std::io::BufRead;
use std::str;

use lazy_static::lazy_static;

use crate::strace::{BufferType, IntegerExpression, Syscall, SyscallArg, SyscallRetVal};

pub struct LogParser {
    reader: Box<dyn BufRead>,
    buf: String,
    unfinished_syscalls: Vec<Syscall>,
}

impl LogParser {
    pub fn new(reader: Box<dyn BufRead>) -> anyhow::Result<Self> {
        Ok(Self {
            reader,
            buf: String::new(),
            unfinished_syscalls: Vec::new(),
        })
    }
}

#[derive(Debug, PartialEq)]
enum ParseResult {
    /// This line was ignored
    /// (strace sometimes outputs complete garbage like '1008333      0.000045 ???( <unfinished ...>')
    IgnoredLine,
    /// This line describes an unfinished syscall
    UnfinishedSyscall(Syscall),
    /// This line describes a previously unfinished syscall that is now finished
    FinishedSyscall {
        sc: Syscall,
        unfinished_index: usize,
    },
    /// This line describes a complete syscall
    Syscall(Syscall),
}

// See also:
// - https://github.com/rbtcollins/strace-parse.rs/blob/master/src/lib.rs for a nom based parsing approach
// - https://github.com/wookietreiber/strace-analyzer/blob/master/src/analysis.rs for a "1 regex per syscall" approach

lazy_static! {
    static ref LINE_REGEX: regex::Regex = regex::RegexBuilder::new(
        r"
^
(?<pid>[0-9]+)\ +
(?<rel_ts>[0-9]+\.[0-9]+)\ +
(
    (
        (?<name>[a-z0-9_]+)
        \(
        (?<arguments>.+)?
    )
    |
    (
        <\.{3}\ 
        (?<name_resumed>[a-z0-9_]+)
        \ resumed>\ 
    )
)
(
    (

        \)
        \ +=\ 
        (
            (
                0x
                (?<ret_val_hex>[a-f0-9]+)
            )
            |
            (
                (?<ret_val_int>[-0-9]+)
                (
                    <
                    (?<ret_val_metadata>[^>]+)
                    >
                    (
                        # (deleted)
                        \(
                        [^\)]+
                        \)
                    )?
                )?
            )
        )
        (
            (\ E[A-Z]+\ \(.*\)) # errno
            |
            (\ \(.*\)) # interpretation like 'Timeout'
        )?
    )
    |
    (?<unfinished>\ <unfinished\ \.{3}>)
)
$
"
    )
    .ignore_whitespace(true)
    .build()
    .unwrap();
    static ref ARG_REGEX: regex::Regex = regex::RegexBuilder::new(
        r#"
(
    (
        (?<macro>
            [a-zA-Z0-9_]+
            \(
            [^\)]+
            \)
        )
    )
    |
    (
        (?<multiplication>
            [0-9x]+
            (
                \*
                [0-9x]+
            )+
        )
    )
    |
    (
        (?<int>[-0-9]+)
        (
            <
            (?<int_metadata>[^>]+)
            >
            (
                # (deleted)
                \(
                [^\)]+
                \)
            )?
        )?
        (\ \/\*\ [A-Za-z0-9_\-\ \+\.\:\?]+\ \*\/)?
    )
    |
    (
        0x
        (?<int_hex>[a-f0-9]+)
        (\ \/\*\ [A-Za-z0-9_\-\ \+\.\:\?]+ \*\/)?
    )
    |
    (
        \[
        (?<array>.+)
        \]
    )
    |
    (
        (?<const_expr>[A-Z_|~\[\]\ 0-9<]+)
        (
            <
            (?<const_expr_metadata>[^>]+)
            >
        )?
    )
    |
    (
        \{
        (?<struct>
            (
                [a-z0-9_]+=
                (
                    ([^\{]+)
                    |
                    (\{[^\{]*\})
                )
                ,\ 
            )*
            (
                (
                    [a-z0-9_]+=
                    (
                        ([^\{]+)
                        |
                        (\{[^\{]*\})
                    )
                )
                |
                \.{3}
            )?
        )
        \}
    )
    |
    (
        (?<buf_abstract_path>@)?
        "
        (?<buf>[^"]*)
        "
    )
)
(
    (,\ )
    |
    [\}\]]
    |
    $
)
"#
    )
    .ignore_whitespace(true)
    .build()
    .unwrap();
    static ref BYTE_REGEX: regex::bytes::Regex =
        regex::bytes::Regex::new(r"\\x[0-9a-f]{2}").unwrap();
}

fn parse_buffer(s: &str) -> anyhow::Result<Vec<u8>> {
    // Parse and replace '\x12' escaped bytes
    let buf = BYTE_REGEX
        .replace_all(s.as_bytes(), |cap: &regex::bytes::Captures| {
            let byte_match = cap.get(0).unwrap().as_bytes();
            let byte = u8::from_str_radix(str::from_utf8(&byte_match[2..]).unwrap(), 16).unwrap();
            vec![byte]
        })
        .into_owned();
    Ok(buf)
}

fn parse_argument(caps: &regex::Captures) -> anyhow::Result<SyscallArg> {
    if let Some(int) = caps.name("int") {
        let metadata = caps
            .name("int_metadata")
            .map(|m| parse_buffer(m.as_str()))
            .map_or(Ok(None), |v| v.map(Some))?;
        Ok(SyscallArg::Integer {
            value: IntegerExpression::Literal(int.as_str().parse()?),
            metadata,
        })
    } else if let Some(hex) = caps.name("int_hex") {
        Ok(SyscallArg::Integer {
            value: IntegerExpression::Literal(i128::from_str_radix(hex.as_str(), 16)?),
            metadata: None,
        })
    } else if let Some(const_) = caps.name("const_expr") {
        // If you read this and are scared by the incomplete expression grammar parsing, lack of generic recursion, etc.:
        // don't be, what strace outputs is actually limited to a few simple cases (or'ed flags, const, mask...)
        let const_str = const_.as_str();
        if const_str.starts_with('~') {
            assert!(!const_str.contains('|'));
            assert_eq!(const_str.chars().nth(1), Some('['));
            assert_eq!(const_str.chars().last(), Some(']'));
            let name = const_str[2..const_str.len() - 1]
                .rsplit(' ')
                .next()
                .unwrap()
                .to_string();
            Ok(SyscallArg::Integer {
                value: IntegerExpression::BinaryNot(Box::new(IntegerExpression::NamedConst(name))),
                metadata: None,
            })
        } else {
            let tokens = const_str.split('|').collect::<Vec<_>>();
            if tokens.len() == 1 {
                let metadata = caps
                    .name("const_expr_metadata")
                    .map(|m| parse_buffer(m.as_str()))
                    .map_or(Ok(None), |v| v.map(Some))?;
                Ok(SyscallArg::Integer {
                    value: IntegerExpression::NamedConst(tokens[0].to_string()),
                    metadata,
                })
            } else {
                let int_tokens = tokens
                    .into_iter()
                    .map(|t| {
                        if let Some(one_shift) = t.strip_prefix("1<<") {
                            IntegerExpression::LeftBitShift {
                                bits: Box::new(IntegerExpression::Literal(1)),
                                shift: Box::new(IntegerExpression::NamedConst(
                                    one_shift.to_string(),
                                )),
                            }
                        } else {
                            IntegerExpression::NamedConst(t.to_string())
                        }
                    })
                    .collect();
                Ok(SyscallArg::Integer {
                    value: IntegerExpression::BinaryOr(int_tokens),
                    metadata: None,
                })
            }
        }
    } else if let Some(struct_) = caps.name("struct") {
        let mut members = HashMap::new();
        let mut struct_ = struct_.as_str().to_string();
        while !struct_.is_empty() {
            // dbg!(&struct_);
            if struct_ == "..." {
                // This should not append with our strace options, but still does, strace bug?
                log::warn!("Truncated structure in strace output");
                break;
            }
            let (k, v) = struct_
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("Unable to extract struct member name"))?;
            // dbg!(&k);
            // dbg!(&v);
            let caps = ARG_REGEX
                .captures(v)
                .ok_or_else(|| anyhow::anyhow!("Unable to parse struct member value"))?;
            let v = parse_argument(&caps)?;
            // dbg!(&v);
            members.insert(k.to_string(), v);
            struct_ = struct_[k.len() + 1 + caps.get(0).unwrap().len()..struct_.len()].to_string();
        }
        Ok(SyscallArg::Struct(members))
    } else if let Some(array) = caps.name("array") {
        let members = ARG_REGEX
            .captures_iter(array.as_str())
            .map(|a| parse_argument(&a))
            .collect::<Result<_, _>>()?;
        Ok(SyscallArg::Array(members))
    } else if let Some(buf) = caps.name("buf") {
        let buf = parse_buffer(buf.as_str())?;
        let type_ = if caps.name("buf_abstract_path").is_some() {
            BufferType::AbstractPath
        } else {
            BufferType::Unknown
        };
        Ok(SyscallArg::Buffer { value: buf, type_ })
    } else if let Some(macro_) = caps.name("macro") {
        let (name, args) = macro_.as_str().split_once('(').unwrap();
        let args = args[..args.len() - 1].to_string();
        let args = ARG_REGEX
            .captures_iter(&args)
            .map(|a| parse_argument(&a))
            .collect::<Result<_, _>>()?;
        Ok(SyscallArg::Macro {
            name: name.to_string(),
            args,
        })
    } else if let Some(multiplication) = caps.name("multiplication") {
        let args = multiplication
            .as_str()
            .split('*')
            .map(|a| -> anyhow::Result<IntegerExpression> {
                let arg = ARG_REGEX
                    .captures(a)
                    .ok_or_else(|| anyhow::anyhow!("Unexpected multiplication argument {a:?}"))?;
                match parse_argument(&arg)? {
                    SyscallArg::Integer { value, .. } => Ok(value),
                    _ => Err(anyhow::anyhow!("Unexpected multiplication argument {a:?}")),
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(SyscallArg::Integer {
            value: IntegerExpression::Multiplication(args),
            metadata: None,
        })
    } else {
        unreachable!("Argument has no group match")
    }
}

fn parse_line(line: &str, unfinished_syscalls: &[Syscall]) -> anyhow::Result<ParseResult> {
    match LINE_REGEX.captures(line) {
        Some(caps) => {
            let pid = caps
                .name("pid")
                .unwrap()
                .as_str()
                .parse()
                .map_err(|e| anyhow::Error::new(e).context("Failed to parse pid"))?;

            let rel_ts = caps
                .name("rel_ts")
                .unwrap()
                .as_str()
                .parse()
                .map_err(|e| anyhow::Error::new(e).context("Failed to parse timestamp"))?;

            if let Some(name) = caps.name("name") {
                let name = name.as_str().to_string();

                let args = if let Some(arguments) = caps.name("arguments") {
                    ARG_REGEX
                        .captures_iter(arguments.as_str())
                        .map(|a| parse_argument(&a))
                        .collect::<Result<_, _>>()?
                } else {
                    Vec::new()
                };

                let ret_val = if let Some(ret_val_int) = caps.name("ret_val_int") {
                    let s = ret_val_int.as_str();
                    s.parse().map_err(|e| {
                        anyhow::Error::new(e)
                            .context(format!("Failed to parse integer return value: {s:?}"))
                    })?
                } else if let Some(ret_val_hex) = caps.name("ret_val_hex") {
                    let s = ret_val_hex.as_str();
                    SyscallRetVal::from_str_radix(s, 16).map_err(|e| {
                        anyhow::Error::new(e)
                            .context(format!("Failed to parse hexadecimal return value: {s:?}"))
                    })?
                } else if caps.name("unfinished").is_some() {
                    return Ok(ParseResult::UnfinishedSyscall(Syscall {
                        pid,
                        rel_ts,
                        name,
                        args,
                        ret_val: SyscallRetVal::MAX, // Set dummy value we will replace
                    }));
                } else {
                    unreachable!();
                };

                let sc = Syscall {
                    pid,
                    rel_ts,
                    name,
                    args,
                    ret_val,
                };
                Ok(ParseResult::Syscall(sc))
            } else if let Some(name_resumed) = caps.name("name_resumed").map(|c| c.as_str()) {
                let ret_val = if let Some(ret_val_int) = caps.name("ret_val_int") {
                    let s = ret_val_int.as_str();
                    s.parse().map_err(|e| {
                        anyhow::Error::new(e)
                            .context(format!("Failed to parse integer return value: {s:?}"))
                    })?
                } else if let Some(ret_val_hex) = caps.name("ret_val_hex") {
                    let s = ret_val_hex.as_str();
                    SyscallRetVal::from_str_radix(s, 16).map_err(|e| {
                        anyhow::Error::new(e)
                            .context(format!("Failed to parse hexadecimal return value: {s:?}"))
                    })?
                } else {
                    unreachable!();
                };

                let (unfinished_index, unfinished_sc) = unfinished_syscalls
                    .iter()
                    .enumerate()
                    .find(|(_i, sc)| (sc.name == name_resumed) && (sc.pid == pid))
                    .ok_or_else(|| anyhow::anyhow!("Unabled to find first part of syscall"))?;
                let sc = Syscall {
                    // Update return val and timestamp (to get return time instead of call time)
                    ret_val,
                    rel_ts,
                    ..unfinished_sc.clone()
                };
                Ok(ParseResult::FinishedSyscall {
                    sc,
                    unfinished_index,
                })
            } else {
                unreachable!();
            }
        }
        None => Ok(ParseResult::IgnoredLine),
    }
}

impl Iterator for LogParser {
    type Item = anyhow::Result<Syscall>;

    /// Parse strace output lines and yield syscalls
    /// Ignore invalid lines, but bubble up errors if the regex matches and we fail subsequent parsing
    fn next(&mut self) -> Option<Self::Item> {
        let sc = loop {
            self.buf.clear();
            let line = match self.reader.read_line(&mut self.buf) {
                Ok(0) => return None, // EOF
                Ok(_) => self.buf.trim_end(),
                Err(e) => return Some(Err(anyhow::Error::new(e).context("Failed to read line"))),
            };

            if line.ends_with(" +++") || line.ends_with(" ---") {
                // Process exited, or signal received, not a syscall
                continue;
            }

            match parse_line(line, &self.unfinished_syscalls) {
                Ok(ParseResult::Syscall(sc)) => {
                    log::trace!("Parsed line: {line:?}");
                    break sc;
                }
                Ok(ParseResult::UnfinishedSyscall(sc)) => {
                    self.unfinished_syscalls.push(sc);
                    continue;
                }
                Ok(ParseResult::FinishedSyscall {
                    sc,
                    unfinished_index,
                }) => {
                    self.unfinished_syscalls.swap_remove(unfinished_index); // I fucking love Rust <3
                    break sc;
                }
                Ok(ParseResult::IgnoredLine) => {
                    log::warn!("Ignored line: {line:?}");
                    continue;
                }
                Err(e) => {
                    log::error!("Failed to parse line: {line:?}");
                    return Some(Err(e));
                }
            };
        };
        Some(Ok(sc))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Cursor;

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_mmap() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "382944      0.000054 mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f52a332e000",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 382944,
                rel_ts: 0.000054,
                name: "mmap".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("NULL".to_string()),
                        metadata: None,
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(8192),
                        metadata: None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::BinaryOr(vec![
                            IntegerExpression::NamedConst("PROT_READ".to_string()),
                            IntegerExpression::NamedConst("PROT_WRITE".to_string()),
                        ]),
                        metadata: None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::BinaryOr(vec![
                            IntegerExpression::NamedConst("MAP_PRIVATE".to_string()),
                            IntegerExpression::NamedConst("MAP_ANONYMOUS".to_string()),
                        ]),
                        metadata:None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(-1),
                        metadata: None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(0),
                        metadata: None
                    },

                ],
                ret_val: 0x7f52a332e000
            })
        );

        assert_eq!(
            parse_line(
                "601646      0.000011 mmap(0x7f2fce8dc000, 1396736, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x26000) = 0x7f2fce8dc000",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 601646,
                rel_ts: 0.000011,
                name: "mmap".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(0x7f2fce8dc000),
                        metadata: None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(1396736),
                        metadata: None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::BinaryOr(vec![
                            IntegerExpression::NamedConst("PROT_READ".to_string()),
                            IntegerExpression::NamedConst("PROT_EXEC".to_string()),
                        ]),
                        metadata: None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::BinaryOr(vec![
                            IntegerExpression::NamedConst("MAP_PRIVATE".to_string()),
                            IntegerExpression::NamedConst("MAP_FIXED".to_string()),
                            IntegerExpression::NamedConst("MAP_DENYWRITE".to_string()),
                        ]),
                        metadata: None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(3),
                        metadata: None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(0x26000),
                        metadata: None
                    },
                ],
                ret_val: 0x7f2fce8dc000
            })
        );
    }

    #[test]
    fn test_access() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "382944      0.000036 access(\"/etc/ld.so.preload\", R_OK) = -1 ENOENT (No such file or directory)",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 382944,
                rel_ts: 0.000036,
                name: "access".to_string(),
                args: vec![
                    SyscallArg::Buffer {
                        value: "/etc/ld.so.preload".as_bytes().to_vec(),
                        type_: BufferType::Unknown
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("R_OK".to_string()),
                        metadata: None,
                    },
                ],
                ret_val: -1
            })
        );
    }

    #[test]
    fn test_rt_sigaction() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "720313      0.000064 rt_sigaction(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7f6da716c510}, NULL, 8) = 0",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 720313,
                rel_ts: 0.000064,
                name: "rt_sigaction".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("SIGTERM".to_string()),
                        metadata: None,
                    },
                    SyscallArg::Struct(HashMap::from([
                        (
                            "sa_handler".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::NamedConst("SIG_DFL".to_string()),
                                metadata: None,
                            },
                        ),
                        (
                            "sa_mask".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::BinaryNot(Box::new(IntegerExpression::NamedConst("RT_1".to_string()))),
                                metadata: None,
                            },
                        ),
                        (
                            "sa_flags".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::NamedConst("SA_RESTORER".to_string()),
                                metadata: None,
                            },
                        ),
                        (
                            "sa_restorer".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(0x7f6da716c510),
                                metadata: None
                            },
                        ),
                    ])),
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("NULL".to_string()),
                        metadata: None,
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(8),
                        metadata: None
                    },
                ],
                ret_val: 0
            })
        );
    }

    #[test]
    fn test_newfstatat() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "772627      0.000010 newfstatat(AT_FDCWD, \"/a/path\", {st_dev=makedev(0xfd, 0x1), st_ino=26427782, st_mode=S_IFDIR|0755, st_nlink=2, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=112, st_size=53248, st_atime=1689948680 /* 2023-07-21T16:11:20.028467954+0200 */, st_atime_nsec=28467954, st_mtime=1692975712 /* 2023-08-25T17:01:52.252908565+0200 */, st_mtime_nsec=252908565, st_ctime=1692975712 /* 2023-08-25T17:01:52.252908565+0200 */, st_ctime_nsec=252908565}, 0) = 0",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 772627,
                rel_ts: 0.000010,
                name: "newfstatat".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("AT_FDCWD".to_string()),
                        metadata: None,
                    },
                    SyscallArg::Buffer {
                        value: "/a/path".as_bytes().to_vec(),
                        type_: BufferType::Unknown
                    },
                    SyscallArg::Struct(HashMap::from([
                        (
                            "st_dev".to_string(),
                            SyscallArg::Macro {
                                name: "makedev".to_string(),
                                args: vec![
                                    SyscallArg::Integer {
                                        value: IntegerExpression::Literal(0xfd),
                                        metadata: None,
                                    },
                                    SyscallArg::Integer {
                                        value: IntegerExpression::Literal(1),
                                        metadata: None,
                                    },
                                ],
                            },
                        ),
                        (
                            "st_ino".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(26427782),
                                metadata: None
                            },
                        ),
                        (
                            "st_mode".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::BinaryOr(vec![
                                    IntegerExpression::NamedConst("S_IFDIR".to_string()),
                                    IntegerExpression::NamedConst("0755".to_string())
                                ]),
                                metadata: None,
                            },
                        ),
                        (
                            "st_nlink".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(2),
                                metadata: None
                            },
                        ),
                        (
                            "st_uid".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(1000),
                                metadata: None
                            },
                        ),
                        (
                            "st_gid".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(1000),
                                metadata: None
                            },
                        ),
                        (
                            "st_blksize".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(4096),
                                metadata: None
                            },
                        ),
                        (
                            "st_blocks".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(112),
                                metadata: None
                            },
                        ),
                        (
                            "st_size".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(53248),
                                metadata: None
                            },
                        ),
                        (
                            "st_atime".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(1689948680),
                                metadata: None
                            },
                        ),
                        (
                            "st_atime_nsec".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(28467954),
                                metadata: None
                            },
                        ),
                        (
                            "st_mtime".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(1692975712),
                                metadata: None
                            },
                        ),
                        (
                            "st_mtime_nsec".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(252908565),
                                metadata: None
                            },
                        ),
                        (
                            "st_ctime".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(1692975712),
                                metadata: None
                            },
                        ),
                        (
                            "st_ctime_nsec".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(252908565),
                                metadata: None
                            },
                        ),
                    ])),
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(0),
                        metadata: None
                    },
                ],
                ret_val: 0
            })
        );
    }

    #[test]
    fn test_getrandom() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "815537      0.000017 getrandom(\"\\x42\\x18\\x81\\x90\\x40\\x63\\x1a\\x2c\", 8, GRND_NONBLOCK) = 8",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 815537,
                rel_ts: 0.000017,
                name: "getrandom".to_string(),
                args: vec![
                    SyscallArg::Buffer {
                        value: vec![0x42, 0x18, 0x81, 0x90, 0x40, 0x63, 0x1a, 0x2c],
                        type_: BufferType::Unknown
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(8),
                        metadata: None
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("GRND_NONBLOCK".to_string()),
                        metadata: None,
                    },
                ],
                ret_val: 8
            })
        );
    }

    #[test]
    fn test_fstatfs() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "244841      0.000033 fstatfs(6, {f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=231830864, f_bfree=38594207, f_bavail=26799417, f_files=58957824, f_ffree=54942232, f_fsid={val=[0x511787a8, 0x92a74a52]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOATIME}) = 0",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 244841,
                rel_ts: 0.000033,
                name: "fstatfs".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(6),
                        metadata: None
                    },
                    SyscallArg::Struct(HashMap::from([
                        (
                            "f_type".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::NamedConst("EXT2_SUPER_MAGIC".to_string()),
                                metadata: None,
                            },
                        ),
                        (
                            "f_bsize".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(4096),
                                metadata: None
                            },
                        ),
                        (
                            "f_blocks".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(231830864),
                                metadata: None
                            },
                        ),
                        (
                            "f_bfree".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(38594207),
                                metadata: None
                            },
                        ),
                        (
                            "f_bavail".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(26799417),
                                metadata: None
                            },
                        ),
                        (
                            "f_files".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(58957824),
                                metadata: None
                            },
                        ),
                        (
                            "f_ffree".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(54942232),
                                metadata: None
                            },
                        ),
                        (
                            "f_fsid".to_string(),
                            SyscallArg::Struct(HashMap::from([
                                (
                                    "val".to_string(),
                                    SyscallArg::Array(vec![
                                        SyscallArg::Integer {
                                            value: IntegerExpression::Literal(1360496552),
                                            metadata: None
                                        },
                                        SyscallArg::Integer {
                                            value: IntegerExpression::Literal(2460437074),
                                            metadata: None
                                        },
                                    ])
                                )
                            ]))
                        ),
                        (
                            "f_namelen".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(255),
                                metadata: None
                            },
                        ),
                        (
                            "f_frsize".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(4096),
                                metadata: None
                            },
                        ),
                        (
                            "f_flags".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::BinaryOr(vec![
                                    IntegerExpression::NamedConst("ST_VALID".to_string()),
                                    IntegerExpression::NamedConst("ST_NOATIME".to_string())
                                ]),
                                metadata: None,
                            },
                        ),
                    ]))
                ],
                ret_val: 0
            })
        );

        assert_eq!(
            parse_line(
                "895683      0.000028 fstatfs(3, {f_type=PROC_SUPER_MAGIC, f_bsize=4096, f_blocks=0, f_bfree=0, f_bavail=0, f_files=0, f_ffree=0, f_fsid={val=[0, 0]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NODEV|ST_NOEXEC|ST_RELATIME}) = 0",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 895683,
                rel_ts: 0.000028,
                name: "fstatfs".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(3),
                        metadata: None
                    },
                    SyscallArg::Struct(HashMap::from([
                        (
                            "f_type".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::NamedConst("PROC_SUPER_MAGIC".to_string()),
                                metadata: None,
                            },
                        ),
                        (
                            "f_bsize".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(4096),
                                metadata: None
                            },
                        ),
                        (
                            "f_blocks".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(0),
                                metadata: None
                            },
                        ),
                        (
                            "f_bfree".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(0),
                                metadata: None
                            },
                        ),
                        (
                            "f_bavail".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(0),
                                metadata: None
                            },
                        ),
                        (
                            "f_files".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(0),
                                metadata: None
                            },
                        ),
                        (
                            "f_ffree".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(0),
                                metadata: None
                            },
                        ),
                        (
                            "f_fsid".to_string(),
                            SyscallArg::Struct(HashMap::from([
                                (
                                    "val".to_string(),
                                    SyscallArg::Array(vec![
                                        SyscallArg::Integer {
                                            value: IntegerExpression::Literal(0),
                                            metadata: None
                                        },
                                        SyscallArg::Integer {
                                            value: IntegerExpression::Literal(0),
                                            metadata: None
                                        },
                                    ])
                                )
                            ]))
                        ),
                        (
                            "f_namelen".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(255),
                                metadata: None
                            },
                        ),
                        (
                            "f_frsize".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(4096),
                                metadata: None
                            },
                        ),
                        (
                            "f_flags".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::BinaryOr(vec![
                                    IntegerExpression::NamedConst("ST_VALID".to_string()),
                                    IntegerExpression::NamedConst("ST_NOSUID".to_string()),
                                    IntegerExpression::NamedConst("ST_NODEV".to_string()),
                                    IntegerExpression::NamedConst("ST_NOEXEC".to_string()),
                                    IntegerExpression::NamedConst("ST_RELATIME".to_string())
                                ]),
                                metadata: None,
                            },
                        ),
                    ]))
                ],
                ret_val: 0
            })
        );
    }

    #[test]
    fn test_open_relative() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "998518      0.000033 openat(AT_FDCWD<\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x64\\x65\\x2f\\x73\\x72\\x63\\x2f\\x73\\x68\\x68>, \"\\x2e\\x2e\", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3<\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x64\\x65\\x2f\\x73\\x72\\x63>",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 998518,
                rel_ts: 0.000033,
                name: "openat".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("AT_FDCWD".to_string()),
                        metadata: Some(vec![0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x6d, 0x64, 0x65, 0x2f, 0x73, 0x72, 0x63, 0x2f, 0x73, 0x68, 0x68]),
                    },
                    SyscallArg::Buffer {
                        value: vec![0x2e, 0x2e],
                        type_: BufferType::Unknown,
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::BinaryOr(vec![
                            IntegerExpression::NamedConst("O_RDONLY".to_string()),
                            IntegerExpression::NamedConst("O_NONBLOCK".to_string()),
                            IntegerExpression::NamedConst("O_CLOEXEC".to_string()),
                            IntegerExpression::NamedConst("O_DIRECTORY".to_string())
                        ]),
                        metadata: None,
                    },
                ],
                ret_val: 3
            })
        );
    }

    #[test]
    fn test_truncated() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "28707      0.000194 sendto(15<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x35\\x34\\x31\\x38\\x32\\x31\\x33\\x5d>, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1694010548, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 28707,
                rel_ts: 0.000194,
                name: "sendto".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(15),
                        metadata: Some(vec![115, 111, 99, 107, 101, 116, 58, 91, 53, 52, 49, 56, 50, 49, 51, 93])
                    },
                    SyscallArg::Array(vec![
                        SyscallArg::Struct(HashMap::from([
                            (
                                "nlmsg_len".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::Literal(20),
                                    metadata: None,
                                },
                            ),
                            (
                                "nlmsg_type".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::NamedConst("RTM_GETADDR".to_string()),
                                    metadata: None,
                                },
                            ),
                            (
                                "nlmsg_flags".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::BinaryOr(vec![
                                        IntegerExpression::NamedConst("NLM_F_REQUEST".to_string()),
                                        IntegerExpression::NamedConst("NLM_F_DUMP".to_string()),
                                    ]),
                                    metadata: None,
                                },
                            ),
                            (
                                "nlmsg_seq".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::Literal(1694010548),
                                    metadata: None,
                                },
                            ),
                            (
                                "nlmsg_pid".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::Literal(0),
                                    metadata: None,
                                },
                            ),
                        ])),
                        SyscallArg::Struct(HashMap::from([
                            (
                                "ifa_family".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::NamedConst("AF_UNSPEC".to_string()),
                                    metadata: None,
                                },
                            ),
                        ])),
                    ]),
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(20),
                        metadata: None,
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(0),
                        metadata: None,
                    },
                    SyscallArg::Struct(HashMap::from([
                        (
                            "sa_family".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::NamedConst("AF_NETLINK".to_string()),
                                metadata: None,
                            },
                        ),
                        (
                            "nl_pid".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(0),
                                metadata: None,
                            },
                        ),
                        (
                            "nl_groups".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Literal(0),
                                metadata: None,
                            },
                        ),
                    ])),
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(12),
                        metadata: None,
                    },
                ],
                ret_val: 20
            })
        );
    }

    #[test]
    fn test_bind() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "688129      0.000023 bind(4<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x34\\x31\\x38\\x34\\x35\\x32\\x32\\x5d>, {sa_family=AF_UNIX, sun_path=@\"\\x62\\x31\\x39\\x33\\x64\\x30\\x62\\x30\\x63\\x63\\x64\\x37\\x30\\x35\\x66\\x39\\x2f\\x62\\x75\\x73\\x2f\\x73\\x79\\x73\\x74\\x65\\x6d\\x63\\x74\\x6c\\x2f\"}, 34) = 0",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 688129,
                rel_ts: 0.000023,
                name: "bind".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(4),
                        metadata: Some("socket:[4184522]".as_bytes().to_vec())
                    },
                    SyscallArg::Struct(HashMap::from([
                        (
                            "sa_family".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::NamedConst("AF_UNIX".to_string()),
                                metadata: None,
                            },
                        ),
                        (
                            "sun_path".to_string(),
                            SyscallArg::Buffer {
                                value: "b193d0b0ccd705f9/bus/systemctl/".as_bytes().to_vec(),
                                type_: BufferType::AbstractPath,
                            },
                        ),
                    ])),
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(34),
                        metadata: None,
                    },
                ],
                ret_val: 0
            })
        );

        assert_eq!(
            parse_line(
                "132360      0.000022 bind(6<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x38\\x31\\x35\\x36\\x39\\x33\\x5d>, {sa_family=AF_INET, sin_port=htons(8025), sin_addr=inet_addr(\"\\x31\\x32\\x37\\x2e\\x30\\x2e\\x30\\x2e\\x31\")}, 16) = 0",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 132360,
                rel_ts: 0.000022,
                name: "bind".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(6),
                        metadata: Some(vec![115, 111, 99, 107, 101, 116, 58, 91, 56, 49, 53, 54, 57, 51, 93]),
                    },
                    SyscallArg::Struct(HashMap::from([
                        (
                            "sa_family".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::NamedConst("AF_INET".to_string()),
                                metadata: None,
                            },
                        ),
                        (
                            "sin_port".to_string(),
                            SyscallArg::Macro {
                                name: "htons".to_string(),
                                args: vec![
                                    SyscallArg::Integer {
                                        value: IntegerExpression::Literal(8025),
                                        metadata: None,
                                    },
                                ],
                            }
                        ),
                        (
                            "sin_addr".to_string(),
                            SyscallArg::Macro {
                                name: "inet_addr".to_string(),
                                args: vec![
                                    SyscallArg::Buffer {
                                        value: vec![49, 50, 55, 46, 48, 46, 48, 46, 49],
                                        type_: BufferType::Unknown,
                                    },
                                ],
                            }
                        ),
                    ])),
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(16),
                        metadata: None,
                    },
                ],
                ret_val: 0
            })
        );
    }

    #[test]
    fn test_multiplication() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "85195      0.000038 prlimit64(0, RLIMIT_NOFILE, {rlim_cur=512*1024, rlim_max=512*1024}, NULL) = 0",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 85195,
                rel_ts: 0.000038,
                name: "prlimit64".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(0),
                        metadata: None,
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("RLIMIT_NOFILE".to_string()),
                        metadata: None,
                    },
                    SyscallArg::Struct(HashMap::from([
                        (
                            "rlim_cur".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Multiplication(vec![
                                    IntegerExpression::Literal(512),
                                    IntegerExpression::Literal(1024),
                                ]),
                                metadata: None,
                            },
                        ),
                        (
                            "rlim_max".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::Multiplication(vec![
                                    IntegerExpression::Literal(512),
                                    IntegerExpression::Literal(1024),
                                ]),
                                metadata: None,
                            },
                        ),
                    ])),
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("NULL".to_string()),
                        metadata: None,
                    },
                ],
                ret_val: 0
            })
        );
    }

    #[test]
    fn test_epoll() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "114586      0.000075 epoll_ctl(3<\\x61\\x6e\\x6f\\x6e\\x5f\\x69\\x6e\\x6f\\x64\\x65\\x3a\\x5b\\x65\\x76\\x65\\x6e\\x74\\x70\\x6f\\x6c\\x6c\\x5d>, EPOLL_CTL_ADD, 4<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x37\\x33\\x31\\x35\\x39\\x38\\x5d>, {events=EPOLLIN, data={u32=4, u64=4}}) = 0",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 114586,
                rel_ts: 0.000075,
                name: "epoll_ctl".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(3),
                        metadata: Some(vec![97, 110, 111, 110, 95, 105, 110, 111, 100, 101, 58, 91, 101, 118, 101, 110, 116, 112, 111, 108, 108, 93]),
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("EPOLL_CTL_ADD".to_string()),
                        metadata: None,
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(4),
                        metadata: Some(vec![115, 111, 99, 107, 101, 116, 58, 91, 55, 51, 49, 53, 57, 56, 93]),
                    },
                    SyscallArg::Struct(HashMap::from([
                        (
                            "events".to_string(),
                            SyscallArg::Integer {
                                value: IntegerExpression::NamedConst("EPOLLIN".to_string()),
                                metadata: None,
                            },
                        ),
                        (
                            "data".to_string(),
                            SyscallArg::Struct(HashMap::from([
                                (
                                    "u32".to_string(),
                                    SyscallArg::Integer {
                                        value: IntegerExpression::Literal(4),
                                        metadata: None,
                                    }
                                ),
                                (
                                    "u64".to_string(),
                                    SyscallArg::Integer {
                                        value: IntegerExpression::Literal(4),
                                        metadata: None,
                                    }
                                ),
                            ]))
                        ),
                    ])),
                ],
                ret_val: 0
            })
        );

        assert_eq!(
            parse_line(
                "3487       0.000130 epoll_pwait(4<\\x61\\x6e\\x6f\\x6e\\x5f\\x69\\x6e\\x6f\\x64\\x65\\x3a\\x5b\\x65\\x76\\x65\\x6e\\x74\\x70\\x6f\\x6c\\x6c\\x5d>, [{events=EPOLLOUT, data={u32=833093633, u64=9163493471957811201}}, {events=EPOLLOUT, data={u32=800587777, u64=9163493471925305345}}], 128, 0, NULL, 0) = 2",
                &[]
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 3487,
                rel_ts: 0.000130,
                name: "epoll_pwait".to_string(),
                args: vec![
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(4),
                        metadata: Some(vec![0x61, 0x6e, 0x6f, 0x6e, 0x5f, 0x69, 0x6e, 0x6f, 0x64, 0x65, 0x3a, 0x5b, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x70, 0x6f, 0x6c, 0x6c, 0x5d]),
                    },
                    SyscallArg::Array(vec![
                        SyscallArg::Struct(HashMap::from([
                            (
                                "events".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::NamedConst("EPOLLOUT".to_string()),
                                    metadata: None,
                                },
                            ),
                            (
                                "data".to_string(),
                                SyscallArg::Struct(HashMap::from([
                                    (
                                        "u32".to_string(),
                                        SyscallArg::Integer {
                                            value: IntegerExpression::Literal(833093633),
                                            metadata: None,
                                        }
                                    ),
                                    (
                                        "u64".to_string(),
                                        SyscallArg::Integer {
                                            value: IntegerExpression::Literal(9163493471957811201),
                                            metadata: None,
                                        }
                                    ),
                                ]))
                            ),
                        ])),
                        SyscallArg::Struct(HashMap::from([
                            (
                                "events".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::NamedConst("EPOLLOUT".to_string()),
                                    metadata: None,
                                },
                            ),
                            (
                                "data".to_string(),
                                SyscallArg::Struct(HashMap::from([
                                    (
                                        "u32".to_string(),
                                        SyscallArg::Integer {
                                            value: IntegerExpression::Literal(800587777),
                                            metadata: None,
                                        }
                                    ),
                                    (
                                        "u64".to_string(),
                                        SyscallArg::Integer {
                                            value: IntegerExpression::Literal(9163493471925305345),
                                            metadata: None,
                                        }
                                    ),
                                ]))
                            ),
                        ])),
                    ]),
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(128),
                        metadata: None,
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(0),
                        metadata: None,
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::NamedConst("NULL".to_string()),
                        metadata: None,
                    },
                    SyscallArg::Integer {
                        value: IntegerExpression::Literal(0),
                        metadata: None,
                    },
                ],
                ret_val: 2
            })
        );
    }

    #[test]
    fn test_interleave() {
        let _ = simple_logger::SimpleLogger::new().init();

        let lines = Cursor::new(
            "1       0.000001 select(4, [3], NULL, NULL, NULL <unfinished ...>
2       0.000002 clock_gettime(CLOCK_REALTIME, {tv_sec=1130322148, tv_nsec=3977000}) = 0
1       0.000003 <... select resumed> )      = 1 (in [3])"
                .as_bytes()
                .to_vec(),
        );
        let parser = LogParser::new(Box::new(lines)).unwrap();
        let syscalls: Vec<Syscall> = parser.into_iter().collect::<Result<_, _>>().unwrap();

        assert_eq!(
            syscalls,
            vec![
                Syscall {
                    pid: 2,
                    rel_ts: 0.000002,
                    name: "clock_gettime".to_string(),
                    args: vec![
                        SyscallArg::Integer {
                            value: IntegerExpression::NamedConst("CLOCK_REALTIME".to_string()),
                            metadata: None,
                        },
                        SyscallArg::Struct(HashMap::from([
                            (
                                "tv_sec".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::Literal(1130322148),
                                    metadata: None,
                                },
                            ),
                            (
                                "tv_nsec".to_string(),
                                SyscallArg::Integer {
                                    value: IntegerExpression::Literal(3977000),
                                    metadata: None,
                                },
                            ),
                        ])),
                    ],
                    ret_val: 0
                },
                Syscall {
                    pid: 1,
                    rel_ts: 0.000003,
                    name: "select".to_string(),
                    args: vec![
                        SyscallArg::Integer {
                            value: IntegerExpression::Literal(4),
                            metadata: None,
                        },
                        SyscallArg::Array(vec![SyscallArg::Integer {
                            value: IntegerExpression::Literal(3),
                            metadata: None,
                        },]),
                        SyscallArg::Integer {
                            value: IntegerExpression::NamedConst("NULL".to_string()),
                            metadata: None,
                        },
                        SyscallArg::Integer {
                            value: IntegerExpression::NamedConst("NULL".to_string()),
                            metadata: None,
                        },
                        SyscallArg::Integer {
                            value: IntegerExpression::NamedConst("NULL".to_string()),
                            metadata: None,
                        },
                    ],
                    ret_val: 1
                }
            ]
        );
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchs {
    extern crate test;

    use super::*;

    use std::iter;

    use test::Bencher;

    #[bench]
    fn bench_parse_buffer(b: &mut Bencher) {
        let s = format!(
            "\"{}\"",
            iter::repeat_with(|| format!("\\x{:02x}", fastrand::u8(..)))
                .take(512)
                .collect::<Vec<_>>()
                .join("")
        );

        b.iter(|| {
            parse_buffer(&s).unwrap();
        });
    }
}
