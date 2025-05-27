//! Strace output parser

use std::{
    fs::File,
    io::{self, BufRead, BufWriter, Write as _},
    path::Path,
};

use crate::strace::Syscall;

mod combinator;
use combinator::parse_line;

use super::{Expression, IntegerExpression};

pub(crate) struct LogParser {
    reader: Box<dyn BufRead>,
    log: Option<BufWriter<File>>,
    buf: String,
    unfinished_syscalls: Vec<SyscallStart>,
}

impl LogParser {
    pub(crate) fn new(reader: Box<dyn BufRead>, log_path: Option<&Path>) -> anyhow::Result<Self> {
        let log = log_path
            .map(|p| -> io::Result<_> {
                let file = File::options().create(true).append(true).open(p)?;
                Ok(BufWriter::with_capacity(64 * 1024, file))
            })
            .transpose()?;
        Ok(Self {
            reader,
            log,
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
    SyscallStart(SyscallStart),
    /// This line describes a previously unfinished syscall that is now finished
    SyscallEnd(SyscallEnd),
    /// This line describes a complete syscall
    Syscall(Syscall),
}

/// A syscall started that did not yet return
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SyscallStart {
    pub pid: u32,
    pub rel_ts: f64,
    pub name: String,
    pub args: Vec<Expression>,
}

impl SyscallStart {
    /// Merge syscall start and end to build a complete syscall invocation description
    pub(crate) fn end(self, end: &SyscallEnd) -> Syscall {
        debug_assert_eq!(self.pid, end.pid);
        debug_assert_eq!(self.name, end.name);
        Syscall {
            pid: self.pid,
            rel_ts: end.rel_ts,
            name: self.name,
            args: self.args,
            ret_val: end.ret_val.clone(),
        }
    }
}

/// A syscall that ended
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SyscallEnd {
    pub pid: u32,
    pub rel_ts: f64,
    pub name: String,
    pub ret_val: IntegerExpression,
}

impl Iterator for LogParser {
    type Item = anyhow::Result<Syscall>;

    /// Parse strace output lines and yield syscalls
    /// Ignore invalid lines, but bubble up errors if the parsing matches and we fail subsequent parsing
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

            if let Some(log) = self.log.as_mut() {
                if let Err(e) = writeln!(log, "{line}") {
                    return Some(Err(e.into()));
                }
            }

            match parse_line(line) {
                Ok(ParseResult::Syscall(sc)) => {
                    log::trace!("Parsed line: {line:?}");
                    break sc;
                }
                Ok(ParseResult::SyscallStart(sc)) => {
                    self.unfinished_syscalls.push(sc);
                }
                Ok(ParseResult::SyscallEnd(sc_end)) => {
                    let Some(unfinished_index) = self
                        .unfinished_syscalls
                        .iter()
                        .position(|sc| (sc.name == sc_end.name) && (sc.pid == sc_end.pid))
                    else {
                        log::warn!("Unable to find first part of syscall");
                        continue;
                    };
                    let sc_start = self.unfinished_syscalls.swap_remove(unfinished_index); // I fucking love Rust <3
                    break sc_start.end(&sc_end);
                }
                Ok(ParseResult::IgnoredLine) => {
                    log::warn!("Ignored line: {line:?}");
                }
                Err(e) => {
                    // Unfortunately, some versions of strace output inconsistent line format,
                    // so we have to ignore some parsing errors
                    // log::error!("Failed to parse line: {line:?}");
                    // return Some(Err(e));
                    log::warn!("Failed to parse line ({e}): {line:?}");
                }
            }
        };
        Some(Ok(sc))
    }
}

#[expect(clippy::unreadable_literal)]
#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io::Cursor};

    use pretty_assertions::assert_eq;

    use super::*;
    use crate::strace::{
        BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue,
    };

    #[test]
    fn test_mmap() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "382944      0.000054 mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f52a332e000",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 382944,
                rel_ts: 0.000054,
                name: "mmap".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("NULL".to_owned()),
                        metadata: None,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(8192),
                        metadata: None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::BinaryOr(vec![
                            IntegerExpressionValue::NamedConst("PROT_READ".to_owned()),
                            IntegerExpressionValue::NamedConst("PROT_WRITE".to_owned()),
                        ]),
                        metadata: None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::BinaryOr(vec![
                            IntegerExpressionValue::NamedConst("MAP_PRIVATE".to_owned()),
                            IntegerExpressionValue::NamedConst("MAP_ANONYMOUS".to_owned()),
                        ]),
                        metadata:None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(-1),
                        metadata: None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0),
                        metadata: None
                    }),

                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0x7f52a332e000), metadata: None }
            })
        );

        assert_eq!(
            parse_line(
                "601646      0.000011 mmap(0x7f2fce8dc000, 1396736, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x26000) = 0x7f2fce8dc000",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 601646,
                rel_ts: 0.000011,
                name: "mmap".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0x7f2fce8dc000),
                        metadata: None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(1396736),
                        metadata: None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::BinaryOr(vec![
                            IntegerExpressionValue::NamedConst("PROT_READ".to_owned()),
                            IntegerExpressionValue::NamedConst("PROT_EXEC".to_owned()),
                        ]),
                        metadata: None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::BinaryOr(vec![
                            IntegerExpressionValue::NamedConst("MAP_PRIVATE".to_owned()),
                            IntegerExpressionValue::NamedConst("MAP_FIXED".to_owned()),
                            IntegerExpressionValue::NamedConst("MAP_DENYWRITE".to_owned()),
                        ]),
                        metadata: None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(3),
                        metadata: None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0x26000),
                        metadata: None
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0x7f2fce8dc000), metadata: None }
            })
        );
    }

    #[test]
    fn test_access() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "382944      0.000036 access(\"/etc/ld.so.preload\", R_OK) = -1 ENOENT (No such file or directory)",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 382944,
                rel_ts: 0.000036,
                name: "access".to_owned(),
                args: vec![
                    Expression::Buffer(BufferExpression {
                        value: "/etc/ld.so.preload".as_bytes().to_vec(),
                        type_: BufferType::Unknown
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("R_OK".to_owned()),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(-1), metadata: None }
            })
        );
    }

    #[test]
    fn test_rt_sigaction() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "720313      0.000064 rt_sigaction(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7f6da716c510}, NULL, 8) = 0",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 720313,
                rel_ts: 0.000064,
                name: "rt_sigaction".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("SIGTERM".to_owned()),
                        metadata: None,
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "sa_handler".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("SIG_DFL".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "sa_mask".to_owned(),
                            Expression::Collection {
                                complement: true,
                                values: vec![
                                    (
                                        None,
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst("RTMIN".to_owned()), 
                                                metadata: None
                                            }
                                        )
                                    ),
                                    (
                                        None,
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst("RT_1".to_owned()), 
                                                metadata: None
                                            }
                                        )
                                    ),
                                ]
                            }
                        ),
                        (
                            "sa_flags".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("SA_RESTORER".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "sa_restorer".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0x7f6da716c510),
                                metadata: None
                            }),
                        ),
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("NULL".to_owned()),
                        metadata: None,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(8),
                        metadata: None
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }

    #[test]
    fn test_rt_sigprocmask() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line("440663      0.002174 rt_sigprocmask(SIG_SETMASK, [], ~[KILL STOP RTMIN RT_1], 8) = 0").unwrap(),
            ParseResult::Syscall(Syscall {pid: 440663,
                rel_ts: 0.002174,
                name: "rt_sigprocmask".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst(
                            "SIG_SETMASK".to_owned(),
                        ),
                        metadata: None,
                    }),
                    Expression::Collection {
                        complement: false,
                        values: vec![],
                    },
                    Expression::Collection {
                        complement: true,
                        values: vec![
                            (
                                None,
                                Expression::Integer(
                                    IntegerExpression {
                                        value: IntegerExpressionValue::NamedConst("KILL".to_owned()),
                                        metadata: None
                                    }
                                )
                            ),
                            (
                                None,
                                Expression::Integer(
                                    IntegerExpression {
                                        value: IntegerExpressionValue::NamedConst("STOP".to_owned()),
                                        metadata: None
                                    }
                                )
                            ),
                            (
                                None,
                                Expression::Integer(
                                    IntegerExpression {
                                        value: IntegerExpressionValue::NamedConst("RTMIN".to_owned()),
                                        metadata: None
                                    }
                                )
                            ),
                            (
                                None,
                                Expression::Integer(
                                    IntegerExpression {
                                        value: IntegerExpressionValue::NamedConst("RT_1".to_owned()),
                                        metadata: None
                                    }
                                )
                            ),
                        ],
                    },
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(
                            8,
                        ),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }

    #[test]
    fn test_newfstatat() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "772627      0.000010 newfstatat(AT_FDCWD, \"/a/path\", {st_dev=makedev(0xfd, 0x1), st_ino=26427782, st_mode=S_IFDIR|0755, st_nlink=2, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=112, st_size=53248, st_atime=1689948680 /* 2023-07-21T16:11:20.028467954+0200 */, st_atime_nsec=28467954, st_mtime=1692975712 /* 2023-08-25T17:01:52.252908565+0200 */, st_mtime_nsec=252908565, st_ctime=1692975712 /* 2023-08-25T17:01:52.252908565+0200 */, st_ctime_nsec=252908565}, 0) = 0",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 772627,
                rel_ts: 0.000010,
                name: "newfstatat".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("AT_FDCWD".to_owned()),
                        metadata: None,
                    }),
                    Expression::Buffer(BufferExpression {
                        value: "/a/path".as_bytes().to_vec(),
                        type_: BufferType::Unknown
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "st_dev".to_owned(),
                            Expression::Macro {
                                name: "makedev".to_owned(),
                                args: vec![
                                    Expression::Integer(IntegerExpression {
                                        value: IntegerExpressionValue::Literal(0xfd),
                                        metadata: None,
                                    }),
                                    Expression::Integer(IntegerExpression {
                                        value: IntegerExpressionValue::Literal(1),
                                        metadata: None,
                                    }),
                                ],
                            },
                        ),
                        (
                            "st_ino".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(26427782),
                                metadata: None
                            }),
                        ),
                        (
                            "st_mode".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::BinaryOr(vec![
                                    IntegerExpressionValue::NamedConst("S_IFDIR".to_owned()),
                                    IntegerExpressionValue::Literal(0o755)
                                ]),
                                metadata: None,
                            }),
                        ),
                        (
                            "st_nlink".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(2),
                                metadata: None
                            }),
                        ),
                        (
                            "st_uid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1000),
                                metadata: None
                            }),
                        ),
                        (
                            "st_gid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1000),
                                metadata: None
                            }),
                        ),
                        (
                            "st_blksize".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(4096),
                                metadata: None
                            }),
                        ),
                        (
                            "st_blocks".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(112),
                                metadata: None
                            }),
                        ),
                        (
                            "st_size".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(53248),
                                metadata: None
                            }),
                        ),
                        (
                            "st_atime".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1689948680),
                                metadata: None
                            }),
                        ),
                        (
                            "st_atime_nsec".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(28467954),
                                metadata: None
                            }),
                        ),
                        (
                            "st_mtime".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1692975712),
                                metadata: None
                            }),
                        ),
                        (
                            "st_mtime_nsec".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(252908565),
                                metadata: None
                            }),
                        ),
                        (
                            "st_ctime".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1692975712),
                                metadata: None
                            }),
                        ),
                        (
                            "st_ctime_nsec".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(252908565),
                                metadata: None
                            }),
                        ),
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0),
                        metadata: None
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }

    #[test]
    fn test_getrandom() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "815537      0.000017 getrandom(\"\\x42\\x18\\x81\\x90\\x40\\x63\\x1a\\x2c\", 8, GRND_NONBLOCK) = 8",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 815537,
                rel_ts: 0.000017,
                name: "getrandom".to_owned(),
                args: vec![
                    Expression::Buffer(BufferExpression {
                        value: vec![0x42, 0x18, 0x81, 0x90, 0x40, 0x63, 0x1a, 0x2c],
                        type_: BufferType::Unknown
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(8),
                        metadata: None
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("GRND_NONBLOCK".to_owned()),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(8), metadata: None }
            })
        );
    }

    #[test]
    fn test_fstatfs() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "244841      0.000033 fstatfs(6, {f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=231830864, f_bfree=38594207, f_bavail=26799417, f_files=58957824, f_ffree=54942232, f_fsid={val=[0x511787a8, 0x92a74a52]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOATIME}) = 0",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 244841,
                rel_ts: 0.000033,
                name: "fstatfs".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(6),
                        metadata: None
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "f_type".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("EXT2_SUPER_MAGIC".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "f_bsize".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(4096),
                                metadata: None
                            }),
                        ),
                        (
                            "f_blocks".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(231830864),
                                metadata: None
                            }),
                        ),
                        (
                            "f_bfree".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(38594207),
                                metadata: None
                            }),
                        ),
                        (
                            "f_bavail".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(26799417),
                                metadata: None
                            }),
                        ),
                        (
                            "f_files".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(58957824),
                                metadata: None
                            }),
                        ),
                        (
                            "f_ffree".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(54942232),
                                metadata: None
                            }),
                        ),
                        (
                            "f_fsid".to_owned(),
                            Expression::Struct(HashMap::from([
                                (
                                    "val".to_owned(),
                                    Expression::Collection {
                                        complement: false,
                                        values: vec![
                                            (
                                                None,
                                                Expression::Integer(IntegerExpression {
                                                    value: IntegerExpressionValue::Literal(1360496552),
                                                    metadata: None
                                                }),
                                            ),
                                            (
                                                None,
                                                Expression::Integer(IntegerExpression {
                                                    value: IntegerExpressionValue::Literal(2460437074),
                                                    metadata: None
                                                }),
                                            )
                                        ]
                                    }
                                )
                            ]))
                        ),
                        (
                            "f_namelen".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(255),
                                metadata: None
                            }),
                        ),
                        (
                            "f_frsize".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(4096),
                                metadata: None
                            }),
                        ),
                        (
                            "f_flags".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::BinaryOr(vec![
                                    IntegerExpressionValue::NamedConst("ST_VALID".to_owned()),
                                    IntegerExpressionValue::NamedConst("ST_NOATIME".to_owned())
                                ]),
                                metadata: None,
                            }),
                        ),
                    ]))
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );

        assert_eq!(
            parse_line(
                "895683      0.000028 fstatfs(3, {f_type=PROC_SUPER_MAGIC, f_bsize=4096, f_blocks=0, f_bfree=0, f_bavail=0, f_files=0, f_ffree=0, f_fsid={val=[0, 0]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NODEV|ST_NOEXEC|ST_RELATIME}) = 0",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 895683,
                rel_ts: 0.000028,
                name: "fstatfs".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(3),
                        metadata: None
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "f_type".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("PROC_SUPER_MAGIC".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "f_bsize".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(4096),
                                metadata: None
                            }),
                        ),
                        (
                            "f_blocks".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None
                            }),
                        ),
                        (
                            "f_bfree".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None
                            }),
                        ),
                        (
                            "f_bavail".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None
                            }),
                        ),
                        (
                            "f_files".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None
                            }),
                        ),
                        (
                            "f_ffree".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None
                            }),
                        ),
                        (
                            "f_fsid".to_owned(),
                            Expression::Struct(HashMap::from([
                                (
                                    "val".to_owned(),
                                    Expression::Collection {
                                        complement: false,
                                        values: vec![
                                            (
                                                None,
                                                Expression::Integer(IntegerExpression {
                                                    value: IntegerExpressionValue::Literal(0),
                                                    metadata: None
                                                }),
                                            ),
                                            (
                                                None,
                                                Expression::Integer(IntegerExpression {
                                                    value: IntegerExpressionValue::Literal(0),
                                                    metadata: None
                                                }),
                                            )
                                        ]
                                    }
                                )
                            ]))
                        ),
                        (
                            "f_namelen".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(255),
                                metadata: None
                            }),
                        ),
                        (
                            "f_frsize".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(4096),
                                metadata: None
                            }),
                        ),
                        (
                            "f_flags".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::BinaryOr(vec![
                                    IntegerExpressionValue::NamedConst("ST_VALID".to_owned()),
                                    IntegerExpressionValue::NamedConst("ST_NOSUID".to_owned()),
                                    IntegerExpressionValue::NamedConst("ST_NODEV".to_owned()),
                                    IntegerExpressionValue::NamedConst("ST_NOEXEC".to_owned()),
                                    IntegerExpressionValue::NamedConst("ST_RELATIME".to_owned())
                                ]),
                                metadata: None,
                            }),
                        ),
                    ]))
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }

    #[test]
    fn test_open_relative() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "998518      0.000033 openat(AT_FDCWD<\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x64\\x65\\x2f\\x73\\x72\\x63\\x2f\\x73\\x68\\x68>, \"\\x2e\\x2e\", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3<\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x64\\x65\\x2f\\x73\\x72\\x63>",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 998518,
                rel_ts: 0.000033,
                name: "openat".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("AT_FDCWD".to_owned()),
                        metadata: Some("/home/mde/src/shh".as_bytes().to_vec()),
                    }),
                    Expression::Buffer(BufferExpression {
                        value: "..".as_bytes().to_vec(),
                        type_: BufferType::Unknown,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::BinaryOr(vec![
                            IntegerExpressionValue::NamedConst("O_RDONLY".to_owned()),
                            IntegerExpressionValue::NamedConst("O_NONBLOCK".to_owned()),
                            IntegerExpressionValue::NamedConst("O_CLOEXEC".to_owned()),
                            IntegerExpressionValue::NamedConst("O_DIRECTORY".to_owned())
                        ]),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression {
                    value: IntegerExpressionValue::Literal(3),
                    metadata: Some("/home/mde/src".as_bytes().to_vec())
                }
            })
        );
    }

    #[test]
    fn test_truncated() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "28707      0.000194 sendto(15<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x35\\x34\\x31\\x38\\x32\\x31\\x33\\x5d>, [{nlmsg_len=20, nlmsg_type=RTM_GETADDR, nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=1694010548, nlmsg_pid=0}, {ifa_family=AF_UNSPEC, ...}], 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 28707,
                rel_ts: 0.000194,
                name: "sendto".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(15),
                        metadata: Some("socket:[5418213]".as_bytes().to_vec())
                    }),
                    Expression::Collection {
                        complement: false,
                        values: vec![
                            (
                                None,
                                Expression::Struct(HashMap::from([
                                    (
                                        "nlmsg_len".to_owned(),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::Literal(20),
                                            metadata: None,
                                        }),
                                    ),
                                    (
                                        "nlmsg_type".to_owned(),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::NamedConst("RTM_GETADDR".to_owned()),
                                            metadata: None,
                                        }),
                                    ),
                                    (
                                        "nlmsg_flags".to_owned(),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::BinaryOr(vec![
                                                IntegerExpressionValue::NamedConst("NLM_F_REQUEST".to_owned()),
                                                IntegerExpressionValue::NamedConst("NLM_F_DUMP".to_owned()),
                                            ]),
                                            metadata: None,
                                        }),
                                    ),
                                    (
                                        "nlmsg_seq".to_owned(),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::Literal(1694010548),
                                            metadata: None,
                                        }),
                                    ),
                                    (
                                        "nlmsg_pid".to_owned(),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::Literal(0),
                                            metadata: None,
                                        }),
                                    ),
                                ])),
                            ),
                            (
                                None,
                                Expression::Struct(HashMap::from([
                                    (
                                        "ifa_family".to_owned(),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::NamedConst("AF_UNSPEC".to_owned()),
                                            metadata: None,
                                        }),
                                    ),
                                ])),
                            )
                        ]
                    },
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(20),
                        metadata: None,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0),
                        metadata: None,
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "sa_family".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("AF_NETLINK".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "nl_pid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None,
                            }),
                        ),
                        (
                            "nl_groups".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None,
                            }),
                        ),
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(12),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(20), metadata: None }
            })
        );

        assert_eq!(
            parse_line("215947      0.000022 read(3, \"\\x12\\xef\"..., 832) = 832",).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 215947,
                rel_ts: 0.000022,
                name: "read".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(3),
                        metadata: None,
                    }),
                    Expression::Buffer(BufferExpression {
                        value: vec![0x12, 0xef],
                        type_: BufferType::Unknown,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(832),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression {
                    value: IntegerExpressionValue::Literal(832),
                    metadata: None
                }
            })
        );
    }

    #[test]
    fn test_invalid() {
        let _ = simple_logger::SimpleLogger::new().init();

        // Bogus output ('{{', note the missing field name) that strace 5.10 can generate
        let res = parse_line(
            "57652      0.000071 sendto(19<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x38\\x34\\x38\\x36\\x39\\x32\\x5d>, {{len=20, type=0x16 /* NLMSG_??? */, flags=NLM_F_REQUEST|0x300, seq=1697715709, pid=0}, \"\\x00\\x00\\x00\\x00\"}, 20, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 20",
        );
        assert_eq!(res.unwrap(), ParseResult::IgnoredLine);
    }

    #[test]
    fn test_bind() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "688129      0.000023 bind(4<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x34\\x31\\x38\\x34\\x35\\x32\\x32\\x5d>, {sa_family=AF_UNIX, sun_path=@\"\\x62\\x31\\x39\\x33\\x64\\x30\\x62\\x30\\x63\\x63\\x64\\x37\\x30\\x35\\x66\\x39\\x2f\\x62\\x75\\x73\\x2f\\x73\\x79\\x73\\x74\\x65\\x6d\\x63\\x74\\x6c\\x2f\"}, 34) = 0",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 688129,
                rel_ts: 0.000023,
                name: "bind".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(4),
                        metadata: Some("socket:[4184522]".as_bytes().to_vec())
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "sa_family".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("AF_UNIX".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "sun_path".to_owned(),
                            Expression::Buffer(BufferExpression {
                                value: "b193d0b0ccd705f9/bus/systemctl/".as_bytes().to_vec(),
                                type_: BufferType::AbstractPath,
                            }),
                        ),
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(34),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );

        assert_eq!(
            parse_line(
                "132360      0.000022 bind(6<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x38\\x31\\x35\\x36\\x39\\x33\\x5d>, {sa_family=AF_INET, sin_port=htons(8025), sin_addr=inet_addr(\"\\x31\\x32\\x37\\x2e\\x30\\x2e\\x30\\x2e\\x31\")}, 16) = 0",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 132360,
                rel_ts: 0.000022,
                name: "bind".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(6),
                        metadata: Some("socket:[815693]".as_bytes().to_vec()),
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "sa_family".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("AF_INET".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "sin_port".to_owned(),
                            Expression::Macro {
                                name: "htons".to_owned(),
                                args: vec![
                                    Expression::Integer(IntegerExpression {
                                        value: IntegerExpressionValue::Literal(8025),
                                        metadata: None,
                                    }),
                                ],
                            }
                        ),
                        (
                            "sin_addr".to_owned(),
                            Expression::Macro {
                                name: "inet_addr".to_owned(),
                                args: vec![
                                    Expression::Buffer(BufferExpression {
                                        value: "127.0.0.1".as_bytes().to_vec(),
                                        type_: BufferType::Unknown,
                                    }),
                                ],
                            }
                        ),
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(16),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }

    #[test]
    fn test_multiplication() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "85195      0.000038 prlimit64(0, RLIMIT_NOFILE, {rlim_cur=512*1024, rlim_max=512*1024}, NULL) = 0",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 85195,
                rel_ts: 0.000038,
                name: "prlimit64".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0),
                        metadata: None,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("RLIMIT_NOFILE".to_owned()),
                        metadata: None,
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "rlim_cur".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Multiplication(vec![
                                    IntegerExpressionValue::Literal(512),
                                    IntegerExpressionValue::Literal(1024),
                                ]),
                                metadata: None,
                            }),
                        ),
                        (
                            "rlim_max".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Multiplication(vec![
                                    IntegerExpressionValue::Literal(512),
                                    IntegerExpressionValue::Literal(1024),
                                ]),
                                metadata: None,
                            }),
                        ),
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("NULL".to_owned()),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }

    #[test]
    fn test_epoll() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "114586      0.000075 epoll_ctl(3<\\x61\\x6e\\x6f\\x6e\\x5f\\x69\\x6e\\x6f\\x64\\x65\\x3a\\x5b\\x65\\x76\\x65\\x6e\\x74\\x70\\x6f\\x6c\\x6c\\x5d>, EPOLL_CTL_ADD, 4<\\x73\\x6f\\x63\\x6b\\x65\\x74\\x3a\\x5b\\x37\\x33\\x31\\x35\\x39\\x38\\x5d>, {events=EPOLLIN, data={u32=4, u64=4}}) = 0",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 114586,
                rel_ts: 0.000075,
                name: "epoll_ctl".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(3),
                        metadata: Some("anon_inode:[eventpoll]".as_bytes().to_vec()),
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("EPOLL_CTL_ADD".to_owned()),
                        metadata: None,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(4),
                        metadata: Some("socket:[731598]".as_bytes().to_vec()),
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "events".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("EPOLLIN".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "data".to_owned(),
                            Expression::Struct(HashMap::from([
                                (
                                    "u32".to_owned(),
                                    Expression::Integer(IntegerExpression {
                                        value: IntegerExpressionValue::Literal(4),
                                        metadata: None,
                                    }),
                                ),
                                (
                                    "u64".to_owned(),
                                    Expression::Integer(IntegerExpression {
                                        value: IntegerExpressionValue::Literal(4),
                                        metadata: None,
                                    }),
                                ),
                            ]))
                        ),
                    ])),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );

        assert_eq!(
            parse_line(
                "3487       0.000130 epoll_pwait(4<\\x61\\x6e\\x6f\\x6e\\x5f\\x69\\x6e\\x6f\\x64\\x65\\x3a\\x5b\\x65\\x76\\x65\\x6e\\x74\\x70\\x6f\\x6c\\x6c\\x5d>, [{events=EPOLLOUT, data={u32=833093633, u64=9163493471957811201}}, {events=EPOLLOUT, data={u32=800587777, u64=9163493471925305345}}], 128, 0, NULL, 0) = 2",
            ).unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 3487,
                rel_ts: 0.000130,
                name: "epoll_pwait".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(4),
                        metadata: Some("anon_inode:[eventpoll]".as_bytes().to_vec()),
                    }),
                    Expression::Collection {
                        complement: false,
                            values: vec![
                            (
                                None,
                                Expression::Struct(HashMap::from([
                                    (
                                        "events".to_owned(),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::NamedConst("EPOLLOUT".to_owned()),
                                            metadata: None,
                                        }),
                                    ),
                                    (
                                        "data".to_owned(),
                                        Expression::Struct(HashMap::from([
                                            (
                                                "u32".to_owned(),
                                                Expression::Integer(IntegerExpression {
                                                    value: IntegerExpressionValue::Literal(833093633),
                                                    metadata: None,
                                                }),
                                            ),
                                            (
                                                "u64".to_owned(),
                                                Expression::Integer(IntegerExpression {
                                                    value: IntegerExpressionValue::Literal(9163493471957811201),
                                                    metadata: None,
                                                }),
                                            ),
                                        ]))
                                    ),
                                ])),
                            ),
                            (
                                None,
                                Expression::Struct(HashMap::from([
                                    (
                                        "events".to_owned(),
                                        Expression::Integer(IntegerExpression {
                                            value: IntegerExpressionValue::NamedConst("EPOLLOUT".to_owned()),
                                            metadata: None,
                                        }),
                                    ),
                                    (
                                        "data".to_owned(),
                                        Expression::Struct(HashMap::from([
                                            (
                                                "u32".to_owned(),
                                                Expression::Integer(IntegerExpression {
                                                    value: IntegerExpressionValue::Literal(800587777),
                                                    metadata: None,
                                                }),
                                            ),
                                            (
                                                "u64".to_owned(),
                                                Expression::Integer(IntegerExpression {
                                                    value: IntegerExpressionValue::Literal(9163493471925305345),
                                                    metadata: None,
                                                }),
                                            ),
                                        ]))
                                    ),
                                ])),
                            )
                        ]
                    },
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(128),
                        metadata: None,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0),
                        metadata: None,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::NamedConst("NULL".to_owned()),
                        metadata: None,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(2), metadata: None }
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
        let parser = LogParser::new(Box::new(lines), None).unwrap();
        let syscalls: Vec<Syscall> = parser.into_iter().collect::<Result<_, _>>().unwrap();

        assert_eq!(
            syscalls,
            vec![
                Syscall {
                    pid: 2,
                    rel_ts: 0.000002,
                    name: "clock_gettime".to_owned(),
                    args: vec![
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst("CLOCK_REALTIME".to_owned()),
                            metadata: None,
                        }),
                        Expression::Struct(HashMap::from([
                            (
                                "tv_sec".to_owned(),
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(1130322148),
                                    metadata: None,
                                }),
                            ),
                            (
                                "tv_nsec".to_owned(),
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(3977000),
                                    metadata: None,
                                }),
                            ),
                        ])),
                    ],
                    ret_val: IntegerExpression {
                        value: IntegerExpressionValue::Literal(0),
                        metadata: None
                    }
                },
                Syscall {
                    pid: 1,
                    rel_ts: 0.000003,
                    name: "select".to_owned(),
                    args: vec![
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::Literal(4),
                            metadata: None,
                        }),
                        Expression::Collection {
                            complement: false,
                            values: vec![(
                                None,
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(3),
                                    metadata: None,
                                })
                            )]
                        },
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst("NULL".to_owned()),
                            metadata: None,
                        }),
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst("NULL".to_owned()),
                            metadata: None,
                        }),
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst("NULL".to_owned()),
                            metadata: None,
                        }),
                    ],
                    ret_val: IntegerExpression {
                        value: IntegerExpressionValue::Literal(1),
                        metadata: None
                    }
                }
            ]
        );
    }

    #[test]
    fn test_getpid() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line("641342      0.000022 getpid()           = 641314").unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 641342,
                rel_ts: 0.000022,
                name: "getpid".to_owned(),
                args: vec![],
                ret_val: IntegerExpression {
                    value: IntegerExpressionValue::Literal(641314),
                    metadata: None
                }
            })
        );
    }

    #[test]
    fn test_close() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line("246722      0.000003 close(39<\\x2f\\x6d\\x65\\x6d\\x66\\x64\\x3a\\x6d\\x6f\\x7a\\x69\\x6c\\x6c\\x61\\x2d\\x69\\x70\\x63>(deleted)) = 0").unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 246722,
                rel_ts: 0.000003,
                name: "close".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(39),
                        metadata: Some("/memfd:mozilla-ipc".as_bytes().to_vec()),
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }

    #[test]
    fn test_sched_getaffinity() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line("231196      0.000017 sched_getaffinity(0, 512, [0 1 2 3 4 5 6 7]) = 8",)
                .unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 231196,
                rel_ts: 0.000017,
                name: "sched_getaffinity".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0),
                        metadata: None,
                    }),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(512),
                        metadata: None,
                    }),
                    Expression::Collection {
                        complement: false,
                        values: vec![
                            (
                                None,
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(0),
                                    metadata: None,
                                }),
                            ),
                            (
                                None,
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(1),
                                    metadata: None,
                                }),
                            ),
                            (
                                None,
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(2),
                                    metadata: None,
                                }),
                            ),
                            (
                                None,
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(3),
                                    metadata: None,
                                }),
                            ),
                            (
                                None,
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(4),
                                    metadata: None,
                                }),
                            ),
                            (
                                None,
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(5),
                                    metadata: None,
                                }),
                            ),
                            (
                                None,
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(6),
                                    metadata: None,
                                }),
                            ),
                            (
                                None,
                                Expression::Integer(IntegerExpression {
                                    value: IntegerExpressionValue::Literal(7),
                                    metadata: None,
                                }),
                            ),
                        ]
                    },
                ],
                ret_val: IntegerExpression {
                    value: IntegerExpressionValue::Literal(8),
                    metadata: None
                }
            })
        );
    }

    #[test]
    fn test_execve() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line("1234      0.000000 execve(\"\\x12\", [\"\\x34\"], [\"\\x56\"]) = 0",)
                .unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 1234,
                rel_ts: 0.000000,
                name: "execve".to_owned(),
                args: vec![
                    Expression::Buffer(BufferExpression {
                        value: vec![18],
                        type_: BufferType::Unknown
                    }),
                    Expression::Collection {
                        complement: false,
                        values: vec![(
                            None,
                            Expression::Buffer(BufferExpression {
                                value: vec![0x34],
                                type_: BufferType::Unknown
                            })
                        ),]
                    },
                    Expression::Collection {
                        complement: false,
                        values: vec![(
                            None,
                            Expression::Buffer(BufferExpression {
                                value: vec![0x56],
                                type_: BufferType::Unknown
                            })
                        ),]
                    },
                ],
                ret_val: IntegerExpression {
                    value: IntegerExpressionValue::Literal(0),
                    metadata: None
                }
            })
        );
    }

    #[expect(clippy::too_many_lines)]
    #[test]
    fn test_ioctl() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line("34274      0.000058 ioctl(1<\\x2f\\x64\\x65\\x76\\x2f\\x70\\x74\\x73\\x2f\\x30>, TCSETSW, {c_iflag=ICRNL|IXON|IUTF8, c_oflag=NL0|CR0|TAB0|BS0|VT0|FF0|OPOST|ONLCR, c_cflag=B38400|CS8|CREAD, c_lflag=ISIG|ICANON|ECHO|ECHOE|ECHOK|IEXTEN|ECHOCTL|ECHOKE, c_line=N_TTY, c_cc=[[VINTR]=0x3, [VQUIT]=0x1c, [VERASE]=0x7f, [VKILL]=0x15, [VEOF]=0x4, [VTIME]=0, [VMIN]=0x1, [VSWTC]=0, [VSTART]=0x11, [VSTOP]=0x13, [VSUSP]=0x1a, [VEOL]=0, [VREPRINT]=0x12, [VDISCARD]=0xf, [VWERASE]=0x17, [VLNEXT]=0x16, [VEOL2]=0, [17]=0, [18]=0]}) = 0",)
                .unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 34274,
                rel_ts: 0.000058,
                name: "ioctl".to_owned(),
                args: vec![
                    Expression::Integer(
                        IntegerExpression {
                            value: IntegerExpressionValue::Literal(
                                1,
                            ),
                            metadata: Some("/dev/pts/0".as_bytes().to_vec()),
                        },
                    ),
                    Expression::Integer(
                        IntegerExpression {
                            value: IntegerExpressionValue::NamedConst(
                                "TCSETSW".to_owned(),
                            ),
                            metadata: None,
                        },
                    ),
                    Expression::Struct(HashMap::from([
                        (
                            "c_cflag".to_owned(),
                            Expression::Integer(
                                IntegerExpression {
                                    value: IntegerExpressionValue::BinaryOr(
                                        vec![
                                            IntegerExpressionValue::NamedConst(
                                                "B38400".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "CS8".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "CREAD".to_owned(),
                                            ),
                                        ],
                                    ),
                                    metadata: None,
                                },
                            ),
                        ),
                        (
                            "c_lflag".to_owned(),
                            Expression::Integer(
                                IntegerExpression {
                                    value: IntegerExpressionValue::BinaryOr(
                                        vec![
                                            IntegerExpressionValue::NamedConst(
                                                "ISIG".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "ICANON".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "ECHO".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "ECHOE".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "ECHOK".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "IEXTEN".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "ECHOCTL".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "ECHOKE".to_owned(),
                                            ),
                                        ],
                                    ),
                                    metadata: None,
                                },
                            ),
                        ),
                        (
                            "c_cc".to_owned(),
                            Expression::Collection {
                                complement: false,
                                values: vec![
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VINTR".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    3,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VQUIT".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    28,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VERASE".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    127,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VKILL".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    21,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VEOF".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    4,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VTIME".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    0,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VMIN".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    1,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VSWTC".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    0,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VSTART".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    17,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VSTOP".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    19,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VSUSP".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    26,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VEOL".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    0,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VREPRINT".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    18,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VDISCARD".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    15,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VWERASE".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    23,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VLNEXT".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    22,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::NamedConst(
                                                    "VEOL2".to_owned(),
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    0,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    17,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    0,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                    (
                                        Some(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    18,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                        Expression::Integer(
                                            IntegerExpression {
                                                value: IntegerExpressionValue::Literal(
                                                    0,
                                                ),
                                                metadata: None,
                                            },
                                        ),
                                    ),
                                ],
                            }
                        ),
                        (
                            "c_line".to_owned(),
                            Expression::Integer(
                                IntegerExpression {
                                    value: IntegerExpressionValue::NamedConst(
                                        "N_TTY".to_owned(),
                                    ),
                                    metadata: None,
                                },
                            ),
                        ),
                        (
                            "c_oflag".to_owned(),
                            Expression::Integer(
                                IntegerExpression {
                                    value: IntegerExpressionValue::BinaryOr(
                                        vec![
                                            IntegerExpressionValue::NamedConst(
                                                "NL0".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "CR0".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "TAB0".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "BS0".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "VT0".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "FF0".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "OPOST".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "ONLCR".to_owned(),
                                            ),
                                        ],
                                    ),
                                    metadata: None,
                                },
                            ),
                        ),
                        (
                            "c_iflag".to_owned(),
                            Expression::Integer(
                                IntegerExpression {
                                    value: IntegerExpressionValue::BinaryOr(
                                        vec![
                                            IntegerExpressionValue::NamedConst(
                                                "ICRNL".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "IXON".to_owned(),
                                            ),
                                            IntegerExpressionValue::NamedConst(
                                                "IUTF8".to_owned(),
                                            ),
                                        ],
                                    ),
                                    metadata: None,
                                },
                            ),
                        ),
                    ]))
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }

    #[test]
    fn test_in_out_args() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "664767      0.000014 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f3b7c000990, parent_tid=0x7f3b7c000990, exit_signal=0, stack=0x7f3b7b800000, stack_size=0x7ff880, tls=0x7f3b7c0006c0} => {parent_tid=[664773]}, 88) = 664773",
            )
            .unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 664767,
                rel_ts: 0.000014,
                name: "clone3".to_owned(),
                args: vec![
                    Expression::Struct(HashMap::from([
                        (
                            "flags".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::BinaryOr(vec![
                                    IntegerExpressionValue::NamedConst("CLONE_VM".to_owned()),
                                    IntegerExpressionValue::NamedConst("CLONE_FS".to_owned()),
                                    IntegerExpressionValue::NamedConst("CLONE_FILES".to_owned()),
                                    IntegerExpressionValue::NamedConst("CLONE_SIGHAND".to_owned()),
                                    IntegerExpressionValue::NamedConst("CLONE_THREAD".to_owned()),
                                    IntegerExpressionValue::NamedConst("CLONE_SYSVSEM".to_owned()),
                                    IntegerExpressionValue::NamedConst("CLONE_SETTLS".to_owned()),
                                    IntegerExpressionValue::NamedConst("CLONE_PARENT_SETTID".to_owned()),
                                    IntegerExpressionValue::NamedConst("CLONE_CHILD_CLEARTID".to_owned()),
                                ]),
                                metadata: None
                            }),
                        ),
                        (
                            "child_tid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0x7f3b7c000990),
                                metadata: None,
                            }),
                        ),
                        (
                            "parent_tid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0x7f3b7c000990),
                                metadata: None,
                            }),
                        ),
                        (
                            "exit_signal".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None,
                            }),
                        ),
                        (
                            "stack".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0x7f3b7b800000),
                                metadata: None,
                            }),
                        ),
                        (
                            "stack_size".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0x7ff880),
                                metadata: None,
                            }),
                        ),
                        (
                            "tls".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0x7f3b7c0006c0),
                                metadata: None,
                            }),
                        ),
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(88),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression {
                    value: IntegerExpressionValue::Literal(664773),
                    metadata: None
                }
            })
        );

        assert_eq!(
            parse_line(
                "237494      0.000026 getpeername(3, {sa_family=AF_UNIX, sun_path=@\"nope\"}, [124 => 20]) = 0",
            )
            .unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 237494,
                rel_ts: 0.000026,
                name: "getpeername".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(3),
                        metadata: None,
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "sa_family".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("AF_UNIX".to_owned()),
                                metadata: None
                            }),
                        ),
                        (
                            "sun_path".to_owned(),
                            Expression::Buffer(BufferExpression {
                                value: "nope".as_bytes().to_vec(),
                                type_: BufferType::AbstractPath
                            }),
                        )
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(124),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );

        // Note: not a real strace line
        assert_eq!(
            parse_line(
                "176051      0.000020 recvmsg(3, {msg_namelen=128 => 16, msg_controllen=56, msg_flags=0}, 0) = 64"
            )
            .unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 176051,
                rel_ts: 0.000020,
                name: "recvmsg".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(3),
                        metadata: None,
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "msg_namelen".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(128),
                                metadata: None
                            }),
                        ),
                        (
                            "msg_controllen".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(56),
                                metadata: None
                            }),
                        ),
                        (
                            "msg_flags".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None
                            }),
                        ),
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(0),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(64), metadata: None }
            })
        );
    }

    #[test]
    fn test_named_args() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "714433      0.000035 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3f3c2f5090) = 714434",
            )
            .unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 714433,
                rel_ts: 0.000035,
                name: "clone".to_owned(),
                args: vec![
                    Expression::Struct(HashMap::from([
                        (
                            "child_stack".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("NULL".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "flags".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::BinaryOr(vec![
                                    IntegerExpressionValue::NamedConst("CLONE_CHILD_CLEARTID".to_owned()),
                                    IntegerExpressionValue::NamedConst("CLONE_CHILD_SETTID".to_owned()),
                                    IntegerExpressionValue::NamedConst("SIGCHLD".to_owned()),
                                ]),
                                metadata: None
                            }),
                        ),
                        (
                            "child_tidptr".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0x7f3f3c2f5090),
                                metadata: None,
                            }),
                        ),
                    ])),
                ],
                ret_val: IntegerExpression {
                    value: IntegerExpressionValue::Literal(714434),
                    metadata: None
                }
            })
        );
    }

    #[test]
    fn test_bitshift() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "794046      0.000024 capset({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, {effective=1<<CAP_SYS_CHROOT, permitted=1<<CAP_SYS_CHROOT, inheritable=0}) = 0",
            )
            .unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 794046,
                rel_ts: 0.000024,
                name: "capset".to_owned(),
                args: vec![
                    Expression::Struct(HashMap::from([
                        (
                            "version".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("_LINUX_CAPABILITY_VERSION_3".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "pid".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None,
                            }),
                        ),
                    ])),
                    Expression::Struct(HashMap::from([
                        (
                            "effective".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::LeftBitShift {
                                    bits: Box::new(IntegerExpressionValue::Literal(1)),
                                    shift: Box::new(IntegerExpressionValue::NamedConst("CAP_SYS_CHROOT".to_owned())),
                                },
                                metadata: None,
                            }),
                        ),
                        (
                            "permitted".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::LeftBitShift {
                                    bits: Box::new(IntegerExpressionValue::Literal(1)),
                                    shift: Box::new(IntegerExpressionValue::NamedConst("CAP_SYS_CHROOT".to_owned())),
                                },
                                metadata: None,
                            }),
                        ),
                        (
                            "inheritable".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None,
                            }),
                        ),
                    ])),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }

    #[test]
    fn test_macro_addr_arg() {
        let _ = simple_logger::SimpleLogger::new().init();

        assert_eq!(
            parse_line(
                "813299      0.000023 connect(93, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, \"\\x12\\x34\", &sin6_addr), sin6_scope_id=0}, 28) = 0",
            )
            .unwrap(),
            ParseResult::Syscall(Syscall {
                pid: 813299,
                rel_ts: 0.000023,
                name: "connect".to_owned(),
                args: vec![
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(93),
                        metadata: None,
                    }),
                    Expression::Struct(HashMap::from([
                        (
                            "sa_family".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::NamedConst("AF_INET6".to_owned()),
                                metadata: None,
                            }),
                        ),
                        (
                            "sin6_port".to_owned(),
                            Expression::Macro {
                                name: "htons".to_owned(),
                                args: vec![
                                    Expression::Integer(IntegerExpression {
                                        value: IntegerExpressionValue::Literal(0),
                                        metadata: None,
                                    }),
                                ],
                            }
                        ),
                        (
                            "sin6_flowinfo".to_owned(),
                            Expression::Macro {
                                name: "htonl".to_owned(),
                                args: vec![
                                    Expression::Integer(IntegerExpression {
                                        value: IntegerExpressionValue::Literal(0),
                                        metadata: None,
                                    }),
                                ],
                            }
                        ),
                        (
                            "sin6_addr".to_owned(),
                            Expression::Macro {
                                name: "inet_pton".to_owned(),
                                args: vec![
                                    Expression::Integer(IntegerExpression {
                                        value: IntegerExpressionValue::NamedConst("AF_INET6".to_owned()),
                                        metadata: None,
                                    }),
                                    Expression::Buffer(BufferExpression {
                                        value: vec![0x12, 0x34],
                                        type_: BufferType::Unknown
                                    }),
                                    Expression::DestinationAddress("sin6_addr".to_owned()),
                                ],
                            }
                        ),
                        (
                            "sin6_scope_id".to_owned(),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None,
                            }),
                        ),
                    ])),
                    Expression::Integer(IntegerExpression {
                        value: IntegerExpressionValue::Literal(28),
                        metadata: None,
                    }),
                ],
                ret_val: IntegerExpression { value: IntegerExpressionValue::Literal(0), metadata: None }
            })
        );
    }
}

#[cfg(all(feature = "nightly", test))]
mod benchs {
    extern crate test;

    use std::io::BufReader;

    use test::Bencher;

    use super::*;

    #[bench]
    fn bench_parse_line(b: &mut Bencher) {
        let log_path = Path::new("strace.log");
        if !log_path.is_file() {
            return;
        }
        let log_lines: Vec<_> = BufReader::new(File::open(log_path).unwrap())
            .lines()
            .take(5000)
            .collect::<Result<_, _>>()
            .unwrap();

        b.iter(|| {
            log_lines.iter().map(|l| parse_line(&l)).for_each(drop);
        });
    }
}
