//! Regex based strace output parser

use std::{collections::HashMap, str};

use lazy_static::lazy_static;

use crate::strace::{
    BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue, Syscall,
    SyscallRetVal,
};

use super::ParseResult;

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
        (?<array>[^\]]+)
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

pub fn parse_line(line: &str, unfinished_syscalls: &[Syscall]) -> anyhow::Result<ParseResult> {
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
                let name = name.as_str().to_owned();

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

fn parse_argument(caps: &regex::Captures) -> anyhow::Result<Expression> {
    if let Some(int) = caps.name("int") {
        let metadata = caps
            .name("int_metadata")
            .map(|m| parse_buffer(m.as_str()))
            .map_or(Ok(None), |v| v.map(Some))?;
        Ok(Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(int.as_str().parse()?),
            metadata,
        }))
    } else if let Some(hex) = caps.name("int_hex") {
        Ok(Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Literal(i128::from_str_radix(hex.as_str(), 16)?),
            metadata: None,
        }))
    } else if let Some(const_) = caps.name("const_expr") {
        let const_str = const_.as_str();
        if (const_str.ends_with(']')) && (const_str.starts_with('[') || const_str.starts_with("~["))
        {
            assert!(!const_str.contains('|'));
            let complement = const_str.starts_with('~');
            let values_str =
                const_str[if complement { 2 } else { 1 }..const_str.len() - 1].to_owned();
            let values = if values_str.is_empty() {
                vec![]
            } else {
                values_str
                    .split(' ')
                    .map(|v| {
                        Expression::Integer(IntegerExpression {
                            value: IntegerExpressionValue::NamedConst(v.to_owned()),
                            metadata: None,
                        })
                    })
                    .collect()
            };
            Ok(Expression::Collection { complement, values })
        } else {
            let tokens = const_str.split('|').collect::<Vec<_>>();
            if tokens.len() == 1 {
                let metadata = caps
                    .name("const_expr_metadata")
                    .map(|m| parse_buffer(m.as_str()))
                    .map_or(Ok(None), |v| v.map(Some))?;
                Ok(Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst(tokens[0].to_owned()),
                    metadata,
                }))
            } else {
                let int_tokens = tokens
                    .into_iter()
                    .map(|t| -> anyhow::Result<_> {
                        if let Some(one_shift) = t.strip_prefix("1<<") {
                            Ok(IntegerExpressionValue::LeftBitShift {
                                bits: Box::new(IntegerExpressionValue::Literal(1)),
                                shift: Box::new(IntegerExpressionValue::NamedConst(
                                    one_shift.to_owned(),
                                )),
                            })
                        } else if t.starts_with("0") {
                            Ok(IntegerExpressionValue::Literal(i128::from_str_radix(t, 8)?))
                        } else {
                            Ok(IntegerExpressionValue::NamedConst(t.to_owned()))
                        }
                    })
                    .collect::<Result<_, _>>()?;
                Ok(Expression::Integer(IntegerExpression {
                    value: IntegerExpressionValue::BinaryOr(int_tokens),
                    metadata: None,
                }))
            }
        }
    } else if let Some(struct_) = caps.name("struct") {
        let mut members = HashMap::new();
        let mut struct_ = struct_.as_str().to_owned();
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
            members.insert(k.to_owned(), v);
            #[allow(clippy::assigning_clones)]
            {
                struct_ =
                    struct_[k.len() + 1 + caps.get(0).unwrap().len()..struct_.len()].to_owned();
            }
        }
        Ok(Expression::Struct(members))
    } else if let Some(array) = caps.name("array") {
        let members = ARG_REGEX
            .captures_iter(array.as_str())
            .map(|a| parse_argument(&a))
            .collect::<Result<_, _>>()?;
        Ok(Expression::Collection {
            complement: false,
            values: members,
        })
    } else if let Some(buf) = caps.name("buf") {
        let buf = parse_buffer(buf.as_str())?;
        let type_ = if caps.name("buf_abstract_path").is_some() {
            BufferType::AbstractPath
        } else {
            BufferType::Unknown
        };
        Ok(Expression::Buffer(BufferExpression { value: buf, type_ }))
    } else if let Some(macro_) = caps.name("macro") {
        let (name, args) = macro_.as_str().split_once('(').unwrap();
        let args = args[..args.len() - 1].to_owned();
        let args = ARG_REGEX
            .captures_iter(&args)
            .map(|a| parse_argument(&a))
            .collect::<Result<_, _>>()?;
        Ok(Expression::Macro {
            name: name.to_owned(),
            args,
        })
    } else if let Some(multiplication) = caps.name("multiplication") {
        let args = multiplication
            .as_str()
            .split('*')
            .map(|a| -> anyhow::Result<IntegerExpressionValue> {
                let arg = ARG_REGEX
                    .captures(a)
                    .ok_or_else(|| anyhow::anyhow!("Unexpected multiplication argument {a:?}"))?;
                match parse_argument(&arg)? {
                    Expression::Integer(IntegerExpression { value, .. }) => Ok(value),
                    _ => Err(anyhow::anyhow!("Unexpected multiplication argument {a:?}")),
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(Expression::Integer(IntegerExpression {
            value: IntegerExpressionValue::Multiplication(args),
            metadata: None,
        }))
    } else {
        unreachable!("Argument has no group match")
    }
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
