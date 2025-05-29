//! Combinator based strace output parser

use std::iter;

use nom::{
    IResult, Parser as _,
    branch::alt,
    bytes::complete::{tag, take, take_until},
    character::complete::{
        self, alpha1, alphanumeric1, char, digit1, hex_digit1, oct_digit1, space1,
    },
    combinator::{map, map_opt, map_res, opt, recognize},
    multi::{count, many_till, many0_count, separated_list0, separated_list1},
    number::complete::double,
    sequence::{delimited, pair, preceded, separated_pair, terminated},
};

use super::ParseResult;
use crate::strace::{
    BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue, Syscall,
    parser::{SyscallEnd, SyscallStart},
};

macro_rules! dbg_parser_entry {
    ($input:expr) => {
        log::trace!("{}:{}\ninput: {:?}", function_name!(), line!(), $input)
    };
}

macro_rules! dbg_parser_success {
    ($output:expr) => {
        log::trace!("{}:{}\nparsed: {:?}", function_name!(), line!(), $output)
    };
}

pub(crate) fn parse_line(line: &str) -> anyhow::Result<ParseResult> {
    match parse_syscall_line(line).map(|s| s.1) {
        Err(nom::Err::Incomplete(_) | nom::Err::Error(_)) => Ok(ParseResult::IgnoredLine),
        Err(nom::Err::Failure(e)) => Err(anyhow::anyhow!("{e}")),
        Ok(res) => Ok(res),
    }
}

// Main line token parsers

#[function_name::named]
fn parse_syscall_line(i: &str) -> IResult<&str, ParseResult> {
    dbg_parser_entry!(i);
    alt((
        // Complete syscall
        map(
            (
                parse_pid,
                parse_rel_ts,
                parse_name,
                parse_args_complete,
                parse_ret_val,
            ),
            |(pid, rel_ts, name, args, ret_val)| {
                ParseResult::Syscall(Syscall {
                    pid,
                    rel_ts,
                    name: name.to_owned(),
                    args,
                    ret_val,
                })
            },
        ),
        // Syscall start
        map(
            (parse_pid, parse_rel_ts, parse_name, parse_args_incomplete),
            |(pid, rel_ts, name, args)| {
                ParseResult::SyscallStart(SyscallStart {
                    pid,
                    rel_ts,
                    name: name.to_owned(),
                    args,
                })
            },
        ),
        // Syscall end
        map(
            (
                parse_pid,
                parse_rel_ts,
                delimited(tag("<... "), parse_name, (tag(" resumed> )"), space1)),
                parse_ret_val,
            ),
            |(pid, rel_ts, name, ret_val)| {
                ParseResult::SyscallEnd(SyscallEnd {
                    pid,
                    rel_ts,
                    name: name.to_owned(),
                    ret_val,
                })
            },
        ),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_pid(i: &str) -> IResult<&str, u32> {
    dbg_parser_entry!(i);
    terminated(map_res(digit1, str::parse), space1)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_rel_ts(i: &str) -> IResult<&str, f64> {
    dbg_parser_entry!(i);
    terminated(double, space1)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_name(i: &str) -> IResult<&str, &str> {
    dbg_parser_entry!(i);
    parse_symbol(i)
}

#[function_name::named]
fn parse_args_complete(i: &str) -> IResult<&str, Vec<Expression>> {
    dbg_parser_entry!(i);
    delimited(char('('), parse_args_inner, terminated(char(')'), space1))
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_args_incomplete(i: &str) -> IResult<&str, Vec<Expression>> {
    dbg_parser_entry!(i);
    delimited(char('('), parse_args_inner, tag(" <unfinished ...>"))
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_args_inner(i: &str) -> IResult<&str, Vec<Expression>> {
    dbg_parser_entry!(i);
    alt((
        map(separated_list1(tag(", "), parse_struct_member), |ne| {
            // Named arguments are stuffed in a single struct
            vec![Expression::Struct(
                ne.into_iter().map(|(n, e)| (n.to_owned(), e)).collect(),
            )]
        }),
        separated_list0(
            tag(", "),
            alt((
                map(parse_in_out_argument, |(ia, oa)| ia.unwrap_or(oa)),
                parse_expression,
            )),
        ),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_in_out_argument(i: &str) -> IResult<&str, (Option<Expression>, Expression)> {
    dbg_parser_entry!(i);
    alt((
        map(
            alt((
                separated_pair(parse_expression, tag(" => "), parse_expression),
                delimited(
                    char('['),
                    separated_pair(parse_expression, tag(" => "), parse_expression),
                    char(']'),
                ),
            )),
            |(ia, oa)| (Some(ia), oa),
        ),
        map(delimited(tag("[{"), parse_expression, tag("}]")), |oa| {
            (None, oa)
        }),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_ret_val(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    preceded(terminated(char('='), space1), parse_int_literal)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

// Shared parsers

#[function_name::named]
fn parse_symbol(i: &str) -> IResult<&str, &str> {
    dbg_parser_entry!(i);
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0_count(alt((alphanumeric1, tag("_")))),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_comment(i: &str) -> IResult<&str, Option<&str>> {
    dbg_parser_entry!(i);
    opt(delimited(tag(" /* "), take_until(" */"), tag(" */")))
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

// Expression

#[function_name::named]
fn parse_expression(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        pair(
            alt((
                parse_expression_mac_addr,
                parse_expression_int,
                parse_expression_struct,
                parse_expression_buf,
                parse_expression_set,
                parse_expression_array,
            )),
            parse_comment,
        ),
        |(u, _)| u,
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_mac_addr(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        (
            map_res(take(2_usize), |s| u8::from_str_radix(s, 16)),
            count(
                map_res(preceded(char(':'), take(2_usize)), |s| {
                    u8::from_str_radix(s, 16)
                }),
                5,
            ),
        ),
        |(f, o)| {
            let mut mac = [0; 6];
            mac[0] = f;
            mac[1..].copy_from_slice(&o);
            Expression::MacAddress(mac)
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_macro_pseudo_address(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(preceded(char('&'), parse_symbol), |s| {
        Expression::DestinationAddress(s.to_owned())
    })
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_int(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(parse_int, Expression::Integer)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_struct(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        delimited(
            char('{'),
            separated_list0(
                tag(", "),
                alt((
                    map(parse_struct_member, |(n, e)| (n.to_owned(), e)),
                    map_opt(parse_int_macro, |e| -> Option<(String, Expression)> {
                        if let IntegerExpression {
                            value: IntegerExpressionValue::Macro { args, .. },
                            ..
                        } = &e
                        {
                            args.iter().find_map(|a| {
                                if let Expression::DestinationAddress(n) = a {
                                    Some((n.to_owned(), Expression::Integer(e.clone())))
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    }),
                )),
            ),
            (opt(tag(", ...")), char('}')),
        ),
        |m| Expression::Struct(m.into_iter().collect()),
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_buf(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(parse_buffer, Expression::Buffer)
        .parse(i)
        .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_set(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        pair(
            opt(char('~')),
            delimited(
                char('['),
                separated_list0(char(' '), parse_int),
                (opt(tag(" ...")), char(']')),
            ),
        ),
        |(neg, values)| Expression::Collection {
            complement: neg.is_some(),
            values: values
                .into_iter()
                .map(|ie| (None, Expression::Integer(ie)))
                .collect(),
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_expression_array(i: &str) -> IResult<&str, Expression> {
    dbg_parser_entry!(i);
    map(
        delimited(
            char('['),
            separated_list0(
                tag(", "),
                (
                    opt(terminated(
                        delimited(char('['), terminated(parse_int, parse_comment), char(']')),
                        char('='),
                    )),
                    parse_expression,
                ),
            ),
            char(']'),
        ),
        |values| Expression::Collection {
            complement: false,
            values,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

// Int expression

#[function_name::named]
fn parse_int(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    alt((
        parse_int_bit_or,
        parse_int_bool_and,
        parse_int_equals,
        parse_int_macro,
        parse_int_multiplication,
        parse_int_substraction,
        parse_int_left_shift,
        parse_int_literal,
        parse_int_named,
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_bit_or(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_int_named,
            char('|'),
            separated_list1(char('|'), parse_int),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::BinaryOr(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::BinaryOr(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_bool_and(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_int_macro,
            tag(" && "),
            separated_list1(tag(" && "), parse_int),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::BooleanAnd(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::BooleanAnd(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_equals(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_int_macro,
            tag(" == "),
            separated_list1(tag(" == "), parse_int),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::Equality(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::Equality(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_macro(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        pair(
            parse_symbol,
            delimited(
                char('('),
                separated_list0(
                    tag(", "),
                    alt((parse_expression_macro_pseudo_address, parse_expression)),
                ),
                char(')'),
            ),
        ),
        |(n, args)| IntegerExpression {
            value: IntegerExpressionValue::Macro {
                name: n.to_owned(),
                args,
            },
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_multiplication(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_int_literal,
            char('*'),
            separated_list1(char('*'), parse_int),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::Multiplication(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::Multiplication(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_substraction(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(
            parse_int_named,
            char('-'),
            separated_list1(char('-'), parse_int),
        ),
        |(f, rs)| IntegerExpression {
            value: IntegerExpressionValue::Substraction(
                iter::once(f.value)
                    .chain(rs.into_iter().map(|r| r.value).flat_map(|e| {
                        // Flatten child expressions
                        if let IntegerExpressionValue::Substraction(es) = e {
                            es.into_iter()
                        } else {
                            vec![e].into_iter()
                        }
                    }))
                    .collect(),
            ),
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_literal(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        (
            alt((
                parse_int_literal_hexa,
                parse_int_literal_oct,
                parse_int_literal_dec,
            )),
            parse_int_metadata,
        ),
        |(v, m)| IntegerExpression {
            value: IntegerExpressionValue::Literal(v),
            metadata: m,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_left_shift(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map(
        separated_pair(parse_int_literal, tag("<<"), parse_int),
        |(b, s)| IntegerExpression {
            value: IntegerExpressionValue::LeftBitShift {
                bits: Box::new(b.value),
                shift: Box::new(s.value),
            },
            metadata: None,
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_named(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser_entry!(i);
    map((parse_symbol, parse_int_metadata), |(e, metadata)| {
        IntegerExpression {
            value: IntegerExpressionValue::NamedSymbol(e.to_owned()),
            metadata,
        }
    })
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_metadata(i: &str) -> IResult<&str, Option<Vec<u8>>> {
    dbg_parser_entry!(i);
    opt(delimited(
        char('<'),
        map(many_till(parse_buffer_byte, char('>')), |r| r.0),
        opt(tag("(deleted)")),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

// Int literal

#[function_name::named]
fn parse_int_literal_hexa(i: &str) -> IResult<&str, i128> {
    dbg_parser_entry!(i);
    preceded(
        tag("0x"),
        map_res(hex_digit1, |s| i128::from_str_radix(s, 16)),
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_literal_oct(i: &str) -> IResult<&str, i128> {
    dbg_parser_entry!(i);
    preceded(
        char('0'),
        map_res(oct_digit1, |s| i128::from_str_radix(s, 8)),
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_int_literal_dec(i: &str) -> IResult<&str, i128> {
    dbg_parser_entry!(i);
    complete::i128(i)
}

// Buffer

#[function_name::named]
fn parse_buffer(i: &str) -> IResult<&str, BufferExpression> {
    dbg_parser_entry!(i);
    map(
        terminated(
            pair(
                opt(char('@')),
                preceded(
                    char('"'),
                    map(many_till(parse_buffer_byte, char('"')), |r| r.0),
                ),
            ),
            opt(tag("...")),
        ),
        |(a, r)| BufferExpression {
            value: r,
            type_: if a.is_some() {
                BufferType::AbstractPath
            } else {
                BufferType::Unknown
            },
        },
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[function_name::named]
fn parse_buffer_byte(i: &str) -> IResult<&str, u8> {
    dbg_parser_entry!(i);
    alt((
        map_res(preceded(tag("\\x"), take(2_usize)), |s| {
            u8::from_str_radix(s, 16)
        }),
        #[expect(clippy::indexing_slicing)]
        // first elem is guaranteed to be here by take(1) parser
        map(take(1_usize), |s: &str| s.as_bytes()[0]),
    ))
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

// Struct

#[function_name::named]
fn parse_struct_member(i: &str) -> IResult<&str, (&str, Expression)> {
    dbg_parser_entry!(i);
    separated_pair(
        parse_symbol,
        char('='),
        alt((
            map(parse_in_out_argument, |(ia, oa)| ia.unwrap_or(oa)),
            parse_expression,
        )),
    )
    .parse(i)
    .inspect(|r| dbg_parser_success!(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_expression_array() {
        assert_eq!(
            parse_expression_array(
                "[[IPV4_DEVCONF_BC_FORWARDING-1]=0, [IPV4_DEVCONF_ARP_EVICT_NOCARRIER-1]=1, [37 /* IPSTATS_MIB_??? */]=22]"
            )
            .unwrap(),
            (
                "",
                Expression::Collection {
                    complement: false,
                    values: vec![
                        (
                            Some(IntegerExpression {
                                value: IntegerExpressionValue::Substraction(vec![
                                    IntegerExpressionValue::NamedSymbol(
                                        "IPV4_DEVCONF_BC_FORWARDING".to_owned()
                                    ),
                                    IntegerExpressionValue::Literal(1)
                                ]),
                                metadata: None
                            }),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(0),
                                metadata: None
                            })
                        ),
                        (
                            Some(IntegerExpression {
                                value: IntegerExpressionValue::Substraction(vec![
                                    IntegerExpressionValue::NamedSymbol(
                                        "IPV4_DEVCONF_ARP_EVICT_NOCARRIER".to_owned()
                                    ),
                                    IntegerExpressionValue::Literal(1)
                                ]),
                                metadata: None
                            }),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(1),
                                metadata: None
                            })
                        ),
                        (
                            Some(IntegerExpression {
                                value: IntegerExpressionValue::Literal(37),
                                metadata: None
                            }),
                            Expression::Integer(IntegerExpression {
                                value: IntegerExpressionValue::Literal(22),
                                metadata: None
                            })
                        )
                    ]
                }
            )
        );
    }
}
