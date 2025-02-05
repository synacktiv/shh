//! Combinator based strace output parser

use std::iter;

use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until},
    character::complete::{
        self, alpha1, alphanumeric1, char, digit1, hex_digit1, oct_digit1, space1,
    },
    combinator::{map, map_opt, map_res, opt, recognize},
    multi::{many0_count, many_till, separated_list0, separated_list1},
    number::complete::double,
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};

use super::ParseResult;
use crate::strace::{
    parser::{SyscallEnd, SyscallStart},
    BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue, Syscall,
};

macro_rules! dbg_parser {
    ($input:expr) => {
        log::trace!("{}:{}\ninput: {:?}", function_name!(), line!(), $input,);
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
    dbg_parser!(i);
    alt((
        // Complete syscall
        map(
            tuple((
                parse_pid,
                parse_rel_ts,
                parse_name,
                parse_args_complete,
                parse_ret_val,
            )),
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
            tuple((parse_pid, parse_rel_ts, parse_name, parse_args_incomplete)),
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
            tuple((
                parse_pid,
                parse_rel_ts,
                delimited(
                    tag("<... "),
                    parse_name,
                    tuple((tag(" resumed> )"), space1)),
                ),
                parse_ret_val,
            )),
            |(pid, rel_ts, name, ret_val)| {
                ParseResult::SyscallEnd(SyscallEnd {
                    pid,
                    rel_ts,
                    name: name.to_owned(),
                    ret_val,
                })
            },
        ),
    ))(i)
}

#[function_name::named]
fn parse_pid(i: &str) -> IResult<&str, u32> {
    dbg_parser!(i);
    terminated(map_res(digit1, str::parse), space1)(i)
}

#[function_name::named]
fn parse_rel_ts(i: &str) -> IResult<&str, f64> {
    dbg_parser!(i);
    terminated(double, space1)(i)
}

#[function_name::named]
fn parse_name(i: &str) -> IResult<&str, &str> {
    dbg_parser!(i);
    parse_symbol(i)
}

#[function_name::named]
fn parse_args_complete(i: &str) -> IResult<&str, Vec<Expression>> {
    dbg_parser!(i);
    delimited(char('('), parse_args_inner, terminated(char(')'), space1))(i)
}

#[function_name::named]
fn parse_args_incomplete(i: &str) -> IResult<&str, Vec<Expression>> {
    dbg_parser!(i);
    delimited(char('('), parse_args_inner, tag(" <unfinished ...>"))(i)
}

#[function_name::named]
fn parse_args_inner(i: &str) -> IResult<&str, Vec<Expression>> {
    dbg_parser!(i);
    alt((
        map(separated_list1(tag(", "), parse_struct_member), |ne| {
            // Named arguments are stuffed in a single struct
            vec![Expression::Struct(
                ne.into_iter().map(|(n, e)| (n.to_owned(), e)).collect(),
            )]
        }),
        separated_list0(tag(", "), alt((parse_in_out_argument, parse_expression))),
    ))(i)
}

#[function_name::named]
fn parse_in_out_argument(i: &str) -> IResult<&str, Expression> {
    dbg_parser!(i);
    map(
        alt((
            separated_pair(parse_expression, tag(" => "), parse_expression),
            delimited(
                char('['),
                separated_pair(parse_expression, tag(" => "), parse_expression),
                char(']'),
            ),
        )),
        |(ia, _oa)| ia,
    )(i)
}

#[function_name::named]
fn parse_ret_val(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser!(i);
    preceded(terminated(char('='), space1), parse_int_literal)(i)
}

// Shared parsers

#[function_name::named]
fn parse_symbol(i: &str) -> IResult<&str, &str> {
    dbg_parser!(i);
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0_count(alt((alphanumeric1, tag("_")))),
    ))(i)
}

#[function_name::named]
fn parse_comment(i: &str) -> IResult<&str, Option<&str>> {
    dbg_parser!(i);
    opt(delimited(tag(" /* "), take_until(" */"), tag(" */")))(i)
}

// Expression

#[function_name::named]
fn parse_expression(i: &str) -> IResult<&str, Expression> {
    dbg_parser!(i);
    map(
        pair(
            alt((
                parse_expression_macro,
                parse_expression_int,
                parse_expression_struct,
                parse_expression_buf,
                parse_expression_set,
                parse_expression_array,
            )),
            parse_comment,
        ),
        |(u, _)| u,
    )(i)
}

#[function_name::named]
fn parse_expression_macro(i: &str) -> IResult<&str, Expression> {
    dbg_parser!(i);
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
        |(n, args)| Expression::Macro {
            name: n.to_owned(),
            args,
        },
    )(i)
}

#[function_name::named]
fn parse_expression_macro_pseudo_address(i: &str) -> IResult<&str, Expression> {
    dbg_parser!(i);
    map(preceded(char('&'), parse_symbol), |s| {
        Expression::DestinationAddress(s.to_owned())
    })(i)
}

#[function_name::named]
fn parse_expression_int(i: &str) -> IResult<&str, Expression> {
    dbg_parser!(i);
    map(parse_int, Expression::Integer)(i)
}

#[function_name::named]
fn parse_expression_struct(i: &str) -> IResult<&str, Expression> {
    dbg_parser!(i);
    map(
        delimited(
            char('{'),
            separated_list0(
                tag(", "),
                alt((
                    map(parse_struct_member, |(n, e)| (n.to_owned(), e)),
                    map_opt(parse_expression_macro, |e| {
                        if let Expression::Macro { args, .. } = &e {
                            args.iter().find_map(|a| {
                                if let Expression::DestinationAddress(n) = a {
                                    Some((n.to_owned(), e.clone()))
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
            tuple((opt(tag(", ...")), char('}'))),
        ),
        |m| Expression::Struct(m.into_iter().collect()),
    )(i)
}

#[function_name::named]
fn parse_expression_buf(i: &str) -> IResult<&str, Expression> {
    dbg_parser!(i);
    map(parse_buffer, Expression::Buffer)(i)
}

#[function_name::named]
fn parse_expression_set(i: &str) -> IResult<&str, Expression> {
    dbg_parser!(i);
    map(
        pair(
            opt(char('~')),
            delimited(
                char('['),
                separated_list0(char(' '), parse_int),
                tuple((opt(tag(" ...")), char(']'))),
            ),
        ),
        |(neg, values)| Expression::Collection {
            complement: neg.is_some(),
            values: values
                .into_iter()
                .map(|ie| (None, Expression::Integer(ie)))
                .collect(),
        },
    )(i)
}

#[function_name::named]
fn parse_expression_array(i: &str) -> IResult<&str, Expression> {
    dbg_parser!(i);
    map(
        delimited(
            char('['),
            separated_list0(
                tag(", "),
                tuple((
                    opt(terminated(
                        delimited(char('['), parse_int, char(']')),
                        char('='),
                    )),
                    parse_expression,
                )),
            ),
            char(']'),
        ),
        |values| Expression::Collection {
            complement: false,
            values,
        },
    )(i)
}

// Int expression

#[function_name::named]
fn parse_int(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser!(i);
    alt((
        parse_int_bit_or,
        parse_int_multiplication,
        parse_int_left_shift,
        parse_int_literal,
        parse_int_named,
    ))(i)
}

#[function_name::named]
fn parse_int_bit_or(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser!(i);
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
    )(i)
}

#[function_name::named]
fn parse_int_multiplication(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser!(i);
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
    )(i)
}

#[function_name::named]
fn parse_int_literal(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser!(i);
    map(
        tuple((
            alt((
                parse_int_literal_hexa,
                parse_int_literal_oct,
                parse_int_literal_dec,
            )),
            parse_int_metadata,
        )),
        |(v, m)| IntegerExpression {
            value: IntegerExpressionValue::Literal(v),
            metadata: m,
        },
    )(i)
}

#[function_name::named]
fn parse_int_left_shift(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser!(i);
    map(
        separated_pair(parse_int_literal, tag("<<"), parse_int),
        |(b, s)| IntegerExpression {
            value: IntegerExpressionValue::LeftBitShift {
                bits: Box::new(b.value),
                shift: Box::new(s.value),
            },
            metadata: None,
        },
    )(i)
}

#[function_name::named]
fn parse_int_named(i: &str) -> IResult<&str, IntegerExpression> {
    dbg_parser!(i);
    map(
        tuple((parse_symbol, parse_int_metadata)),
        |(e, metadata)| IntegerExpression {
            value: IntegerExpressionValue::NamedConst(e.to_owned()),
            metadata,
        },
    )(i)
}

#[function_name::named]
fn parse_int_metadata(i: &str) -> IResult<&str, Option<Vec<u8>>> {
    dbg_parser!(i);
    opt(delimited(
        char('<'),
        map(many_till(parse_buffer_byte, char('>')), |r| r.0),
        opt(tag("(deleted)")),
    ))(i)
}

// Int literal

#[function_name::named]
fn parse_int_literal_hexa(i: &str) -> IResult<&str, i128> {
    dbg_parser!(i);
    preceded(
        tag("0x"),
        map_res(hex_digit1, |s| i128::from_str_radix(s, 16)),
    )(i)
}

#[function_name::named]
fn parse_int_literal_oct(i: &str) -> IResult<&str, i128> {
    dbg_parser!(i);
    preceded(
        char('0'),
        map_res(oct_digit1, |s| i128::from_str_radix(s, 8)),
    )(i)
}

#[function_name::named]
fn parse_int_literal_dec(i: &str) -> IResult<&str, i128> {
    dbg_parser!(i);
    complete::i128(i)
}

// Buffer

#[function_name::named]
fn parse_buffer(i: &str) -> IResult<&str, BufferExpression> {
    dbg_parser!(i);
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
    )(i)
}

#[function_name::named]
fn parse_buffer_byte(i: &str) -> IResult<&str, u8> {
    dbg_parser!(i);
    alt((
        map_res(preceded(tag("\\x"), take(2_usize)), |s| {
            u8::from_str_radix(s, 16)
        }),
        map(take(1_usize), |s: &str| s.as_bytes()[0]),
    ))(i)
}

// Struct

#[function_name::named]
fn parse_struct_member(i: &str) -> IResult<&str, (&str, Expression)> {
    dbg_parser!(i);
    separated_pair(parse_symbol, char('='), parse_expression)(i)
}
