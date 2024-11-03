//! PEG based strace output parser

use itertools::Itertools;
use pest::{iterators::Pair, Parser as _};

use crate::strace::{
    BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue, Syscall,
};

use super::{ParseResult, SyscallEnd, SyscallStart};

#[derive(pest_derive::Parser)]
#[grammar = "strace/parser/peg.pest"]
struct PegParser;

pub(crate) fn parse_line(line: &str) -> anyhow::Result<ParseResult> {
    let pair = match PegParser::parse(Rule::syscall_line, line) {
        Err(_) => return Ok(ParseResult::IgnoredLine),
        #[expect(clippy::unwrap_used)]
        Ok(mut p) => pair_descend(p.next().unwrap(), 1).unwrap(),
    };
    log::trace!("{:#?}", pair);
    match pair.as_rule() {
        Rule::syscall_line_complete => Ok(ParseResult::Syscall(pair.try_into()?)),
        Rule::syscall_line_start => Ok(ParseResult::SyscallStart(pair.try_into()?)),
        Rule::syscall_line_end => Ok(ParseResult::SyscallEnd(pair.try_into()?)),
        _ => anyhow::bail!("Unhandled pair: {pair:?}"),
    }
}

fn pair_descend(pair: Pair<'_, Rule>, levels: usize) -> anyhow::Result<Pair<'_, Rule>> {
    let mut pair = pair;
    let mut levels = levels;
    while levels > 0 {
        if let Some(below_pair) = pair.clone().into_inner().next() {
            pair = below_pair;
        } else {
            anyhow::bail!("Missing child node for {pair:?}");
        }
        levels -= 1;
    }
    Ok(pair)
}

impl TryFrom<Pair<'_, Rule>> for Expression {
    type Error = anyhow::Error;

    fn try_from(pair: Pair<Rule>) -> Result<Self, Self::Error> {
        match pair.as_rule() {
            Rule::int => Ok(Expression::Integer(pair_descend(pair, 1)?.try_into()?)),
            Rule::buffer => Ok(Expression::Buffer(pair.try_into()?)),
            Rule::r#struct => Ok(Expression::Struct(
                pair.into_inner()
                    .map(|m| -> anyhow::Result<_> {
                        let m = pair_descend(m, 1)?;
                        match m.as_rule() {
                            Rule::named_affectation => {
                                let (name_pair, val_pair) =
                                    m.into_inner().next_tuple().ok_or_else(|| {
                                        anyhow::anyhow!("Missing struct member name/value")
                                    })?;
                                let val: Expression = pair_descend(val_pair, 1)?.try_into()?;
                                Ok((name_pair.as_str().to_owned(), val))
                            }
                            Rule::r#macro => {
                                let macro_: Expression = m.try_into()?;
                                let member_name = if let Expression::Macro { args, .. } = &macro_ {
                                    args.iter()
                                        .find_map(|a| {
                                            if let Expression::DestinationAddress(n) = a {
                                                Some(n.to_owned())
                                            } else {
                                                None
                                            }
                                        })
                                        .ok_or_else(|| {
                                            anyhow::anyhow!("Missing macro destination address")
                                        })?
                                } else {
                                    anyhow::bail!("Missing macro");
                                };
                                Ok((member_name, macro_))
                            }
                            _ => anyhow::bail!("Unhandled pair: {m:?}"),
                        }
                    })
                    .collect::<Result<_, _>>()?,
            )),
            Rule::r#macro => {
                let (name, args) = pair
                    .into_inner()
                    .next_tuple()
                    .ok_or_else(|| anyhow::anyhow!("Missing macro child nodes"))?;
                Ok(Expression::Macro {
                    name: name.as_str().to_owned(),
                    args: args
                        .into_inner()
                        .map(|p| {
                            let p = pair_descend(p, 1)?;
                            match p.as_rule() {
                                Rule::expression => Expression::try_from(pair_descend(p, 1)?),
                                Rule::pseudo_addr => Ok(Expression::DestinationAddress(
                                    pair_descend(p, 1)?.as_str().to_owned(),
                                )),
                                _ => anyhow::bail!("Unhandled pair: {p:?}"),
                            }
                        })
                        .collect::<Result<_, _>>()?,
                })
            }
            Rule::array => Ok(Expression::Collection {
                complement: false,
                values: pair
                    .into_inner()
                    .map(|p| Expression::try_from(pair_descend(p, 1)?))
                    .collect::<Result<_, _>>()?,
            }),
            Rule::set => {
                let complement = pair.as_str().starts_with('~');
                Ok(Expression::Collection {
                    complement,
                    values: pair
                        .into_inner()
                        .map(|p| -> anyhow::Result<_> {
                            Ok(Expression::Integer(IntegerExpression::try_from(
                                pair_descend(p, 1)?,
                            )?))
                        })
                        .collect::<Result<_, _>>()?,
                })
            }
            _ => anyhow::bail!("Unhandled pair: {pair:?}"),
        }
    }
}

impl TryFrom<Pair<'_, Rule>> for BufferExpression {
    type Error = anyhow::Error;

    fn try_from(pair: Pair<Rule>) -> Result<Self, Self::Error> {
        let type_ = if pair.as_str().starts_with('@') {
            BufferType::AbstractPath
        } else {
            BufferType::Unknown
        };
        Ok(BufferExpression {
            value: pair
                .into_inner()
                .map(|b| {
                    let s = b.as_str();
                    if let Some(s2) = s.strip_prefix("\\x") {
                        debug_assert_eq!(s.len(), 4);
                        u8::from_str_radix(s2, 16).map_err(anyhow::Error::new)
                    } else {
                        debug_assert_eq!(s.len(), 1);
                        Ok(s.as_bytes()[0])
                    }
                })
                .collect::<Result<_, _>>()?,
            type_,
        })
    }
}

/// Helper to parse 'literal' pair
fn lit_pair(pair: Pair<Rule>) -> anyhow::Result<IntegerExpression> {
    let (val, metadata) = match pair.as_rule() {
        Rule::literal_int_oct => (i128::from_str_radix(pair.as_str(), 8)?, None),
        Rule::literal_int_hex => (
            #[expect(clippy::unwrap_used)]
            pair.as_str()
                .strip_prefix("0x")
                .map(|s| i128::from_str_radix(s, 16))
                .unwrap()?,
            None,
        ),
        Rule::literal_int_dec => {
            let mut children = pair.into_inner();
            let val_pair = children
                .next()
                .ok_or_else(|| anyhow::anyhow!("Missing dec value node"))?;
            let mut metadata_pair = children.next();
            // TODO use Option::take_if if it gets stable
            if metadata_pair
                .as_ref()
                .is_some_and(|p| matches!(p.as_rule(), Rule::comment))
            {
                metadata_pair = None;
            }
            (
                val_pair.as_str().parse()?,
                metadata_pair
                    .map(|p| BufferExpression::try_from(p).map(|e| e.value))
                    .map_or(Ok(None), |v| v.map(Some))?,
            )
        }
        _ => anyhow::bail!("Unhandled pair: {pair:?}"),
    };
    Ok(IntegerExpression {
        value: IntegerExpressionValue::Literal(val),
        metadata,
    })
}

impl TryFrom<Pair<'_, Rule>> for IntegerExpression {
    type Error = anyhow::Error;

    fn try_from(pair: Pair<Rule>) -> Result<Self, Self::Error> {
        match pair.as_rule() {
            Rule::literal_int => {
                let pair = pair_descend(pair, 1)?;
                lit_pair(pair)
            }
            Rule::named_constant => {
                let mut children = pair.into_inner();
                let val_pair = children
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Missing named const name"))?;
                let metadata_pair = children.next();
                Ok(IntegerExpression {
                    value: IntegerExpressionValue::NamedConst(val_pair.as_str().to_owned()),
                    metadata: metadata_pair
                        .map(|p| BufferExpression::try_from(p).map(|e| e.value))
                        .map_or(Ok(None), |v| v.map(Some))?,
                })
            }
            Rule::or => {
                let mut children = pair.into_inner();
                let mut or_elems = Vec::with_capacity(children.len());
                or_elems.push(IntegerExpressionValue::NamedConst(
                    children
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Missing or first node"))?
                        .as_str()
                        .to_owned(),
                ));
                or_elems.extend(
                    children
                        .map(|c| IntegerExpression::try_from(pair_descend(c, 1)?).map(|e| e.value))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .flat_map(|e| {
                            // Flatten or child expressions
                            if let IntegerExpressionValue::BinaryOr(es) = e {
                                es.into_iter()
                            } else {
                                vec![e].into_iter()
                            }
                        }),
                );
                Ok(IntegerExpression {
                    value: IntegerExpressionValue::BinaryOr(or_elems),
                    metadata: None,
                })
            }
            Rule::multiplication => {
                let mut children = pair.into_inner();
                let mut mul_elems = Vec::with_capacity(children.len());
                mul_elems.push(
                    lit_pair(pair_descend(
                        children
                            .next()
                            .ok_or_else(|| anyhow::anyhow!("Missing multiplication first node"))?,
                        1,
                    )?)?
                    .value,
                );
                mul_elems.append(
                    &mut children
                        .map(|c| IntegerExpression::try_from(pair_descend(c, 1)?).map(|e| e.value))
                        .collect::<Result<Vec<_>, _>>()?,
                );
                Ok(IntegerExpression {
                    value: IntegerExpressionValue::Multiplication(mul_elems),
                    metadata: None,
                })
            }
            Rule::left_bit_shift => {
                let (left_pair, right_pair) = pair
                    .into_inner()
                    .next_tuple()
                    .ok_or_else(|| anyhow::anyhow!("Missing bit shift nodes"))?;
                let left: IntegerExpression = lit_pair(pair_descend(left_pair, 1)?)?;
                let right: IntegerExpression = pair_descend(right_pair, 1)?.try_into()?;
                Ok(IntegerExpression {
                    value: IntegerExpressionValue::LeftBitShift {
                        bits: Box::new(left.value),
                        shift: Box::new(right.value),
                    },
                    metadata: None,
                })
            }
            _ => anyhow::bail!("Unhandled pair: {pair:?}"),
        }
    }
}

impl TryFrom<Pair<'_, Rule>> for Syscall {
    type Error = anyhow::Error;

    fn try_from(pair: Pair<Rule>) -> Result<Self, Self::Error> {
        let mut subpairs = pair.into_inner();
        // Note if the grammar is correct, we should *never* panic below
        let pid = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing pid node"))?
            .as_str()
            .parse()?;
        let rel_ts = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing ts node"))?
            .as_str()
            .parse()?;
        let name = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing name node"))?
            .as_str()
            .to_owned();

        let args_pair = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing arguments node"))?;
        let args_pair = pair_descend(args_pair, 1)?;
        let args = match args_pair.as_rule() {
            Rule::unnamed_arguments => args_pair
                .into_inner()
                .map(|p| {
                    let p = pair_descend(p, 1)?;
                    match p.as_rule() {
                        Rule::in_argument => pair_descend(p, 2)?.try_into(),
                        Rule::in_out_argument => {
                            // Only take the 'in' part, ignore the rest
                            pair_descend(p, 2)?.try_into()
                        }
                        _ => anyhow::bail!("Unhandled pair: {p:?}"),
                    }
                })
                .collect::<Result<_, _>>()?,
            Rule::named_arguments => {
                // Handle name arguments as a single struct
                vec![Expression::Struct(
                    args_pair
                        .into_inner()
                        .map(|p| -> anyhow::Result<_> {
                            let (n, v) = p
                                .into_inner()
                                .next_tuple()
                                .ok_or_else(|| anyhow::anyhow!("Missing name arguments nodes"))?;
                            Ok((n.as_str().to_owned(), pair_descend(v, 1)?.try_into()?))
                        })
                        .collect::<Result<_, _>>()?,
                )]
            }
            _ => anyhow::bail!("Unhandled pair: {args_pair:?}"),
        };

        let ret_val_pair = pair_descend(
            subpairs
                .next()
                .ok_or_else(|| anyhow::anyhow!("Missing return value node"))?,
            2,
        )?;
        let IntegerExpressionValue::Literal(ret_val) =
            IntegerExpression::try_from(ret_val_pair)?.value
        else {
            anyhow::bail!("Return value is not a literal int");
        };

        Ok(Self {
            pid,
            rel_ts,
            name,
            args,
            ret_val,
        })
    }
}
impl TryFrom<Pair<'_, Rule>> for SyscallStart {
    type Error = anyhow::Error;

    fn try_from(pair: Pair<Rule>) -> Result<Self, Self::Error> {
        let mut subpairs = pair.into_inner();
        // Note if the grammar is correct, we should *never* panic below
        let pid = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing pid node"))?
            .as_str()
            .parse()?;
        let rel_ts = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing ts node"))?
            .as_str()
            .parse()?;
        let name = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing name node"))?
            .as_str()
            .to_owned();

        let args_pair = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing arguments node"))?;
        let args_pair = pair_descend(args_pair, 1)?;
        let args = match args_pair.as_rule() {
            Rule::unnamed_arguments => args_pair
                .into_inner()
                .map(|p| {
                    let p = pair_descend(p, 1)?;
                    match p.as_rule() {
                        Rule::in_argument => pair_descend(p, 2)?.try_into(),
                        Rule::in_out_argument => {
                            // Only take the 'in' part, ignore the rest
                            pair_descend(p, 2)?.try_into()
                        }
                        _ => anyhow::bail!("Unhandled pair: {p:?}"),
                    }
                })
                .collect::<Result<_, _>>()?,
            Rule::named_arguments => {
                // Handle name arguments as a single struct
                vec![Expression::Struct(
                    args_pair
                        .into_inner()
                        .map(|p| -> anyhow::Result<_> {
                            let (n, v) = p
                                .into_inner()
                                .next_tuple()
                                .ok_or_else(|| anyhow::anyhow!("Missing name arguments nodes"))?;
                            Ok((n.as_str().to_owned(), pair_descend(v, 1)?.try_into()?))
                        })
                        .collect::<Result<_, _>>()?,
                )]
            }
            _ => anyhow::bail!("Unhandled pair: {args_pair:?}"),
        };

        Ok(Self {
            pid,
            rel_ts,
            name,
            args,
        })
    }
}

impl TryFrom<Pair<'_, Rule>> for SyscallEnd {
    type Error = anyhow::Error;

    fn try_from(pair: Pair<Rule>) -> Result<Self, Self::Error> {
        let mut subpairs = pair.into_inner();
        // Note if the grammar is correct, we should *never* panic below
        let pid = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing pid node"))?
            .as_str()
            .parse()?;
        let rel_ts = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing ts node"))?
            .as_str()
            .parse()?;
        let name = subpairs
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing name node"))?
            .as_str()
            .to_owned();

        let ret_val_pair = pair_descend(
            subpairs
                .next()
                .ok_or_else(|| anyhow::anyhow!("Missing return value node"))?,
            2,
        )?;
        let IntegerExpressionValue::Literal(ret_val) =
            IntegerExpression::try_from(ret_val_pair)?.value
        else {
            anyhow::bail!("Return value is not a literal int");
        };

        Ok(Self {
            pid,
            rel_ts,
            name,
            ret_val,
        })
    }
}
