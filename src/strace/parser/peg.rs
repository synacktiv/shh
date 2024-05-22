//! PEG based strace output parser

use itertools::Itertools;
use pest::iterators::Pair;
use pest::Parser as _;

use crate::strace::{
    BufferExpression, BufferType, Expression, IntegerExpression, IntegerExpressionValue, Syscall,
};

use super::ParseResult;

#[derive(pest_derive::Parser)]
#[grammar = "strace/parser/peg.pest"]
struct PegParser;

pub fn parse_line(line: &str, unfinished_syscalls: &[Syscall]) -> anyhow::Result<ParseResult> {
    let pair = match PegParser::parse(Rule::syscall_line, line) {
        Err(_) => return Ok(ParseResult::IgnoredLine),
        Ok(mut p) => pair_descend(p.next().unwrap(), 1).unwrap(),
    };
    log::trace!("{:#?}", pair);
    match pair.as_node_tag() {
        Some("complete") => Ok(ParseResult::Syscall(pair.try_into()?)),
        Some("start") => Ok(ParseResult::UnfinishedSyscall(pair.try_into()?)),
        Some("end") => {
            let sc_end: Syscall = pair.try_into()?;
            let (unfinished_index, sc_start) = unfinished_syscalls
                .iter()
                .enumerate()
                .find(|(_i, sc)| (sc.name == sc_end.name) && (sc.pid == sc_end.pid))
                .ok_or_else(|| anyhow::anyhow!("Unabled to find first part of syscall"))?;
            let sc_merged = Syscall {
                // Update return val and timestamp (to get return time instead of call time)
                ret_val: sc_end.ret_val,
                rel_ts: sc_end.rel_ts,
                ..sc_start.clone()
            };
            Ok(ParseResult::FinishedSyscall {
                sc: sc_merged,
                unfinished_index,
            })
        }
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
        match pair.as_node_tag() {
            Some("int") => Ok(Expression::Integer(pair_descend(pair, 1)?.try_into()?)),
            Some("buf") => Ok(Expression::Buffer(pair.try_into()?)),
            Some("struct") => Ok(Expression::Struct(
                pair.into_inner()
                    .map(|m| -> anyhow::Result<_> {
                        let m = pair_descend(m, 1)?;
                        match m.as_node_tag() {
                            Some("member_named") => {
                                let (name_pair, val_pair) =
                                    m.into_inner().next_tuple().ok_or_else(|| {
                                        anyhow::anyhow!("Missing struct member name/value")
                                    })?;
                                let val: Expression = pair_descend(val_pair, 1)?.try_into()?;
                                Ok((name_pair.as_str().to_owned(), val))
                            }
                            Some("macro_addr") => {
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
            Some("macro") | Some("macro_addr") => {
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
                            match p.as_node_tag() {
                                Some("expr") => Expression::try_from(pair_descend(p, 1)?),
                                Some("addr") => Ok(Expression::DestinationAddress(
                                    pair_descend(p, 1)?.as_str().to_owned(),
                                )),
                                _ => anyhow::bail!("Unhandled pair: {p:?}"),
                            }
                        })
                        .collect::<Result<_, _>>()?,
                })
            }
            Some("array") => Ok(Expression::Collection {
                complement: false,
                values: pair
                    .into_inner()
                    .map(|p| Expression::try_from(pair_descend(p, 1)?))
                    .collect::<Result<_, _>>()?,
            }),
            Some("set") => {
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
    let (val, metadata) = match pair.as_node_tag() {
        Some("oct") => (i128::from_str_radix(pair.as_str(), 8)?, None),
        Some("hex") => (
            pair.as_str()
                .strip_prefix("0x")
                .map(|s| i128::from_str_radix(s, 16))
                .unwrap()?,
            None,
        ),
        Some("dec") => {
            let mut children = pair.into_inner();
            let val_pair = children
                .next()
                .ok_or_else(|| anyhow::anyhow!("Missing dec value node"))?;
            let mut metadata_pair = children.next();
            // TODO use Option::take_if if it gets stable
            if metadata_pair
                .as_ref()
                .is_some_and(|p| p.as_node_tag() == Some("com"))
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
        match pair.as_node_tag() {
            Some("lit") => {
                let pair = pair_descend(pair, 1)?;
                lit_pair(pair)
            }
            Some("named") => {
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
            Some("or") => {
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
            Some("mul") => {
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
            Some("lshift") => {
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
        let pair_tag = pair
            .as_node_tag()
            .ok_or_else(|| anyhow::anyhow!("Unhandled pair: {pair:?}"))?
            .to_owned();
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

        let args = if pair_tag.as_str() != "end" {
            let args_pair = subpairs
                .next()
                .ok_or_else(|| anyhow::anyhow!("Missing arguments node"))?;
            let args_pair = pair_descend(args_pair, 1)?;
            match args_pair.as_node_tag() {
                Some("unnamed") => args_pair
                    .into_inner()
                    .map(|p| {
                        let p = pair_descend(p, 1)?;
                        match p.as_node_tag() {
                            Some("in") => pair_descend(p, 2)?.try_into(),
                            Some("in_out") => {
                                // Only take the 'in' part, ignore the rest
                                pair_descend(p, 2)?.try_into()
                            }
                            _ => anyhow::bail!("Unhandled pair: {p:?}"),
                        }
                    })
                    .collect::<Result<_, _>>()?,
                Some("named") => {
                    // Handle name arguments as a single struct
                    vec![Expression::Struct(
                        args_pair
                            .into_inner()
                            .map(|p| -> anyhow::Result<_> {
                                let (name, val) = p.into_inner().next_tuple().ok_or_else(|| {
                                    anyhow::anyhow!("Missing name arguments nodes")
                                })?;
                                Ok((name.as_str().to_owned(), pair_descend(val, 1)?.try_into()?))
                            })
                            .collect::<Result<_, _>>()?,
                    )]
                }
                _ => anyhow::bail!("Unhandled pair: {args_pair:?}"),
            }
        } else {
            vec![]
        };
        let ret_val = match pair_tag.as_str() {
            "complete" | "end" => {
                let ret_val_pair = pair_descend(
                    subpairs
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Missing return value node"))?,
                    2,
                )?;
                if let IntegerExpressionValue::Literal(val) =
                    IntegerExpression::try_from(ret_val_pair)?.value
                {
                    val
                } else {
                    anyhow::bail!("Return value is not a literal int");
                }
            }
            "start" => i128::MAX,
            tag => anyhow::bail!("Unhandled pair tag: {tag:?}"),
        };
        Ok(Syscall {
            pid,
            rel_ts,
            name,
            args,
            ret_val,
        })
    }
}
