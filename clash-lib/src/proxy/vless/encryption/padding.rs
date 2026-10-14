use std::io;

use super::{DEFAULT_PADDING, PaddingKind, PaddingRule, invalid};

pub(super) fn parse_padding(blocks: &[String]) -> io::Result<Vec<PaddingRule>> {
    if blocks.is_empty() {
        return Ok(DEFAULT_PADDING
            .into_iter()
            .map(|(kind, probability, from, to)| PaddingRule {
                kind,
                probability,
                from,
                to,
            })
            .collect());
    }

    let mut rules = Vec::with_capacity(blocks.len());
    let mut max_padding_len = 0_i64;

    for (index, block) in blocks.iter().enumerate() {
        let parts = block.split('-').collect::<Vec<_>>();
        if parts.len() < 3 || parts[..3].iter().any(|part| part.is_empty()) {
            return Err(invalid(format!(
                "invalid vless encryption padding length/gap parameter: {block}"
            )));
        }

        let parse = |value: &str| {
            value.parse::<i64>().map_err(|err| {
                invalid(format!(
                    "invalid vless encryption padding parameter '{block}': {err}"
                ))
            })
        };
        let probability = parse(parts[0])?;
        let from = parse(parts[1])?;
        let to = parse(parts[2])?;

        if !(0..=100).contains(&probability) {
            return Err(invalid(format!(
                "vless encryption padding probability must be between 0 and 100: {block}"
            )));
        }
        if from < 0 || to < 0 || from > to {
            return Err(invalid(format!(
                "invalid vless encryption padding range: {block}"
            )));
        }
        if index == 0 && (probability != 100 || from < 35 || to < 35) {
            return Err(invalid(
                "first vless encryption padding length must be 100% and at least 35 bytes",
            ));
        }

        let kind = if index % 2 == 0 {
            max_padding_len = max_padding_len.saturating_add(from.max(to));
            PaddingKind::Length
        } else {
            PaddingKind::Gap
        };
        rules.push(PaddingRule {
            kind,
            probability,
            from,
            to,
        });
    }

    if max_padding_len > 65_553 {
        return Err(invalid(
            "total vless encryption padding length must not exceed 65553 bytes",
        ));
    }

    Ok(rules)
}
