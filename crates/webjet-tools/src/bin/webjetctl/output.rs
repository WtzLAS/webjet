//! Printing results: text or `--json`.

use crate::cli::*;
use anyhow::{Result, anyhow};
use serde_json::Value;
use webjet_core::types::now_ms;

pub(crate) fn print(cli: &Cli, v: &Value) {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
        return;
    }
    match v {
        Value::Object(_) | Value::Array(_) => println!(
            "{}",
            serde_yaml::to_string(v).unwrap_or_default().trim_end()
        ),
        other => println!("{other}"),
    }
}

/// The result of a command: a sentence for people, an object with `--json`.
pub(crate) fn report(cli: &Cli, text: impl std::fmt::Display, v: Value) {
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        println!("{text}");
    }
}

/// When a token issued now for `hours` expires (ms since the epoch).
pub(crate) fn expires_at(hours: u64) -> Result<u64> {
    hours
        .checked_mul(3_600_000)
        .and_then(|ms| now_ms().checked_add(ms))
        .ok_or_else(|| anyhow!("--expires-hours {hours} is too far in the future"))
}

/// The log entry index a submit reply names.
pub(crate) fn entry(r: &Value) -> Value {
    r["index"].clone()
}

pub(crate) fn print_table(rows: &[Vec<String>]) {
    if rows.is_empty() {
        return;
    }
    let cols = rows[0].len();
    let w: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .map(|r| r.get(c).map_or(0, |s| s.len()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    for r in rows {
        let line: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, s)| format!("{:<w$}", s, w = w[i]))
            .collect();
        println!("{}", line.join("  ").trim_end());
    }
}
