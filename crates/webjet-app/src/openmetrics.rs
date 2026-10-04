//! Reading the OpenMetrics text the agent exports (§12.5, the same text
//! Prometheus scrapes) back into families and samples for the Metrics tab.

/// One sample line: `name{labels} value [timestamp]`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sample {
    /// The full sample name, e.g. `webjet_route_bytes_total`.
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub value: f64,
    /// Unix milliseconds, when the sample carries one.
    pub ts_ms: Option<u64>,
}

impl Sample {
    pub fn label(&self, k: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }

    /// `k="v", …` without the labels every sample of a report shares.
    pub fn labels_text(&self, skip: &[&str]) -> String {
        self.labels
            .iter()
            .filter(|(k, _)| !skip.contains(&k.as_str()))
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("  ")
    }
}

/// A metric family: its `# TYPE` / `# HELP` metadata and its samples.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Family {
    pub name: String,
    /// `counter`, `gauge`, … (`unknown` without a TYPE line).
    pub kind: String,
    pub help: String,
    pub samples: Vec<Sample>,
}

impl Family {
    /// Sum of all sample values.
    pub fn total(&self) -> f64 {
        self.samples.iter().map(|s| s.value).sum()
    }

    /// Case-insensitive match on the name, help text or a label value.
    pub fn matches(&self, filter: &str) -> bool {
        let f = filter.trim().to_ascii_lowercase();
        f.is_empty()
            || self.name.to_ascii_lowercase().contains(&f)
            || self.help.to_ascii_lowercase().contains(&f)
            || self.samples.iter().any(|s| {
                s.labels
                    .iter()
                    .any(|(_, v)| v.to_ascii_lowercase().contains(&f))
            })
    }
}

/// Parse an OpenMetrics text exposition. Lines that don't parse are skipped:
/// this only feeds a viewer.
pub fn parse(text: &str) -> Vec<Family> {
    let mut out: Vec<Family> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line == "# EOF" {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            let mut it = rest.splitn(3, ' ');
            let (Some(what), Some(name)) = (it.next(), it.next()) else {
                continue;
            };
            let arg = it.next().unwrap_or("").to_string();
            let f = family(&mut out, name);
            match what {
                "TYPE" => f.kind = arg,
                "HELP" => f.help = unescape(&arg),
                _ => {}
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let Some(s) = sample(line) else { continue };
        let base = base_name(&out, &s.name);
        family(&mut out, &base).samples.push(s);
    }
    for f in &mut out {
        if f.kind.is_empty() {
            f.kind = "unknown".into();
        }
    }
    out
}

fn family<'a>(out: &'a mut Vec<Family>, name: &str) -> &'a mut Family {
    let i = match out.iter().position(|f| f.name == name) {
        Some(i) => i,
        None => {
            out.push(Family {
                name: name.to_string(),
                ..Default::default()
            });
            out.len() - 1
        }
    };
    &mut out[i]
}

/// The family a sample belongs to: its name, or its name without an
/// OpenMetrics suffix when a family of that name was declared.
fn base_name(out: &[Family], sample: &str) -> String {
    for suffix in ["_total", "_created", "_count", "_sum", "_bucket", "_info"] {
        if let Some(b) = sample.strip_suffix(suffix)
            && out.iter().any(|f| f.name == b)
        {
            return b.to_string();
        }
    }
    sample.to_string()
}

fn unescape(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => o.push('\n'),
                Some(x) => o.push(x),
                None => o.push('\\'),
            }
        } else {
            o.push(c);
        }
    }
    o
}

fn sample(line: &str) -> Option<Sample> {
    let (name, rest) = line.split_at(line.find(['{', ' '])?);
    let mut labels = Vec::new();
    let rest = if let Some(r) = rest.strip_prefix('{') {
        // Label values are quoted and may contain escaped quotes and braces.
        let mut chars = r.char_indices().peekable();
        let mut end = None;
        loop {
            // key
            while chars.peek().is_some_and(|(_, c)| *c == ',' || *c == ' ') {
                chars.next();
            }
            match chars.peek() {
                Some((i, '}')) => {
                    end = Some(*i + 1);
                    break;
                }
                None => break,
                _ => {}
            }
            let mut key = String::new();
            for (_, c) in chars.by_ref() {
                if c == '=' {
                    break;
                }
                key.push(c);
            }
            if chars.next().map(|(_, c)| c) != Some('"') {
                return None;
            }
            let mut val = String::new();
            let mut closed = false;
            while let Some((_, c)) = chars.next() {
                match c {
                    '\\' => match chars.next() {
                        Some((_, 'n')) => val.push('\n'),
                        Some((_, x)) => val.push(x),
                        None => return None,
                    },
                    '"' => {
                        closed = true;
                        break;
                    }
                    c => val.push(c),
                }
            }
            if !closed {
                return None;
            }
            labels.push((key.trim().to_string(), val));
        }
        r.get(end?..)?
    } else {
        rest
    };
    let mut parts = rest.split_whitespace();
    let value = match parts.next()? {
        "+Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        v => v.parse().ok()?,
    };
    let ts_ms = parts
        .next()
        .and_then(|t| t.parse::<f64>().ok())
        .map(|t| (t * 1000.0).round() as u64);
    Some(Sample {
        name: name.to_string(),
        labels,
        value,
        ts_ms,
    })
}

/// A value for people: integers as such, ratios and fractions with up to
/// three decimals, bytes with a unit when the family counts bytes.
pub fn value_text(family: &str, v: f64) -> String {
    if family.contains("bytes") {
        return crate::model::bytes(v.max(0.0) as u64);
    }
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else if family.ends_with("_ratio") {
        format!("{:.1}%", v * 100.0)
    } else {
        format!("{v:.3}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = r#"# TYPE webjet_route_bytes counter
# HELP webjet_route_bytes Bytes on a route.
webjet_route_bytes_total{node="n1",owner="alice",route_id="09",direction="fwd"} 1000 1700000000.123
webjet_route_bytes_total{node="n1",owner="alice",route_id="09",direction="rev"} 24 1700000000.123
# TYPE webjet_link_loss_ratio gauge
# HELP webjet_link_loss_ratio Packet loss on a hop, 0 to 1.
webjet_link_loss_ratio{node="n1",peer="n3",transport="kcp"} 0.05 1700000000.123
# TYPE webjet_rule_flows counter
# HELP webjet_rule_flows Flows a rule admitted.
webjet_rule_flows_total{rule_id="web \"tier\" {x}",decision="allow"} 7
# EOF
"#;

    #[test]
    fn parses_the_agents_exposition() {
        let f = parse(TEXT);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].name, "webjet_route_bytes");
        assert_eq!(f[0].kind, "counter");
        assert_eq!(f[0].help, "Bytes on a route.");
        assert_eq!(f[0].samples.len(), 2);
        assert_eq!(f[0].total(), 1024.0);
        assert_eq!(f[0].samples[0].label("direction"), Some("fwd"));
        assert_eq!(f[0].samples[0].ts_ms, Some(1_700_000_000_123));
        assert_eq!(f[1].samples[0].value, 0.05);
        assert_eq!(f[2].samples[0].label("rule_id"), Some("web \"tier\" {x}"));
        assert_eq!(f[2].samples[0].ts_ms, None);
        assert!(f[1].matches("LOSS") && f[1].matches("kcp") && !f[1].matches("route"));
        assert_eq!(
            f[0].samples[0].labels_text(&["node", "owner"]),
            "route_id=09  direction=fwd"
        );
    }

    #[test]
    fn tolerates_junk_and_families_without_metadata() {
        let f = parse("garbage\nfoo 3\nbar{a=\"unterminated} 1\n# EOF\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "unknown");
        assert_eq!(f[0].samples[0].value, 3.0);
    }

    #[test]
    fn formats_values() {
        assert_eq!(value_text("webjet_link_loss_ratio", 0.05), "5.0%");
        assert_eq!(value_text("webjet_route_bytes", 2048.0), "2.0 KiB");
        assert_eq!(value_text("webjet_report_seq", 12.0), "12");
        assert_eq!(value_text("webjet_link_rtt_ms", 1.23456), "1.235");
    }
}
