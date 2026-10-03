//! Padding scheme for the first packets of hop sessions (§9.7.4), in the
//! manner of AnyTLS: for packet number `n`, a list of segment size ranges.
//! A `c` entry means "stop splitting here if the payload is exhausted".

use anyhow::{Result, anyhow, bail};
use rand::Rng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seg {
    Range(u16, u16),
    Check,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scheme {
    pub stop: u32,
    pub lines: Vec<(u32, Vec<Seg>)>,
}

pub fn parse_line(s: &str) -> Result<(u32, Vec<Seg>)> {
    let (n, rest) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("padding line without '=': {s:?}"))?;
    let n: u32 = n.trim().parse()?;
    let mut segs = Vec::new();
    for p in rest.split(',') {
        let p = p.trim();
        if p == "c" {
            segs.push(Seg::Check);
            continue;
        }
        let (a, b) = p
            .split_once('-')
            .ok_or_else(|| anyhow!("bad padding range {p:?}"))?;
        let (a, b): (u16, u16) = (a.parse()?, b.parse()?);
        if a > b || b > 16384 {
            bail!("bad padding range {p:?}");
        }
        segs.push(Seg::Range(a, b));
    }
    Ok((n, segs))
}

/// The built-in padding scheme, like AnyTLS's: `stop` and its lines.
pub const DEFAULT_STOP: u32 = 8;
pub const DEFAULT_LINES: [&str; 8] = [
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000",
];

impl Scheme {
    /// The built-in default (`DEFAULT_LINES`).
    pub fn default_scheme() -> Scheme {
        Scheme {
            stop: DEFAULT_STOP,
            lines: DEFAULT_LINES
                .iter()
                .filter_map(|l| parse_line(l).ok())
                .collect(),
        }
    }

    pub fn from_wire(p: &webjet_proto::PaddingScheme) -> Result<Scheme> {
        let lines = p
            .lines
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|l| parse_line(l))
            .collect::<Result<Vec<_>>>()?;
        Ok(Scheme {
            stop: p.stop,
            lines,
        })
    }

    pub fn segments(&self, pkt: u32) -> Option<&[Seg]> {
        if pkt >= self.stop {
            return None;
        }
        self.lines
            .iter()
            .find(|(n, _)| *n == pkt)
            .map(|(_, s)| s.as_slice())
    }

    /// Split a payload of `len` bytes for packet `pkt` into record sizes
    /// `(data_bytes, pad_bytes)`. Returns `None` when the scheme no longer
    /// applies.
    pub fn plan(&self, pkt: u32, len: usize) -> Option<Vec<(usize, usize)>> {
        let segs = self.segments(pkt)?;
        let mut rng = rand::thread_rng();
        let mut left = len;
        let mut out = Vec::new();
        for s in segs {
            match s {
                Seg::Check => {
                    if left == 0 {
                        break;
                    }
                }
                Seg::Range(a, b) => {
                    let size = rng.gen_range(*a as usize..=*b as usize);
                    let data = left.min(size);
                    out.push((data, size - data));
                    left -= data;
                }
            }
        }
        if left > 0 {
            out.push((left, 0));
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_covers_payload() {
        let s = Scheme::default_scheme();
        for pkt in 0..10 {
            for len in [0usize, 10, 700, 5000] {
                if let Some(p) = s.plan(pkt, len) {
                    assert_eq!(p.iter().map(|x| x.0).sum::<usize>(), len);
                }
            }
        }
        assert!(s.plan(8, 10).is_none());
    }
}
