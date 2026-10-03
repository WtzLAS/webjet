//! `webjetd.toml` (§13.4): local, per-node settings. Everything that must be
//! the same network-wide lives in the tree instead.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use webjet_proto::Transport;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub listen: Listen,
    /// Public addresses to advertise when they differ from the listen
    /// addresses (port forwarding, cloud NAT).
    #[serde(default)]
    pub public: Vec<PublicAddr>,
    #[serde(default)]
    pub tun: Tun,
    #[serde(default)]
    pub dns: Dns,
    #[serde(default)]
    pub gateway: Gateway,
    #[serde(default)]
    pub limits: LocalLimits,
    /// OpenMetrics endpoint for Prometheus (§12.5).
    #[serde(default)]
    pub metrics: MetricsCfg,
    /// Local transport priorities (§9.6); override the tree's.
    #[serde(default)]
    pub transport: HashMap<String, u8>,
    #[serde(default)]
    pub controller: ControllerCfg,
    /// The control socket for `webjetctl` (§13.1).
    #[serde(default = "default_control")]
    pub control_socket: PathBuf,
    #[serde(default = "default_log")]
    pub log: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    pub tls: Option<SocketAddr>,
    pub kcp: Option<SocketAddr>,
    pub anytls: Option<SocketAddr>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAddr {
    pub addr: SocketAddr,
    pub transport: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tun {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub name: Option<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

impl Default for Tun {
    fn default() -> Self {
        Tun {
            enabled: true,
            name: None,
            mtu: default_mtu(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// Install split DNS for the suffix and forwarded zones (§11.10.7).
    #[serde(default = "yes")]
    pub configure_system: bool,
}

impl Default for Dns {
    fn default() -> Self {
        Dns {
            configure_system: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    /// Subnet routes this node serves, within its grants (§11.9.2).
    #[serde(default)]
    pub route: Vec<GatewayRoute>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayRoute {
    pub published: String,
    pub interface: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct LocalLimits {
    pub relay_capacity_mbps: Option<u32>,
    pub rate_ceiling_mbps: Option<u32>,
    #[serde(flatten)]
    pub other: HashMap<String, u64>,
}

impl LocalLimits {
    pub fn get(&self, name: &str) -> Option<u64> {
        match name {
            "relay_capacity_mbps" => self.relay_capacity_mbps.map(|v| v as u64),
            "rate_ceiling_mbps" => self.rate_ceiling_mbps.map(|v| v as u64),
            _ => self.other.get(name).copied(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsCfg {
    /// `host:port` to serve `/metrics` on. On a controller it serves every
    /// node's latest report (the network-wide scrape target); elsewhere this
    /// node's own metrics. Keep it on localhost or the overlay IP (§4.1).
    pub listen: Option<SocketAddr>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerCfg {
    /// Run the controller role (requires a SigningKeyCert for this node).
    #[serde(default)]
    pub enabled: bool,
    /// `webjet-signer` socket; when absent an in-process key file is used.
    pub signer_socket: Option<PathBuf>,
    /// Tree head lifetime in hours (§7.3, §24: 24–72 h).
    #[serde(default = "default_head_hours")]
    pub head_lifetime_hours: u64,
}

fn yes() -> bool {
    true
}
fn default_mtu() -> u16 {
    1280
}
fn default_head_hours() -> u64 {
    48
}
fn default_data_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/webjet")
    } else if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\webjet")
    } else {
        PathBuf::from("/var/lib/webjet")
    }
}
fn default_control() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"\\.\pipe\webjet")
    } else {
        PathBuf::from("/run/webjet/control.sock")
    }
}
fn default_log() -> String {
    "info".into()
}

impl Default for Config {
    fn default() -> Self {
        toml::from_str("").expect("defaults")
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Config> {
        let Some(p) = path else {
            return Ok(Config::default());
        };
        if !p.exists() {
            return Ok(Config::default());
        }
        let s = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        let mut c: Config = toml::from_str(&s).with_context(|| format!("parse {}", p.display()))?;
        if c.control_socket.is_relative() {
            c.control_socket = c.data_dir.join(&c.control_socket);
        }
        Ok(c)
    }

    pub fn local_priority(&self, t: Transport) -> Option<u8> {
        self.transport
            .iter()
            .find(|(k, _)| Transport::parse(k) == Some(t))
            .map(|(_, v)| *v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_example() {
        let c: Config = toml::from_str(
            r#"
data_dir = "/tmp/wj"
[listen]
tls = "0.0.0.0:443"
kcp = "0.0.0.0:443"
[tun]
mtu = 1300
[[gateway.route]]
published = "10.2.2.0/24"
interface = "eth1"
[limits]
relay_capacity_mbps = 900
conntrack_per_peer = 100
[transport]
"tcp+tls" = 5
"#,
        )
        .unwrap();
        assert_eq!(c.tun.mtu, 1300);
        assert_eq!(c.limits.get("conntrack_per_peer"), Some(100));
        assert_eq!(c.local_priority(Transport::TcpTls), Some(5));
        assert_eq!(c.gateway.route.len(), 1);
    }
}
