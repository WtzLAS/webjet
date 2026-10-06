//! `webjetd.toml` (§13.4): how this machine runs the agent (addresses,
//! interface, key storage, logging). The network configuration and each
//! node's overrides of it (transport priorities, limits, seeds, DNS) live in
//! the signed tree instead (§6.18, §6.19) and are changed with
//! `webjetctl network config` and `webjetctl local config`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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
    /// This node as a reverse proxy target (§11.11).
    #[serde(default)]
    pub proxy: ProxyCfg,
    /// Direct paths and hole punching (§11.7): which local addresses are
    /// offered as candidates and which peer addresses may be dialed.
    #[serde(default)]
    pub nat: NatCfg,
    /// Removed in 0.4.0 (now node-scope configuration in the tree); kept
    /// only to explain the move when an old file still has it.
    #[serde(default)]
    limits: Option<toml::Value>,
    /// Where the identity key is stored at rest (§8.3).
    #[serde(default)]
    pub key: crate::keystore::KeyCfg,
    /// OpenMetrics endpoint for Prometheus (§12.5).
    #[serde(default)]
    pub metrics: MetricsCfg,
    /// Removed in 0.4.0, like `limits`.
    #[serde(default)]
    transport: Option<toml::Value>,
    #[serde(default)]
    pub controller: ControllerCfg,
    /// The control socket for `webjetctl` (§13.1).
    #[serde(default = "default_control")]
    pub control_socket: PathBuf,
    #[serde(default = "default_log")]
    pub log: String,
    /// `json` for structured JSON lines (§19.6), otherwise text.
    #[serde(default)]
    pub log_format: Option<String>,
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
    /// `ip:port`, `[ipv6]:port` or `name:port`; a DNS name is resolved
    /// while the agent runs and every address it gives is advertised.
    pub addr: HostPort,
    pub transport: String,
}

/// `host:port` where the host is an IP address or a DNS name.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl HostPort {
    /// The socket address when the host is an IP address.
    pub fn ip(&self) -> Option<SocketAddr> {
        let ip: std::net::IpAddr = self.host.parse().ok()?;
        Some(SocketAddr::new(ip, self.port))
    }

    /// The DNS name, when the host isn't an IP address.
    pub fn name(&self) -> Option<&str> {
        self.ip().is_none().then_some(self.host.as_str())
    }
}

impl TryFrom<String> for HostPort {
    type Error = String;
    fn try_from(s: String) -> std::result::Result<Self, String> {
        if let Ok(a) = s.parse::<SocketAddr>() {
            return Ok(HostPort {
                host: a.ip().to_string(),
                port: a.port(),
            });
        }
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("{s:?}: expected host:port"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| format!("{s:?}: port {port:?} isn't a number from 1 to 65535"))?;
        if port == 0 {
            return Err(format!("{s:?}: port 0"));
        }
        let host = host.strip_suffix('.').unwrap_or(host);
        if host.contains(':') || !webjet_core::validate::valid_dns_name(host) {
            return Err(format!(
                "{s:?}: the host must be an IP address (IPv6 in brackets) or a DNS name"
            ));
        }
        Ok(HostPort {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

impl std::fmt::Display for HostPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip() {
            Some(a) => write!(f, "{a}"),
            None => write!(f, "{}:{}", self.host, self.port),
        }
    }
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
#[serde(deny_unknown_fields)]
pub struct ProxyCfg {
    /// Accept reverse proxy flows that keep the client's real address as
    /// their source, and route the replies back into the overlay (Linux,
    /// with the tun interface). Off: proxies reach this node from their
    /// own overlay address instead.
    #[serde(default)]
    pub accept_real_ip: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatCfg {
    /// Leave out tunnel interfaces (point-to-point ones, and names like
    /// `wg*`, `tun*`, `utun*`, `tailscale*`, `zt*`, `ppp*`): another VPN is
    /// not a direct path. Peer addresses the system would reach through
    /// such an interface aren't dialed either, unless all traffic goes
    /// through it (a full-tunnel VPN).
    #[serde(default = "yes")]
    pub skip_tunnels: bool,
    /// More interfaces to leave out (`*` matches any characters).
    #[serde(default)]
    pub exclude_interfaces: Vec<String>,
    /// Interfaces to use even though they look like tunnels.
    #[serde(default)]
    pub allow_interfaces: Vec<String>,
    /// Addresses never offered nor dialed for direct paths (`10.1.1.0/24`).
    #[serde(default, deserialize_with = "nets")]
    pub exclude_cidrs: Vec<ipnet::IpNet>,
    /// Ask the router for a port mapping (UPnP IGD, NAT-PMP, PCP) and
    /// offer it as a candidate.
    #[serde(default = "yes")]
    pub port_mapping: bool,
}

impl Default for NatCfg {
    fn default() -> Self {
        NatCfg {
            skip_tunnels: true,
            exclude_interfaces: Vec::new(),
            allow_interfaces: Vec::new(),
            exclude_cidrs: Vec::new(),
            port_mapping: true,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerCfg {
    /// The controller role runs when the network grants this node CONTROL
    /// (the `control` role, §4). `false` keeps it from running here anyway.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// `webjetd signer` socket; when absent an in-process key file is used.
    pub signer_socket: Option<PathBuf>,
    /// Tree head lifetime in hours (§7.3, §24: 24–72 h).
    #[serde(default = "default_head_hours")]
    pub head_lifetime_hours: u64,
}

impl Default for ControllerCfg {
    fn default() -> Self {
        ControllerCfg {
            enabled: true,
            signer_socket: None,
            head_lifetime_hours: default_head_hours(),
        }
    }
}

fn yes() -> bool {
    true
}

fn nets<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<ipnet::IpNet>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|s| {
            s.parse::<ipnet::IpNet>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .map(|n| n.trunc())
                .map_err(|_| serde::de::Error::custom(format!("{s:?} is not an address or prefix")))
        })
        .collect()
}
fn default_mtu() -> u16 {
    1280
}
fn default_head_hours() -> u64 {
    48
}
fn default_data_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Webjet/state")
    } else if cfg!(windows) {
        program_data().join("Webjet").join("state")
    } else {
        PathBuf::from("/var/lib/webjet")
    }
}
fn default_control() -> PathBuf {
    crate::ipc::default_control()
}

fn program_data() -> PathBuf {
    std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
}

/// Where webjetd.toml lives by default (§19.1).
pub fn default_config_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Webjet/webjetd.toml")
    } else if cfg!(windows) {
        program_data().join("Webjet").join("webjetd.toml")
    } else {
        PathBuf::from("/etc/webjet/webjetd.toml")
    }
}
fn default_log() -> String {
    "info".into()
}

impl Default for Config {
    fn default() -> Self {
        // Every field has a serde default, so an empty document always parses.
        toml::from_str("").unwrap_or_else(|e| unreachable!("default configuration: {e}"))
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
        c.check_removed()
            .with_context(|| format!("in {}", p.display()))?;
        if c.control_socket.is_relative() {
            c.control_socket = c.data_dir.join(&c.control_socket);
        }
        Ok(c)
    }

    /// Use `dir` as the data directory (`--data-dir`). Without a config file
    /// the control socket moves with it.
    pub fn override_data_dir(&mut self, dir: PathBuf, have_config_file: bool) {
        self.data_dir = dir;
        if !have_config_file {
            self.control_socket = if cfg!(windows) {
                crate::ipc::default_control()
            } else {
                self.data_dir.join("control.sock")
            };
        }
    }

    /// Sections that moved into the tree in 0.4.0: refuse to start with them
    /// rather than silently ignore what the operator meant to set.
    fn check_removed(&self) -> Result<()> {
        let mut moved = Vec::new();
        if let Some(t) = &self.transport {
            moved.push(format!(
                "[transport] -> `webjetctl local config set transport.priority.<kcp|anytls|tls> <0-255>` ({})",
                t.to_string().trim()
            ));
        }
        if let Some(l) = &self.limits {
            moved.push(format!(
                "[limits] -> `webjetctl local config set limits.value.<name> <value>` ({})",
                l.to_string().trim()
            ));
        }
        if moved.is_empty() {
            return Ok(());
        }
        anyhow::bail!(
            "these sections moved to this node's configuration in the network tree (0.4.0); remove them here and set them with webjetctl:\n  {}",
            moved.join("\n  ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_section() {
        let c: Config = toml::from_str("").unwrap();
        assert!(c.nat.skip_tunnels && c.nat.port_mapping);
        let c: Config = toml::from_str(
            "[nat]\nskip_tunnels = false\nexclude_interfaces = [\"eth9\"]\nallow_interfaces = [\"wg-lan\"]\nexclude_cidrs = [\"10.1.1.7/24\", \"192.0.2.1\"]\nport_mapping = false\n",
        )
        .unwrap();
        assert!(!c.nat.skip_tunnels && !c.nat.port_mapping);
        assert_eq!(c.nat.exclude_cidrs[0].to_string(), "10.1.1.0/24");
        assert_eq!(c.nat.exclude_cidrs[1].to_string(), "192.0.2.1/32");
        assert!(toml::from_str::<Config>("[nat]\nexclude_cidrs = [\"nope\"]\n").is_err());
    }
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
[controller]
enabled = false
"#,
        )
        .unwrap();
        assert_eq!(c.tun.mtu, 1300);
        assert_eq!(c.gateway.route.len(), 1);
        assert!(!c.controller.enabled);
        assert!(c.check_removed().is_ok());
        assert!(Config::default().controller.enabled);
    }

    #[test]
    fn public_addresses_take_ips_and_dns_names() {
        let c: Config = toml::from_str(
            r#"
[[public]]
addr = "203.0.113.5:443"
transport = "tls"
[[public]]
addr = "[2001:db8::1]:443"
transport = "kcp"
[[public]]
addr = "SV.wolf109909.top.:4883"
transport = "kcp"
"#,
        )
        .unwrap();
        let p: Vec<_> = c.public.iter().map(|p| &p.addr).collect();
        assert_eq!(p[0].ip(), Some("203.0.113.5:443".parse().unwrap()));
        assert_eq!(p[1].ip(), Some("[2001:db8::1]:443".parse().unwrap()));
        assert_eq!(p[2].ip(), None);
        assert_eq!(p[2].name(), Some("sv.wolf109909.top"));
        assert_eq!(p[2].port, 4883);
        assert_eq!(p[2].to_string(), "sv.wolf109909.top:4883");
        for bad in [
            "sv.wolf109909.top",
            "sv.wolf109909.top:0",
            "bad host:443",
            "2001:db8::1:443",
        ] {
            let t = format!("[[public]]\naddr = \"{bad}\"\ntransport = \"kcp\"\n");
            assert!(toml::from_str::<Config>(&t).is_err(), "{bad}");
        }
    }

    #[test]
    fn moved_sections_are_refused() {
        let c: Config =
            toml::from_str("[transport]\nkcp = 0\n[limits]\nconntrack_per_peer = 9\n").unwrap();
        let e = c.check_removed().unwrap_err().to_string();
        assert!(
            e.contains("transport.priority") && e.contains("limits."),
            "{e}"
        );
    }
}
