//! Operating-system integration (§19.1): routes, split DNS, gateway NAT and
//! local interface information.
//!
//! | | Linux | macOS | Windows |
//! |---|---|---|---|
//! | routes | `ip route` | `route` | `netsh interface ipvX ... route` (active store) |
//! | split DNS | systemd-resolved (`resolvectl`) | `/etc/resolver/<domain>` | NRPT rules (comment `webjet`) |
//! | gateway NAT | iptables MASQUERADE | — | — (gateways run on Linux) |
//! | reverse proxy | iptables DNAT, connmark + policy routing | — | — (Linux only) |
//!
//! Everything the agent adds is removed again by [`cleanup`] (at shutdown and
//! on uninstall).

use ipnet::IpNet;
use std::net::IpAddr;
use std::process::Command;

/// Marker for system state the agent owns (NRPT comment, resolver files).
pub const OWNER_TAG: &str = "webjet";

fn run(cmd: &str, args: &[&str]) -> bool {
    let mut c = Command::new(cmd);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match c.output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            tracing::debug!(
                "{cmd} {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::debug!("{cmd}: {e}");
            false
        }
    }
}

#[cfg(windows)]
fn powershell(script: &str) -> bool {
    run(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
    )
}

/// PowerShell single-quoted string literal.
pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

// ---------------------------------------------------------------- routes

/// The command that adds (or removes) a route to `net` through `dev`.
pub fn route_cmd(add: bool, net: &IpNet, dev: &str) -> (&'static str, Vec<String>) {
    let n = net.to_string();
    if cfg!(target_os = "linux") {
        let verb = if add { "replace" } else { "del" };
        (
            "ip",
            vec!["route".into(), verb.into(), n, "dev".into(), dev.into()],
        )
    } else if cfg!(target_os = "macos") {
        let fam = if net.addr().is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        let verb = if add { "add" } else { "delete" };
        (
            "route",
            vec![
                "-q".into(),
                "-n".into(),
                verb.into(),
                fam.into(),
                n,
                "-interface".into(),
                dev.into(),
            ],
        )
    } else {
        let fam = if net.addr().is_ipv4() { "ipv4" } else { "ipv6" };
        let verb = if add { "add" } else { "delete" };
        (
            "netsh",
            vec![
                "interface".into(),
                fam.into(),
                verb.into(),
                "route".into(),
                format!("prefix={n}"),
                format!("interface={dev}"),
                "store=active".into(),
            ],
        )
    }
}

pub fn add_route(net: &IpNet, dev: &str) {
    let (cmd, args) = route_cmd(true, net, dev);
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    if run(cmd, &a) {
        tracing::debug!("route {net} via {dev}");
    } else {
        tracing::warn!("could not add route {net} via {dev}");
    }
}

pub fn del_route(net: &IpNet, dev: &str) {
    let (cmd, args) = route_cmd(false, net, dev);
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    run(cmd, &a);
}

// ---------------------------------------------------------------- split DNS (§11.10.1)

/// The PowerShell that replaces webjet's NRPT rules with one per domain.
pub fn nrpt_script(resolver: &[IpAddr], domains: &[String]) -> String {
    let ns = resolver
        .iter()
        .map(|r| ps_quote(&r.to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let mut s = format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq {} }} | Remove-DnsClientNrptRule -Force; ",
        ps_quote(OWNER_TAG)
    );
    for d in domains {
        s.push_str(&format!(
            "Add-DnsClientNrptRule -Namespace {} -NameServers @({ns}) -Comment {} | Out-Null; ",
            ps_quote(&format!(".{}", d.trim_matches('.'))),
            ps_quote(OWNER_TAG)
        ));
    }
    s.push_str("Clear-DnsClientCache");
    s
}

pub fn configure_dns(dev: &str, resolver: &[IpAddr], domains: &[String]) {
    if resolver.is_empty() {
        return;
    }
    if cfg!(target_os = "linux") {
        let mut args: Vec<String> = vec!["dns".into(), dev.into()];
        args.extend(resolver.iter().map(|r| r.to_string()));
        let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        if !run("resolvectl", &a) {
            tracing::warn!(
                "resolvectl not available; configure DNS for {} manually",
                domains.join(", ")
            );
            return;
        }
        let mut d: Vec<String> = vec!["domain".into(), dev.into()];
        d.extend(domains.iter().map(|x| format!("~{x}")));
        let a: Vec<&str> = d.iter().map(|s| s.as_str()).collect();
        run("resolvectl", &a);
    } else if cfg!(target_os = "macos") {
        let _ = std::fs::create_dir_all("/etc/resolver");
        // Remove files of domains no longer configured.
        if let Ok(rd) = std::fs::read_dir("/etc/resolver") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let ours = std::fs::read_to_string(e.path())
                    .map(|s| s.contains(&format!("# {OWNER_TAG}")))
                    .unwrap_or(false);
                if ours && !domains.contains(&name) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        for d in domains {
            let body: String = format!("# {OWNER_TAG}\n")
                + &resolver
                    .iter()
                    .map(|r| format!("nameserver {r}\n"))
                    .collect::<String>();
            let _ = std::fs::write(format!("/etc/resolver/{d}"), body);
        }
    } else {
        #[cfg(windows)]
        if !powershell(&nrpt_script(resolver, domains)) {
            tracing::warn!("could not set NRPT rules for {}", domains.join(", "));
        }
    }
}

/// Remove everything the agent configured in the system (§20.8).
pub fn cleanup(dev: &str) {
    if cfg!(target_os = "linux") {
        run("resolvectl", &["revert", dev]);
    } else if cfg!(target_os = "macos") {
        if let Ok(rd) = std::fs::read_dir("/etc/resolver") {
            for e in rd.flatten() {
                if std::fs::read_to_string(e.path())
                    .map(|s| s.contains(&format!("# {OWNER_TAG}")))
                    .unwrap_or(false)
                {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    } else {
        #[cfg(windows)]
        powershell(&format!(
            "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq {} }} | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache",
            ps_quote(OWNER_TAG)
        ));
    }
    let _ = dev;
}

// ---------------------------------------------------------------- gateway NAT (§11.9.4)

/// Masquerade overlay sources out of the LAN interface and allow forwarding
/// between the tun and LAN interfaces. Gateways run on Linux (§19.1).
pub fn setup_gateway_nat(pool: &[IpNet], tun: &str, lan_if: &str) -> bool {
    if !cfg!(target_os = "linux") {
        tracing::warn!("subnet gateways run on Linux only (§19.1)");
        return false;
    }
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
    let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1");
    let mut ok = true;
    for p in pool {
        let bin = if p.addr().is_ipv4() {
            "iptables"
        } else {
            "ip6tables"
        };
        let src = p.to_string();
        let rule = ["-s", src.as_str(), "-o", lan_if, "-j", "MASQUERADE"];
        let mut check = vec!["-t", "nat", "-C", "POSTROUTING"];
        check.extend_from_slice(&rule);
        if !run(bin, &check) {
            let mut add = vec!["-t", "nat", "-A", "POSTROUTING"];
            add.extend_from_slice(&rule);
            ok &= run(bin, &add);
        }
        for (i, o) in [(tun, lan_if), (lan_if, tun)] {
            let fwd = ["-i", i, "-o", o, "-j", "ACCEPT"];
            let mut c = vec!["-C", "FORWARD"];
            c.extend_from_slice(&fwd);
            if !run(bin, &c) {
                let mut a = vec!["-A", "FORWARD"];
                a.extend_from_slice(&fwd);
                run(bin, &a);
            }
        }
    }
    if ok {
        tracing::info!("gateway NAT configured on {lan_if}");
    } else {
        tracing::warn!("gateway NAT setup failed on {lan_if} (iptables missing?)");
    }
    ok
}

// ---------------------------------------------------------------- reverse proxy (§11.11)

/// The ingress's chains (in the nat, filter and mangle tables).
pub const PROXY_CHAIN: &str = "WEBJET-PROXY";
/// The target's chains for real client addresses (mangle table).
pub const REAL_IP_IN: &str = "WEBJET-REALIP";
pub const REAL_IP_OUT: &str = "WEBJET-REALIP-OUT";
/// Connection mark and routing table for replies to real client addresses.
pub const REAL_IP_MARK: &str = "0x574a0000/0xffff0000";
pub const REAL_IP_TABLE: &str = "22346";

fn ipt(v6: bool) -> &'static str {
    if v6 { "ip6tables" } else { "iptables" }
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// Run `bin -t table <op> chain spec`, true when it succeeded.
fn ipt_run(bin: &str, table: &str, op: &str, chain: &str, spec: &[String]) -> bool {
    let mut a: Vec<&str> = vec!["-w", "-t", table, op, chain];
    a.extend(spec.iter().map(String::as_str));
    run(bin, &a)
}

/// Create (or empty) `chain` and make sure `from` jumps to it first.
fn ipt_chain(bin: &str, table: &str, chain: &str, from: &str, jump: &[String]) -> bool {
    ipt_run(bin, table, "-N", chain, &[]);
    let ok = ipt_run(bin, table, "-F", chain, &[]);
    let mut spec = jump.to_vec();
    spec.extend(args(&["-j", chain]));
    ok && (ipt_run(bin, table, "-C", from, &spec) || {
        let mut a = vec!["1".to_string()];
        a.extend(spec);
        ipt_run(bin, table, "-I", from, &a)
    })
}

/// Remove `chain` and every jump from `from` to it.
fn ipt_drop_chain(bin: &str, table: &str, chain: &str, from: &str, jump: &[String]) {
    let mut spec = jump.to_vec();
    spec.extend(args(&["-j", chain]));
    for _ in 0..8 {
        if !ipt_run(bin, table, "-D", from, &spec) {
            break;
        }
    }
    ipt_run(bin, table, "-F", chain, &[]);
    ipt_run(bin, table, "-X", chain, &[]);
}

fn nat_jump(tun: &str) -> Vec<String> {
    args(&["-m", "addrtype", "--dst-type", "LOCAL", "!", "-i", tun])
}

/// The rules the ingress puts into its chains, per table: DNAT each listen
/// port to `addr` (the proxy address, routed into the tun interface), let
/// those flows through FORWARD, clamp the TCP MSS to the overlay MTU.
pub fn proxy_ingress_rules(
    tun: &str,
    addr: &IpAddr,
    listens: &[(&str, u16)],
) -> Vec<(&'static str, Vec<String>)> {
    let a = addr.to_string();
    let mut v = Vec::new();
    for (proto, port) in listens {
        v.push((
            "nat",
            args(&[
                "-p",
                proto,
                "--dport",
                &port.to_string(),
                "-j",
                "DNAT",
                "--to-destination",
                &a,
            ]),
        ));
    }
    v.push(("filter", args(&["-o", tun, "-d", &a, "-j", "ACCEPT"])));
    v.push(("filter", args(&["-i", tun, "-s", &a, "-j", "ACCEPT"])));
    v.push((
        "mangle",
        args(&[
            "-o",
            tun,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--clamp-mss-to-pmtu",
        ]),
    ));
    v
}

/// Capture the listen ports into the tun interface (ingress, Linux only).
/// `addrs`: the proxy address of each address family. An empty `listens`
/// removes everything.
pub fn proxy_ingress(tun: &str, addrs: &[IpAddr], listens: &[(&str, u16)]) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let mut ok = true;
    for v6 in [false, true] {
        let bin = ipt(v6);
        let addr = addrs.iter().find(|a| a.is_ipv6() == v6);
        let Some(addr) = addr.filter(|_| !listens.is_empty()) else {
            proxy_ingress_clear_family(tun, v6);
            continue;
        };
        let _ = std::fs::write(
            if v6 {
                "/proc/sys/net/ipv6/conf/all/forwarding"
            } else {
                "/proc/sys/net/ipv4/ip_forward"
            },
            "1",
        );
        ok &= ipt_chain(bin, "nat", PROXY_CHAIN, "PREROUTING", &nat_jump(tun));
        ok &= ipt_chain(bin, "filter", PROXY_CHAIN, "FORWARD", &[]);
        ok &= ipt_chain(bin, "mangle", PROXY_CHAIN, "FORWARD", &[]);
        for (table, spec) in proxy_ingress_rules(tun, addr, listens) {
            ok &= ipt_run(bin, table, "-A", PROXY_CHAIN, &spec);
        }
    }
    if !ok {
        tracing::warn!("reverse proxy: iptables setup failed (iptables missing?)");
    }
    ok
}

fn proxy_ingress_clear_family(tun: &str, v6: bool) {
    let bin = ipt(v6);
    ipt_drop_chain(bin, "nat", PROXY_CHAIN, "PREROUTING", &nat_jump(tun));
    ipt_drop_chain(bin, "filter", PROXY_CHAIN, "FORWARD", &[]);
    ipt_drop_chain(bin, "mangle", PROXY_CHAIN, "FORWARD", &[]);
}

/// Accept flows with real client addresses (target, Linux only): mark
/// connections that come in on the tun interface from outside the overlay
/// `pool`, and route packets of marked connections back into the tun
/// interface (the replies), whatever the main routing table says.
pub fn proxy_real_ip(tun: &str, pool: &[IpNet]) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let mut ok = true;
    for v6 in [false, true] {
        let nets: Vec<&IpNet> = pool.iter().filter(|p| p.addr().is_ipv6() == v6).collect();
        if nets.is_empty() {
            continue;
        }
        let bin = ipt(v6);
        ok &= ipt_chain(bin, "mangle", REAL_IP_IN, "PREROUTING", &args(&["-i", tun]));
        // Replies from this host (OUTPUT) and from containers or other
        // hosts it forwards for (PREROUTING on other interfaces).
        ok &= ipt_chain(bin, "mangle", REAL_IP_OUT, "OUTPUT", &[]);
        ok &= ipt_chain(
            bin,
            "mangle",
            REAL_IP_OUT,
            "PREROUTING",
            &args(&["!", "-i", tun]),
        );
        for n in &nets {
            ok &= ipt_run(
                bin,
                "mangle",
                "-A",
                REAL_IP_IN,
                &args(&["-s", &n.to_string(), "-j", "RETURN"]),
            );
        }
        ok &= ipt_run(
            bin,
            "mangle",
            "-A",
            REAL_IP_IN,
            &args(&["-j", "CONNMARK", "--set-xmark", REAL_IP_MARK]),
        );
        ok &= ipt_run(
            bin,
            "mangle",
            "-A",
            REAL_IP_OUT,
            &args(&[
                "-m",
                "connmark",
                "--mark",
                REAL_IP_MARK,
                "-j",
                "MARK",
                "--set-xmark",
                REAL_IP_MARK,
            ]),
        );
        let fam = if v6 { "-6" } else { "-4" };
        let rules = std::process::Command::new("ip")
            .args([fam, "rule", "show"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        if !rules.contains(&format!("lookup {REAL_IP_TABLE}")) {
            ok &= run(
                "ip",
                &[
                    fam,
                    "rule",
                    "add",
                    "fwmark",
                    REAL_IP_MARK,
                    "lookup",
                    REAL_IP_TABLE,
                    "priority",
                    REAL_IP_TABLE,
                ],
            );
        }
        ok &= run(
            "ip",
            &[
                fam,
                "route",
                "replace",
                "default",
                "dev",
                tun,
                "table",
                REAL_IP_TABLE,
            ],
        );
        if !v6 {
            // Loose reverse-path filtering: the client's address routes out
            // of another interface.
            let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{tun}/rp_filter"), "2");
        }
    }
    if ok {
        tracing::info!("reverse proxy: accepting real client addresses on {tun}");
    } else {
        tracing::warn!("reverse proxy: real client address setup failed (iptables/ip missing?)");
    }
    ok
}

/// Remove the reverse proxy's iptables chains and routing rule.
pub fn proxy_clear(tun: &str) {
    if !cfg!(target_os = "linux") {
        return;
    }
    for v6 in [false, true] {
        proxy_ingress_clear_family(tun, v6);
        let bin = ipt(v6);
        ipt_drop_chain(bin, "mangle", REAL_IP_IN, "PREROUTING", &args(&["-i", tun]));
        let out_jumps = [("OUTPUT", vec![]), ("PREROUTING", args(&["!", "-i", tun]))];
        for (from, jump) in &out_jumps {
            let mut spec = jump.clone();
            spec.extend(args(&["-j", REAL_IP_OUT]));
            for _ in 0..8 {
                if !ipt_run(bin, "mangle", "-D", from, &spec) {
                    break;
                }
            }
        }
        ipt_run(bin, "mangle", "-F", REAL_IP_OUT, &[]);
        ipt_run(bin, "mangle", "-X", REAL_IP_OUT, &[]);
        let fam = if v6 { "-6" } else { "-4" };
        for _ in 0..4 {
            if !run(
                "ip",
                &[
                    fam,
                    "rule",
                    "del",
                    "fwmark",
                    REAL_IP_MARK,
                    "lookup",
                    REAL_IP_TABLE,
                ],
            ) {
                break;
            }
        }
        run("ip", &[fam, "route", "flush", "table", REAL_IP_TABLE]);
    }
}

// ---------------------------------------------------------------- interfaces

use crate::nat::is_overlay_if;

fn interfaces() -> Vec<if_addrs::Interface> {
    if_addrs::get_if_addrs().unwrap_or_default()
}

/// The interface exists and has an address (the gateway's LAN check, §11.9.2).
pub fn iface_up(name: &str) -> bool {
    if cfg!(target_os = "linux")
        && let Ok(s) = std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
    {
        return s.trim() != "down";
    }
    interfaces().iter().any(|i| i.name == name)
}

/// Directly connected networks, to detect clashes with published prefixes.
pub fn local_networks() -> Vec<IpNet> {
    let mut v: Vec<IpNet> = interfaces()
        .into_iter()
        .filter(|i| !i.is_loopback() && !is_overlay_if(&i.name))
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) => IpNet::new(IpAddr::V4(a.ip), a.prefixlen)
                .ok()
                .map(|n| n.trunc()),
            if_addrs::IfAddr::V6(a) => IpNet::new(IpAddr::V6(a.ip), a.prefixlen)
                .ok()
                .map(|n| n.trunc()),
        })
        .filter(|n| {
            n.prefix_len() > 0
                && !matches!(n.addr(), IpAddr::V6(x) if (x.segments()[0] & 0xffc0) == 0xfe80)
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_commands() {
        let n: IpNet = "192.168.50.0/24".parse().unwrap();
        let (cmd, args) = route_cmd(true, &n, "webjet0");
        if cfg!(target_os = "linux") {
            assert_eq!(
                (cmd, args.join(" ").as_str()),
                ("ip", "route replace 192.168.50.0/24 dev webjet0")
            );
        } else if cfg!(target_os = "macos") {
            assert_eq!(cmd, "route");
            assert!(
                args.join(" ")
                    .contains("add -inet 192.168.50.0/24 -interface webjet0")
            );
        } else {
            assert_eq!(
                args.join(" "),
                "interface ipv4 add route prefix=192.168.50.0/24 interface=webjet0 store=active"
            );
        }
    }

    #[test]
    fn nrpt_script_quotes_and_cleans() {
        let s = nrpt_script(
            &["10.7.255.53".parse().unwrap()],
            &["internal".into(), "corp.example".into()],
        );
        assert!(s.starts_with("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'webjet' } | Remove-DnsClientNrptRule -Force;"));
        assert!(s.contains("Add-DnsClientNrptRule -Namespace '.internal' -NameServers @('10.7.255.53') -Comment 'webjet'"));
        assert!(s.contains("-Namespace '.corp.example'"));
        assert_eq!(ps_quote("a'b"), "'a''b'");
    }

    #[test]
    fn proxy_ingress_rules_capture_each_port() {
        let r = proxy_ingress_rules(
            "webjet0",
            &"10.7.255.53".parse().unwrap(),
            &[("tcp", 8080), ("udp", 5353)],
        );
        let line = |i: usize| format!("{} {}", r[i].0, r[i].1.join(" "));
        assert_eq!(
            line(0),
            "nat -p tcp --dport 8080 -j DNAT --to-destination 10.7.255.53"
        );
        assert_eq!(
            line(1),
            "nat -p udp --dport 5353 -j DNAT --to-destination 10.7.255.53"
        );
        assert_eq!(line(2), "filter -o webjet0 -d 10.7.255.53 -j ACCEPT");
        assert_eq!(line(3), "filter -i webjet0 -s 10.7.255.53 -j ACCEPT");
        assert!(line(4).starts_with("mangle -o webjet0 -p tcp") && line(4).contains("TCPMSS"));
    }

    #[test]
    fn interfaces_are_listed() {
        // Every machine running the tests has some non-overlay network.
        let nets = local_networks();
        assert!(nets.iter().all(|n| n.prefix_len() > 0));
    }
}
