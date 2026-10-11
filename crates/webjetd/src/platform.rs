//! Operating-system integration (§19.1): routes, split DNS, gateway NAT and
//! local interface information.
//!
//! | | Linux | macOS | FreeBSD (OPNsense) | Windows |
//! |---|---|---|---|---|
//! | routes | `ip route` | `route` | `route` | `netsh interface ipvX ... route` (active store) |
//! | split DNS | systemd-resolved (`resolvectl`) | `/etc/resolver/<domain>` | — (warns) | NRPT rules (comment `webjet`) |
//! | gateway NAT | iptables MASQUERADE | — | — | — (gateways run on Linux) |
//! | reverse proxy | iptables DNAT, connmark + policy routing | — | — | — (Linux only) |
//! | multicast groups | `/proc/net/igmp{,6}` | `getifmaddrs` | `getifmaddrs` | `GetMulticastIpAddressTable` |
//!
//! Everything the agent adds is removed again by [`cleanup`] (at shutdown and
//! on uninstall).

use ipnet::IpNet;
use std::net::IpAddr;
use std::process::Command;
use webjet_core::packet::Flow;

/// Marker for system state the agent owns (NRPT comment, resolver files).
pub const OWNER_TAG: &str = "webjet";

/// Longest a platform command may run: a hung `resolvectl`, `netsh` or
/// PowerShell would otherwise stall the agent's refresh for good.
const COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

fn run(cmd: &str, args: &[&str]) -> bool {
    match output(cmd, args) {
        Some(o) if o.status.success() => true,
        Some(o) => {
            tracing::debug!(
                "{cmd} {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        None => false,
    }
}

/// Run a command to completion with [`COMMAND_TIMEOUT`]; a command that
/// overruns is killed. None if it couldn't start or was killed.
fn output(cmd: &str, args: &[&str]) -> Option<std::process::Output> {
    use std::io::Read;
    use std::process::Stdio;
    let mut c = Command::new(cmd);
    c.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            tracing::debug!("{cmd}: {e}");
            return None;
        }
    };
    // Drain both pipes while waiting, or a chatty child blocks on a full one.
    let drain = |p: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(mut p) = p {
                let _ = p.read_to_end(&mut v);
            }
            v
        })
    };
    let out = drain(child.stdout.take().map(|p| Box::new(p) as _));
    let err = drain(child.stderr.take().map(|p| Box::new(p) as _));
    let deadline = std::time::Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                tracing::warn!("{cmd} {}: timed out", args.join(" "));
                return None;
            }
            Err(e) => {
                tracing::debug!("{cmd}: {e}");
                return None;
            }
        }
    };
    Some(std::process::Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
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
    } else if cfg!(any(target_os = "macos", target_os = "freebsd")) {
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

/// Route `net` through `dev`; false if the command failed (the caller
/// reports and retries).
pub fn add_route(net: &IpNet, dev: &str) -> bool {
    let (cmd, args) = route_cmd(true, net, dev);
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    // BSD `route add` fails on a route that already exists (left by an
    // earlier run, or the interface's own); `change` then points it at
    // `dev`, as Linux's `ip route replace` does in one step.
    let ok = run(cmd, &a)
        || (cfg!(any(target_os = "macos", target_os = "freebsd")) && run(cmd, &bsd_change(&a)));
    if ok {
        tracing::debug!("route {net} via {dev}");
    }
    ok
}

/// A BSD `route add …` command line as `route change …`.
fn bsd_change<'a>(add: &[&'a str]) -> Vec<&'a str> {
    add.iter()
        .map(|&w| if w == "add" { "change" } else { w })
        .collect()
}

pub fn del_route(net: &IpNet, dev: &str) -> bool {
    let (cmd, args) = route_cmd(false, net, dev);
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    run(cmd, &a)
}

// ---------------------------------------------------------------- tun interface (FreeBSD)

/// FreeBSD's tun driver only creates `tunN` interfaces, and unlike Linux's
/// they outlive the process that opened them: an agent that was killed
/// leaves its renamed interface behind (with its addresses and routes), and
/// the next start couldn't take the name. Destroy `name` if it is such a
/// leftover: a tun interface (`ifconfig -g tun` lists it) nobody else uses.
/// Only for names that aren't `tunN`, which the driver hands out itself.
pub fn destroy_stale_tun(name: &str) -> bool {
    if !cfg!(target_os = "freebsd") || is_tun_unit(name) {
        return false;
    }
    let members = output("ifconfig", &["-g", "tun"])
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if !members.split_whitespace().any(|m| m == name) {
        return false;
    }
    // ifconfig names the process that holds a tun interface open.
    let shown = output("ifconfig", &[name])
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if shown.contains("Opened by PID") {
        tracing::warn!("tun interface {name} is in use by another process");
        return false;
    }
    let ok = run("ifconfig", &[name, "destroy"]);
    if ok {
        tracing::info!("removed the tun interface {name} an earlier run left behind");
    } else {
        tracing::warn!("could not remove the leftover tun interface {name}");
    }
    ok
}

/// `tun` followed by a unit number: a name FreeBSD's tun driver gives out.
pub fn is_tun_unit(name: &str) -> bool {
    name.strip_prefix("tun")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
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
                    .is_ok_and(|s| s.contains(&format!("# {OWNER_TAG}")));
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
    } else if cfg!(target_os = "freebsd") {
        // No per-domain resolver configuration to hook into: on OPNsense
        // Unbound owns DNS (a domain override does it by hand).
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            tracing::warn!(
                "split DNS is not configured on FreeBSD: forward {} to {} yourself \
                 (OPNsense: Unbound DNS → Query Forwarding)",
                domains.join(", "),
                resolver
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        });
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
                    .is_ok_and(|s| s.contains(&format!("# {OWNER_TAG}")))
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
/// Priority of the per-flow rules that route replies of real-IP UDP flows
/// into the tun interface (`proxy_reply_route`).
pub const REAL_IP_UDP_PRIO: &str = "22345";

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
        // Only the reply direction: packets towards the server (the ICMP
        // "fragmentation needed" this host sends a container whose reply is
        // too big for the tun interface, related to the connection) must
        // take the normal route, or the server never learns the path MTU
        // and every full-size reply is lost.
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
                "-m",
                "conntrack",
                "--ctdir",
                "REPLY",
                "-j",
                "MARK",
                "--set-xmark",
                REAL_IP_MARK,
            ]),
        );
        let fam = if v6 { "-6" } else { "-4" };
        let rules = output("ip", &[fam, "rule", "show"])
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

/// The `ip rule` selector for the replies of a real-IP UDP flow (`f`: as
/// received, client → this node): locally sent, from the flow's port to
/// the client's address and port.
fn reply_rule(f: &Flow) -> Vec<String> {
    let host = if f.src.is_ipv6() { 128 } else { 32 };
    args(&[
        if f.src.is_ipv6() { "-6" } else { "-4" },
        "rule",
        "add",
        "to",
        &format!("{}/{host}", f.src),
        "ipproto",
        "udp",
        "sport",
        &f.dport.to_string(),
        "dport",
        &f.sport.to_string(),
        "iif",
        "lo",
        "lookup",
        REAL_IP_TABLE,
        "priority",
        REAL_IP_UDP_PRIO,
    ])
}

/// Route a real-IP UDP flow's replies into the tun interface (`add`) or
/// stop doing so (Linux only). A UDP server on a wildcard address lets the
/// kernel pick each reply's source by its route to the client: through
/// another interface, the reply would leave with that interface's address
/// in a connection of its own, never meeting the connection mark. This
/// rule makes the route lookup pick the tun interface, and with it the
/// overlay address the client's packets came to.
pub fn proxy_reply_route(f: &Flow, add: bool) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let mut a = reply_rule(f);
    if !add {
        a[2] = "del".into();
    }
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    run("ip", &a)
}

/// Remove every per-flow reply rule (`proxy_reply_route`) of a family.
fn proxy_reply_routes_clear(fam: &str) {
    let n = output("ip", &[fam, "rule", "show", "priority", REAL_IP_UDP_PRIO])
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        .unwrap_or(0);
    if n == 0 {
        return;
    }
    let batch = format!("rule del priority {REAL_IP_UDP_PRIO}\n").repeat(n);
    let child = Command::new("ip")
        .args([fam, "-force", "-batch", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if let Ok(mut c) = child {
        if let Some(mut i) = c.stdin.take() {
            use std::io::Write;
            let _ = i.write_all(batch.as_bytes());
        }
        let _ = c.wait();
    }
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
        proxy_reply_routes_clear(fam);
        run("ip", &[fam, "route", "flush", "table", REAL_IP_TABLE]);
    }
}

// ---------------------------------------------------------------- multicast groups

/// The multicast groups the host has joined on interface `dev` (§9.5.1),
/// as the OS keeps them for IGMP/MLD; `None` when it can't tell (then
/// everything is taken). Linux: /proc/net/igmp{,6}; macOS and FreeBSD:
/// getifmaddrs;
/// Windows: GetMulticastIpAddressTable.
pub fn multicast_groups(dev: &str) -> Option<std::collections::HashSet<IpAddr>> {
    let mut v = groups_os(dev)?;
    v.retain(|a| a.is_multicast());
    Some(v)
}

#[cfg(target_os = "linux")]
fn groups_os(dev: &str) -> Option<std::collections::HashSet<IpAddr>> {
    let v4 = std::fs::read_to_string("/proc/net/igmp").ok()?;
    let v6 = std::fs::read_to_string("/proc/net/igmp6").unwrap_or_default();
    let mut out = parse_proc_igmp(&v4, dev);
    out.extend(parse_proc_igmp6(&v6, dev));
    Some(out)
}

/// `/proc/net/igmp`: a line per interface (`Idx Device : Count Querier`)
/// followed by indented lines per group, the address in hex as the kernel
/// holds it (network order read as a host integer).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_igmp(text: &str, dev: &str) -> std::collections::HashSet<IpAddr> {
    let mut out = std::collections::HashSet::new();
    let mut ours = false;
    for line in text.lines().skip(1) {
        if !line.starts_with(char::is_whitespace) {
            ours = line.split_whitespace().nth(1) == Some(dev);
        } else if ours
            && let Some(hex) = line.split_whitespace().next()
            && let Ok(x) = u32::from_str_radix(hex, 16)
        {
            out.insert(IpAddr::from(x.to_ne_bytes()));
        }
    }
    out
}

/// `/proc/net/igmp6`: `idx device address-hex users flags timer`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_igmp6(text: &str, dev: &str) -> std::collections::HashSet<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.get(1) != Some(&dev) {
                return None;
            }
            let mut b = [0u8; 16];
            // Checks the length and every digit; never slices inside a
            // multi-byte character.
            hex::decode_to_slice(f.get(2)?, &mut b).ok()?;
            Some(IpAddr::from(b))
        })
        .collect()
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn groups_os(dev: &str) -> Option<std::collections::HashSet<IpAddr>> {
    // `struct ifmaddrs` (<ifaddrs.h>), the same on both; declared here
    // because the libc crate lacks it for Apple targets.
    #[repr(C)]
    struct IfMaddrs {
        next: *mut IfMaddrs,
        name: *mut libc::sockaddr,
        addr: *mut libc::sockaddr,
        lladdr: *mut libc::sockaddr,
    }
    unsafe extern "C" {
        fn getifmaddrs(ifmap: *mut *mut IfMaddrs) -> libc::c_int;
        fn freeifmaddrs(ifmp: *mut IfMaddrs);
    }
    let cname = std::ffi::CString::new(dev).ok()?;
    // SAFETY: a valid C string.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return None;
    }
    let mut head: *mut IfMaddrs = std::ptr::null_mut();
    // SAFETY: getifmaddrs fills `head` with a list we free below.
    if unsafe { getifmaddrs(&mut head) } != 0 {
        return None;
    }
    let mut out = std::collections::HashSet::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: entries of the list getifmaddrs returned; the sockaddrs
        // are read by their family.
        unsafe {
            let e = &*cur;
            let on_dev = !e.name.is_null()
                && i32::from((*e.name).sa_family) == libc::AF_LINK
                && u32::from((*(e.name as *const libc::sockaddr_dl)).sdl_index) == index;
            if on_dev && !e.addr.is_null() {
                match i32::from((*e.addr).sa_family) {
                    libc::AF_INET => {
                        let a = &*(e.addr as *const libc::sockaddr_in);
                        out.insert(IpAddr::from(a.sin_addr.s_addr.to_ne_bytes()));
                    }
                    libc::AF_INET6 => {
                        let a = &*(e.addr as *const libc::sockaddr_in6);
                        out.insert(IpAddr::from(a.sin6_addr.s6_addr));
                    }
                    _ => {}
                }
            }
            cur = e.next;
        }
    }
    // SAFETY: the list getifmaddrs returned, freed once.
    unsafe { freeifmaddrs(head) };
    Some(out)
}

#[cfg(windows)]
fn groups_os(dev: &str) -> Option<std::collections::HashSet<IpAddr>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, FreeMibTable, GetMulticastIpAddressTable,
        MIB_MULTICASTIPADDRESS_TABLE,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};
    let alias: Vec<u16> = dev.encode_utf16().chain(Some(0)).collect();
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: a NUL-terminated alias and an out pointer.
    if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } != 0 {
        return None;
    }
    let mut table: *mut MIB_MULTICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: fills `table`, freed with FreeMibTable below.
    if unsafe { GetMulticastIpAddressTable(AF_UNSPEC, &mut table) } != 0 || table.is_null() {
        return None;
    }
    let mut out = std::collections::HashSet::new();
    // SAFETY: `NumEntries` rows follow the header; addresses are read by
    // their family.
    unsafe {
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for r in rows {
            if r.InterfaceLuid.Value != luid.Value {
                continue;
            }
            match r.Address.si_family {
                AF_INET => {
                    out.insert(IpAddr::from(
                        r.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                    ));
                }
                AF_INET6 => {
                    out.insert(IpAddr::from(r.Address.Ipv6.sin6_addr.u.Byte));
                }
                _ => {}
            }
        }
        FreeMibTable(table as *const _);
    }
    Some(out)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
fn groups_os(_dev: &str) -> Option<std::collections::HashSet<IpAddr>> {
    None
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
        } else if cfg!(any(target_os = "macos", target_os = "freebsd")) {
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
    fn bsd_route_change_and_tun_units() {
        assert_eq!(
            bsd_change(&[
                "-q",
                "-n",
                "add",
                "-inet",
                "10.7.0.0/16",
                "-interface",
                "webjet0"
            ]),
            [
                "-q",
                "-n",
                "change",
                "-inet",
                "10.7.0.0/16",
                "-interface",
                "webjet0"
            ]
        );
        assert!(is_tun_unit("tun0") && is_tun_unit("tun17"));
        assert!(!is_tun_unit("tun") && !is_tun_unit("webjet0") && !is_tun_unit("tunx1"));
        // Never touches anything for a driver-made name (or off FreeBSD).
        assert!(!destroy_stale_tun("tun3"));
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
    fn reply_rule_selects_a_flows_replies() {
        let f = Flow {
            proto: 17,
            src: "203.0.113.5".parse().unwrap(),
            dst: "10.7.0.11".parse().unwrap(),
            sport: 41210,
            dport: 27015,
        };
        assert_eq!(
            reply_rule(&f).join(" "),
            "-4 rule add to 203.0.113.5/32 ipproto udp sport 27015 dport 41210 iif lo \
             lookup 22346 priority 22345"
        );
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
    fn proc_igmp_is_parsed() {
        let v4 = "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter
1\tlo        :     1      V3
\t\t\t\t010000E0     1 0:00000000\t\t0
5\twebjet0   :     2      V3
\t\t\t\tFB0000E0     1 0:00000000\t\t0
\t\t\t\t010000E0     1 0:00000000\t\t0
";
        let g = parse_proc_igmp(v4, "webjet0");
        let want = |a: [u8; 4]| IpAddr::from(u32::from_le_bytes(a).to_ne_bytes());
        // The kernel prints the network-order word as a host integer: on
        // little-endian machines the bytes come out reversed.
        assert!(g.contains(&want([224, 0, 0, 251])) && g.contains(&want([224, 0, 0, 1])));
        assert_eq!(g.len(), 2);
        assert!(parse_proc_igmp(v4, "eth0").is_empty());
        let v6 = "1    lo              ff020000000000000000000000000001     1 0000000C 0
5    webjet0         ff0200000000000000000000000000fb     1 00000004 0
5    webjet0         ff020000000000000000000000000001     1 0000000C 0
";
        let g6 = parse_proc_igmp6(v6, "webjet0");
        assert!(g6.contains(&"ff02::fb".parse::<IpAddr>().unwrap()));
        assert_eq!(g6.len(), 2);
        // Damaged lines are skipped, a multi-byte character among them.
        let bad = "5 webjet0 ff02000000000000000000000000é01 1 0 0
5 webjet0 ff02000000000000000000000000zz01 1 0 0
5 webjet0 ff02 1 0 0
";
        assert!(parse_proc_igmp6(bad, "webjet0").is_empty());
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    fn loopback_groups_are_read() {
        // Every IPv4-capable interface has joined all-hosts.
        let lo = if cfg!(any(target_os = "macos", target_os = "freebsd")) {
            "lo0"
        } else {
            "lo"
        };
        let g = multicast_groups(lo).expect("groups");
        assert!(g.contains(&IpAddr::from([224, 0, 0, 1])), "{g:?}");
    }

    #[test]
    fn interfaces_are_listed() {
        // Every machine running the tests has some non-overlay network.
        let nets = local_networks();
        assert!(nets.iter().all(|n| n.prefix_len() > 0));
    }
}
