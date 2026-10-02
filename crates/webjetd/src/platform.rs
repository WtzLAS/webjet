//! Operating-system integration: routes, split DNS, gateway NAT and local
//! interface information. Linux uses `ip`/`iptables`/`resolvectl`; macOS
//! uses `route` and `/etc/resolver`; Windows uses `netsh`/PowerShell.

use ipnet::IpNet;
use std::net::IpAddr;
use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> bool {
    match Command::new(cmd).args(args).output() {
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

fn output(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).output().ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn add_route(net: &IpNet, dev: &str) {
    let n = net.to_string();
    let ok = if cfg!(target_os = "linux") {
        run("ip", &["route", "replace", &n, "dev", dev])
    } else if cfg!(target_os = "macos") {
        let fam = if net.addr().is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        run("route", &["-q", "-n", "add", fam, &n, "-interface", dev])
    } else if cfg!(windows) {
        run("netsh", &["interface", "ip", "add", "route", &n, dev])
    } else {
        false
    };
    if ok {
        tracing::debug!("route {n} via {dev}");
    } else {
        tracing::warn!("could not add route {n} via {dev}");
    }
}

pub fn del_route(net: &IpNet, dev: &str) {
    let n = net.to_string();
    if cfg!(target_os = "linux") {
        run("ip", &["route", "del", &n, "dev", dev]);
    } else if cfg!(target_os = "macos") {
        let fam = if net.addr().is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        run("route", &["-q", "-n", "delete", fam, &n, "-interface", dev]);
    } else if cfg!(windows) {
        run("netsh", &["interface", "ip", "delete", "route", &n, dev]);
    }
}

/// Split DNS (§11.10.7): send only the overlay suffix and forwarded zones
/// to the overlay resolver.
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
        for d in domains {
            let body: String = resolver
                .iter()
                .map(|r| format!("nameserver {r}\n"))
                .collect();
            let _ = std::fs::write(format!("/etc/resolver/{d}"), body);
        }
    } else if cfg!(windows) {
        for d in domains {
            let ns = resolver
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(",");
            run(
                "powershell",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!("Add-DnsClientNrptRule -Namespace '.{d}' -NameServers {ns}"),
                ],
            );
        }
    }
}

/// Gateway NAT (§11.9.4): masquerade overlay sources out of the LAN
/// interface and allow forwarding between the tun and LAN interfaces.
pub fn setup_gateway_nat(pool: &[IpNet], tun: &str, lan_if: &str) -> bool {
    if !cfg!(target_os = "linux") {
        tracing::warn!("subnet gateways are supported on Linux only");
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

pub fn iface_up(name: &str) -> bool {
    if cfg!(target_os = "linux") {
        return std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
            .map(|s| s.trim() != "down")
            .unwrap_or(false);
    }
    output("ifconfig", &[name])
        .map(|s| s.contains("UP"))
        .unwrap_or(false)
}

/// Addresses of local interfaces, for HOST candidates (§11.7).
pub fn local_ips() -> Vec<IpAddr> {
    let mut v = Vec::new();
    if cfg!(target_os = "linux") {
        if let Some(out) = output("ip", &["-o", "addr", "show", "scope", "global"]) {
            for line in out.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if let Some(i) = f.iter().position(|x| *x == "inet" || *x == "inet6") {
                    if f.get(1)
                        .map(|d| d.starts_with("webjet") || d.starts_with("tun"))
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    if let Some(a) = f
                        .get(i + 1)
                        .and_then(|c| c.split('/').next())
                        .and_then(|a| a.parse().ok())
                    {
                        v.push(a);
                    }
                }
            }
        }
    } else if let Some(out) = output("ifconfig", &[]) {
        let mut skip = false;
        for line in out.lines() {
            if !line.starts_with(['\t', ' ']) {
                skip = line.starts_with("utun") || line.starts_with("lo");
            }
            let t = line.trim();
            if skip {
                continue;
            }
            if let Some(rest) = t.strip_prefix("inet ") {
                if let Some(a) = rest.split_whitespace().next().and_then(|a| a.parse().ok()) {
                    v.push(a);
                }
            }
        }
    }
    v.retain(|a: &IpAddr| {
        !a.is_loopback()
            && !a.is_unspecified()
            && !matches!(a, IpAddr::V6(x) if (x.segments()[0] & 0xffc0) == 0xfe80)
    });
    v.sort();
    v.dedup();
    v.truncate(4);
    v
}

/// Directly connected networks, to detect clashes with published prefixes.
pub fn local_networks() -> Vec<IpNet> {
    let mut v = Vec::new();
    if cfg!(target_os = "linux") {
        if let Some(out) = output("ip", &["-o", "route", "show", "scope", "link"]) {
            for line in out.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.iter().any(|x| x.starts_with("webjet")) {
                    continue;
                }
                if let Some(n) = f.first().and_then(|n| n.parse::<IpNet>().ok()) {
                    v.push(n);
                }
            }
        }
    }
    v
}
