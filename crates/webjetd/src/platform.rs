//! Operating-system integration (§19.1): routes, split DNS, gateway NAT and
//! local interface information.
//!
//! | | Linux | macOS | Windows |
//! |---|---|---|---|
//! | routes | `ip route` | `route` | `netsh interface ipvX ... route` (active store) |
//! | split DNS | systemd-resolved (`resolvectl`) | `/etc/resolver/<domain>` | NRPT rules (comment `webjet`) |
//! | gateway NAT | iptables MASQUERADE | — | — (gateways run on Linux) |
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
            tracing::debug!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
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
    run("powershell.exe", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
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
        ("ip", vec!["route".into(), verb.into(), n, "dev".into(), dev.into()])
    } else if cfg!(target_os = "macos") {
        let fam = if net.addr().is_ipv4() { "-inet" } else { "-inet6" };
        let verb = if add { "add" } else { "delete" };
        ("route", vec!["-q".into(), "-n".into(), verb.into(), fam.into(), n, "-interface".into(), dev.into()])
    } else {
        let fam = if net.addr().is_ipv4() { "ipv4" } else { "ipv6" };
        let verb = if add { "add" } else { "delete" };
        ("netsh", vec!["interface".into(), fam.into(), verb.into(), "route".into(), format!("prefix={n}"), format!("interface={dev}"), "store=active".into()])
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
    let ns = resolver.iter().map(|r| ps_quote(&r.to_string())).collect::<Vec<_>>().join(",");
    let mut s = format!("Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq {} }} | Remove-DnsClientNrptRule -Force; ", ps_quote(OWNER_TAG));
    for d in domains {
        s.push_str(&format!("Add-DnsClientNrptRule -Namespace {} -NameServers @({ns}) -Comment {} | Out-Null; ", ps_quote(&format!(".{}", d.trim_matches('.'))), ps_quote(OWNER_TAG)));
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
            tracing::warn!("resolvectl not available; configure DNS for {} manually", domains.join(", "));
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
                let ours = std::fs::read_to_string(e.path()).map(|s| s.contains(&format!("# {OWNER_TAG}"))).unwrap_or(false);
                if ours && !domains.contains(&name) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        for d in domains {
            let body: String = format!("# {OWNER_TAG}\n") + &resolver.iter().map(|r| format!("nameserver {r}\n")).collect::<String>();
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
                if std::fs::read_to_string(e.path()).map(|s| s.contains(&format!("# {OWNER_TAG}"))).unwrap_or(false) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    } else {
        #[cfg(windows)]
        powershell(&format!("Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq {} }} | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache", ps_quote(OWNER_TAG)));
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
        let bin = if p.addr().is_ipv4() { "iptables" } else { "ip6tables" };
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

// ---------------------------------------------------------------- interfaces

fn is_overlay_if(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("webjet") || n.starts_with("utun") || n.starts_with("tun") || n.starts_with("wintun")
}

fn interfaces() -> Vec<if_addrs::Interface> {
    if_addrs::get_if_addrs().unwrap_or_default()
}

/// The interface exists and has an address (the gateway's LAN check, §11.9.2).
pub fn iface_up(name: &str) -> bool {
    if cfg!(target_os = "linux") {
        if let Ok(s) = std::fs::read_to_string(format!("/sys/class/net/{name}/operstate")) {
            return s.trim() != "down";
        }
    }
    interfaces().iter().any(|i| i.name == name)
}

/// Addresses of local interfaces, for HOST candidates (§11.7).
pub fn local_ips() -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = interfaces()
        .into_iter()
        .filter(|i| !i.is_loopback() && !i.is_link_local() && !is_overlay_if(&i.name))
        .map(|i| i.ip())
        .filter(|a| !a.is_unspecified() && !matches!(a, IpAddr::V6(x) if (x.segments()[0] & 0xffc0) == 0xfe80))
        .collect();
    v.sort();
    v.dedup();
    v.truncate(4);
    v
}

/// Directly connected networks, to detect clashes with published prefixes.
pub fn local_networks() -> Vec<IpNet> {
    let mut v: Vec<IpNet> = interfaces()
        .into_iter()
        .filter(|i| !i.is_loopback() && !is_overlay_if(&i.name))
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(a) => IpNet::new(IpAddr::V4(a.ip), a.prefixlen).ok().map(|n| n.trunc()),
            if_addrs::IfAddr::V6(a) => IpNet::new(IpAddr::V6(a.ip), a.prefixlen).ok().map(|n| n.trunc()),
        })
        .filter(|n| n.prefix_len() > 0 && !matches!(n.addr(), IpAddr::V6(x) if (x.segments()[0] & 0xffc0) == 0xfe80))
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
            assert_eq!((cmd, args.join(" ").as_str()), ("ip", "route replace 192.168.50.0/24 dev webjet0"));
        } else if cfg!(target_os = "macos") {
            assert_eq!(cmd, "route");
            assert!(args.join(" ").contains("add -inet 192.168.50.0/24 -interface webjet0"));
        } else {
            assert_eq!(args.join(" "), "interface ipv4 add route prefix=192.168.50.0/24 interface=webjet0 store=active");
        }
    }

    #[test]
    fn nrpt_script_quotes_and_cleans() {
        let s = nrpt_script(&["10.7.255.53".parse().unwrap()], &["internal".into(), "corp.example".into()]);
        assert!(s.starts_with("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'webjet' } | Remove-DnsClientNrptRule -Force;"));
        assert!(s.contains("Add-DnsClientNrptRule -Namespace '.internal' -NameServers @('10.7.255.53') -Comment 'webjet'"));
        assert!(s.contains("-Namespace '.corp.example'"));
        assert_eq!(ps_quote("a'b"), "'a''b'");
    }

    #[test]
    fn interfaces_are_listed() {
        // Every machine running the tests has some non-overlay network.
        let nets = local_networks();
        assert!(nets.iter().all(|n| n.prefix_len() > 0));
        assert!(local_ips().iter().all(|a| !a.is_loopback()));
    }
}
