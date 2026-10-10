//! FreeBSD (and OPNsense) services: rc.d scripts that run the programs
//! under daemon(8), enabled in `/etc/rc.conf.d/<name>`.
//!
//! * `webjetd`: the agent, as root (FreeBSD has no capability to create tun
//!   interfaces, change routes or open BPF devices otherwise).
//! * `webjet_signer`: `webjetd signer` (§19.2), as root like on macOS,
//!   ordered before the agent.
//! * The remote upgrade helper (§19.8) has no path or queue trigger here:
//!   a cron job runs `webjetup apply-upgrade` every minute, which does
//!   nothing without a queued request (as the Windows scheduled task).
//!
//! daemon(8) supervises each program: it restarts it after it exits, passes
//! SIGTERM on at `service … stop` (the agent then removes its routes and
//! interface), and sends the output to syslog under the program's tag. On
//! OPNsense that is System › Log Files › General. The scripts are enabled in
//! `/etc/rc.conf.d/<name>`, which plain FreeBSD reads with the rc.conf
//! settings and from which OPNsense starts add-on services at boot.
//!
//! The generators are plain functions, tested on every platform; the
//! commands only run on FreeBSD.

use crate::layout::{Layout, SIGNER_SERVICE, UPGRADE_SERVICE};
use crate::system::{Sys, query};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// The agent's rc.d name (also its syslog tag and `service` name).
pub const AGENT: &str = "webjetd";
/// The signer's rc.d name: rc.subr names become shell variables
/// (`webjet_signer_enable`), so no hyphen.
pub const SIGNER: &str = "webjet_signer";

/// The rc.d scripts' directory (local services).
pub const RC_DIR: &str = "/usr/local/etc/rc.d";
/// Per-service settings rc.subr's `load_rc_config` reads.
pub const RC_CONF_DIR: &str = "/etc/rc.conf.d";
/// cron(8) reads job files here as well as /etc/cron.d.
pub const CRON_DIR: &str = "/usr/local/etc/cron.d";
/// The upgrade helper's output, when it has something to say.
pub const UPGRADE_LOG: &str = "/var/log/webjet-upgrade.log";

pub fn rc_script_path(name: &str) -> PathBuf {
    Path::new(RC_DIR).join(name)
}

pub fn rc_conf_path(name: &str) -> PathBuf {
    Path::new(RC_CONF_DIR).join(name)
}

pub fn cron_path() -> PathBuf {
    Path::new(CRON_DIR).join(UPGRADE_SERVICE)
}

/// An rc.d service running `program args` under daemon(8).
struct RcService<'a> {
    name: &'a str,
    desc: &'a str,
    /// The rcorder lines besides PROVIDE and KEYWORD.
    order: &'a str,
    /// daemon(8)'s process title and syslog tag.
    tag: &'a str,
    /// Seconds daemon(8) waits before restarting the program.
    restart_delay: u32,
    /// rc.conf-overridable values `(suffix, default, comment)`, referred to
    /// in `args` as `${<name>_<suffix>}`; a `config` one must exist.
    settings: &'a [(&'a str, String, &'a str)],
    program: &'a Path,
    args: &'a str,
}

impl RcService<'_> {
    fn script(&self) -> String {
        let RcService {
            name,
            desc,
            order,
            tag,
            restart_delay,
            settings,
            program,
            args,
        } = self;
        let mut doc = String::new();
        let mut defaults = String::new();
        let mut required = Vec::new();
        for (suffix, default, comment) in *settings {
            doc.push_str(&format!(
                "# {name}_{suffix}: {comment} (default {default}).\n"
            ));
            defaults.push_str(&format!(": ${{{name}_{suffix}:=\"{default}\"}}\n"));
            if *suffix == "config" {
                required.push(format!("${{{name}_{suffix}}}"));
            }
        }
        let required = if required.is_empty() {
            String::new()
        } else {
            format!("required_files=\"{}\"\n", required.join(" "))
        };
        format!(
            "#!/bin/sh
#
# {desc}. Written by webjetup, which rewrites it on every install and
# upgrade: put settings into {conf} instead.
#
# PROVIDE: {name}
{order}# KEYWORD: shutdown
#
# {name}_enable: start at boot (webjetup sets YES).
{doc}
. /etc/rc.subr

name={name}
rcvar={name}_enable
desc=\"{desc}\"

load_rc_config $name

: ${{{name}_enable:=\"NO\"}}
{defaults}
pidfile=\"/var/run/{name}.pid\"
command=\"/usr/sbin/daemon\"
# daemon(8) supervises it: restarted {restart_delay} s after it exits, SIGTERM
# passed on at stop, output to syslog with the tag {tag}.
command_args=\"-P ${{pidfile}} -R {restart_delay} -S -T {tag} -t {tag} {program} {args}\"
{required}
run_rc_command \"$1\"
",
            conf = rc_conf_path(name).display(),
            program = program.display(),
        )
    }
}

/// The agent's rc.d script.
pub fn agent_script(l: &Layout) -> String {
    RcService {
        name: AGENT,
        desc: "Webjet agent",
        // After the network, and after syslogd to keep the first lines.
        order: "# REQUIRE: NETWORKING syslogd\n",
        tag: AGENT,
        restart_delay: 5,
        settings: &[("config", l.config.display().to_string(), "webjetd.toml")],
        program: &l.program("webjetd"),
        args: &format!("--config ${{{AGENT}_config}} run"),
    }
    .script()
}

/// The signer's rc.d script (`webjetd signer`).
pub fn signer_script(l: &Layout) -> String {
    RcService {
        name: SIGNER,
        desc: "Webjet signer (a controller's signing key)",
        order: "# REQUIRE: FILESYSTEMS syslogd\n# BEFORE: webjetd\n",
        tag: SIGNER_SERVICE,
        restart_delay: 2,
        settings: &[
            ("key", l.signer_key.display().to_string(), "the signing key"),
            (
                "socket",
                l.signer_socket.display().to_string(),
                "the socket the agent connects to",
            ),
        ],
        program: &l.program("webjetd"),
        args: &format!("signer --key ${{{SIGNER}_key}} --socket ${{{SIGNER}_socket}}"),
    }
    .script()
}

/// The cron job that runs the upgrade helper. Without a queued request it
/// does nothing and prints nothing; it also finishes an upgrade a reboot
/// cut short.
pub fn upgrade_cron(l: &Layout) -> String {
    format!(
        "# Webjet remote upgrades (webjetup install --no-remote-upgrade removes this).
# Written by webjetup.
SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
* * * * * root {bin} apply-upgrade >> {UPGRADE_LOG} 2>&1
",
        bin = l.program(crate::layout::SELF).display()
    )
}

/// Write the rc.d script `name` (when it changed) and enable it at boot.
/// Whether the script changed.
pub fn install(sys: &Sys, name: &str, script: &str) -> Result<bool> {
    let path = rc_script_path(name);
    sys.mkdir(Path::new(RC_DIR), false)?;
    let changed = crate::system::write_if_changed(sys, &path, script, 0o755)?;
    sys.run(
        "sysrc",
        &[
            "-f",
            &rc_conf_path(name).to_string_lossy(),
            &format!("{name}_enable=YES"),
        ],
    )?;
    Ok(changed)
}

/// (Re)start service `name`.
pub fn restart(sys: &Sys, name: &str) -> Result<()> {
    sys.run("service", &[name, "restart"])
}

/// Stop service `name` if it runs (`onestop` works also when disabled).
pub fn stop(sys: &Sys, name: &str) {
    if rc_script_path(name).exists() {
        sys.try_run("service", &[name, "onestop"]);
    }
}

/// Stop service `name`, remove its script and its rc.conf.d file.
pub fn remove(sys: &Sys, name: &str) -> Result<()> {
    let path = rc_script_path(name);
    if !path.exists() {
        return Ok(());
    }
    stop(sys, name);
    sys.remove_file(&path)?;
    sys.remove_file(&rc_conf_path(name))
}

/// What rc.subr says about service `name`; `None` when it isn't installed.
pub fn state(name: &str) -> Option<String> {
    if !rc_script_path(name).exists() {
        return None;
    }
    let running = if query("service", &[name, "onestatus"]).is_some() {
        "running"
    } else {
        "stopped"
    };
    let enabled = query("service", &[name, "enabled"]).is_some();
    Some(if enabled {
        running.to_string()
    } else {
        format!("{running} (not started at boot: {name}_enable isn't YES)")
    })
}

/// The tun interface an agent that was killed left behind (FreeBSD keeps
/// it after the process is gone), for `webjetup nuke`.
pub fn destroy_interface(sys: &Sys, ifname: &str) {
    if query("ifconfig", &[ifname]).is_some() {
        sys.try_run("ifconfig", &[ifname, "destroy"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Layout {
        let mut l = Layout::system();
        l.bin_dir = PathBuf::from("/usr/local/bin");
        l.config = PathBuf::from("/usr/local/etc/webjet/webjetd.toml");
        l.signer_key = PathBuf::from("/var/db/webjet-signer/signing.key");
        l.signer_socket = PathBuf::from("/var/run/webjet-signer/signer.sock");
        l
    }

    #[test]
    fn agent_script_runs_webjetd_under_daemon() {
        let s = agent_script(&layout());
        assert!(s.starts_with("#!/bin/sh\n"));
        for line in [
            "# PROVIDE: webjetd\n",
            "# REQUIRE: NETWORKING syslogd\n",
            "# KEYWORD: shutdown\n",
            ". /etc/rc.subr\n",
            "name=webjetd\n",
            "rcvar=webjetd_enable\n",
            ": ${webjetd_enable:=\"NO\"}\n",
            ": ${webjetd_config:=\"/usr/local/etc/webjet/webjetd.toml\"}\n",
            "pidfile=\"/var/run/webjetd.pid\"\n",
            "command=\"/usr/sbin/daemon\"\n",
            "command_args=\"-P ${pidfile} -R 5 -S -T webjetd -t webjetd /usr/local/bin/webjetd --config ${webjetd_config} run\"\n",
            "required_files=\"${webjetd_config}\"\n",
            "run_rc_command \"$1\"\n",
        ] {
            assert!(s.contains(line), "{line:?} missing from\n{s}");
        }
        // rcorder reads only the header's PROVIDE/REQUIRE/BEFORE/KEYWORD.
        let header: Vec<&str> = s.lines().take_while(|l| l.starts_with('#')).collect();
        assert!(header.contains(&"# PROVIDE: webjetd"));
    }

    #[test]
    fn signer_script_starts_before_the_agent() {
        let s = signer_script(&layout());
        for line in [
            "# PROVIDE: webjet_signer\n",
            "# BEFORE: webjetd\n",
            "rcvar=webjet_signer_enable\n",
            ": ${webjet_signer_key:=\"/var/db/webjet-signer/signing.key\"}\n",
            ": ${webjet_signer_socket:=\"/var/run/webjet-signer/signer.sock\"}\n",
            "-T webjet-signer -t webjet-signer /usr/local/bin/webjetd signer --key ${webjet_signer_key} --socket ${webjet_signer_socket}\"\n",
        ] {
            assert!(s.contains(line), "{line:?} missing from\n{s}");
        }
        assert!(!s.contains("required_files"), "the signer creates its key");
    }

    #[test]
    #[cfg(unix)]
    fn scripts_are_valid_shell() {
        let d = tempfile::tempdir().unwrap();
        for (name, s) in [
            ("agent", agent_script(&layout())),
            ("signer", signer_script(&layout())),
        ] {
            let p = d.path().join(name);
            std::fs::write(&p, s).unwrap();
            let st = std::process::Command::new("sh")
                .arg("-n")
                .arg(&p)
                .status()
                .unwrap();
            assert!(st.success(), "{name}");
        }
    }

    #[test]
    fn upgrade_cron_runs_the_helper_every_minute_as_root() {
        let c = upgrade_cron(&layout());
        assert!(c.contains(
            "* * * * * root /usr/local/bin/webjetup apply-upgrade >> /var/log/webjet-upgrade.log 2>&1\n"
        ));
        assert_eq!(
            cron_path(),
            Path::new("/usr/local/etc/cron.d/webjet-upgrade")
        );
        assert_eq!(rc_conf_path(AGENT), Path::new("/etc/rc.conf.d/webjetd"));
    }
}
