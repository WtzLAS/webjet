//! The signer service (`webjetup install --signer`): `webjetd signer` holds
//! a controller's signing key in its own process (§19.2), and webjetd talks
//! to it through `[controller] signer_socket`.
//!
//! * Linux: systemd unit `webjet-signer.service`, running as its own user
//!   `webjet-signer` in the agent's group, so the agent can reach the socket
//!   (mode 0660, `--group-access`) but not read the key. It is ordered before
//!   webjetd and pulled in by it.
//! * macOS: launchd daemon `net.webjet.signer` (root, like the agent).
//! * Windows: service `webjet-signer` (LocalSystem), which webjetd's service
//!   depends on.
//!
//! An in-process key the agent already uses (`signing.key` in its state) is
//! moved to the signer, so the controller keeps its certified key.

use crate::layout::{
    LINUX_USER, Layout, SERVICE, SIGNER_LAUNCHD_LABEL, SIGNER_SERVICE, SIGNER_USER,
};
use crate::system::{self, Sys, have, query};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Whether this installation uses the signer service: webjetd.toml points
/// the controller at the signer's socket.
pub fn configured(l: &Layout) -> bool {
    std::fs::read_to_string(&l.config)
        .ok()
        .and_then(|s| configured_socket(&s))
        .is_some_and(|p| p == l.signer_socket)
}

fn configured_socket(toml_text: &str) -> Option<PathBuf> {
    let v: toml::Value = toml::from_str(toml_text).ok()?;
    v.get("controller")?
        .get("signer_socket")?
        .as_str()
        .map(PathBuf::from)
}

/// webjetd.toml with `[controller] signer_socket` set to `socket`, keeping
/// everything else (comments included). `None` when it is set already.
pub fn with_signer_socket(toml_text: &str, socket: &Path) -> Result<Option<String>> {
    let mut doc: toml_edit::DocumentMut = toml_text.parse().context("webjetd.toml")?;
    let want = socket.to_string_lossy();
    if doc
        .get("controller")
        .and_then(|c| c.get("signer_socket"))
        .and_then(|s| s.as_str())
        == Some(want.as_ref())
    {
        return Ok(None);
    }
    if !doc.contains_key("controller") {
        doc["controller"] = toml_edit::table();
    }
    let Some(t) = doc["controller"].as_table_like_mut() else {
        bail!("webjetd.toml: `controller` is not a table");
    };
    t.insert("signer_socket", toml_edit::value(want.as_ref()));
    Ok(Some(doc.to_string()))
}

fn systemd_unit(l: &Layout) -> String {
    format!(
        "[Unit]
Description=Webjet controller signing key (webjetd signer)
Documentation=https://forgejo.wolf109909.top/webj8/webjet
Before={SERVICE}.service

[Service]
ExecStart={bin} signer --key {key} --socket {socket} --group-access
Restart=on-failure
RestartSec=2
User={SIGNER_USER}
Group={LINUX_USER}
StateDirectory=webjet-signer
StateDirectoryMode=0700
RuntimeDirectory=webjet-signer
RuntimeDirectoryMode=0750
UMask=0077
CapabilityBoundingSet=
PrivateNetwork=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
LimitCORE=0

[Install]
WantedBy=multi-user.target {SERVICE}.service
",
        bin = l.program("webjetd").display(),
        key = l.signer_key.display(),
        socket = l.signer_socket.display(),
    )
}

fn launchd_plist(l: &Layout) -> String {
    let log = l.signer_log.as_deref().map_or_else(
        || "/var/log/webjet-signer.log".into(),
        |p| p.display().to_string(),
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{SIGNER_LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array><string>{bin}</string><string>signer</string><string>--key</string><string>{key}</string><string>--socket</string><string>{socket}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>Umask</key><integer>63</integer>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"#,
        bin = l.program("webjetd").display(),
        key = l.signer_key.display(),
        socket = l.signer_socket.display(),
    )
}

fn windows_command(l: &Layout) -> String {
    format!(
        "\"{}\" signer-service --key \"{}\" --socket \"{}\"",
        l.program("webjetd").display(),
        l.signer_key.display(),
        l.signer_socket.display()
    )
}

/// Move the agent's in-process signing key to the signer, so the controller
/// keeps its (certified) key. Refuses when both exist and differ.
fn adopt_key(sys: &Sys, l: &Layout) -> Result<()> {
    let old = l.data_dir.join("signing.key");
    if !old.exists() {
        return Ok(());
    }
    if l.signer_key.exists() {
        if std::fs::read(&old).ok() == std::fs::read(&l.signer_key).ok() {
            return sys.remove_file(&old);
        }
        bail!(
            "both {} (the agent's key) and {} (the signer's) exist and differ; keep the certified one and delete the other",
            old.display(),
            l.signer_key.display()
        );
    }
    println!("    moving the controller's signing key to the signer");
    if let Some(d) = l.signer_key.parent() {
        sys.mkdir(d, true)?;
    }
    sys.install_file(&old, &l.signer_key, 0o600)?;
    sys.remove_file(&old)
}

/// Install (or update) the signer's service, point webjetd at it, and when
/// `start`, (re)start it. Run before the agent starts.
pub fn setup(sys: &Sys, l: &Layout, start: bool) -> Result<()> {
    println!("==> Signer service ({SIGNER_SERVICE})");
    adopt_key(sys, l)?;
    let text = std::fs::read_to_string(&l.config).unwrap_or_default();
    if let Some(new) = with_signer_socket(&text, &l.signer_socket)? {
        if let Some(old) = configured_socket(&text) {
            println!("    replacing signer_socket = {}", old.display());
        }
        sys.write(&l.config, &new, 0o644)?;
    }
    if cfg!(target_os = "macos") {
        let plist = l.signer_service_file.clone().unwrap_or_else(|| {
            PathBuf::from(format!(
                "/Library/LaunchDaemons/{SIGNER_LAUNCHD_LABEL}.plist"
            ))
        });
        let want = launchd_plist(l);
        if std::fs::read_to_string(&plist).ok().as_deref() != Some(want.as_str()) {
            sys.write(&plist, &want, 0o644)?;
        }
        if start {
            sys.try_run(
                "launchctl",
                &["bootout", "system", &plist.to_string_lossy()],
            );
            sys.run(
                "launchctl",
                &["bootstrap", "system", &plist.to_string_lossy()],
            )?;
        }
    } else if cfg!(windows) {
        if let Some(d) = l.signer_key.parent() {
            sys.mkdir(d, true)?;
            system::windows_restrict(sys, d)?;
        }
        if query("sc.exe", &["query", SIGNER_SERVICE]).is_none() {
            sys.run(
                "sc.exe",
                &[
                    "create",
                    SIGNER_SERVICE,
                    "binPath=",
                    &windows_command(l),
                    "start=",
                    "auto",
                    "DisplayName=",
                    "Webjet signer",
                ],
            )?;
            sys.try_run(
                "sc.exe",
                &[
                    "description",
                    SIGNER_SERVICE,
                    "Holds the Webjet controller's signing key",
                ],
            );
            sys.try_run(
                "sc.exe",
                &[
                    "failure",
                    SIGNER_SERVICE,
                    "reset=",
                    "86400",
                    "actions=",
                    "restart/2000/restart/5000/restart/30000",
                ],
            );
        }
        system::windows_agent_depends(sys, true);
        if start {
            sys.try_run("sc.exe", &["start", SIGNER_SERVICE]);
        }
    } else {
        system::ensure_linux_user(sys)?;
        system::ensure_user(sys, SIGNER_USER)?;
        if let Some(d) = l.signer_key.parent()
            && (d.exists() || sys.dry)
        {
            sys.run(
                "chown",
                &[
                    "-R",
                    &format!("{SIGNER_USER}:{LINUX_USER}"),
                    &d.to_string_lossy(),
                ],
            )?;
        }
        let unit = l.signer_service_file.clone().unwrap_or_else(|| {
            PathBuf::from(format!("/etc/systemd/system/{SIGNER_SERVICE}.service"))
        });
        let want = systemd_unit(l);
        if std::fs::read_to_string(&unit).ok().as_deref() != Some(want.as_str()) {
            sys.write(&unit, &want, 0o644)?;
        }
        if !have("systemctl") {
            println!(
                "    systemd isn't running here: start the signer yourself (as user {SIGNER_USER}, before webjetd)"
            );
            return Ok(());
        }
        sys.run("systemctl", &["daemon-reload"])?;
        sys.run("systemctl", &["enable", SIGNER_SERVICE])?;
        if start {
            sys.run("systemctl", &["restart", SIGNER_SERVICE])?;
        }
    }
    Ok(())
}

/// Stop and unregister the signer's service. The key stays.
pub fn remove(sys: &Sys, l: &Layout) -> Result<()> {
    if cfg!(target_os = "macos") {
        if let Some(p) = &l.signer_service_file
            && p.exists()
        {
            sys.try_run("launchctl", &["bootout", "system", &p.to_string_lossy()]);
            sys.remove_file(p)?;
        }
    } else if cfg!(windows) {
        if query("sc.exe", &["query", SIGNER_SERVICE]).is_some() {
            sys.try_run("sc.exe", &["stop", SIGNER_SERVICE]);
            sys.run("sc.exe", &["delete", SIGNER_SERVICE])?;
        }
    } else if let Some(unit) = &l.signer_service_file
        && unit.exists()
    {
        if have("systemctl") {
            sys.try_run("systemctl", &["disable", "--now", SIGNER_SERVICE]);
        }
        sys.remove_file(unit)?;
        if have("systemctl") {
            sys.try_run("systemctl", &["daemon-reload"]);
        }
    }
    Ok(())
}

/// Delete the signer's key and its user (`webjetup nuke`).
pub fn nuke(sys: &Sys, l: &Layout) -> Result<()> {
    if let Some(d) = l.signer_key.parent()
        && d != l.config_dir
        && d != l.data_dir
    {
        sys.remove_dir_all(d)?;
    }
    if let Some(log) = &l.signer_log {
        sys.remove_file(log)?;
    }
    if cfg!(target_os = "linux") && query("id", &["-u", SIGNER_USER]).is_some() {
        sys.run("userdel", &[SIGNER_USER])?;
    }
    Ok(())
}

/// What the service manager says about the signer, when it is installed.
pub fn state(l: &Layout) -> Option<String> {
    if cfg!(target_os = "macos") {
        l.signer_service_file
            .as_deref()
            .is_some_and(Path::exists)
            .then(|| system::launchd_state(SIGNER_LAUNCHD_LABEL))
    } else if cfg!(windows) {
        query("sc.exe", &["query", SIGNER_SERVICE]).map(|_| system::windows_state(SIGNER_SERVICE))
    } else {
        l.signer_service_file
            .as_deref()
            .is_some_and(Path::exists)
            .then(|| {
                if have("systemctl") {
                    system::systemd_state(SIGNER_SERVICE)
                } else {
                    "installed (no systemd here)".into()
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_points_at_the_signer() {
        let sock = Path::new("/var/run/webjet-signer/signer.sock");
        let empty = with_signer_socket("", sock).unwrap().unwrap();
        assert_eq!(configured_socket(&empty).as_deref(), Some(sock));
        // Comments and other settings survive; an existing section is reused.
        let text = "# mine\n[controller]\nhead_lifetime_hours = 48 # keep\n\n[metrics]\nlisten = \"127.0.0.1:9100\"\n";
        let out = with_signer_socket(text, sock).unwrap().unwrap();
        assert!(out.starts_with("# mine\n"), "{out}");
        assert!(out.contains("head_lifetime_hours = 48 # keep"), "{out}");
        assert!(out.contains("listen = \"127.0.0.1:9100\""), "{out}");
        assert_eq!(out.matches("[controller]").count(), 1, "{out}");
        let v: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(
            v["controller"]["head_lifetime_hours"].as_integer(),
            Some(48)
        );
        assert_eq!(configured_socket(&out).as_deref(), Some(sock));
        // Already set: nothing to write. Set elsewhere: replaced.
        assert_eq!(with_signer_socket(&out, sock).unwrap(), None);
        let other = "[controller]\nsigner_socket = \"/tmp/x.sock\"\n";
        let out = with_signer_socket(other, sock).unwrap().unwrap();
        assert_eq!(configured_socket(&out).as_deref(), Some(sock));
        assert!(with_signer_socket("controller = 1\n", sock).is_err());
        assert!(with_signer_socket("not toml [", sock).is_err());
    }

    #[test]
    fn service_files_run_the_signer() {
        let mut l = Layout::system();
        l.signer_key = PathBuf::from("/var/lib/webjet-signer/signing.key");
        l.signer_socket = PathBuf::from("/var/run/webjet-signer/signer.sock");
        let unit = systemd_unit(&l);
        assert!(unit.contains(&format!(
            "ExecStart={} signer --key /var/lib/webjet-signer/signing.key --socket /var/run/webjet-signer/signer.sock --group-access\n",
            l.program("webjetd").display()
        )));
        assert!(
            unit.contains("User=webjet-signer\nGroup=webjet\n"),
            "{unit}"
        );
        assert!(unit.contains("Before=webjetd.service\n"));
        assert!(unit.contains("WantedBy=multi-user.target webjetd.service\n"));
        assert!(unit.contains("PrivateNetwork=yes\n"));
        let plist = launchd_plist(&l);
        assert!(plist.contains("<string>net.webjet.signer</string>"));
        assert!(plist.contains("<string>signer</string><string>--key</string>"));
        assert!(
            !plist.contains("--group-access"),
            "root on macOS, like the agent"
        );
        let cmd = windows_command(&l);
        assert!(cmd.contains("\" signer-service --key \""), "{cmd}");
    }

    #[test]
    fn the_agents_key_moves_to_the_signer() {
        let d = tempfile::tempdir().unwrap();
        let mut l = Layout::system();
        l.data_dir = d.path().join("state");
        l.signer_key = d.path().join("signer").join("signing.key");
        let sys = Sys { dry: false };
        // Nothing to move.
        adopt_key(&sys, &l).unwrap();
        assert!(!l.signer_key.exists());
        std::fs::create_dir_all(&l.data_dir).unwrap();
        std::fs::write(l.data_dir.join("signing.key"), [7u8; 32]).unwrap();
        adopt_key(&sys, &l).unwrap();
        assert_eq!(std::fs::read(&l.signer_key).unwrap(), [7u8; 32]);
        assert!(!l.data_dir.join("signing.key").exists());
        // The same key in both places: the agent's copy goes.
        std::fs::write(l.data_dir.join("signing.key"), [7u8; 32]).unwrap();
        adopt_key(&sys, &l).unwrap();
        assert!(!l.data_dir.join("signing.key").exists());
        // Different keys: refuse.
        std::fs::write(l.data_dir.join("signing.key"), [8u8; 32]).unwrap();
        assert!(
            adopt_key(&sys, &l)
                .unwrap_err()
                .to_string()
                .contains("differ")
        );
        assert_eq!(std::fs::read(&l.signer_key).unwrap(), [7u8; 32]);
    }
}
