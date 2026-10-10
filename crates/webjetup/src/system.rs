//! Changes to the machine: files, the service manager and system settings.
//! Every change goes through [`Sys`], which prints it and, with
//! `--dry-run`, only prints it.

use crate::layout::{self, LAUNCHD_LABEL, LINUX_USER, Layout, SERVICE};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Sys {
    pub dry: bool,
}

/// Whether setting up a service (re)starts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    /// Register it only.
    No,
    /// Restart it (new programs).
    Yes,
    /// Restart it only when its service definition changed (an install of
    /// the version that is installed already: its programs stayed).
    IfChanged,
}

impl Start {
    pub fn from_bool(start: bool) -> Start {
        if start { Start::Yes } else { Start::No }
    }

    /// Whether to (re)start now, given whether the definition `changed`.
    pub fn now(self, changed: bool) -> bool {
        match self {
            Start::No => false,
            Start::Yes => true,
            Start::IfChanged => changed,
        }
    }
}

/// Whether `prog` is on `PATH`.
pub fn have(prog: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|d| {
        let p = d.join(prog);
        p.is_file() || (cfg!(windows) && d.join(format!("{prog}.exe")).is_file())
    })
}

/// Run a read-only query; `None` if it can't run or fails.
pub fn query(prog: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Sys {
    pub fn say(&self, what: &str) {
        if self.dry {
            println!("    would {what}");
        } else {
            println!("    {what}");
        }
    }

    /// Run a command that must succeed.
    pub fn run(&self, prog: &str, args: &[&str]) -> Result<()> {
        self.say(&format!("run {prog} {}", args.join(" ")));
        if self.dry {
            return Ok(());
        }
        let st = Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .status()
            .with_context(|| format!("run {prog}"))?;
        if !st.success() {
            bail!("{prog} {} failed ({st})", args.join(" "));
        }
        Ok(())
    }

    /// Run a command whose failure doesn't matter (stopping a stopped service).
    pub fn try_run(&self, prog: &str, args: &[&str]) -> bool {
        if self.dry {
            self.say(&format!("run {prog} {}", args.join(" ")));
            return true;
        }
        Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    pub fn mkdir(&self, p: &Path, private: bool) -> Result<()> {
        if p.is_dir() {
            return Ok(());
        }
        self.say(&format!("create {}", p.display()));
        if self.dry {
            return Ok(());
        }
        std::fs::create_dir_all(p).with_context(|| format!("create {}", p.display()))?;
        set_mode(p, if private { 0o700 } else { 0o755 })
    }

    /// Replace `p` with `contents` atomically (a temporary file, synced, then
    /// renamed over it): a crash leaves the old file or the new one, never a
    /// truncated one. A symbolic link is followed, so its target changes.
    pub fn write(&self, p: &Path, contents: &str, mode: u32) -> Result<()> {
        self.say(&format!("write {}", p.display()));
        if self.dry {
            return Ok(());
        }
        let p = if p.is_symlink() {
            std::fs::canonicalize(p).with_context(|| format!("resolve {}", p.display()))?
        } else {
            p.to_path_buf()
        };
        let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
            bail!("can't write {}", p.display());
        };
        // The new file is root's: keep the owner the old one had.
        #[cfg(unix)]
        let owner = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&p).ok().map(|m| (m.uid(), m.gid()))
        };
        webjet_release::write_atomic(dir, name, contents.as_bytes(), mode)?;
        #[cfg(unix)]
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(&p, Some(uid), Some(gid))
                .with_context(|| format!("chown {}", p.display()))?;
        }
        set_mode(&p, mode)?;
        sync_dir(dir);
        Ok(())
    }

    /// Put `src` at `dest`, replacing it even while it runs: copy next to it
    /// (synced, so a crash never leaves an empty program), then rename over
    /// it. On Windows a running file can't be replaced, only renamed: it is
    /// moved aside first, and back if the replacement fails.
    pub fn install_file(&self, src: &Path, dest: &Path, mode: u32) -> Result<()> {
        self.say(&format!("install {}", dest.display()));
        if self.dry {
            return Ok(());
        }
        let tmp = dest.with_extension("webjetup-new");
        let res = (|| -> Result<()> {
            copy_synced(src, &tmp)?;
            set_mode(&tmp, mode)?;
            let aside = if cfg!(windows) && dest.exists() {
                let old = aside_path(dest)?;
                std::fs::rename(dest, &old)
                    .with_context(|| format!("move {} aside", dest.display()))?;
                Some(old)
            } else {
                None
            };
            if let Err(e) = std::fs::rename(&tmp, dest) {
                if let Some(old) = aside {
                    let _ = std::fs::rename(old, dest);
                }
                return Err(e).with_context(|| format!("replace {}", dest.display()));
            }
            Ok(())
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        res?;
        if let Some(dir) = dest.parent() {
            sync_dir(dir);
        }
        Ok(())
    }

    pub fn remove_file(&self, p: &Path) -> Result<()> {
        if !p.exists() && p.symlink_metadata().is_err() {
            return Ok(());
        }
        self.say(&format!("remove {}", p.display()));
        if self.dry {
            return Ok(());
        }
        std::fs::remove_file(p).with_context(|| format!("remove {}", p.display()))
    }

    pub fn remove_dir_all(&self, p: &Path) -> Result<()> {
        if !p.exists() {
            return Ok(());
        }
        // A last line of defence against a broken layout.
        if p.parent().is_none() || p.components().count() < 3 {
            bail!("refusing to remove {}", p.display());
        }
        self.say(&format!("remove {} and everything in it", p.display()));
        if self.dry {
            return Ok(());
        }
        std::fs::remove_dir_all(p).with_context(|| format!("remove {}", p.display()))
    }
}

/// Copy `src` to `dest` (replacing it) and flush it to disk.
pub fn copy_synced(src: &Path, dest: &Path) -> Result<()> {
    let mut from = std::fs::File::open(src).with_context(|| format!("open {}", src.display()))?;
    let mut to =
        std::fs::File::create(dest).with_context(|| format!("create {}", dest.display()))?;
    std::io::copy(&mut from, &mut to).with_context(|| format!("copy to {}", dest.display()))?;
    to.sync_all()
        .with_context(|| format!("sync {}", dest.display()))
}

/// Where [`Sys::install_file`] moves a file aside on Windows. A file moved
/// aside before may still run (the upgrade helper's own program, put back
/// by a rollback while it runs) and then can't be removed or replaced: use
/// the next free name instead. Leftovers go on a later install.
fn aside_path(dest: &Path) -> Result<PathBuf> {
    for i in 0..10 {
        let old = if i == 0 {
            dest.with_extension("webjetup-old")
        } else {
            dest.with_extension(format!("webjetup-old{i}"))
        };
        if old.symlink_metadata().is_err() || std::fs::remove_file(&old).is_ok() {
            return Ok(old);
        }
    }
    bail!(
        "can't move {} aside: earlier copies are still in use",
        dest.display()
    )
}

/// Let the owner run `p` (a downloaded program).
pub fn make_executable(p: &Path) -> Result<()> {
    set_mode(p, 0o755)
}

/// Flush a directory's entries (a rename in it) to disk, where that exists.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// webjetd.toml's text, `""` when there is none yet. Any other error is
/// returned: an edit must never start from an empty file because the real
/// one couldn't be read, and then replace it.
pub fn read_config(l: &Layout) -> Result<String> {
    match std::fs::read_to_string(&l.config) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", l.config.display())),
    }
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", p.display()))
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) -> Result<()> {
    Ok(())
}

/// Installing needs root (Unix) or an elevated Administrator (Windows).
pub fn privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and can't fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // `net session` works only in an elevated prompt.
        Command::new("net")
            .args(["session"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

pub fn require_privileges(dry: bool) -> Result<()> {
    if dry || privileged() {
        return Ok(());
    }
    if cfg!(windows) {
        bail!("run webjetup from an Administrator prompt");
    }
    bail!("run webjetup as root (sudo webjetup …)");
}

// ---------------------------------------------------------------- the service

/// What the service manager says about webjetd.
pub fn service_state(l: &Layout) -> String {
    if cfg!(target_os = "macos") {
        if !l.service_file.as_deref().is_some_and(Path::exists) {
            return "not installed".into();
        }
        launchd_state(LAUNCHD_LABEL)
    } else if cfg!(windows) {
        windows_state(SERVICE)
    } else if cfg!(target_os = "freebsd") {
        crate::freebsd::state(crate::freebsd::AGENT).unwrap_or_else(|| "not installed".into())
    } else {
        if !l.service_file.as_deref().is_some_and(Path::exists) {
            return "not installed".into();
        }
        if !have("systemctl") {
            return "installed (no systemd here)".into();
        }
        systemd_state(SERVICE)
    }
}

/// `systemctl is-active` for a unit (it prints the state but exits
/// non-zero when the unit isn't active).
pub fn systemd_state(unit: &str) -> String {
    Command::new("systemctl")
        .args(["is-active", unit])
        .stderr(Stdio::null())
        .output()
        .map_or_else(
            |_| "unknown".into(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        )
}

/// The `state = …` line of `launchctl print system/<label>`.
pub fn launchd_state(label: &str) -> String {
    match query("launchctl", &["print", &format!("system/{label}")]) {
        Some(out) => out
            .lines()
            .find_map(|line| line.trim().strip_prefix("state = ").map(str::to_string))
            .unwrap_or_else(|| "loaded".into()),
        None => "not loaded".into(),
    }
}

/// What `sc.exe query` says about a Windows service.
pub fn windows_state(service: &str) -> String {
    match query("sc.exe", &["query", service]) {
        Some(out) if out.contains("RUNNING") => "running".into(),
        Some(out) if out.contains("STOPPED") => "stopped".into(),
        Some(_) => "changing".into(),
        None => "not installed".into(),
    }
}

/// The Windows service command line: `webjetd --config <file> service`.
fn windows_service_command(l: &Layout) -> String {
    format!(
        "\"{}\" --config \"{}\" service",
        l.program("webjetd").display(),
        l.config.display()
    )
}

/// Split-DNS (NRPT) rules webjetd tags with the comment `webjet`.
const WINDOWS_NRPT_CLEANUP: &str = "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'webjet' } | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache";

/// A Windows service's settings, as webjetup registers them.
pub struct WindowsService<'a> {
    pub name: &'a str,
    pub command: String,
    pub display_name: &'a str,
    pub description: &'a str,
    /// `sc.exe depend=` (services separated by `/`); `None` leaves them.
    pub depends: Option<String>,
    /// `sc.exe failure actions=`.
    pub failure_actions: &'a str,
}

/// Whether `sc.exe qc` output (an existing service's configuration) already
/// has the command line, automatic start and dependencies of `s`.
fn windows_service_current(qc: &str, s: &WindowsService) -> bool {
    let field = |key: &str| {
        qc.lines()
            .find_map(|l| l.trim().strip_prefix(key))
            .and_then(|r| r.trim_start().strip_prefix(':'))
            .map(str::trim)
    };
    let deps_ok = s.depends.as_deref().is_none_or(|want| {
        // The first dependency is on the DEPENDENCIES line, every further
        // one on a line of its own.
        let mut have: Vec<String> = Vec::new();
        let mut in_deps = false;
        for l in qc.lines() {
            let t = l.trim();
            if let Some(r) = t.strip_prefix("DEPENDENCIES") {
                in_deps = true;
                let r = r.trim_start().trim_start_matches(':').trim();
                if !r.is_empty() {
                    have.push(r.to_ascii_lowercase());
                }
            } else if in_deps {
                match t.strip_prefix(':') {
                    Some(r) if !r.trim().is_empty() => have.push(r.trim().to_ascii_lowercase()),
                    _ => in_deps = false,
                }
            }
        }
        let mut want: Vec<String> = want
            .split('/')
            .filter(|d| !d.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        want.sort();
        have.sort();
        want == have
    });
    field("BINARY_PATH_NAME") == Some(s.command.as_str())
        && field("START_TYPE").is_some_and(|t| t.contains("AUTO_START"))
        && field("DISPLAY_NAME") == Some(s.display_name)
        && deps_ok
}

/// Register `s` as an automatic LocalSystem service, or bring an existing
/// one's command line, start type, dependencies and display name up to
/// date; description and failure actions are always set again. Whether it
/// was created or changed.
pub fn windows_service(sys: &Sys, s: &WindowsService) -> Result<bool> {
    let changed = match query("sc.exe", &["qc", s.name]) {
        None => {
            let mut args = vec![
                "create",
                s.name,
                "binPath=",
                &s.command,
                "start=",
                "auto",
                "DisplayName=",
                s.display_name,
            ];
            if let Some(d) = &s.depends {
                args.extend(["depend=", d]);
            }
            sys.run("sc.exe", &args)?;
            true
        }
        Some(qc) if windows_service_current(&qc, s) => false,
        Some(_) => {
            let mut args = vec![
                "config",
                s.name,
                "binPath=",
                &s.command,
                "start=",
                "auto",
                "DisplayName=",
                s.display_name,
            ];
            if let Some(d) = &s.depends {
                args.extend(["depend=", d]);
            }
            sys.run("sc.exe", &args)?;
            true
        }
    };
    sys.try_run("sc.exe", &["description", s.name, s.description]);
    sys.try_run(
        "sc.exe",
        &[
            "failure",
            s.name,
            "reset=",
            "86400",
            "actions=",
            s.failure_actions,
        ],
    );
    Ok(changed)
}

/// webjetd as a service that starts after the time and DNS client services
/// (§18.6), and the signer when there is one, restarting after failures.
fn agent_windows_service(l: &Layout) -> WindowsService<'static> {
    WindowsService {
        name: SERVICE,
        command: windows_service_command(l),
        display_name: crate::layout::SERVICE_DISPLAY_NAME,
        description: crate::layout::SERVICE_DESCRIPTION,
        depends: Some(agent_depends(
            query("sc.exe", &["query", crate::layout::SIGNER_SERVICE]).is_some(),
        )),
        failure_actions: "restart/5000/restart/5000/restart/30000",
    }
}

fn windows_service_exists() -> bool {
    query("sc.exe", &["query", SERVICE]).is_some()
}

/// The agent's Windows service dependencies; the signer's service joins
/// them when it is installed, so the agent starts after it.
pub fn windows_agent_depends(sys: &Sys, signer: bool) {
    if !windows_service_exists() {
        return;
    }
    sys.try_run(
        "sc.exe",
        &["config", SERVICE, "depend=", &agent_depends(signer)],
    );
}

/// The services webjetd waits for on Windows: time and DNS (§18.6), and the
/// signer when there is one.
fn agent_depends(signer: bool) -> String {
    if signer {
        format!("W32Time/Dnscache/{}", crate::layout::SIGNER_SERVICE)
    } else {
        "W32Time/Dnscache".to_string()
    }
}

/// Stop the agent if it runs.
pub fn stop(sys: &Sys, l: &Layout) {
    if cfg!(target_os = "macos") {
        if let Some(p) = &l.service_file
            && p.exists()
        {
            sys.try_run("launchctl", &["bootout", "system", &p.to_string_lossy()]);
        }
    } else if cfg!(windows) {
        if !windows_service_exists() {
            return;
        }
        sys.try_run("sc.exe", &["stop", SERVICE]);
        if sys.dry {
            return;
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(60) {
            if query("sc.exe", &["query", SERVICE]).is_none_or(|o| o.contains("STOPPED")) {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        println!("    webjetd did not stop within 60 s");
    } else if cfg!(target_os = "freebsd") {
        crate::freebsd::stop(sys, crate::freebsd::AGENT);
    } else if l.service_file.as_deref().is_some_and(Path::exists) && have("systemctl") {
        sys.try_run("systemctl", &["stop", SERVICE]);
    }
}

/// What webjetd may do as its unprivileged user on Linux: create the tun
/// interface and set routes (NET_ADMIN), listen on ports below 1024 as a
/// relay (NET_BIND_SERVICE), and capture outgoing broadcast and multicast
/// with a packet socket (NET_RAW, §9.5.2).
pub const AGENT_CAPABILITIES: &str = "CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW";

/// `tss` owns /dev/tpmrm0; an identity key sealed in the TPM (§8.3) needs it.
fn systemd_unit(l: &Layout, tss_group: bool) -> String {
    let groups = if tss_group {
        "SupplementaryGroups=tss\n"
    } else {
        ""
    };
    format!(
        "[Unit]
Description=Webjet agent
Documentation=https://forgejo.wolf109909.top/webj8/webjet
Wants=network-online.target time-sync.target
After=network-online.target time-sync.target

[Service]
ExecStart={bin} run
Restart=on-failure
RestartSec=5
User={LINUX_USER}
{groups}AmbientCapabilities={caps}
CapabilityBoundingSet={caps}
StateDirectory=webjet
StateDirectoryMode=0700
RuntimeDirectory=webjet
RuntimeDirectoryMode=0751
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
LimitCORE=0
LimitMEMLOCK=1M

[Install]
WantedBy=multi-user.target
",
        bin = l.program("webjetd").display(),
        caps = AGENT_CAPABILITIES
    )
}

/// The launchd daemon. webjetd logs to stdout (tracing) and panics to stderr:
/// both go to the log file.
fn launchd_plist(l: &Layout) -> String {
    let log = l.log.as_deref().map_or_else(
        || "/var/log/webjetd.log".into(),
        |p| p.display().to_string(),
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array><string>{bin}</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"#,
        bin = l.program("webjetd").display()
    )
}

/// The Linux system user exists.
pub fn ensure_linux_user(sys: &Sys) -> Result<()> {
    ensure_user(sys, LINUX_USER)
}

/// A Linux system user `name` exists.
pub fn ensure_user(sys: &Sys, name: &str) -> Result<()> {
    if query("id", &["-u", name]).is_some() {
        return Ok(());
    }
    let nologin = ["/usr/sbin/nologin", "/sbin/nologin"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("/bin/false");
    sys.run(
        "useradd",
        &["--system", "--no-create-home", "--shell", nologin, name],
    )
}

/// The state directory belongs to the agent's user (enrollment ran as root).
pub fn fix_linux_ownership(sys: &Sys, l: &Layout) -> Result<()> {
    if l.data_dir.exists() || sys.dry {
        sys.run(
            "chown",
            &[
                "-R",
                &format!("{LINUX_USER}:"),
                &l.data_dir.to_string_lossy(),
            ],
        )?;
    }
    Ok(())
}

/// Write a service definition when it differs from `want`: each release's
/// is the one it was tested with, so an upgrade replaces an older one.
/// Whether it changed.
pub fn write_if_changed(sys: &Sys, path: &Path, want: &str, mode: u32) -> Result<bool> {
    if std::fs::read_to_string(path).ok().as_deref() == Some(want) {
        return Ok(false);
    }
    if path.exists() {
        println!("    updating {}", path.display());
    }
    if let Some(d) = path.parent() {
        sys.mkdir(d, false)?;
    }
    sys.write(path, want, mode)?;
    Ok(true)
}

/// Register the agent's service, or bring its definition up to date, and
/// (re)start it as `start` says. Whether it was (re)started.
pub fn setup_service(sys: &Sys, l: &Layout, start: Start) -> Result<bool> {
    if cfg!(target_os = "macos") {
        let plist = l
            .service_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("/Library/LaunchDaemons/net.webjet.webjetd.plist"));
        // launchd reads the plist again on bootstrap.
        let go = start.now(write_if_changed(sys, &plist, &launchd_plist(l), 0o644)?);
        if go {
            sys.try_run(
                "launchctl",
                &["bootout", "system", &plist.to_string_lossy()],
            );
            sys.run(
                "launchctl",
                &["bootstrap", "system", &plist.to_string_lossy()],
            )?;
        }
        Ok(go)
    } else if cfg!(windows) {
        let go = start.now(windows_service(sys, &agent_windows_service(l))?);
        if go {
            stop(sys, l);
            sys.run("sc.exe", &["start", SERVICE])?;
        }
        Ok(go)
    } else if cfg!(target_os = "freebsd") {
        let name = crate::freebsd::AGENT;
        let go = start.now(crate::freebsd::install(
            sys,
            name,
            &crate::freebsd::agent_script(l),
        )?);
        if go {
            crate::freebsd::restart(sys, name)?;
        }
        Ok(go)
    } else {
        let unit = l
            .service_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/systemd/system/webjetd.service"));
        let tss = query("getent", &["group", "tss"]).is_some();
        let go = start.now(write_if_changed(sys, &unit, &systemd_unit(l, tss), 0o644)?);
        if !have("systemctl") {
            println!(
                "    systemd isn't running here: start the agent yourself (webjetd run as user {LINUX_USER})"
            );
            return Ok(false);
        }
        sys.run("systemctl", &["daemon-reload"])?;
        sys.run("systemctl", &["enable", SERVICE])?;
        if go {
            sys.run("systemctl", &["restart", SERVICE])?;
        }
        Ok(go)
    }
}

/// Stop the agent and unregister the service. webjetd cleans up its routes
/// and DNS settings when it stops.
pub fn remove_service(sys: &Sys, l: &Layout) -> Result<()> {
    if cfg!(target_os = "macos") {
        stop(sys, l);
        if let Some(p) = &l.service_file {
            sys.remove_file(p)?;
        }
    } else if cfg!(windows) {
        if !windows_service_exists() {
            return Ok(());
        }
        // The agent removes its split-DNS rules when it stops; this catches
        // what an unclean stop left behind.
        stop(sys, l);
        sys.run("sc.exe", &["delete", SERVICE])?;
        sys.try_run(
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                WINDOWS_NRPT_CLEANUP,
            ],
        );
    } else if cfg!(target_os = "freebsd") {
        crate::freebsd::remove(sys, crate::freebsd::AGENT)?;
    } else if let Some(unit) = &l.service_file
        && unit.exists()
    {
        if have("systemctl") {
            sys.try_run("systemctl", &["disable", "--now", SERVICE]);
        }
        sys.remove_file(unit)?;
        if have("systemctl") {
            sys.try_run("systemctl", &["daemon-reload"]);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- Windows PATH

/// PowerShell to add or drop `dir` in the machine-wide PATH.
fn windows_path_script(dir: &Path, add: bool) -> String {
    let d = dir.to_string_lossy().replace('\'', "''");
    if add {
        format!(
            "$p=[Environment]::GetEnvironmentVariable('Path','Machine'); if (($p -split ';') -notcontains '{d}') {{ [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';') + ';{d}'), 'Machine') }}"
        )
    } else {
        format!(
            "$p=[Environment]::GetEnvironmentVariable('Path','Machine'); [Environment]::SetEnvironmentVariable('Path', ((($p -split ';') | Where-Object {{ $_ -and $_ -ne '{d}' }}) -join ';'), 'Machine')"
        )
    }
}

pub fn windows_path(sys: &Sys, dir: &Path, add: bool) -> Result<()> {
    sys.run(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &windows_path_script(dir, add),
        ],
    )
}

/// PowerShell that creates the shortcut `lnk` to `target`.
fn windows_shortcut_script(lnk: &Path, target: &Path) -> String {
    let q = |p: &Path| p.to_string_lossy().replace('\'', "''");
    format!(
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath='{}'; $s.Description='Webjet'; $s.Save()",
        q(lnk),
        q(target)
    )
}

/// The Start menu shortcut to the desktop app: created when `target` is
/// installed, removed otherwise. A failure is only a note.
pub fn windows_shortcut(sys: &Sys, lnk: &Path, target: &Path) -> Result<()> {
    if !(target.exists() || sys.dry) {
        return sys.remove_file(lnk);
    }
    if lnk.exists() {
        return Ok(());
    }
    sys.say(&format!("create the shortcut {}", lnk.display()));
    if !sys.dry
        && !sys.try_run(
            "powershell.exe",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &windows_shortcut_script(lnk, target),
            ],
        )
    {
        println!("    note: creating {} failed", lnk.display());
    }
    Ok(())
}

/// Restrict a directory to SYSTEM and Administrators (§19.1).
pub fn windows_restrict(sys: &Sys, dir: &Path) -> Result<()> {
    sys.run(
        "icacls",
        &[
            &dir.to_string_lossy(),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ],
    )
}

// ---------------------------------------------------------------- leftovers for nuke

/// Delete the identity keys webjetd put in the System keychain and, when
/// webjetd.toml names one (`[key] keychain`), that keychain (macOS).
///
/// Items are deleted through the Security framework by reference, without
/// reading them, so it works whatever their access list says (0.4.0 created
/// them readable only by webjetctl), and without UI, so it can't hang on a
/// consent dialog. Afterwards it checks that none are left.
pub fn delete_keychain_items(sys: &Sys, config: &Path) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }
    let mut keychains = vec![PathBuf::from(layout::SYSTEM_KEYCHAIN)];
    if let Some(k) = configured_keychain(config)
        && !keychains.contains(&k)
    {
        keychains.push(k);
    }
    for kc in &keychains {
        if sys.dry {
            sys.say(&format!(
                "delete the {} items from {}",
                layout::KEYCHAIN_SERVICE,
                kc.display()
            ));
            continue;
        }
        if !kc.exists() {
            continue;
        }
        let n = keychain::delete_all(kc)
            .with_context(|| format!("delete identity keys from {}", kc.display()))?;
        if n > 0 {
            println!("    removed {n} identity key(s) from {}", kc.display());
        }
        let left = keychain::count(kc)?;
        if left > 0 {
            bail!(
                "{left} identity key(s) are still in {} (service {}); delete them with \
                 `sudo security delete-generic-password -s {} {}`",
                kc.display(),
                layout::KEYCHAIN_SERVICE,
                layout::KEYCHAIN_SERVICE,
                kc.display()
            );
        }
    }
    Ok(())
}

/// `[key] keychain` from webjetd.toml, if set.
fn configured_keychain(config: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(config).ok()?;
    let v: toml::Table = text.parse().ok()?;
    let p = v.get("key")?.get("keychain")?.as_str()?;
    let p = PathBuf::from(p);
    Some(if p.is_relative() {
        config.parent().unwrap_or(Path::new("/")).join(p)
    } else {
        p
    })
}

#[cfg(target_os = "macos")]
mod keychain {
    use super::layout::KEYCHAIN_SERVICE;
    use anyhow::{Result, anyhow, bail};
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::keychain_item::SecKeychainItemDelete;
    use std::path::Path;

    fn find(
        kc: &Path,
    ) -> Result<Vec<security_framework::os::macos::keychain_item::SecKeychainItem>> {
        let keychain =
            SecKeychain::open(kc).map_err(|e| anyhow!("open keychain {}: {e}", kc.display()))?;
        let found = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .keychains(&[keychain])
            .service(KEYCHAIN_SERVICE)
            .load_refs(true)
            .limit(Limit::All)
            .search();
        let found = match found {
            Ok(v) => v,
            Err(e) if e.code() == errSecItemNotFound => return Ok(Vec::new()),
            Err(e) => bail!("search {}: {e}", kc.display()),
        };
        Ok(found
            .into_iter()
            .filter_map(|r| match r {
                SearchResult::Ref(Reference::KeychainItem(i)) => Some(i),
                _ => None,
            })
            .collect())
    }

    pub fn delete_all(kc: &Path) -> Result<usize> {
        use core_foundation::base::TCFType;
        let _ui = SecKeychain::disable_user_interaction();
        let items = find(kc)?;
        for item in &items {
            // SAFETY: `item` is a live keychain item reference.
            let status = unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef()) };
            if status != 0 {
                bail!("{}", security_framework::base::Error::from_code(status));
            }
        }
        Ok(items.len())
    }

    pub fn count(kc: &Path) -> Result<usize> {
        let _ui = SecKeychain::disable_user_interaction();
        Ok(find(kc)?.len())
    }
}

#[cfg(not(target_os = "macos"))]
mod keychain {
    use anyhow::Result;
    use std::path::Path;
    pub fn delete_all(_: &Path) -> Result<usize> {
        Ok(0)
    }
    pub fn count(_: &Path) -> Result<usize> {
        Ok(0)
    }
}

/// Split-DNS files webjetd left in /etc/resolver after an unclean stop.
pub fn macos_resolver_files() -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir("/etc/resolver") else {
        return Vec::new();
    };
    rd.flatten()
        .map(|e| e.path())
        .filter(|p| {
            std::fs::read_to_string(p)
                .is_ok_and(|s| s.lines().any(|l| l.trim_start().starts_with("# webjet")))
        })
        .collect()
}

/// Remove this executable. Windows can't delete a running program, so a
/// helper deletes it a moment after webjetup exits.
pub fn remove_self(sys: &Sys, path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let running = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());
    let is_self = running.as_deref() == path.canonicalize().ok().as_deref();
    if cfg!(windows) && is_self {
        sys.say(&format!("remove {} after webjetup exits", path.display()));
        if sys.dry {
            return Ok(());
        }
        let cmd = format!(
            "ping -n 3 127.0.0.1 >nul & del /f /q \"{}\" & rmdir \"{}\"",
            path.display(),
            path.parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );
        Command::new("cmd.exe")
            .args(["/C", &cmd])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("schedule removal")?;
        return Ok(());
    }
    sys.remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_files_point_at_the_installed_agent() {
        let l = Layout::system();
        let unit = systemd_unit(&l, false);
        assert!(unit.contains(&format!("ExecStart={} run", l.program("webjetd").display())));
        assert!(unit.contains(
            "User=webjet\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW\n"
        ));
        assert!(
            unit.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW\n"),
            "relays listen on 443; multicast capture needs a packet socket"
        );
        assert!(systemd_unit(&l, true).contains("User=webjet\nSupplementaryGroups=tss\n"));
        let plist = launchd_plist(&l);
        assert!(plist.contains("<string>net.webjet.webjetd</string>"));
        for key in ["StandardOutPath", "StandardErrorPath"] {
            assert!(
                plist.contains(&format!(
                    "<key>{key}</key><string>/var/log/webjetd.log</string>"
                )),
                "webjetd logs to stdout: {key}"
            );
        }
        assert!(plist.contains(&format!(
            "<string>{}</string><string>run</string>",
            l.program("webjetd").display()
        )));
    }

    #[test]
    fn start_modes() {
        assert!(!Start::No.now(true) && !Start::No.now(false));
        assert!(Start::Yes.now(false) && Start::Yes.now(true));
        assert!(Start::IfChanged.now(true) && !Start::IfChanged.now(false));
    }

    #[test]
    fn service_definitions_are_rewritten_only_when_they_differ() {
        let d = tempfile::tempdir().unwrap();
        let sys = Sys { dry: false };
        let unit = d.path().join("dir/webjetd.service");
        assert!(
            write_if_changed(&sys, &unit, "old", 0o644).unwrap(),
            "created"
        );
        assert!(
            !write_if_changed(&sys, &unit, "old", 0o644).unwrap(),
            "unchanged"
        );
        assert!(
            write_if_changed(&sys, &unit, "new", 0o644).unwrap(),
            "updated"
        );
        assert_eq!(std::fs::read_to_string(&unit).unwrap(), "new");
        let dry = Sys { dry: true };
        assert!(write_if_changed(&dry, &unit, "newer", 0o644).unwrap());
        assert_eq!(std::fs::read_to_string(&unit).unwrap(), "new");
    }

    /// `sc.exe qc` output of a service an older webjetup registered.
    const SC_QC: &str = r#"[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: webjetd
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Webjet\webjetd.exe" --config "C:\ProgramData\Webjet\webjetd.toml" service
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Webjet agent
        DEPENDENCIES       : W32Time
                           : Dnscache
        SERVICE_START_NAME : LocalSystem
"#;

    #[test]
    fn windows_services_are_compared_with_what_is_registered() {
        let svc = |command: &str, depends: Option<&str>| WindowsService {
            name: "webjetd",
            command: command.to_string(),
            display_name: "Webjet agent",
            description: "",
            depends: depends.map(str::to_string),
            failure_actions: "",
        };
        let cmd = r#""C:\Program Files\Webjet\webjetd.exe" --config "C:\ProgramData\Webjet\webjetd.toml" service"#;
        assert!(windows_service_current(
            SC_QC,
            &svc(cmd, Some("W32Time/Dnscache"))
        ));
        assert!(windows_service_current(
            SC_QC,
            &svc(cmd, Some("dnscache/w32time"))
        ));
        assert!(windows_service_current(SC_QC, &svc(cmd, None)));
        assert!(
            !windows_service_current(SC_QC, &svc(cmd, Some("W32Time/Dnscache/webjet-signer"))),
            "a new dependency"
        );
        assert!(
            !windows_service_current(SC_QC, &svc(&cmd.replace(" service", " run"), None)),
            "another command line"
        );
        assert!(!windows_service_current(
            &SC_QC.replace("2   AUTO_START", "3   DEMAND_START"),
            &svc(cmd, None)
        ));
    }

    #[test]
    fn keychain_path_from_the_config() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("webjetd.toml");
        assert_eq!(configured_keychain(&c), None, "no config");
        std::fs::write(
            &c,
            "[key]\nstorage = \"keychain\"\nkeychain = \"k.keychain-db\"\n",
        )
        .unwrap();
        assert_eq!(
            configured_keychain(&c),
            Some(d.path().join("k.keychain-db"))
        );
        std::fs::write(&c, "[key]\nkeychain = \"/x/k.keychain-db\"\n").unwrap();
        assert_eq!(
            configured_keychain(&c),
            Some(PathBuf::from("/x/k.keychain-db"))
        );
        std::fs::write(&c, "[key]\nstorage = \"file\"\n").unwrap();
        assert_eq!(configured_keychain(&c), None);
    }

    /// Items created by another program with the default access list (as
    /// 0.4.0's webjetctl did) can't be read by webjetup, but are deleted.
    /// Runs against a temporary keychain (no root needed).
    #[cfg(target_os = "macos")]
    #[test]
    fn nuke_deletes_keychain_items_it_cannot_read() {
        use security_framework::os::macos::keychain::CreateOptions;
        let d = tempfile::tempdir().unwrap();
        let kcp = d.path().join("test.keychain-db");
        let mut kc = CreateOptions::new().password("pw").create(&kcp).unwrap();
        kc.unlock(Some("pw")).unwrap();
        let add = |service: &str, account: &str| {
            let ok = Command::new("security")
                .args([
                    "add-generic-password",
                    "-s",
                    service,
                    "-a",
                    account,
                    "-w",
                    "secret",
                ])
                .arg(&kcp)
                .status()
                .unwrap()
                .success();
            assert!(ok, "security add-generic-password");
        };
        add(layout::KEYCHAIN_SERVICE, "identity-1");
        add(layout::KEYCHAIN_SERVICE, "identity-2");
        add("something.else", "identity-1");
        assert_eq!(keychain::count(&kcp).unwrap(), 2);
        assert_eq!(keychain::delete_all(&kcp).unwrap(), 2);
        assert_eq!(keychain::count(&kcp).unwrap(), 0);
        assert_eq!(keychain::delete_all(&kcp).unwrap(), 0, "nothing left");
        let other = Command::new("security")
            .args(["find-generic-password", "-s", "something.else"])
            .arg(&kcp)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(other.success(), "other items are kept");
        drop(kc);
    }

    #[test]
    fn windows_service_runs_the_agent_with_its_config() {
        let l = Layout::system();
        let cmd = windows_service_command(&l);
        assert!(cmd.starts_with(&format!("\"{}\"", l.program("webjetd").display())));
        assert!(cmd.ends_with(&format!("--config \"{}\" service", l.config.display())));
    }

    #[test]
    fn windows_path_scripts_quote_the_directory() {
        let s = windows_path_script(Path::new(r"C:\Program Files\Web'jet"), true);
        assert!(s.contains(r"C:\Program Files\Web''jet"));
        assert!(windows_path_script(Path::new(r"C:\X"), false).contains("-ne 'C:\\X'"));
    }

    #[test]
    fn dry_run_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let sys = Sys { dry: true };
        let f = d.path().join("a/b/file");
        sys.mkdir(f.parent().unwrap(), false).unwrap();
        assert!(!f.parent().unwrap().exists());
        let real = d.path().join("keep");
        std::fs::write(&real, "x").unwrap();
        sys.remove_file(&real).unwrap();
        assert!(real.exists());
        assert!(sys.run("definitely-not-a-program", &[]).is_ok());
    }

    #[test]
    fn install_file_replaces_atomically() {
        let d = tempfile::tempdir().unwrap();
        let sys = Sys { dry: false };
        let (src, dest) = (d.path().join("new"), d.path().join("prog"));
        std::fs::write(&src, "v2").unwrap();
        std::fs::write(&dest, "v1").unwrap();
        sys.install_file(&src, &dest, 0o755).unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "v2");
        assert!(!dest.with_extension("webjetup-new").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }

    #[test]
    fn install_file_leaves_nothing_behind_on_failure() {
        let d = tempfile::tempdir().unwrap();
        let sys = Sys { dry: false };
        let dest = d.path().join("prog");
        std::fs::write(&dest, "v1").unwrap();
        assert!(
            sys.install_file(&d.path().join("missing"), &dest, 0o755)
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "v1");
        assert!(!dest.with_extension("webjetup-new").exists());
        // A destination that can't be replaced (a directory here) keeps
        // its content and leaves no temporary file.
        let src = d.path().join("new");
        std::fs::write(&src, "v2").unwrap();
        let dir = d.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("x"), "x").unwrap();
        assert!(sys.install_file(&src, &dir, 0o755).is_err());
        assert!(dir.join("x").exists());
        assert!(!dir.with_extension("webjetup-new").exists());
    }

    #[test]
    fn aside_names_skip_files_still_in_use() {
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("webjetup.exe");
        assert_eq!(
            aside_path(&dest).unwrap(),
            d.path().join("webjetup.webjetup-old")
        );
        // A leftover that can be removed is reused.
        std::fs::write(d.path().join("webjetup.webjetup-old"), "x").unwrap();
        assert_eq!(
            aside_path(&dest).unwrap(),
            d.path().join("webjetup.webjetup-old")
        );
        assert!(!d.path().join("webjetup.webjetup-old").exists());
        // One that can't (a non-empty directory stands in for a running
        // program) is skipped.
        std::fs::create_dir(d.path().join("webjetup.webjetup-old")).unwrap();
        std::fs::write(d.path().join("webjetup.webjetup-old/x"), "x").unwrap();
        assert_eq!(
            aside_path(&dest).unwrap(),
            d.path().join("webjetup.webjetup-old1")
        );
    }

    #[test]
    fn writes_replace_the_file_and_follow_links() {
        let d = tempfile::tempdir().unwrap();
        let sys = Sys { dry: false };
        let p = d.path().join("webjetd.toml");
        std::fs::write(&p, "old").unwrap();
        sys.write(&p, "new", 0o644).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new");
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            1,
            "no temporary file left"
        );
        #[cfg(unix)]
        {
            let link = d.path().join("link.toml");
            std::os::unix::fs::symlink(&p, &link).unwrap();
            sys.write(&link, "via link", 0o644).unwrap();
            assert!(link.is_symlink());
            assert_eq!(std::fs::read_to_string(&p).unwrap(), "via link");
        }
    }

    #[test]
    fn config_reads_fail_unless_the_file_is_missing() {
        let d = tempfile::tempdir().unwrap();
        let mut l = Layout::system();
        l.config = d.path().join("webjetd.toml");
        assert_eq!(read_config(&l).unwrap(), "");
        std::fs::write(&l.config, "[log]\n").unwrap();
        assert_eq!(read_config(&l).unwrap(), "[log]\n");
        std::fs::write(&l.config, [0xff, 0xfe, 0x00]).unwrap();
        assert!(
            read_config(&l).is_err(),
            "not UTF-8: refused, not treated as empty"
        );
    }

    #[test]
    fn refuses_to_remove_shallow_paths() {
        let sys = Sys { dry: false };
        let root = if cfg!(windows) {
            PathBuf::from(r"C:\")
        } else {
            PathBuf::from("/usr")
        };
        assert!(sys.remove_dir_all(&root).is_err());
    }
}
