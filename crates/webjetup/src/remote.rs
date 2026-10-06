//! Remote upgrades (architecture §19.8, ops guide 3.3): the root helper that
//! carries out an admin's signed upgrade request.
//!
//! webjetd, which on Linux runs unprivileged, checks the request against
//! its tree and drops it into `<spool>/queue/`. The service manager starts
//! `webjetup apply-upgrade` as root when it appears:
//!
//! * Linux: `webjet-upgrade.path` (PathExists) starts the oneshot
//!   `webjet-upgrade.service`; a drop-in lets the sandboxed agent write the
//!   queue;
//! * macOS: launchd job `net.webjet.upgrade` with QueueDirectories;
//! * Windows: scheduled task "Webjet upgrade", as SYSTEM, every minute.
//!
//! The helper trusts nothing the agent wrote: it checks the request itself
//! against the network's root key and the node id pinned in `trust.json`
//! when webjetup set it up, refuses downgrades and replays, downloads only
//! the files whose SHA-256 the admin signed, keeps the previous programs,
//! and puts them back when the new agent doesn't report the new version
//! within [`HEALTH_TIMEOUT`]. It also replaces webjetup itself (the one
//! exception to "webjetup never updates itself").
//!
//! On by default; `webjetup install --no-remote-upgrade` turns it off (no
//! helper, and `[upgrade] remote = false` so the agent refuses too).

use crate::layout::{
    LINUX_USER, Layout, SELF, SERVICE, UPGRADE_LAUNCHD_LABEL, UPGRADE_SERVICE, UPGRADE_TASK,
};
use crate::release::{Client, Repo};
use crate::system::{self, Sys, have, query};
use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use webjet_release::{self as rel, HelperStatus, UpgradeState};

/// How long the new agent has to come up and report its version.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(120);

/// Request ids the helper has used, with their expiry (in the spool).
const USED_FILE: &str = "used.json";
/// The programs before the last upgrade (in the spool).
const PREVIOUS_DIR: &str = "previous";

// ---------------------------------------------------------------- configuration

/// `[upgrade] remote` in webjetd.toml (default on).
pub fn configured_on(toml_text: &str) -> bool {
    toml::from_str::<toml::Value>(toml_text)
        .ok()
        .and_then(|v| v.get("upgrade")?.get("remote")?.as_bool())
        .unwrap_or(true)
}

fn has_section(toml_text: &str) -> bool {
    toml::from_str::<toml::Value>(toml_text)
        .ok()
        .is_some_and(|v| v.get("upgrade").is_some())
}

/// webjetd.toml with `[upgrade] remote` set to `on` (or the section dropped,
/// for an agent that doesn't know it), comments kept. `None`: no change.
pub fn with_remote(toml_text: &str, on: Option<bool>) -> Result<Option<String>> {
    let mut doc: toml_edit::DocumentMut = toml_text.parse().context("webjetd.toml")?;
    match on {
        None => {
            if doc.remove("upgrade").is_none() {
                return Ok(None);
            }
        }
        Some(on) => {
            if configured_on(toml_text) == on && (on || has_section(toml_text)) {
                return Ok(None);
            }
            if !doc.contains_key("upgrade") {
                doc["upgrade"] = toml_edit::table();
            }
            let Some(t) = doc["upgrade"].as_table_like_mut() else {
                bail!("webjetd.toml: `upgrade` is not a table");
            };
            t.insert("remote", toml_edit::value(on));
        }
    }
    Ok(Some(doc.to_string()))
}

/// Whether the installed webjetd knows `[upgrade]` (0.9.0 and later; older
/// ones refuse a webjetd.toml that has it).
fn agent_supports(l: &Layout) -> bool {
    query(&l.program("webjetd").to_string_lossy(), &["features"])
        .is_some_and(|o| o.lines().any(|f| f.trim() == "remote-upgrade"))
}

// ---------------------------------------------------------------- service files

fn queue(l: &Layout) -> PathBuf {
    rel::queue_dir(&l.upgrade_spool)
}

fn systemd_path_unit(l: &Layout) -> String {
    format!(
        "[Unit]
Description=Start the Webjet upgrade helper when the agent queues an admin's request

[Path]
PathExists={request}
Unit={UPGRADE_SERVICE}.service

[Install]
WantedBy=multi-user.target
",
        request = rel::request_path(&l.upgrade_spool).display()
    )
}

fn systemd_service_unit(l: &Layout) -> String {
    format!(
        "[Unit]
Description=Webjet upgrade helper (webjetup apply-upgrade)
Documentation=https://forgejo.wolf109909.top/webj8/webjet
After=network-online.target

[Service]
Type=oneshot
ExecStart={bin} apply-upgrade
TimeoutStartSec=30min
",
        bin = l.program(SELF).display()
    )
}

/// Lets the agent's sandbox (ProtectSystem=strict) write the queue.
fn systemd_dropin(l: &Layout) -> String {
    format!(
        "# Written by webjetup: remote upgrades (webjetup install --no-remote-upgrade removes it).
[Service]
ReadWritePaths=-{queue}
",
        queue = queue(l).display()
    )
}

fn systemd_dropin_path(l: &Layout) -> Option<PathBuf> {
    let unit = l.service_file.as_ref()?;
    let dir = unit.parent()?.join(format!("{SERVICE}.service.d"));
    Some(dir.join("remote-upgrade.conf"))
}

fn systemd_dir(l: &Layout) -> PathBuf {
    l.service_file
        .as_deref()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("/etc/systemd/system"), Path::to_path_buf)
}

fn launchd_plist(l: &Layout) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{UPGRADE_LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array><string>{bin}</string><string>apply-upgrade</string></array>
  <key>QueueDirectories</key><array><string>{queue}</string></array>
  <key>StandardOutPath</key><string>/var/log/webjet-upgrade.log</string>
  <key>StandardErrorPath</key><string>/var/log/webjet-upgrade.log</string>
</dict></plist>
"#,
        bin = l.program(SELF).display(),
        queue = queue(l).display()
    )
}

fn launchd_plist_path() -> PathBuf {
    PathBuf::from(format!(
        "/Library/LaunchDaemons/{UPGRADE_LAUNCHD_LABEL}.plist"
    ))
}

fn windows_task_command(l: &Layout) -> String {
    format!("\"{}\" apply-upgrade", l.program(SELF).display())
}

// ---------------------------------------------------------------- setup and removal

/// Set up (or keep, or remove) the helper after an install or enrollment.
/// `want`: `--remote-upgrade` (true) or `--no-remote-upgrade` (false);
/// `None` keeps what webjetd.toml says (on by default). `enrolled_now`: an
/// enrollment just wrote the node's state, so pin it again ([`write_trust`]).
///
/// Run before the agent starts: on Linux its sandbox must see the queue
/// directory when it starts to be able to write it.
pub fn setup(
    sys: &Sys,
    l: &Layout,
    repo: &Repo,
    want: Option<bool>,
    enrolled_now: bool,
) -> Result<()> {
    let text = std::fs::read_to_string(&l.config).unwrap_or_default();
    if !sys.dry && !agent_supports(l) {
        // An agent from before 0.9.0 would refuse the whole file.
        if let Some(new) = with_remote(&text, None)? {
            println!("    removing [upgrade] from webjetd.toml (this webjetd doesn't know it)");
            sys.write(&l.config, &new, 0o644)?;
        }
        if want == Some(true) {
            println!("    this webjetd has no remote upgrades (they came with 0.9.0)");
        }
        return remove(sys, l);
    }
    if let Some(w) = want
        && let Some(new) = with_remote(&text, Some(w))?
    {
        sys.write(&l.config, &new, 0o644)?;
    }
    let on = want.unwrap_or_else(|| configured_on(&text));
    if !on {
        println!("==> Remote upgrades are off ([upgrade] remote = false)");
        return remove(sys, l);
    }
    if cfg!(target_os = "linux") && !have("systemctl") {
        println!("    systemd isn't running here: no remote upgrade helper");
        return Ok(());
    }
    println!(
        "==> Remote upgrade helper (an admin's signed request upgrades this node; off: --no-remote-upgrade)"
    );
    sys.mkdir(&l.upgrade_spool, false)?;
    if cfg!(windows) {
        system::windows_restrict(sys, &l.upgrade_spool)?;
    }
    if l.enrolled() || sys.dry {
        write_trust(sys, l, repo, enrolled_now)?;
    }
    let q = queue(l);
    sys.mkdir(&q, true)?;
    if cfg!(target_os = "linux") {
        // The agent's user writes requests here and nothing else of the
        // spool, which stays root's.
        sys.run("chown", &[&format!("{LINUX_USER}:"), &q.to_string_lossy()])?;
    }
    install_trigger(sys, l)
}

/// `trust.json`: the root key and node id the helper checks against, read
/// from the node's state. That state belongs to the agent's user, so it is
/// pinned once, after an enrollment (`force`) or when there is none yet, and
/// a later install keeps it: an agent taken over in between can't swap in
/// its own root key. Only the repository is updated.
fn write_trust(sys: &Sys, l: &Layout, repo: &Repo, force: bool) -> Result<()> {
    if sys.dry {
        sys.say(&format!(
            "write {}",
            rel::trust_path(&l.upgrade_spool).display()
        ));
        return Ok(());
    }
    let read = |p: PathBuf| -> Result<Vec<u8>> {
        rel::read_untrusted(&p)?.ok_or_else(|| anyhow!("{} is missing", p.display()))
    };
    let path = rel::trust_path(&l.upgrade_spool);
    let kept = if force {
        None
    } else {
        rel::read_untrusted(&path)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<rel::Trust>(&b).ok())
    };
    let t = match kept {
        Some(t) => rel::Trust {
            repo: repo.web.clone(),
            ..t
        },
        None => {
            let node = read(l.data_dir.join("node.json"))?;
            let genesis = read(l.data_dir.join("genesis.wj"))?;
            rel::Trust::from_state(&node, &genesis, &repo.web)?
        }
    };
    let want = serde_json::to_vec_pretty(&t)?;
    if std::fs::read(&path).ok().as_deref() == Some(want.as_slice()) {
        return Ok(());
    }
    sys.say(&format!("write {}", path.display()));
    rel::write_atomic(&l.upgrade_spool, rel::TRUST_FILE, &want, 0o644)
}

fn install_trigger(sys: &Sys, l: &Layout) -> Result<()> {
    if cfg!(target_os = "macos") {
        let plist = launchd_plist_path();
        let want = launchd_plist(l);
        if std::fs::read_to_string(&plist).ok().as_deref() != Some(want.as_str()) {
            sys.write(&plist, &want, 0o644)?;
            sys.try_run(
                "launchctl",
                &["bootout", "system", &plist.to_string_lossy()],
            );
        }
        if query(
            "launchctl",
            &["print", &format!("system/{UPGRADE_LAUNCHD_LABEL}")],
        )
        .is_none()
        {
            sys.run(
                "launchctl",
                &["bootstrap", "system", &plist.to_string_lossy()],
            )?;
        }
    } else if cfg!(windows) {
        sys.run(
            "schtasks.exe",
            &[
                "/Create",
                "/TN",
                UPGRADE_TASK,
                "/SC",
                "MINUTE",
                "/MO",
                "1",
                "/RU",
                "SYSTEM",
                "/RL",
                "HIGHEST",
                "/TR",
                &windows_task_command(l),
                "/F",
            ],
        )?;
    } else {
        let dir = systemd_dir(l);
        for (path, want) in [
            (
                dir.join(format!("{UPGRADE_SERVICE}.path")),
                systemd_path_unit(l),
            ),
            (
                dir.join(format!("{UPGRADE_SERVICE}.service")),
                systemd_service_unit(l),
            ),
        ] {
            if std::fs::read_to_string(&path).ok().as_deref() != Some(want.as_str()) {
                sys.write(&path, &want, 0o644)?;
            }
        }
        if let Some(p) = systemd_dropin_path(l) {
            let want = systemd_dropin(l);
            if std::fs::read_to_string(&p).ok().as_deref() != Some(want.as_str()) {
                if let Some(d) = p.parent() {
                    sys.mkdir(d, false)?;
                }
                sys.write(&p, &want, 0o644)?;
            }
        }
        sys.run("systemctl", &["daemon-reload"])?;
        sys.run(
            "systemctl",
            &["enable", "--now", &format!("{UPGRADE_SERVICE}.path")],
        )?;
    }
    Ok(())
}

/// Remove the helper: trigger, service files and spool (but not webjetup).
pub fn remove(sys: &Sys, l: &Layout) -> Result<()> {
    if cfg!(target_os = "macos") {
        let plist = launchd_plist_path();
        if plist.exists() {
            sys.try_run(
                "launchctl",
                &["bootout", "system", &plist.to_string_lossy()],
            );
            sys.remove_file(&plist)?;
        }
    } else if cfg!(windows) {
        if query("schtasks.exe", &["/Query", "/TN", UPGRADE_TASK]).is_some() {
            sys.run("schtasks.exe", &["/Delete", "/TN", UPGRADE_TASK, "/F"])?;
        }
    } else {
        let dir = systemd_dir(l);
        let path = dir.join(format!("{UPGRADE_SERVICE}.path"));
        let service = dir.join(format!("{UPGRADE_SERVICE}.service"));
        let dropin = systemd_dropin_path(l);
        let any = path.exists() || service.exists() || dropin.as_deref().is_some_and(Path::exists);
        if any {
            if have("systemctl") {
                sys.try_run(
                    "systemctl",
                    &["disable", "--now", &format!("{UPGRADE_SERVICE}.path")],
                );
            }
            sys.remove_file(&path)?;
            sys.remove_file(&service)?;
            if let Some(d) = &dropin {
                sys.remove_file(d)?;
                if let Some(parent) = d.parent() {
                    let _ = std::fs::remove_dir(parent);
                }
            }
            if have("systemctl") {
                sys.try_run("systemctl", &["daemon-reload"]);
            }
        }
    }
    sys.remove_dir_all(&l.upgrade_spool)
}

/// One line for `webjetup status`.
pub fn state(l: &Layout) -> String {
    if !queue(l).is_dir() {
        let text = std::fs::read_to_string(&l.config).unwrap_or_default();
        return if configured_on(&text) {
            "no helper".into()
        } else {
            "off".into()
        };
    }
    match rel::read_status(&l.upgrade_spool) {
        Ok(Some(s)) => format!(
            "on; last: {} {}{}",
            s.version,
            serde_json::to_value(s.state)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            s.error.map(|e| format!(" ({e})")).unwrap_or_default()
        ),
        Ok(None) => "on".into(),
        Err(e) => format!("on; status unreadable: {e:#}"),
    }
}

// ---------------------------------------------------------------- the helper

fn write_status(l: &Layout, s: &HelperStatus) {
    println!(
        "==> {:?} {}{}",
        s.state,
        s.version,
        s.error
            .as_deref()
            .map(|e| format!(": {e}"))
            .unwrap_or_default()
    );
    let res = serde_json::to_vec_pretty(s)
        .map_err(anyhow::Error::from)
        .and_then(|b| rel::write_atomic(&l.upgrade_spool, rel::STATUS_FILE, &b, 0o644));
    if let Err(e) = res {
        eprintln!("webjetup: writing the upgrade status: {e:#}");
    }
}

/// Request ids used, dropping expired ones; `Err` when `id` is among them.
fn mark_used(l: &Layout, id: &str, expires_at: u64, now: u64) -> Result<()> {
    let path = l.upgrade_spool.join(USED_FILE);
    let mut used: Vec<(String, u64)> = rel::read_untrusted(&path)
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    used.retain(|(_, exp)| *exp > now);
    if used.iter().any(|(u, _)| u == id) {
        bail!("this request was used already");
    }
    used.push((id.to_string(), expires_at));
    rel::write_atomic(
        &l.upgrade_spool,
        USED_FILE,
        &serde_json::to_vec(&used)?,
        0o600,
    )
}

/// Remove what is in the queue directory (only what is older than
/// `older_than`, if given), following no links.
fn clear_queue(l: &Layout, older_than: Option<Duration>) {
    let Ok(entries) = std::fs::read_dir(queue(l)) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if let Some(age) = older_than
            && m.modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_none_or(|a| a < age)
        {
            continue;
        }
        let dir = m.is_dir();
        let _ = if dir {
            std::fs::remove_dir_all(&p)
        } else {
            std::fs::remove_file(&p)
        };
    }
}

/// `webjetup apply-upgrade`: take the queued request, if any, and carry it
/// out. Always removes the request, so the trigger doesn't fire again.
pub fn apply(sys: &Sys, l: &Layout) -> Result<()> {
    system::require_privileges(sys.dry)?;
    let req_path = rel::request_path(&l.upgrade_spool);
    let raw = match rel::read_untrusted(&req_path) {
        Ok(None) => {
            // launchd runs the helper while the queue has anything in it:
            // drop leftovers (an agent's temporary file that never became a
            // request) once they are old, so it doesn't run forever.
            if !sys.dry {
                clear_queue(l, Some(Duration::from_secs(60)));
            }
            return Ok(());
        }
        Ok(Some(b)) => Ok(b),
        Err(e) => Err(e),
    };
    // Taken: never act on the same file twice, whatever happens next. The
    // whole queue is emptied, so launchd (which runs the helper while the
    // directory has anything in it) and systemd don't start it again.
    if !sys.dry {
        clear_queue(l, None);
    }
    let refused = |version: &str, e: anyhow::Error| {
        write_status(
            l,
            &HelperStatus {
                id: String::new(),
                version: version.to_string(),
                from: None,
                state: UpgradeState::Refused,
                error: Some(format!("{e:#}")),
                at: rel::now_ms(),
            },
        );
        Err(e)
    };
    let raw = match raw {
        Ok(b) => b,
        Err(e) => return refused("", e),
    };
    let checked = (|| -> Result<(rel::Plan, Repo)> {
        let trust: rel::Trust = serde_json::from_slice(
            &rel::read_untrusted(&rel::trust_path(&l.upgrade_spool))?
                .ok_or_else(|| anyhow!("the helper isn't set up (no trust.json)"))?,
        )
        .context("trust.json")?;
        let q: rel::QueuedRequest = serde_json::from_slice(&raw).context("the queued request")?;
        let (request, account) = q.decode()?;
        let target = rel::target().ok_or_else(|| anyhow!("no Webjet release for this platform"))?;
        let installed = crate::installed_version(l);
        let now = rel::now_ms();
        let plan = rel::plan(
            &request,
            &account,
            &trust.root()?,
            &trust.node()?,
            target,
            installed.as_deref(),
            now,
        )?;
        mark_used(l, &plan.id, plan.expires_at, now)?;
        Ok((plan, Repo::parse(&trust.repo)?))
    })();
    let (plan, repo) = match checked {
        Ok(x) => x,
        Err(e) => return refused("", e),
    };
    let from = crate::installed_version(l);
    println!(
        "==> Remote upgrade {} → {} requested by {} ({})",
        from.as_deref().unwrap_or("?"),
        plan.version,
        plan.account_name,
        plan.account_id
    );
    let status = |state, error: Option<String>| HelperStatus {
        id: plan.id.clone(),
        version: plan.version.clone(),
        from: from.clone(),
        state,
        error,
        at: rel::now_ms(),
    };
    write_status(l, &status(UpgradeState::Running, None));
    let outcome = upgrade(sys, l, &repo, &plan);
    let (state, error) = match outcome {
        Ok(()) => (UpgradeState::Done, None),
        Err(Outcome::Failed(e)) => (UpgradeState::Failed, Some(format!("{e:#}"))),
        Err(Outcome::RolledBack(e)) => (UpgradeState::RolledBack, Some(format!("{e:#}"))),
        Err(Outcome::RollbackFailed(e)) => (UpgradeState::RollbackFailed, Some(format!("{e:#}"))),
    };
    write_status(l, &status(state, error.clone()));
    match error {
        None => Ok(()),
        Some(e) => bail!(e),
    }
}

enum Outcome {
    /// Nothing was replaced.
    Failed(anyhow::Error),
    /// Replaced, unhealthy, put back.
    RolledBack(anyhow::Error),
    /// Replaced, unhealthy, and putting it back failed too.
    RollbackFailed(anyhow::Error),
}

fn upgrade(sys: &Sys, l: &Layout, repo: &Repo, plan: &rel::Plan) -> Result<(), Outcome> {
    let stage = tempfile::tempdir().map_err(|e| Outcome::Failed(e.into()))?;
    let fetch = || -> Result<PathBuf> {
        let c = Client::new();
        let archive = c.fetch_pinned(
            repo,
            &plan.version,
            &plan.archive.name,
            &plan.archive.sha256,
            stage.path(),
        )?;
        crate::release::extract(&archive, stage.path(), &crate::wanted_files())?;
        let up = c.fetch_pinned(
            repo,
            &plan.version,
            &plan.webjetup.name,
            &plan.webjetup.sha256,
            stage.path(),
        )?;
        Ok(up)
    };
    let new_self = fetch().map_err(Outcome::Failed)?;
    backup(sys, l).map_err(Outcome::Failed)?;
    let install = || -> Result<()> {
        crate::install(sys, l, repo, Some(&plan.version), Some(stage.path()), true)?;
        sys.install_file(&new_self, &l.program(SELF), 0o755)?;
        restart(sys, l)
    };
    let want = plan.version.trim_start_matches('v');
    let problem = match install() {
        Ok(()) => match healthy(l, want, HEALTH_TIMEOUT) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        },
        Err(e) => e,
    };
    println!("==> {problem:#}; putting the previous version back");
    let back = || -> Result<()> {
        restore(sys, l)?;
        restart(sys, l)?;
        let old =
            crate::installed_version(l).ok_or_else(|| anyhow!("no webjetd after restoring"))?;
        healthy(l, &old, HEALTH_TIMEOUT)
    };
    match back() {
        Ok(()) => Err(Outcome::RolledBack(problem)),
        Err(e) => Err(Outcome::RollbackFailed(anyhow!(
            "{problem:#}; rolling back failed too: {e:#}"
        ))),
    }
}

fn restart(sys: &Sys, l: &Layout) -> Result<()> {
    if crate::signer::configured(l) {
        crate::signer::setup(sys, l, true)?;
    }
    crate::start_after_install(sys, l, true)
}

fn previous(l: &Layout) -> PathBuf {
    l.upgrade_spool.join(PREVIOUS_DIR)
}

fn backed_up_files() -> Vec<String> {
    let mut v = crate::wanted_files();
    v.push(crate::layout::exe(SELF));
    v
}

/// Copy the installed programs (and webjetup) aside.
fn backup(sys: &Sys, l: &Layout) -> Result<()> {
    let dir = previous(l);
    sys.remove_dir_all(&dir)?;
    sys.mkdir(&dir, true)?;
    for f in backed_up_files() {
        let src = l.bin_dir.join(&f);
        if src.exists() {
            sys.install_file(&src, &dir.join(&f), 0o755)?;
        }
    }
    Ok(())
}

fn restore(sys: &Sys, l: &Layout) -> Result<()> {
    system::stop(sys, l);
    let dir = previous(l);
    for f in backed_up_files() {
        let src = dir.join(&f);
        if src.exists() {
            let mode = if f.ends_with(".txt") { 0o644 } else { 0o755 };
            sys.install_file(&src, &l.bin_dir.join(&f), mode)?;
        }
    }
    Ok(())
}

/// Wait until the agent answers on its control socket with version `want`.
fn healthy(l: &Layout, want: &str, timeout: Duration) -> Result<()> {
    let ctl = l.program("webjetctl");
    let start = Instant::now();
    let mut last = String::from("no answer");
    while start.elapsed() < timeout {
        match query(&ctl.to_string_lossy(), &["--json", "local", "status"]) {
            Some(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
                let have = v.get("version").and_then(|x| x.as_str()).unwrap_or("");
                if have == want {
                    println!("==> The agent runs {want}");
                    return Ok(());
                }
                last = format!("the agent reports version {have:?}");
            }
            None => last = "the agent doesn't answer".into(),
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    bail!(
        "{last} {} s after the restart (wanted {want})",
        timeout.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_switch() {
        assert!(configured_on(""));
        assert!(configured_on("[upgrade]\n"));
        assert!(!configured_on("[upgrade]\nremote = false\n"));
        // Off: written, comments kept.
        let off = with_remote("# mine\n[tun]\nmtu = 1300\n", Some(false))
            .unwrap()
            .unwrap();
        assert!(off.starts_with("# mine\n"), "{off}");
        assert!(!configured_on(&off));
        // Off again: no change. On: set back.
        assert_eq!(with_remote(&off, Some(false)).unwrap(), None);
        let on = with_remote(&off, Some(true)).unwrap().unwrap();
        assert!(configured_on(&on) && on.contains("remote = true"), "{on}");
        // On by default: nothing written.
        assert_eq!(with_remote("", Some(true)).unwrap(), None);
        // For an old agent the section goes.
        let gone = with_remote(&off, None).unwrap().unwrap();
        assert!(!gone.contains("upgrade"), "{gone}");
        assert!(gone.contains("mtu = 1300"));
        assert_eq!(with_remote("", None).unwrap(), None);
        assert!(with_remote("upgrade = 1\n", Some(false)).is_err());
    }

    #[test]
    fn service_files_start_the_helper() {
        let mut l = Layout::system();
        l.upgrade_spool = PathBuf::from("/var/lib/webjet-upgrade");
        l.service_file = Some(PathBuf::from("/etc/systemd/system/webjetd.service"));
        let path = systemd_path_unit(&l);
        assert!(
            path.contains("PathExists=/var/lib/webjet-upgrade/queue/request.json\n"),
            "{path}"
        );
        assert!(path.contains("Unit=webjet-upgrade.service\n"));
        let svc = systemd_service_unit(&l);
        assert!(svc.contains(&format!(
            "ExecStart={} apply-upgrade\n",
            l.program(SELF).display()
        )));
        assert!(svc.contains("Type=oneshot\n"));
        // The agent's sandbox may write the queue, and nothing else of the spool.
        assert!(systemd_dropin(&l).contains("ReadWritePaths=-/var/lib/webjet-upgrade/queue\n"));
        assert_eq!(
            systemd_dropin_path(&l).unwrap(),
            Path::new("/etc/systemd/system/webjetd.service.d/remote-upgrade.conf")
        );
        let plist = launchd_plist(&l);
        assert!(plist.contains("<string>net.webjet.upgrade</string>"));
        assert!(plist.contains("<key>QueueDirectories</key><array><string>/var/lib/webjet-upgrade/queue</string></array>"));
        assert!(windows_task_command(&l).ends_with("\" apply-upgrade"));
    }

    #[test]
    fn requests_are_used_once() {
        let d = tempfile::tempdir().unwrap();
        let mut l = Layout::system();
        l.upgrade_spool = d.path().to_path_buf();
        mark_used(&l, "a", 2_000, 1_000).unwrap();
        assert!(mark_used(&l, "a", 2_000, 1_500).is_err());
        mark_used(&l, "b", 3_000, 1_500).unwrap();
        // Expired ids are forgotten (a request can't be used after expiry anyway).
        mark_used(&l, "a", 4_000, 2_500).unwrap();
    }

    #[test]
    fn without_a_request_the_helper_does_nothing() {
        let d = tempfile::tempdir().unwrap();
        let mut l = Layout::system();
        l.upgrade_spool = d.path().to_path_buf();
        apply(&Sys { dry: true }, &l).unwrap();
        assert!(rel::read_status(&l.upgrade_spool).unwrap().is_none());
    }

    #[test]
    fn a_request_without_trust_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let mut l = Layout::system();
        l.upgrade_spool = d.path().to_path_buf();
        std::fs::create_dir_all(queue(&l)).unwrap();
        let q = rel::QueuedRequest::new(b"r", b"a");
        std::fs::write(
            rel::request_path(&l.upgrade_spool),
            serde_json::to_vec(&q).unwrap(),
        )
        .unwrap();
        let e = apply(&Sys { dry: false }, &l);
        if !system::privileged() {
            assert!(format!("{:#}", e.unwrap_err()).contains("root"));
            return;
        }
        assert!(format!("{:#}", e.unwrap_err()).contains("trust.json"));
        assert!(!rel::request_path(&l.upgrade_spool).exists(), "taken");
        let st = rel::read_status(&l.upgrade_spool).unwrap().unwrap();
        assert_eq!(st.state, UpgradeState::Refused);
    }
}
