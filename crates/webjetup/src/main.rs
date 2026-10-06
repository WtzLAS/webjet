//! webjetup: installs, upgrades and removes Webjet on Linux, macOS and
//! Windows from the published releases.
//!
//!   webjetup install [VERSION]     install or upgrade (default: latest);
//!                                  --signer adds the signer service
//!   webjetup enroll <STRING>       enroll this node and start the agent
//!   webjetup status                what's installed and running
//!   webjetup list                  published releases
//!   webjetup remove                programs and service; keeps the identity
//!   webjetup nuke                  everything, including the node's identity

mod layout;
mod release;
mod signer;
mod system;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use layout::{Layout, PROGRAMS, RETIRED_PROGRAMS, SELF};
use release::{Client, Repo};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use system::Sys;

#[derive(Parser)]
#[command(
    name = "webjetup",
    version,
    about = "Install, upgrade and remove Webjet"
)]
struct Cli {
    /// The repository releases come from.
    #[arg(long, global = true, env = "WEBJETUP_REPO", default_value = release::DEFAULT_REPO)]
    repo: String,
    /// Show what would change without changing anything.
    #[arg(long, global = true)]
    dry_run: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install Webjet, or upgrade it to VERSION (default: the latest release).
    #[command(visible_alias = "upgrade")]
    Install {
        /// A release tag like v0.2.0, or `latest`.
        version: Option<String>,
        /// Install from an unpacked release directory or archive instead of
        /// downloading (no checksum check: you vouch for the files).
        #[arg(long, value_name = "PATH")]
        from: Option<PathBuf>,
        /// Enroll this node with an enrollment string as part of the install.
        #[arg(long, value_name = "STRING")]
        enroll: Option<String>,
        /// Install even if this version is installed already.
        #[arg(long)]
        force: bool,
        /// Don't start the agent (a later `webjetup enroll` starts it).
        #[arg(long)]
        no_start: bool,
        /// Also install the signer service, which holds a controller's
        /// signing key in a separate process (`webjetd signer`, §19.2), and
        /// point webjetd at it. Kept on later upgrades. An existing
        /// in-process key moves to the signer.
        #[arg(long)]
        signer: bool,
    },
    /// Enroll this node with an enrollment string from `webjetctl network node enroll`
    /// and (re)start the agent. Also used to re-key a node.
    Enroll {
        /// The enrollment string (`wj1:…`); `-` reads it from stdin.
        string: String,
    },
    /// Show the installed version, the service and this node's state.
    Status,
    /// List published releases.
    List {
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Stop the agent and remove the programs and the service. The node's
    /// identity, state and configuration stay, so a reinstall picks up where
    /// it left off.
    #[command(visible_alias = "uninstall")]
    Remove {
        /// Don't ask for confirmation.
        #[arg(short, long)]
        yes: bool,
    },
    /// Remove everything: programs, service, the node's identity key and
    /// network state, configuration, logs and leftover system settings, and
    /// webjetup itself. The node has to be enrolled again afterwards. Account
    /// keys in users' home directories are not touched.
    Nuke {
        /// Don't ask for confirmation.
        #[arg(short, long)]
        yes: bool,
    },
}

fn main() {
    // Like other command-line tools, end quietly when the reader of our
    // output goes away (`webjetup status | head`) instead of panicking on a
    // failed print: Rust ignores SIGPIPE by default.
    #[cfg(unix)]
    // SAFETY: restoring the default disposition of a signal, before any
    // other thread exists.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("webjetup: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let sys = Sys { dry: cli.dry_run };
    let layout = Layout::system();
    match cli.cmd {
        Cmd::Install {
            version,
            from,
            enroll,
            force,
            no_start,
            signer,
        } => {
            system::require_privileges(sys.dry)?;
            let repo = Repo::parse(&cli.repo)?;
            install(
                &sys,
                &layout,
                &repo,
                version.as_deref(),
                from.as_deref(),
                force,
            )?;
            // The signer starts first: the controller asks it for its key.
            if signer || signer::configured(&layout) {
                signer::setup(&sys, &layout, !no_start)?;
            }
            if let Some(s) = enroll {
                do_enroll(&sys, &layout, &s, !no_start)?;
            } else {
                start_after_install(&sys, &layout, !no_start)?;
            }
            Ok(())
        }
        Cmd::Enroll { string } => {
            system::require_privileges(sys.dry)?;
            let s = if string == "-" {
                read_stdin_line()?
            } else {
                string
            };
            do_enroll(&sys, &layout, &s, true)
        }
        Cmd::Status => status(&layout),
        Cmd::List { limit } => list(&Repo::parse(&cli.repo)?, &layout, limit),
        Cmd::Remove { yes } => {
            system::require_privileges(sys.dry)?;
            if !(yes || sys.dry) {
                confirm(
                    "Remove the Webjet programs and service? The node's identity and state are kept.",
                    "yes",
                )?;
            }
            remove(&sys, &layout)?;
            println!(
                "Webjet removed. The node's identity and state are kept in {}.",
                layout.data_dir.display()
            );
            println!(
                "Reinstall with `webjetup install`, or delete everything with `webjetup nuke`."
            );
            Ok(())
        }
        Cmd::Nuke { yes } => {
            system::require_privileges(sys.dry)?;
            if !(yes || sys.dry) {
                println!("This deletes Webjet completely from this machine, including:");
                println!(
                    "  - the node's identity key and network state ({})",
                    layout.data_dir.display()
                );
                println!("  - the configuration ({})", layout.config.display());
                println!("  - the programs, the service and webjetup itself");
                println!(
                    "The node must be enrolled again (and its old record revoked by an admin)."
                );
                confirm("Type `nuke` to continue", "nuke")?;
            }
            nuke(&sys, &layout)?;
            println!("Webjet has been removed from this machine.");
            Ok(())
        }
    }
}

fn read_stdin_line() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    let s = s.trim().to_string();
    if s.is_empty() {
        bail!("no enrollment string on stdin");
    }
    Ok(s)
}

/// Ask on the terminal; refuses without one (use --yes in scripts).
fn confirm(question: &str, answer: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("not confirmed: run with --yes to skip the question");
    }
    print!("{question} [{answer}]: ");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    let s = s.trim();
    if s == answer || (answer == "yes" && s == "y") {
        Ok(())
    } else {
        bail!("cancelled")
    }
}

/// `webjetd --version` of the installed agent, e.g. `0.2.0`.
fn installed_version(l: &Layout) -> Option<String> {
    let exe = l.program("webjetd");
    if !exe.exists() {
        return None;
    }
    let out = system::query(&exe.to_string_lossy(), &["--version"])?;
    out.split_whitespace().nth(1).map(str::to_string)
}

// ---------------------------------------------------------------- install

fn wanted_files() -> Vec<String> {
    let mut v: Vec<String> = PROGRAMS.iter().map(|p| layout::exe(p)).collect();
    v.extend(layout::extra_files().iter().map(|s| s.to_string()));
    v
}

/// Unpack (or copy) the release files into `stage`.
fn stage_from(from: &Path, stage: &Path) -> Result<()> {
    let wanted = wanted_files();
    if from.is_dir() {
        for f in &wanted {
            let src = from.join(f);
            if src.exists() {
                std::fs::copy(&src, stage.join(f))
                    .with_context(|| format!("copy {}", src.display()))?;
            }
        }
    } else {
        release::extract(from, stage, &wanted)?;
    }
    Ok(())
}

fn install(
    sys: &Sys,
    l: &Layout,
    repo: &Repo,
    version: Option<&str>,
    from: Option<&Path>,
    force: bool,
) -> Result<()> {
    let target = layout::target().ok_or_else(|| anyhow!("no Webjet release for this platform"))?;
    let stage = tempfile::tempdir()?;
    let have = installed_version(l);
    match from {
        Some(path) => {
            println!("==> Installing from {}", path.display());
            stage_from(path, stage.path())?;
        }
        None => {
            let client = Client::new();
            let tag = match version.map(release::normalize_version) {
                None => client.latest(repo)?,
                Some(v) if v == "latest" => client.latest(repo)?,
                Some(v) => v,
            };
            if !force && have.as_deref() == Some(tag.trim_start_matches('v')) {
                println!("Webjet {tag} is already installed (use --force to reinstall).");
                return Ok(());
            }
            client.check_release(repo, &tag)?;
            println!("==> Webjet {tag} for {target}");
            let archive = client.fetch_verified(
                repo,
                &tag,
                &layout::archive_name(&tag, target),
                stage.path(),
            )?;
            release::extract(&archive, stage.path(), &wanted_files())?;
        }
    }
    for f in wanted_files() {
        if !stage.path().join(&f).exists() {
            bail!("{f} is missing from the release");
        }
    }
    // The new agent must run here before we replace the old one.
    if !sys.dry {
        let staged = stage.path().join(layout::exe("webjetd"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        }
        let v = system::query(&staged.to_string_lossy(), &["--version"])
            .ok_or_else(|| anyhow!("the downloaded webjetd doesn't run on this machine"))?;
        println!("    {}", v.trim());
    }

    println!("==> Installing into {}", l.bin_dir.display());
    system::stop(sys, l);
    sys.mkdir(&l.bin_dir, false)?;
    for f in wanted_files() {
        let mode = if f.ends_with(".txt") { 0o644 } else { 0o755 };
        sys.install_file(&stage.path().join(&f), &l.bin_dir.join(&f), mode)?;
    }
    remove_retired(sys, l)?;
    // webjetup installs itself next to the programs, so `webjetup` keeps
    // working after install.sh's temporary copy is gone.
    install_self(sys, l)?;
    sys.mkdir(&l.config_dir, false)?;
    sys.mkdir(&l.data_dir, true)?;
    if cfg!(windows) {
        system::windows_restrict(sys, &l.config_dir)?;
        system::windows_path(sys, &l.bin_dir, true)?;
    }
    if cfg!(target_os = "linux") {
        system::ensure_linux_user(sys)?;
    }
    if !l.config.exists() {
        sys.write(&l.config, "# webjetd configuration: see docs/configuration.md.\n# Everything has a default; an empty file is a valid configuration.\n", 0o644)?;
    }
    Ok(())
}

/// Programs of older releases that newer ones merged into others.
fn remove_retired(sys: &Sys, l: &Layout) -> Result<()> {
    for p in RETIRED_PROGRAMS {
        sys.remove_file(&l.program(p))?;
    }
    Ok(())
}

fn install_self(sys: &Sys, l: &Layout) -> Result<()> {
    let me = std::env::current_exe().context("finding webjetup's own path")?;
    let dest = l.program(SELF);
    if me.canonicalize().ok() == dest.canonicalize().ok() {
        return Ok(());
    }
    sys.install_file(&me, &dest, 0o755)
}

fn start_after_install(sys: &Sys, l: &Layout, start: bool) -> Result<()> {
    if l.enrolled() {
        if cfg!(target_os = "linux") {
            system::fix_linux_ownership(sys, l)?;
        }
        system::setup_service(sys, l, start)?;
        if start {
            println!("==> Webjet agent (re)started.");
        }
    } else {
        // Without an identity the agent can't run: register the service but
        // let `webjetup enroll` start it.
        system::setup_service(sys, l, false)?;
        println!("==> Installed. Enroll this node to start the agent:");
        println!(
            "      {}webjetup enroll '<enrollment string>'",
            if cfg!(windows) { "" } else { "sudo " }
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- enroll

fn do_enroll(sys: &Sys, l: &Layout, string: &str, start: bool) -> Result<()> {
    let s = string.trim();
    if !s.starts_with("wj1:") {
        bail!("that doesn't look like an enrollment string (they start with wj1:)");
    }
    // Releases before 0.3.0 enrolled with `webjetd enroll`, 0.3.x with
    // `webjetctl enroll`, later ones with `webjetctl local enroll`.
    let version = installed_version(l);
    let legacy = version.as_deref().is_some_and(layout::before_0_3);
    let flat = version.as_deref().is_some_and(layout::before_0_4);
    let exe = l.program(if legacy { "webjetd" } else { "webjetctl" });
    if !exe.exists() && !sys.dry {
        bail!("Webjet isn't installed: run `webjetup install` first");
    }
    println!("==> Enrolling this node");
    let config = l.config.to_string_lossy();
    let args: Vec<&str> = if legacy {
        vec!["--config", &config, "enroll", s]
    } else if flat {
        vec!["enroll", "--config", &config, s]
    } else {
        vec!["local", "enroll", "--config", &config, s]
    };
    // The first controller of a new network (`webjetctl local init`) enrolls its
    // own node through its running agent, so it must not be stopped.
    if bootstrapping(l) {
        sys.run(&exe.to_string_lossy(), &args)?;
        println!("==> Enrolled the bootstrap controller's node.");
        return Ok(());
    }
    system::stop(sys, l);
    sys.run(&exe.to_string_lossy(), &args)?;
    if cfg!(target_os = "linux") {
        system::fix_linux_ownership(sys, l)?;
    }
    system::setup_service(sys, l, start)?;
    if start {
        println!("==> Enrolled; the agent is running. Check with `webjetctl local status`.");
    }
    Ok(())
}

/// Whether this is a bootstrap controller that hasn't enrolled its node yet
/// (`"bootstrap": true` in node.json, written by `webjetctl local init`).
fn bootstrapping(l: &Layout) -> bool {
    std::fs::read(l.data_dir.join("node.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("bootstrap").and_then(|b| b.as_bool()))
        .unwrap_or(false)
}
// ---------------------------------------------------------------- status and list

fn status(l: &Layout) -> Result<()> {
    let have = installed_version(l);
    println!("webjetup  {}", env!("CARGO_PKG_VERSION"));
    println!("webjetd   {}", have.as_deref().unwrap_or("not installed"));
    println!("programs  {}", l.bin_dir.display());
    println!(
        "config    {}{}",
        l.config.display(),
        if l.config.exists() { "" } else { " (missing)" }
    );
    println!("state     {}", l.data_dir.display());
    let enrolled = l.enrolled_checked();
    println!(
        "enrolled  {}",
        match enrolled {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown (can't read the state; run as root)",
        }
    );
    println!("service   {}", system::service_state(l));
    if let Some(st) = signer::state(l) {
        println!("signer    {st}");
    }
    if let Some(log) = &l.log {
        println!("log       {}", log.display());
    } else if cfg!(target_os = "linux") {
        println!("log       journalctl -u webjetd");
    }
    let ctl = l.program("webjetctl");
    if let Some(v) = have.as_deref()
        && enrolled == Some(true)
        && ctl.exists()
    {
        let args: &[&str] = if layout::before_0_4(v) {
            &["--json", "status"]
        } else {
            &["--json", "local", "status"]
        };
        match system::query(&ctl.to_string_lossy(), args) {
            Some(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
                if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                    println!("node      {name}");
                }
                if let Some(ips) = v.get("ips").and_then(|n| n.as_array()) {
                    let ips: Vec<&str> = ips.iter().filter_map(|i| i.as_str()).collect();
                    println!("addresses {}", ips.join(", "));
                }
                if let Some(p) = v.get("peers") {
                    println!("peers     {p}");
                }
            }
            None => println!("agent     not answering (is it running? are you root?)"),
        }
    }
    Ok(())
}

fn list(repo: &Repo, l: &Layout, limit: usize) -> Result<()> {
    let releases = Client::new().releases(repo, limit)?;
    let have = installed_version(l).map(|v| format!("v{v}"));
    if releases.is_empty() {
        println!("No releases published at {}.", repo.web);
    }
    for r in releases {
        let mark = if have.as_deref() == Some(r.tag_name.as_str()) {
            "  (installed)"
        } else {
            ""
        };
        let date = r.published_at.get(..10).unwrap_or("");
        let pre = if r.prerelease { "  pre-release" } else { "" };
        println!("{:<10} {date}{pre}{mark}", r.tag_name);
    }
    Ok(())
}

// ---------------------------------------------------------------- remove and nuke

fn remove(sys: &Sys, l: &Layout) -> Result<()> {
    println!("==> Stopping and removing the service");
    system::remove_service(sys, l)?;
    signer::remove(sys, l)?;
    println!("==> Removing the programs");
    for f in wanted_files() {
        sys.remove_file(&l.bin_dir.join(&f))?;
        // Left over from replacing running programs on Windows.
        sys.remove_file(&l.bin_dir.join(&f).with_extension("webjetup-old"))?;
    }
    remove_retired(sys, l)?;
    if cfg!(windows) {
        system::windows_path(sys, &l.bin_dir, false)?;
    }
    Ok(())
}

fn nuke(sys: &Sys, l: &Layout) -> Result<()> {
    remove(sys, l)?;
    println!("==> Deleting the node's identity and state");
    // Keys sealed in the System keychain live outside the state directory.
    system::delete_keychain_items(sys, &l.config)?;
    signer::nuke(sys, l)?;
    if cfg!(target_os = "linux") {
        sys.remove_dir_all(&l.data_dir)?;
        sys.remove_dir_all(&l.config_dir)?;
        if let Some(rt) = &l.runtime_dir {
            sys.remove_dir_all(rt)?;
        }
        // DNS settings an agent that died left on its interface.
        if system::have("resolvectl") {
            sys.try_run("resolvectl", &["revert", layout::LINUX_TUN]);
        }
        if system::query("id", &["-u", layout::LINUX_USER]).is_some() {
            sys.run("userdel", &[layout::LINUX_USER])?;
        }
    } else {
        // macOS and Windows keep config and state in one directory.
        sys.remove_dir_all(&l.config_dir)?;
    }
    if cfg!(target_os = "macos") {
        for f in system::macos_resolver_files() {
            sys.remove_file(&f)?;
        }
    }
    if let Some(log) = &l.log {
        sys.remove_file(log)?;
    }
    println!("==> Removing webjetup");
    system::remove_self(sys, &l.program(SELF))?;
    if cfg!(windows) && !sys.dry {
        // Empty now except for webjetup, which goes after we exit.
        let _ = std::fs::remove_dir(&l.bin_dir);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_commands() {
        let c = Cli::try_parse_from([
            "webjetup",
            "install",
            "0.2.0",
            "--signer",
            "--enroll",
            "wj1:x",
            "--dry-run",
        ])
        .unwrap();
        assert!(c.dry_run);
        assert!(
            matches!(c.cmd, Cmd::Install { version: Some(v), enroll: Some(_), signer: true, .. } if v == "0.2.0")
        );
        assert!(matches!(
            Cli::try_parse_from(["webjetup", "upgrade"]).unwrap().cmd,
            Cmd::Install { version: None, .. }
        ));
        assert!(matches!(
            Cli::try_parse_from(["webjetup", "uninstall", "-y"])
                .unwrap()
                .cmd,
            Cmd::Remove { yes: true }
        ));
        assert!(matches!(
            Cli::try_parse_from(["webjetup", "nuke", "--yes"])
                .unwrap()
                .cmd,
            Cmd::Nuke { yes: true }
        ));
    }

    #[test]
    fn wanted_files_cover_the_programs() {
        let w = wanted_files();
        for p in PROGRAMS {
            assert!(w.contains(&layout::exe(p)));
        }
    }

    #[test]
    fn stage_from_directory() {
        let src = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        for f in wanted_files() {
            std::fs::write(src.path().join(&f), f.as_bytes()).unwrap();
        }
        std::fs::write(src.path().join("unrelated"), "x").unwrap();
        stage_from(src.path(), stage.path()).unwrap();
        for f in wanted_files() {
            assert!(stage.path().join(&f).exists());
        }
        assert!(!stage.path().join("unrelated").exists());
    }

    #[test]
    fn enrollment_strings_are_checked() {
        let l = Layout::system();
        let e = do_enroll(&Sys { dry: true }, &l, "not-a-ticket", true).unwrap_err();
        assert!(e.to_string().contains("wj1:"));
    }
}
