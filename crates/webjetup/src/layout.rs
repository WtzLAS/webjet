//! Where Webjet lives on each platform (§19.1, docs/configuration.md).

use std::path::PathBuf;

/// The programs of a Webjet installation.
pub const PROGRAMS: [&str; 2] = ["webjetd", "webjetctl"];

/// Programs of releases before 0.3.0, merged into `webjetctl root` and
/// `webjetd signer` since; removed when found.
pub const RETIRED_PROGRAMS: [&str; 2] = ["webjet-root", "webjet-signer"];

/// The Windows service's display name and description.
pub const SERVICE_DISPLAY_NAME: &str = "Webjet agent";
pub const SERVICE_DESCRIPTION: &str = "Webjet overlay network agent";

/// This tool's own name.
pub const SELF: &str = "webjetup";

/// The service name (systemd unit, Windows service).
pub const SERVICE: &str = "webjetd";

/// The launchd label on macOS.
pub const LAUNCHD_LABEL: &str = "net.webjet.webjetd";

/// The signer's service (`webjetd signer`, §19.2): systemd unit and Windows
/// service name, launchd label, and the Linux user it runs as.
pub const SIGNER_SERVICE: &str = "webjet-signer";
pub const SIGNER_LAUNCHD_LABEL: &str = "net.webjet.signer";
pub const SIGNER_USER: &str = "webjet-signer";

/// The remote upgrade helper (`webjetup apply-upgrade`, §19.8): systemd
/// units (`.path` starts `.service`), launchd label, Windows scheduled task.
pub const UPGRADE_SERVICE: &str = "webjet-upgrade";
pub const UPGRADE_LAUNCHD_LABEL: &str = "net.webjet.upgrade";
pub const UPGRADE_TASK: &str = "Webjet upgrade";

/// The Keychain service name under which webjetd stores identity keys.
pub const KEYCHAIN_SERVICE: &str = "net.webjet.identity";
/// Where webjetd keeps them unless `[key] keychain` says otherwise.
pub const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// The system user webjetd runs as on Linux.
pub const LINUX_USER: &str = "webjet";

/// The tun interface name, for leftover DNS settings on Linux.
pub const LINUX_TUN: &str = "webjet0";

/// `name` with the platform's executable suffix.
pub fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Files installed next to the programs besides the programs themselves.
pub fn extra_files() -> &'static [&'static str] {
    if cfg!(windows) {
        &["wintun.dll", "wintun-LICENSE.txt"]
    } else {
        &[]
    }
}

/// The paths of an installation on this machine.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Programs (and on Windows wintun.dll).
    pub bin_dir: PathBuf,
    /// The directory holding webjetd.toml (on macOS and Windows also the state).
    pub config_dir: PathBuf,
    pub config: PathBuf,
    /// Identity key and network state.
    pub data_dir: PathBuf,
    /// systemd unit or launchd property list.
    pub service_file: Option<PathBuf>,
    pub log: Option<PathBuf>,
    /// Control socket directory.
    pub runtime_dir: Option<PathBuf>,
    /// The signer's key, socket (named pipe on Windows), service file and
    /// log, for `webjetup install --signer`.
    pub signer_key: PathBuf,
    pub signer_socket: PathBuf,
    pub signer_service_file: Option<PathBuf>,
    pub signer_log: Option<PathBuf>,
    /// The remote upgrade helper's spool (status, trust, backups; `queue/`
    /// is the agent's), `webjet_release::default_spool_dir`.
    pub upgrade_spool: PathBuf,
}

fn env_dir(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

impl Layout {
    /// The standard layout for this platform (the defaults of webjetd).
    pub fn system() -> Layout {
        if cfg!(target_os = "macos") {
            let base = PathBuf::from("/Library/Application Support/Webjet");
            Layout {
                bin_dir: PathBuf::from("/usr/local/bin"),
                config: base.join("webjetd.toml"),
                data_dir: base.join("state"),
                config_dir: base.clone(),
                service_file: Some(PathBuf::from(format!(
                    "/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
                ))),
                log: Some(PathBuf::from("/var/log/webjetd.log")),
                runtime_dir: None,
                signer_key: base.join("signer").join("signing.key"),
                signer_socket: PathBuf::from("/var/run/webjet-signer/signer.sock"),
                signer_service_file: Some(PathBuf::from(format!(
                    "/Library/LaunchDaemons/{SIGNER_LAUNCHD_LABEL}.plist"
                ))),
                signer_log: Some(PathBuf::from("/var/log/webjet-signer.log")),
                upgrade_spool: webjet_release::default_spool_dir(),
            }
        } else if cfg!(windows) {
            let program_data = env_dir("ProgramData", r"C:\ProgramData");
            let data = program_data.join("Webjet");
            Layout {
                bin_dir: env_dir("ProgramFiles", r"C:\Program Files").join("Webjet"),
                config: data.join("webjetd.toml"),
                data_dir: data.join("state"),
                config_dir: data,
                service_file: None,
                log: None,
                runtime_dir: None,
                signer_key: program_data.join("webjet-signer").join("signing.key"),
                signer_socket: PathBuf::from(r"\\.\pipe\webjet-signer"),
                signer_service_file: None,
                signer_log: None,
                upgrade_spool: webjet_release::default_spool_dir(),
            }
        } else {
            Layout {
                bin_dir: PathBuf::from("/usr/local/bin"),
                config_dir: PathBuf::from("/etc/webjet"),
                config: PathBuf::from("/etc/webjet/webjetd.toml"),
                data_dir: PathBuf::from("/var/lib/webjet"),
                service_file: Some(PathBuf::from(format!(
                    "/etc/systemd/system/{SERVICE}.service"
                ))),
                log: None,
                runtime_dir: Some(PathBuf::from("/run/webjet")),
                signer_key: PathBuf::from("/var/lib/webjet-signer/signing.key"),
                signer_socket: PathBuf::from("/var/run/webjet-signer/signer.sock"),
                signer_service_file: Some(PathBuf::from(format!(
                    "/etc/systemd/system/{SIGNER_SERVICE}.service"
                ))),
                signer_log: None,
                upgrade_spool: webjet_release::default_spool_dir(),
            }
        }
    }

    pub fn program(&self, name: &str) -> PathBuf {
        self.bin_dir.join(exe(name))
    }

    /// Whether this node has been enrolled (webjetd keeps node.json then).
    pub fn enrolled(&self) -> bool {
        self.data_dir.join("node.json").exists()
    }

    /// Like `enrolled`, but `None` when the state directory can't be read
    /// (it is private to the agent's user, so without root).
    pub fn enrolled_checked(&self) -> Option<bool> {
        self.data_dir.join("node.json").try_exists().ok()
    }
}

/// Whether a version (`0.2.2`, `v0.2.2`) predates the 0.3.0 command layout
/// (`webjetd enroll`, `webjetd install`, separate webjet-root/webjet-signer).
pub fn before_0_3(version: &str) -> bool {
    let v = version.trim().trim_start_matches('v');
    let mut parts = v.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    let (major, minor) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    major == 0 && minor < 3
}

/// Whether a version predates the 0.4.0 command layout (`webjetctl enroll`
/// rather than `webjetctl local enroll`).
pub fn before_0_4(version: &str) -> bool {
    let v = version.trim().trim_start_matches('v');
    let mut parts = v.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    let (major, minor) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    major == 0 && minor < 4
}

pub use webjet_release::{archive_name, target};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_layouts() {
        assert!(before_0_3("0.2.2") && before_0_3("v0.1.0"));
        assert!(!before_0_3("0.3.0") && !before_0_3("v0.10.1") && !before_0_3("1.0.0"));
        assert!(before_0_4("0.3.0") && before_0_4("v0.2.2"));
        assert!(!before_0_4("0.4.0") && !before_0_4("v0.10.0") && !before_0_4("1.0.0"));
    }

    #[test]
    fn names() {
        assert_eq!(
            archive_name("v0.2.0", "aarch64-apple-darwin"),
            "webjet-v0.2.0-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            archive_name("v0.2.0", "x86_64-pc-windows-msvc"),
            "webjet-v0.2.0-x86_64-pc-windows-msvc.zip"
        );
        assert!(
            target().is_some(),
            "release targets cover the platforms the tests run on"
        );
        let l = Layout::system();
        assert!(l.data_dir.starts_with(&l.config_dir) || cfg!(target_os = "linux"));
        assert!(l.program("webjetd").ends_with(exe("webjetd")));
    }
}
