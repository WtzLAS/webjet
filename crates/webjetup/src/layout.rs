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
}

fn env_dir(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
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
                config_dir: base,
                service_file: Some(PathBuf::from(format!(
                    "/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
                ))),
                log: Some(PathBuf::from("/var/log/webjetd.log")),
                runtime_dir: None,
            }
        } else if cfg!(windows) {
            let data = env_dir("ProgramData", r"C:\ProgramData").join("Webjet");
            Layout {
                bin_dir: env_dir("ProgramFiles", r"C:\Program Files").join("Webjet"),
                config: data.join("webjetd.toml"),
                data_dir: data.join("state"),
                config_dir: data,
                service_file: None,
                log: None,
                runtime_dir: None,
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

/// The release target of this build of webjetup, which is also the machine's
/// (install.sh picks the matching webjetup).
pub fn target() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("aarch64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(windows, target_arch = "x86_64")) {
        Some("x86_64-pc-windows-msvc")
    } else {
        None
    }
}

/// The release archive for `target`: a zip on Windows, else a gzipped tar.
pub fn archive_name(tag: &str, target: &str) -> String {
    if target.contains("windows") {
        format!("webjet-{tag}-{target}.zip")
    } else {
        format!("webjet-{tag}-{target}.tar.gz")
    }
}

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
