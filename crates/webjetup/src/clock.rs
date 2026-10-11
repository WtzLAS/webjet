//! Setting the clock right before enrolling (§18.6). A computer whose
//! clock is more than a minute off is turned away without an answer by
//! every controller, so `webjetup enroll` checks first.
//!
//! Only Windows is changed: there the Windows Time service is often stopped
//! or set to start manually, and a dual-boot machine's clock can be hours
//! off. Elsewhere a wrong clock is reported and left to the operator.

use crate::layout::Layout;
use crate::system::Sys;
use webjet_core::sntp;

/// Further than this from the time servers and webjetup resynchronizes.
/// Well inside the PSK gate's 60 s.
const RESYNC_MS: i64 = 10_000;

/// Time servers given to Windows Time when it has no working source of its
/// own (0x9: client mode, special poll interval).
const W32_PEERS: &str = "time.windows.com,0x9 ntp.aliyun.com,0x9 time.cloudflare.com,0x9";

/// The `[clock] servers` of webjetd.toml, or the built-in list.
pub fn servers(l: &Layout) -> Vec<String> {
    let configured = std::fs::read_to_string(&l.config)
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .and_then(|t| t.get("clock")?.get("servers")?.as_array().cloned());
    match configured {
        Some(v) => v
            .iter()
            .filter_map(|s| s.as_str().map(String::from))
            .collect(),
        None => sntp::SERVERS.iter().map(|s| s.to_string()).collect(),
    }
}

/// Check the clock before enrolling, and on Windows set it right.
/// Never fails: enrollment then reports what is wrong.
pub fn check(sys: &Sys, l: &Layout) {
    let servers = servers(l);
    if cfg!(windows) {
        // webjetd's service depends on it; make sure it runs at boot.
        sys.try_run("sc.exe", &["config", "W32Time", "start=", "auto"]);
        sys.try_run("sc.exe", &["start", "W32Time"]);
    }
    if servers.is_empty() {
        return;
    }
    if sys.dry {
        sys.say("check the clock against time servers");
        return;
    }
    let Some(o) = sntp::offset(&servers, sntp::TIMEOUT) else {
        println!("    couldn't reach a time server (UDP 123); not checking the clock");
        return;
    };
    if o.ahead_ms.abs() <= RESYNC_MS {
        return;
    }
    println!("    {}", o.describe());
    if !cfg!(windows) {
        println!(
            "    set the clock right before enrolling: {}",
            sntp::fix_hint()
        );
        return;
    }
    if !resync(sys) {
        // No usable source (a computer with "Local CMOS Clock", say):
        // give it public servers and try again.
        sys.try_run(
            "w32tm",
            &[
                "/config",
                &format!("/manualpeerlist:{W32_PEERS}"),
                "/syncfromflags:manual",
                "/update",
            ],
        );
        resync(sys);
    }
    match sntp::offset(&servers, sntp::TIMEOUT) {
        Some(o) if o.ahead_ms.abs() <= RESYNC_MS => println!("    the clock is right now"),
        Some(o) => println!(
            "    {} even after `w32tm /resync`: {}",
            o.describe(),
            sntp::fix_hint()
        ),
        None => {}
    }
}

/// `w32tm /resync /force`, after which Windows Time sets the clock at once.
fn resync(sys: &Sys) -> bool {
    sys.try_run("w32tm", &["/resync", "/force"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_come_from_the_config_or_the_built_in_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = Layout::system();
        l.config = dir.path().join("webjetd.toml");
        assert_eq!(servers(&l).len(), sntp::SERVERS.len(), "no file");
        std::fs::write(&l.config, "[clock]\nservers = [\"ntp.example:123\"]\n").unwrap();
        assert_eq!(servers(&l), vec!["ntp.example:123".to_string()]);
        std::fs::write(&l.config, "[clock]\nservers = []\n").unwrap();
        assert!(servers(&l).is_empty(), "turned off");
    }
}
