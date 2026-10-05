//! Gossip protocol versions (§10.6.5). Every self-signed record
//! (EndpointRecord, LinkStateAdvert, AttachmentRecord) carries the gossip
//! protocol of the software that signed it. A node ignores records from
//! software below [`MIN_GOSSIP_PROTOCOL`], so an outdated node can't feed
//! records the rest of the network (or webjet-app) no longer understands.
//!
//! The number goes up only with an incompatible change to gossip or to how
//! records are read, so a rolling upgrade between compatible releases keeps
//! every node's records.

/// The gossip protocol this software speaks.
/// - 0: before 0.7.0 (no `protocol` field; EndpointRecord `software` older
///   than `webjetd/0.7.0`)
/// - 1: 0.7.0 (no `protocol` field, `software` is `webjetd/0.7.x`)
/// - 2: the `protocol` field is set (0.7.1 on)
pub const GOSSIP_PROTOCOL: u16 = 2;

/// Records below this gossip protocol are ignored: not stored, not
/// forwarded, not used for routing and not shown.
pub const MIN_GOSSIP_PROTOCOL: u16 = 1;

/// Whether records of this gossip protocol are used.
pub fn accepted(protocol: u16) -> bool {
    protocol >= MIN_GOSSIP_PROTOCOL
}

/// The gossip protocol of an EndpointRecord: its `protocol` field, else
/// inferred from `software` (`webjetd/x.y.z`) for software from before the
/// field: 1 from 0.7.0 on, 0 before that or when unknown.
pub fn endpoint_protocol(field: u16, software: Option<&str>) -> u16 {
    if field > 0 {
        return field;
    }
    match software.and_then(software_version) {
        Some(v) if v >= (0, 7, 0) => 1,
        _ => 0,
    }
}

/// The version in a `software` string (`webjetd/0.7.0`, `webjetd/0.7.1-rc1`).
pub fn software_version(software: &str) -> Option<(u64, u64, u64)> {
    let v = software.rsplit('/').next()?.trim().trim_start_matches('v');
    let mut parts = v.split('.').map(|p| {
        let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u64>().ok()
    });
    let major = parts.next()??;
    let minor = parts.next()??;
    let patch = parts.next().flatten().unwrap_or(0);
    Some((major, minor, patch))
}

/// The version number alone (`0.7.0` from `webjetd/0.7.0`).
pub fn version_text(software: &str) -> &str {
    software.strip_prefix("webjetd/").unwrap_or(software)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_software_versions() {
        assert_eq!(software_version("webjetd/0.6.1"), Some((0, 6, 1)));
        assert_eq!(software_version("webjetd/0.7.1-rc1"), Some((0, 7, 1)));
        assert_eq!(software_version("webjetd/v1.2"), Some((1, 2, 0)));
        assert_eq!(software_version("webjetd/"), None);
        assert_eq!(software_version("webjetd/dev"), None);
        assert_eq!(version_text("webjetd/0.6.1"), "0.6.1");
    }

    #[test]
    fn infers_the_protocol_of_records_without_the_field() {
        assert_eq!(endpoint_protocol(0, Some("webjetd/0.6.1")), 0);
        assert_eq!(endpoint_protocol(0, Some("webjetd/0.5.0")), 0);
        assert_eq!(endpoint_protocol(0, Some("webjetd/0.7.0")), 1);
        assert_eq!(endpoint_protocol(0, None), 0);
        assert_eq!(endpoint_protocol(0, Some("garbage")), 0);
        assert_eq!(
            endpoint_protocol(GOSSIP_PROTOCOL, Some("webjetd/0.6.1")),
            GOSSIP_PROTOCOL
        );
        assert!(!accepted(0));
        assert!(accepted(1));
        assert!(accepted(GOSSIP_PROTOCOL));
    }
}
