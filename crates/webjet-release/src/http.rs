//! Finding, downloading and checking release files (webjetup installs them,
//! webjetctl pins their checksums in remote upgrade requests).
//!
//! Releases live on a Forgejo (or Gitea) repository: the API answers which
//! releases exist, and each release has `webjet-<tag>-<target>.tar.gz` (a
//! `.zip` on Windows) with a `<file>.sha256` next to it.

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The official repository; builds can override it with `WEBJETUP_REPO`.
pub const DEFAULT_REPO: &str = match option_env!("WEBJETUP_REPO") {
    Some(r) => r,
    None => "https://forgejo.wolf109909.top/webj8/webjet",
};

/// Set to `1` to allow a repository on plain `http://` (test setups).
pub const ALLOW_HTTP_ENV: &str = "WEBJET_ALLOW_HTTP";

/// A repository's web and API base URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    /// `https://host/owner/repo`
    pub web: String,
    /// `https://host/api/v1/repos/owner/repo`
    pub api: String,
}

impl Repo {
    /// An `https://host/owner/repo` URL. Plain `http://` only with
    /// `WEBJET_ALLOW_HTTP=1`: over http, anyone on the path could change the
    /// release files and the checksums published next to them.
    pub fn parse(url: &str) -> Result<Repo> {
        let allow = std::env::var(ALLOW_HTTP_ENV).is_ok_and(|v| v.trim() == "1");
        Self::parse_with(url, allow)
    }

    /// Like [`Repo::parse`], also accepting `http://`: for a URL root chose
    /// already (the remote upgrade helper's `trust.json`, written when
    /// `webjetup` allowed it), whose downloads are checked against
    /// checksums the admin signed.
    pub fn parse_pinned(url: &str) -> Result<Repo> {
        Self::parse_with(url, true)
    }

    fn parse_with(url: &str, allow_http: bool) -> Result<Repo> {
        let web = url.trim().trim_end_matches('/');
        let (scheme, rest) = web
            .split_once("://")
            .ok_or_else(|| anyhow!("repository URL {url:?} has no scheme"))?;
        match scheme {
            "https" => {}
            "http" if allow_http => {}
            "http" => bail!(
                "repository URL {url:?} uses plain http, where release files and their checksums \
                 can be changed in transit: use https (or set {ALLOW_HTTP_ENV}=1 to allow it)"
            ),
            _ => bail!("repository URL {url:?} must use https"),
        }
        let mut parts = rest.split('/');
        let host = parts
            .next()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| anyhow!("repository URL {url:?} has no host"))?;
        let path: Vec<&str> = parts.collect();
        let [owner, repo] = path.as_slice() else {
            bail!("repository URL {url:?} must look like {scheme}://{host}/<owner>/<repo>");
        };
        if owner.is_empty() || repo.is_empty() {
            bail!("repository URL {url:?} must look like {scheme}://{host}/<owner>/<repo>");
        }
        Ok(Repo {
            web: web.to_string(),
            api: format!("{scheme}://{host}/api/v1/repos/{owner}/{repo}"),
        })
    }

    pub fn download_url(&self, tag: &str, file: &str) -> String {
        format!("{}/releases/download/{tag}/{file}", self.web)
    }
}

pub use crate::normalize_version;

/// The hex digest from a `sha256sum`-style line.
pub fn parse_sha256(text: &str) -> Result<String> {
    let first = text.split_whitespace().next().unwrap_or("");
    if first.len() == 64 && first.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(first.to_ascii_lowercase())
    } else {
        bail!(
            "not a SHA-256 checksum: {:?}",
            text.chars().take(80).collect::<String>()
        )
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    #[serde(default)]
    pub published_at: String,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub draft: bool,
}

/// The server answered 404: the release or file isn't published.
#[derive(Debug)]
pub struct NotFound(pub String);

impl std::fmt::Display for NotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: not found", self.0)
    }
}

impl std::error::Error for NotFound {}

/// Whether `e` (or what it wraps) is a [`NotFound`]: the release or file
/// isn't published, as opposed to a network failure.
pub fn is_not_found(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<NotFound>())
}

/// How a failed attempt ends: try again, or give up now.
enum Failure {
    Retry(anyhow::Error),
    Final(anyhow::Error),
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Failure::Final(e)
    }
}

const ATTEMPTS: u32 = 4;

/// How long one request may take at most.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(900);

/// Run `f` up to [`ATTEMPTS`] times, waiting 1, 2, 4 s between tries, and
/// never starting a try after `deadline`.
fn retry<T>(
    deadline: Option<Instant>,
    mut f: impl FnMut() -> std::result::Result<T, Failure>,
) -> Result<T> {
    let mut attempt = 1;
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(Failure::Final(e)) => return Err(e),
            Err(Failure::Retry(e)) if attempt >= ATTEMPTS => return Err(e),
            Err(Failure::Retry(e))
                if deadline.is_some_and(|d| {
                    Instant::now() + Duration::from_secs(1 << (attempt - 1)) >= d
                }) =>
            {
                return Err(e.context("out of time for the downloads"));
            }
            Err(Failure::Retry(e)) => {
                eprintln!("    {e:#}; retrying");
                std::thread::sleep(Duration::from_secs(1 << (attempt - 1)));
                attempt += 1;
            }
        }
    }
}
/// The key exchange groups webjetup offers (see [`Client::new`]).
fn classic_kx_groups() -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
    use rustls::crypto::aws_lc_rs::kx_group;
    vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1]
}

pub struct Client {
    agent: ureq::Agent,
    /// No request runs past this (see [`Client::with_deadline`]).
    deadline: Option<Instant>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Client {
        // Classic key exchange only. The workspace builds rustls with
        // `prefer-post-quantum` (the overlay wants ML-KEM), which puts a large
        // X25519MLKEM768 share first in the ClientHello; some servers and
        // middleboxes reset such handshakes now and then, and release files
        // are public data checked against their SHA-256 anyway.
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = classic_kx_groups();
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(Arc::new(provider))
            .root_certs(ureq::tls::RootCerts::WebPki)
            .build();
        let agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .proxy(ureq::Proxy::try_from_env())
            .timeout_connect(Some(Duration::from_secs(20)))
            .timeout_global(Some(REQUEST_TIMEOUT))
            .user_agent(format!("webjetup/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .new_agent();
        Client {
            agent,
            deadline: None,
        }
    }

    /// Every request, retries included, ends within `limit` from now (the
    /// remote upgrade helper runs under a service manager's time limit).
    #[must_use]
    pub fn with_deadline(mut self, limit: Duration) -> Client {
        self.deadline = Some(Instant::now() + limit);
        self
    }

    /// One GET. Network errors (resets, timeouts) and 5xx may be retried;
    /// other HTTP errors like 404 are final.
    fn get_once(
        &self,
        url: &str,
    ) -> std::result::Result<ureq::http::Response<ureq::Body>, Failure> {
        let mut timeout = REQUEST_TIMEOUT;
        if let Some(d) = self.deadline {
            timeout = timeout.min(d.saturating_duration_since(Instant::now()));
            if timeout.is_zero() {
                return Err(Failure::Final(anyhow!(
                    "{url}: out of time for the downloads"
                )));
            }
        }
        self.agent
            .get(url)
            .config()
            .timeout_global(Some(timeout))
            .build()
            .call()
            .map_err(|e| match e {
                ureq::Error::StatusCode(404) => Failure::Final(NotFound(url.to_string()).into()),
                ureq::Error::StatusCode(c) if c < 500 => Failure::Final(anyhow!("{url}: HTTP {c}")),
                e => Failure::Retry(anyhow!("{url}: {e}")),
            })
    }

    /// GET with a few retries (see [`Client::get_once`]).
    fn get(&self, url: &str) -> Result<ureq::http::Response<ureq::Body>> {
        retry(self.deadline, || self.get_once(url))
    }

    pub fn text(&self, url: &str) -> Result<String> {
        // One retry loop around request and body: a body that breaks off
        // asks again.
        retry(self.deadline, || {
            let mut r = self.get_once(url)?;
            r.body_mut()
                .read_to_string()
                .map_err(|e| Failure::Retry(anyhow!("{url}: {e}")))
        })
    }

    /// Download `url` into `dest`, returning the file's SHA-256.
    pub fn download(&self, url: &str, dest: &Path) -> Result<String> {
        // A connection that drops mid-file starts the download over.
        retry(self.deadline, || {
            let resp = self.get_once(url)?;
            let mut reader = resp.into_body().into_reader();
            let mut file = std::fs::File::create(dest)
                .with_context(|| format!("create {}", dest.display()))
                .map_err(Failure::Final)?;
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| Failure::Retry(anyhow!("download {url}: {e}")))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                file.write_all(&buf[..n])
                    .with_context(|| format!("write {}", dest.display()))
                    .map_err(Failure::Final)?;
            }
            file.sync_all().map_err(|e| Failure::Final(e.into()))?;
            Ok(hex::encode(hasher.finalize()))
        })
    }

    /// Fail clearly when `tag` isn't a published release. Only a definite
    /// "not found" counts; other errors are left to the download.
    pub fn check_release(&self, repo: &Repo, tag: &str) -> Result<()> {
        match self.get(&format!("{}/releases/tags/{tag}", repo.api)) {
            Err(e) if is_not_found(&e) => {
                bail!(
                    "there is no release {tag} at {} (see `webjetup list`)",
                    repo.web
                )
            }
            _ => Ok(()),
        }
    }

    pub fn latest(&self, repo: &Repo) -> Result<String> {
        let body = self
            .text(&format!("{}/releases/latest", repo.api))
            .context("finding the latest release")?;
        let r: ReleaseInfo = serde_json::from_str(&body).context("reading the release list")?;
        Ok(r.tag_name)
    }

    pub fn releases(&self, repo: &Repo, limit: usize) -> Result<Vec<ReleaseInfo>> {
        let body = self
            .text(&format!("{}/releases?limit={limit}", repo.api))
            .context("listing releases")?;
        let mut v: Vec<ReleaseInfo> =
            serde_json::from_str(&body).context("reading the release list")?;
        v.retain(|r| !r.draft);
        Ok(v)
    }

    /// The published SHA-256 of `file` of release `tag` (its `.sha256`).
    pub fn published_sha256(&self, repo: &Repo, tag: &str, file: &str) -> Result<String> {
        let url = repo.download_url(tag, file);
        parse_sha256(&self.text(&format!("{url}.sha256"))?)
    }

    /// Download `file` of release `tag` into `dir` and check it against its
    /// published `.sha256`.
    pub fn fetch_verified(
        &self,
        repo: &Repo,
        tag: &str,
        file: &str,
        dir: &Path,
    ) -> Result<PathBuf> {
        let want = self.published_sha256(repo, tag, file)?;
        self.fetch_pinned(repo, tag, file, &want, dir)
    }

    /// Download `file` of release `tag` into `dir` and check it against
    /// `want` (lowercase hex), ignoring what the server publishes: a remote
    /// upgrade installs only the bytes the admin pinned.
    pub fn fetch_pinned(
        &self,
        repo: &Repo,
        tag: &str,
        file: &str,
        want: &str,
        dir: &Path,
    ) -> Result<PathBuf> {
        if file.contains(['/', '\\']) || file.starts_with('.') {
            bail!("bad release file name {file:?}");
        }
        let url = repo.download_url(tag, file);
        let dest = dir.join(file);
        println!("==> Downloading {url}");
        let have = self.download(&url, &dest)?;
        if have != want {
            let _ = std::fs::remove_file(&dest);
            bail!("checksum mismatch for {file}: expected {want}, got {have}");
        }
        println!("    SHA-256 {have} OK");
        Ok(dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_urls() {
        let r = Repo::parse("https://forgejo.example.net/webj8/webjet/").unwrap();
        assert_eq!(r.web, "https://forgejo.example.net/webj8/webjet");
        assert_eq!(
            r.api,
            "https://forgejo.example.net/api/v1/repos/webj8/webjet"
        );
        assert_eq!(
            r.download_url("v0.2.0", "a.tar.gz"),
            "https://forgejo.example.net/webj8/webjet/releases/download/v0.2.0/a.tar.gz"
        );
        assert!(Repo::parse("forgejo.example.net/webj8/webjet").is_err());
        assert!(Repo::parse("https://forgejo.example.net/webjet").is_err());
        assert!(Repo::parse("ftp://h/o/r").is_err());
        assert!(Repo::parse(DEFAULT_REPO).is_ok());
        // Plain http only where explicitly allowed.
        assert!(Repo::parse_with("http://h/o/r", false).is_err());
        assert!(Repo::parse_with("http://h/o/r", true).is_ok());
        assert!(Repo::parse_pinned("http://h/o/r").is_ok());
        assert!(Repo::parse_pinned("ftp://h/o/r").is_err());
    }

    #[test]
    fn retries_network_errors_but_not_final_ones() {
        let mut calls = 0;
        let r: Result<u32> = retry(None, || {
            calls += 1;
            if calls < 2 {
                Err(Failure::Retry(anyhow!("reset")))
            } else {
                Ok(7)
            }
        });
        assert_eq!((r.unwrap(), calls), (7, 2));
        let mut calls = 0;
        let r: Result<u32> = retry(None, || {
            calls += 1;
            Err(Failure::Final(NotFound("u".into()).into()))
        });
        let e = r.unwrap_err();
        assert!(is_not_found(&e) && is_not_found(&e.context("more")));
        assert!(!is_not_found(&anyhow!("host not found")));
        assert_eq!(calls, 1, "a 404 is not retried");
        // No try starts after the deadline.
        let mut calls = 0;
        let r: Result<u32> = retry(Some(Instant::now() + Duration::from_millis(500)), || {
            calls += 1;
            Err(Failure::Retry(anyhow!("reset")))
        });
        assert!(r.is_err());
        assert_eq!(calls, 1, "the 1 s wait would end after the deadline");
    }

    #[test]
    fn download_client_offers_only_classic_key_exchange() {
        let names: Vec<String> = classic_kx_groups()
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();
        assert!(!names.is_empty());
        assert!(names.iter().all(|n| !n.contains("MLKEM")), "{names:?}");
    }

    #[test]
    fn versions_and_sums() {
        assert_eq!(normalize_version("0.2.0"), "v0.2.0");
        assert_eq!(normalize_version("v0.2.0"), "v0.2.0");
        assert_eq!(normalize_version("latest"), "latest");
        let s = "65EC1F165CB9FA749FCC0032E846B3190E376C37292541D1A6435749E5C8CF4B  webjet.tar.gz\n";
        assert_eq!(parse_sha256(s).unwrap(), s[..64].to_ascii_lowercase());
        assert!(parse_sha256("<html>not found</html>").is_err());
    }
}
