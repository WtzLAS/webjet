//! Finding, downloading, checking and unpacking release archives.
//!
//! Releases live on a Forgejo (or Gitea) repository: the API answers which
//! releases exist, and each release has `webjet-<tag>-<target>.tar.gz` (a
//! `.zip` on Windows) with a `<file>.sha256` next to it.

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The official repository; builds can override it with `WEBJETUP_REPO`.
pub const DEFAULT_REPO: &str = match option_env!("WEBJETUP_REPO") {
    Some(r) => r,
    None => "https://forgejo.wolf109909.top/webj8/webjet",
};

/// A repository's web and API base URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    /// `https://host/owner/repo`
    pub web: String,
    /// `https://host/api/v1/repos/owner/repo`
    pub api: String,
}

impl Repo {
    pub fn parse(url: &str) -> Result<Repo> {
        let web = url.trim().trim_end_matches('/');
        let (scheme, rest) = web
            .split_once("://")
            .ok_or_else(|| anyhow!("repository URL {url:?} has no scheme"))?;
        if scheme != "https" && scheme != "http" {
            bail!("repository URL {url:?} must use http or https");
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

/// `0.2.0` → `v0.2.0`; `latest` stays as it is.
pub fn normalize_version(v: &str) -> String {
    let v = v.trim();
    if v == "latest" || v.starts_with('v') {
        v.to_string()
    } else {
        format!("v{v}")
    }
}

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

/// Run `f` up to [`ATTEMPTS`] times, waiting 1, 2, 4 s between tries.
fn retry<T>(mut f: impl FnMut() -> std::result::Result<T, Failure>) -> Result<T> {
    let mut attempt = 1;
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(Failure::Final(e)) => return Err(e),
            Err(Failure::Retry(e)) if attempt >= ATTEMPTS => return Err(e),
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
            .timeout_global(Some(Duration::from_secs(900)))
            .user_agent(format!("webjetup/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .new_agent();
        Client { agent }
    }

    /// GET with a few retries for network errors (resets, timeouts); HTTP
    /// errors like 404 are final.
    fn get(&self, url: &str) -> Result<ureq::http::Response<ureq::Body>> {
        retry(|| {
            self.agent.get(url).call().map_err(|e| match e {
                ureq::Error::StatusCode(404) => Failure::Final(anyhow!("{url}: not found")),
                ureq::Error::StatusCode(c) if c < 500 => Failure::Final(anyhow!("{url}: HTTP {c}")),
                e => Failure::Retry(anyhow!("{url}: {e}")),
            })
        })
    }

    pub fn text(&self, url: &str) -> Result<String> {
        retry(|| {
            let mut r = self.get(url).map_err(Failure::Final)?;
            r.body_mut()
                .read_to_string()
                .map_err(|e| Failure::Retry(anyhow!("{url}: {e}")))
        })
    }

    /// Download `url` into `dest`, returning the file's SHA-256.
    pub fn download(&self, url: &str, dest: &Path) -> Result<String> {
        // A connection that drops mid-file starts the download over.
        retry(|| {
            let resp = self.get(url).map_err(Failure::Final)?;
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
            Err(e) if e.to_string().ends_with(": not found") => {
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

    /// Download `file` of release `tag` into `dir` and check it against its
    /// published `.sha256`.
    pub fn fetch_verified(
        &self,
        repo: &Repo,
        tag: &str,
        file: &str,
        dir: &Path,
    ) -> Result<PathBuf> {
        let url = repo.download_url(tag, file);
        let want = parse_sha256(&self.text(&format!("{url}.sha256"))?)?;
        let dest = dir.join(file);
        println!("==> Downloading {url}");
        let have = self.download(&url, &dest)?;
        if have != want {
            bail!("checksum mismatch for {file}: expected {want}, got {have}");
        }
        println!("    SHA-256 {have} OK");
        Ok(dest)
    }
}

/// SHA-256 of a local file (tests compare unpacked files with it).
#[cfg(test)]
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Unpack the files named in `wanted` from a release archive into `dest`.
/// Only plain files are taken, by their file name, so an archive can't write
/// anywhere else. Returns the names found.
pub fn extract(archive: &Path, dest: &Path, wanted: &[String]) -> Result<Vec<String>> {
    let name = archive.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let mut found = Vec::new();
    if name.ends_with(".zip") {
        let f = std::fs::File::open(archive)?;
        let mut z =
            zip::ZipArchive::new(f).with_context(|| format!("read {}", archive.display()))?;
        for i in 0..z.len() {
            let mut entry = z.by_index(i)?;
            if !entry.is_file() {
                continue;
            }
            let Some(base) = entry
                .enclosed_name()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            else {
                continue;
            };
            if wanted.contains(&base) && !found.contains(&base) {
                let mut out = std::fs::File::create(dest.join(&base))?;
                std::io::copy(&mut entry, &mut out)?;
                found.push(base);
            }
        }
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        let f = std::fs::File::open(archive)?;
        let mut t = tar::Archive::new(flate2::read::GzDecoder::new(f));
        for entry in t
            .entries()
            .with_context(|| format!("read {}", archive.display()))?
        {
            let mut entry = entry?;
            if entry.header().entry_type() != tar::EntryType::Regular {
                continue;
            }
            let Some(base) = entry
                .path()?
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
            else {
                continue;
            };
            if wanted.contains(&base) && !found.contains(&base) {
                let mut out = std::fs::File::create(dest.join(&base))?;
                std::io::copy(&mut entry, &mut out)?;
                found.push(base);
            }
        }
    } else {
        bail!("{} is not a .tar.gz or .zip archive", archive.display());
    }
    Ok(found)
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
    }

    #[test]
    fn retries_network_errors_but_not_final_ones() {
        let mut calls = 0;
        let r: Result<u32> = retry(|| {
            calls += 1;
            if calls < 2 {
                Err(Failure::Retry(anyhow!("reset")))
            } else {
                Ok(7)
            }
        });
        assert_eq!((r.unwrap(), calls), (7, 2));
        let mut calls = 0;
        let r: Result<u32> = retry(|| {
            calls += 1;
            Err(Failure::Final(anyhow!("not found")))
        });
        assert!(r.is_err());
        assert_eq!(calls, 1, "a 404 is not retried");
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

    fn tar_gz(path: &Path, files: &[(&str, &[u8])]) {
        let f = std::fs::File::create(path).unwrap();
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(
            f,
            flate2::Compression::fast(),
        ));
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Regular);
            // Path names are written raw so the test can include "../" escapes.
            h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn extract_takes_only_wanted_plain_files() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("webjet-v0.2.0-x.tar.gz");
        tar_gz(
            &a,
            &[
                ("webjetd", b"agent"),
                ("../../evil", b"x"),
                ("sub/webjetctl", b"ctl"),
                ("README", b"r"),
            ],
        );
        let out = d.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let wanted: Vec<String> = ["webjetd", "webjetctl", "evil"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut got = extract(&a, &out, &wanted).unwrap();
        got.sort();
        assert_eq!(got, ["evil", "webjetctl", "webjetd"]);
        // Everything lands directly in `out`, never outside it.
        assert_eq!(std::fs::read(out.join("evil")).unwrap(), b"x");
        assert!(!d.path().join("evil").exists());
        assert!(!out.join("README").exists());
        assert_eq!(
            sha256_file(&out.join("webjetd")).unwrap(),
            hex::encode(Sha256::digest(b"agent"))
        );
    }

    #[test]
    fn extract_zip() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("webjet-v0.2.0-x86_64-pc-windows-msvc.zip");
        {
            let mut z = zip::ZipWriter::new(std::fs::File::create(&a).unwrap());
            let o = zip::write::SimpleFileOptions::default();
            z.start_file("webjetd.exe", o).unwrap();
            z.write_all(b"exe").unwrap();
            z.start_file("wintun.dll", o).unwrap();
            z.write_all(b"dll").unwrap();
            z.start_file("../escape.exe", o).unwrap();
            z.write_all(b"no").unwrap();
            z.finish().unwrap();
        }
        let wanted: Vec<String> = ["webjetd.exe", "wintun.dll", "escape.exe"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut got = extract(&a, d.path(), &wanted).unwrap();
        got.sort();
        assert_eq!(
            got,
            ["webjetd.exe", "wintun.dll"],
            "names escaping the archive are skipped"
        );
    }
}
