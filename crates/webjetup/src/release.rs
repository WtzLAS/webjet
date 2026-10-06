//! Unpacking release archives; finding and downloading them is
//! `webjet_release::http`, shared with webjetctl.

pub use webjet_release::http::*;

use anyhow::{Context, Result, bail};
#[cfg(test)]
use sha2::{Digest, Sha256};
use std::path::Path;

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
    use std::io::Write;

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
