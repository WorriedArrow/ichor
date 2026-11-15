//! Pinned downloads of third-party test artifacts (busybox, Alpine, ...).
//!
//! Each artifact is fetched from its official upstream with `curl`, checked
//! against a SHA-256 pinned in this repository, and cached under
//! `target/<dir>/`. A cached copy is re-hashed on every use. Concurrent
//! callers (parallel tests) share one download per process, and separate
//! processes each write their own partial file and rename it into place.
//! Artifacts are never committed: several are GPL-licensed.

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use std::sync::Mutex;

use crate::{Result, sha256, workspace_root};

/// A file to fetch.
#[derive(Clone, Copy, Debug)]
pub struct Artifact {
    /// Cache directory under `target/`.
    pub dir: &'static str,
    /// File name in that directory.
    pub file: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
    /// Environment variable that points at a local copy instead.
    pub env: &'static str,
    /// For a registry blob: the URL of an anonymous bearer token to send.
    pub token_url: Option<&'static str>,
}

fn check(a: &Artifact, bytes: &[u8], what: &str) -> Result<()> {
    let got = sha256::hex(&sha256::digest(bytes));
    if got != a.sha256 {
        return Err(format!("{what}: SHA-256 is {got}, expected {}", a.sha256));
    }
    Ok(())
}

impl Artifact {
    /// The artifact's bytes, downloading and caching it if needed.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        static DONE: Mutex<BTreeMap<&'static str, Vec<u8>>> = Mutex::new(BTreeMap::new());
        let mut done = DONE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(b) = done.get(self.url) {
            return Ok(b.clone());
        }
        let b = self.fetch()?;
        done.insert(self.url, b.clone());
        Ok(b)
    }

    fn fetch(&self) -> Result<Vec<u8>> {
        if let Some(p) = std::env::var_os(self.env) {
            let b = fs::read(&p).map_err(|e| format!("reading {}: {e}", p.to_string_lossy()))?;
            check(self, &b, &p.to_string_lossy())?;
            return Ok(b);
        }
        let dir = workspace_root().join("target").join(self.dir);
        let path = dir.join(self.file);
        if let Ok(b) = fs::read(&path)
            && check(self, &b, "cached copy").is_ok()
        {
            return Ok(b);
        }
        fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        let partial = dir.join(format!("{}.partial.{}", self.file, std::process::id()));
        let mut curl = Command::new("curl");
        curl.args(["--silent", "--show-error", "--fail", "--location"])
            .args(["--retry", "3", "--output"])
            .arg(&partial);
        if let Some(t) = self.token_url {
            curl.arg("--header")
                .arg(format!("Authorization: Bearer {}", bearer_token(t)?));
        }
        let status = curl
            .arg(self.url)
            .status()
            .map_err(|e| format!("running curl for {}: {e} (or set {})", self.url, self.env))?;
        if !status.success() {
            return Err(format!(
                "downloading {} failed ({status}); set {} to a local copy",
                self.url, self.env
            ));
        }
        let b = fs::read(&partial).map_err(|e| format!("reading {}: {e}", partial.display()))?;
        if let Err(e) = check(self, &b, self.url) {
            let _ = fs::remove_file(&partial);
            return Err(e);
        }
        fs::rename(&partial, &path).map_err(|e| format!("caching {}: {e}", path.display()))?;
        Ok(b)
    }
}

/// An anonymous registry token from `url` (a JSON body with `"token"`).
fn bearer_token(url: &str) -> Result<String> {
    let out = Command::new("curl")
        .args(["--silent", "--show-error", "--fail", "--location", url])
        .output()
        .map_err(|e| format!("running curl for {url}: {e}"))?;
    if !out.status.success() {
        return Err(format!("fetching a registry token from {url} failed"));
    }
    let body = String::from_utf8_lossy(&out.stdout);
    let start = body
        .find("\"token\"")
        .and_then(|i| body[i + 7..].find('"').map(|j| i + 7 + j + 1))
        .ok_or("registry token response has no token")?;
    let end = body[start..]
        .find('"')
        .map(|j| start + j)
        .ok_or("registry token response is malformed")?;
    Ok(body[start..end].to_string())
}

/// The official static busybox 1.35.0 (musl, x86-64) from busybox.net.
pub const BUSYBOX: Artifact = Artifact {
    dir: "busybox/1.35.0",
    file: "busybox",
    url: "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox",
    sha256: "6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348",
    env: "ICHOR_BUSYBOX",
    token_url: None,
};

/// An official Alpine 3.20 `main` package (signed by Alpine's keys, which
/// the minirootfs trusts). Branch packages are replaced on updates, so the
/// cached copy (and CI's cache) is what keeps these reproducible.
const fn alpine_pkg(file: &'static str, url: &'static str, sha256: &'static str) -> Artifact {
    Artifact {
        dir: "alpine-pkgs/3.20",
        file,
        url,
        sha256,
        env: "ICHOR_ALPINE_PKGS_UNUSED",
        token_url: None,
    }
}

/// Packages put in the Alpine disk's `/mirror` for `apk` to install.
pub const ALPINE_PACKAGES: &[Artifact] = &[
    alpine_pkg(
        "tree-2.1.1-r0.apk",
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/tree-2.1.1-r0.apk",
        "538045ec484b1f4edd758c7f33fa53aea488372fbdf2d35998d6f2e87f59f7af",
    ),
    alpine_pkg(
        "oniguruma-6.9.9-r0.apk",
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/oniguruma-6.9.9-r0.apk",
        "209d7404cf17adecc8ce966afaa5806b896ae12d165c8f1747e7da15df876f71",
    ),
    alpine_pkg(
        "jq-1.7.1-r0.apk",
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/jq-1.7.1-r0.apk",
        "219edabad0ef4250055d23df237b8d8103015a855e75367951c14314f833c507",
    ),
];

/// Alpine Linux 3.20.3 minirootfs (x86-64). The hash matches Alpine's
/// published `.sha256` for this release.
pub const ALPINE_MINIROOTFS: Artifact = Artifact {
    dir: "alpine/3.20.3",
    file: "alpine-minirootfs-3.20.3-x86_64.tar.gz",
    url: "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz",
    sha256: "d4e6fd67dcf75e40c451560ac7265166c2b72a0f38ddc9aae756a7de3d1efa0c",
    env: "ICHOR_ALPINE_MINIROOTFS",
    token_url: None,
};

/// Debian 12 (bookworm) slim, the official image's one layer for
/// linux/amd64, from Docker Hub. Pinned by the image manifest
/// `sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018`
/// (`library/debian:bookworm-slim`, amd64, as of 2026-11-15), whose only
/// layer is this blob; registry blobs are content-addressed, so the
/// layer's digest is its SHA-256.
pub const DEBIAN_BOOKWORM_SLIM: Artifact = Artifact {
    dir: "debian/bookworm-slim",
    file: "layer-dd051e1b8c92.tar.gz",
    url: "https://registry-1.docker.io/v2/library/debian/blobs/sha256:dd051e1b8c92ff101fa3071ab97ea4924885942f15644e01c3dc095764e863e3",
    sha256: "dd051e1b8c92ff101fa3071ab97ea4924885942f15644e01c3dc095764e863e3",
    env: "ICHOR_DEBIAN_LAYER",
    token_url: Some(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull",
    ),
};
