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

/// Mozilla's CA bundle as PEM, from curl's official extract: the control
/// plane's root store, carried on the boot volume as `\ichor\roots.pem`
/// (ADR-0012 §4). Configuration, not code; MPL-2.0 data, never committed.
pub const MOZILLA_ROOTS: Artifact = Artifact {
    dir: "roots",
    file: "cacert-2026-11-05.pem",
    url: "https://curl.se/ca/cacert-2026-11-05.pem",
    sha256: "427c064216761a1e72a8b30f0d954d08cb6e4435a82091fb865afd20c8497285",
    env: "ICHOR_ROOTS",
    token_url: None,
};

/// The Public Suffix List (publicsuffix.org), pinned to a commit: carried
/// in the CA bundle (`trust_bundle`) so that no wildcard certificate for a
/// whole public suffix verifies. MPL-2.0 data, never committed.
pub const PUBLIC_SUFFIX_LIST: Artifact = Artifact {
    dir: "roots",
    file: "public_suffix_list-7a21dc34.dat",
    url: "https://raw.githubusercontent.com/publicsuffix/list/7a21dc3491d43db036124fdd6a3a77d1cc44ad8a/public_suffix_list.dat",
    sha256: "a73b72cf4c58dea1a5b59f8a193b95ac65f74a1a1c7e1f296d734bc5497fbb9c",
    env: "ICHOR_PUBLIC_SUFFIX_LIST",
    token_url: None,
};

/// Most the boot volume's `\ichor\roots.pem` may hold (frame's
/// `ROOTS_MAX`).
const ROOTS_MAX: usize = 512 * 1024;

/// The Public Suffix List's ICANN rules (comments and blank lines left
/// out) as the CA bundle's `PUBLIC SUFFIX LIST` block. Its private section
/// (names companies let others register under, `s3.amazonaws.com` among
/// them) is left out, as Chrome leaves it out for wildcards: Amazon's own
/// S3 certificate is `*.s3.amazonaws.com`, and registries serve layers
/// from S3.
pub fn public_suffix_block() -> Result<String> {
    let list = PUBLIC_SUFFIX_LIST.bytes()?;
    let list = String::from_utf8(list).map_err(|_| "the public suffix list is not UTF-8")?;
    let (Some(start), Some(end)) = (
        list.find("===BEGIN ICANN DOMAINS==="),
        list.find("===END ICANN DOMAINS==="),
    ) else {
        return Err("the public suffix list has no ICANN section".into());
    };
    let label = x509::SUFFIX_BLOCK;
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in list[start..end].lines().map(str::trim) {
        if !line.is_empty() && !line.starts_with("//") {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(&format!("-----END {label}-----\n"));
    Ok(out)
}

/// The control plane's trust bundle, `\ichor\roots.pem`: Mozilla's roots
/// and the Public Suffix List.
pub fn trust_bundle() -> Result<Vec<u8>> {
    let mut b = MOZILLA_ROOTS.bytes()?;
    b.push(b'\n');
    b.extend_from_slice(public_suffix_block()?.as_bytes());
    if b.len() > ROOTS_MAX {
        return Err(format!(
            "the trust bundle is {} bytes, more than the boot volume's {ROOTS_MAX} (frame's ROOTS_MAX)",
            b.len()
        ));
    }
    Ok(b)
}

/// The x509-limbo certificate path-validation suite (C2SP), pinned to a
/// commit: `cargo xtask x509-limbo` scores `services/x509` against it.
pub const X509_LIMBO: Artifact = Artifact {
    dir: "x509-limbo",
    file: "limbo-519f4bcf.json",
    url: "https://raw.githubusercontent.com/C2SP/x509-limbo/519f4bcf6a31d20e1b7011a0586e233dbbd3e732/limbo.json",
    sha256: "56799cefd65fc9e0bdb9cb0f97fce6734533b45df3de4fc17fdc7b7b79654fca",
    env: "ICHOR_X509_LIMBO",
    token_url: None,
};

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
    // Milestone 5's servers: nginx (with its pcre) from main, and redis
    // 7.2 (the last BSD-licensed series) from community.
    alpine_pkg(
        "pcre-8.45-r3.apk",
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/pcre-8.45-r3.apk",
        "998e0945061652386ad1a38fc2425513f4ddf47011b0d382f5c802190f1c53e1",
    ),
    alpine_pkg(
        "nginx-1.26.3-r0.apk",
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/nginx-1.26.3-r0.apk",
        "0cb1ca897f34f4313e82261bf51029a070d0ea0d2695b7532fbf5d7a32c18ed5",
    ),
    alpine_pkg(
        "redis-7.2.9-r0.apk",
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/community/x86_64/redis-7.2.9-r0.apk",
        "9c8d51b1fba7cebc1c7864b88971e3ba3ea2d9a8082d46eebcbe4b446918f779",
    ),
];

/// Alpine 3.20's `linux-virt` kernel package (Linux 6.6.142, the kernel
/// Alpine ships for VMs), for the Linux reference benchmarks: only
/// `boot/vmlinuz-virt` is used. Size and version match the signed
/// APKINDEX; like the other branch packages, the cache keeps it once the
/// branch moves on.
pub const ALPINE_LINUX_VIRT: Artifact = Artifact {
    dir: "alpine-kernel/3.20",
    file: "linux-virt-6.6.142-r0.apk",
    url: "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/linux-virt-6.6.142-r0.apk",
    sha256: "0d84e30c04c52426b0bf10b01616c45f7d0c5384a59552e4c4a6caeb13a3f6e7",
    env: "ICHOR_LINUX_VIRT_APK",
    token_url: None,
};

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

/// A Debian package for the local `file:` repository, with the control
/// fields the generated `Packages` index needs. Size and SHA-256 come
/// from the verified file itself.
#[derive(Clone, Copy, Debug)]
pub struct DebianPackage {
    pub artifact: Artifact,
    pub package: &'static str,
    pub version: &'static str,
    pub depends: &'static str,
}

const fn deb(
    package: &'static str,
    version: &'static str,
    depends: &'static str,
    file: &'static str,
    url: &'static str,
    sha256: &'static str,
) -> DebianPackage {
    DebianPackage {
        artifact: Artifact {
            dir: "debian/pool",
            file,
            url,
            sha256,
            env: "ICHOR_DEBIAN_POOL_UNUSED",
            token_url: None,
        },
        package,
        version,
        depends,
    }
}

/// Official bookworm (Debian 12) packages, from snapshot.debian.org (a
/// permanent archive) as of 2026-11-01; versions and dependencies are
/// those in bookworm's `main/binary-amd64/Packages`. `jq` needs `libjq1`,
/// which needs `libonig5`, so apt has dependencies to resolve.
pub const DEBIAN_PACKAGES: &[DebianPackage] = &[
    deb(
        "hello",
        "2.10-3",
        "libc6 (>= 2.34)",
        "hello_2.10-3_amd64.deb",
        "https://snapshot.debian.org/archive/debian/20261101T000000Z/pool/main/h/hello/hello_2.10-3_amd64.deb",
        "2e6e2f1a0007dc43bc91c273fd36e91e40a4f1c2765a03eca68b70a42103878a",
    ),
    deb(
        "jq",
        "1.6-2.1+deb12u2",
        "libjq1 (= 1.6-2.1+deb12u2), libc6 (>= 2.34)",
        "jq_1.6-2.1+deb12u2_amd64.deb",
        "https://snapshot.debian.org/archive/debian/20261101T000000Z/pool/main/j/jq/jq_1.6-2.1+deb12u2_amd64.deb",
        "f2303584378ac85f6d3a9ae8e46412196061681e81610d3b020abe4b5d389eb0",
    ),
    deb(
        "libjq1",
        "1.6-2.1+deb12u2",
        "libc6 (>= 2.36), libonig5 (>= 6.8.1)",
        "libjq1_1.6-2.1+deb12u2_amd64.deb",
        "https://snapshot.debian.org/archive/debian/20261101T000000Z/pool/main/j/jq/libjq1_1.6-2.1+deb12u2_amd64.deb",
        "f501b6349a3c2462af59e7a598ebd71e7889de46c9ddf852eb12ebeba7df21a2",
    ),
    deb(
        "libonig5",
        "6.9.8-1",
        "libc6 (>= 2.14)",
        "libonig5_6.9.8-1_amd64.deb",
        "https://snapshot.debian.org/archive/debian/20261101T000000Z/pool/main/libo/libonig/libonig5_6.9.8-1_amd64.deb",
        "59ecfce6d88c7c4b09496ce182b3b8303e8e8477664e009b16ae83a09cd12be7",
    ),
];
