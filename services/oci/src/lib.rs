//! Pulling container images (ADR-0012 §3, §4), sans-I/O: a [`Puller`]
//! says which HTTP request to make next ([`Step::Fetch`]) and takes the
//! response, until the image is in ([`Step::Done`]). The caller does DNS,
//! TCP and TLS.
//!
//! The registry protocol is the OCI distribution API (Docker Hub's too):
//! a 401 with a Bearer challenge sends us to the token service; an image
//! index is resolved to the `linux/amd64` manifest; the config and every
//! layer are fetched as blobs, following redirects to a CDN without the
//! registry's token. **Everything is verified**: a manifest fetched by
//! digest must hash to it (as must a tag's, if the reference also names a
//! digest), and every blob must hash to its descriptor's digest and size.
//!
//! [`convert`] turns the pulled layers into one Ichor image
//! (`services/layer`), and [`ImageConfig`] reads the config's entrypoint,
//! command, environment and working directory.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod json;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crypto::sha2::Sha256;
use http::{Request, Response, Url};
use json::Value;

const INDEX_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];
const MANIFEST_TYPES: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// Why a pull failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The registry answered with this status.
    Status(u16),
    /// A document was not what the protocol says it is.
    Malformed(&'static str),
    /// Content did not hash to its digest.
    Digest(String),
    /// No manifest for linux/amd64.
    NoPlatform,
    Unsupported(String),
    TooManyRedirects,
}

/// An image reference: `[registry/]repository[:tag][@sha256:digest]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    /// The registry's API host (`registry-1.docker.io` for Docker Hub).
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl Reference {
    /// Parses a reference as `docker pull` does: no registry means Docker
    /// Hub, a single-name repository there means `library/`, no tag or
    /// digest means `latest`.
    pub fn parse(s: &str) -> Option<Reference> {
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => {
                let hex = d.strip_prefix("sha256:")?;
                if hex.len() != 64 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return None;
                }
                (r, Some(d.to_ascii_lowercase()))
            }
            None => (s, None),
        };
        let (registry, path) = match rest.split_once('/') {
            Some((first, path))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first, path)
            }
            _ => ("docker.io", rest),
        };
        let (repository, tag) = match path.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r, Some(t)),
            _ => (path, None),
        };
        if repository.is_empty()
            || !repository
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-/".contains(&c))
        {
            return None;
        }
        let (registry, repository) = if registry == "docker.io" {
            let repo = if repository.contains('/') {
                repository.to_string()
            } else {
                format!("library/{repository}")
            };
            ("registry-1.docker.io".to_string(), repo)
        } else {
            (registry.to_string(), repository.to_string())
        };
        let tag = match (tag, &digest) {
            (Some(t), _) => Some(t.to_string()),
            (None, None) => Some("latest".to_string()),
            (None, Some(_)) => None,
        };
        Some(Reference {
            registry,
            repository,
            tag,
            digest,
        })
    }
}

/// A blob or manifest descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

fn descriptor(v: &Value) -> Result<Descriptor, Error> {
    let digest = v
        .get("digest")
        .and_then(Value::as_str)
        .ok_or(Error::Malformed("descriptor without a digest"))?;
    if !digest.starts_with("sha256:") || digest.len() != 71 {
        return Err(Error::Unsupported(format!("digest {digest}")));
    }
    Ok(Descriptor {
        media_type: v
            .get("mediaType")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        digest: digest.to_string(),
        size: v.get("size").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// `sha256:<hex>` of `data`.
pub fn digest_of(data: &[u8]) -> String {
    let mut s = String::from("sha256:");
    for b in Sha256::hash(data) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A pulled image, verified.
#[derive(Clone, Debug)]
pub struct Pulled {
    /// The digest of the platform manifest.
    pub manifest_digest: String,
    pub config: Vec<u8>,
    /// Layer descriptors and contents, lowest first.
    pub layers: Vec<(Descriptor, Vec<u8>)>,
}

/// What to do next.
#[derive(Clone, Debug)]
pub enum Step {
    Fetch(Request),
    Done(Pulled),
}

#[derive(Clone, Debug)]
enum State {
    /// Fetching a manifest or index by tag or digest; `expect` is the
    /// digest it must hash to, if known.
    Manifest {
        reference: String,
        expect: Option<String>,
    },
    /// Fetching the token, then retrying `retry`.
    Token {
        url: Url,
        retry: Box<State>,
    },
    /// Fetching blob `i` (0 is the config, then the layers).
    Blob {
        i: usize,
    },
    Done,
}

use alloc::boxed::Box;

/// The pull protocol for one image.
#[derive(Debug)]
pub struct Puller {
    r: Reference,
    state: State,
    token: Option<String>,
    /// A redirect to follow for the current request.
    redirect: Option<Url>,
    redirects: u32,
    manifest_digest: String,
    blobs: Vec<Descriptor>,
    data: Vec<Vec<u8>>,
}

const MAX_REDIRECTS: u32 = 5;

impl Puller {
    pub fn new(r: Reference) -> Puller {
        let (reference, expect) = match (&r.tag, &r.digest) {
            (Some(t), d) => (t.clone(), d.clone()),
            (None, Some(d)) => (d.clone(), Some(d.clone())),
            (None, None) => ("latest".into(), None),
        };
        Puller {
            r,
            state: State::Manifest { reference, expect },
            token: None,
            redirect: None,
            redirects: 0,
            manifest_digest: String::new(),
            blobs: Vec::new(),
            data: Vec::new(),
        }
    }

    fn url(&self, path: &str) -> Url {
        Url::https(
            &self.r.registry,
            443,
            &format!("/v2/{}/{path}", self.r.repository),
        )
    }

    fn authed(&self, req: Request) -> Request {
        // The token is for the registry only, never for a CDN it redirects
        // to.
        match &self.token {
            Some(t) if req.url.host == self.r.registry => {
                req.header("Authorization", &format!("Bearer {t}"))
            }
            _ => req,
        }
    }

    /// The request to make now, or the finished image.
    pub fn step(&mut self) -> Step {
        if let Some(u) = self.redirect.clone() {
            return Step::Fetch(self.authed(Request::get(u)));
        }
        match &self.state {
            State::Manifest { reference, .. } => {
                let accept = [
                    INDEX_TYPES[0],
                    INDEX_TYPES[1],
                    MANIFEST_TYPES[0],
                    MANIFEST_TYPES[1],
                ]
                .join(", ");
                let req = Request::get(self.url(&format!("manifests/{reference}")))
                    .header("Accept", &accept);
                Step::Fetch(self.authed(req))
            }
            State::Token { url, .. } => Step::Fetch(Request::get(url.clone())),
            State::Blob { i } => {
                let req = Request::get(self.url(&format!("blobs/{}", self.blobs[*i].digest)));
                Step::Fetch(self.authed(req))
            }
            State::Done => {
                let mut data = core::mem::take(&mut self.data).into_iter();
                let config = data.next().unwrap_or_default();
                let layers = self.blobs.iter().skip(1).cloned().zip(data).collect();
                Step::Done(Pulled {
                    manifest_digest: self.manifest_digest.clone(),
                    config,
                    layers,
                })
            }
        }
    }

    /// Takes the response to the last [`Puller::step`] request.
    pub fn on_response(&mut self, resp: Response) -> Result<(), Error> {
        if (300..400).contains(&resp.status) {
            let base = match self.redirect.clone() {
                Some(u) => u,
                None => self.url(""),
            };
            let loc = resp
                .header("location")
                .and_then(|l| base.join(l))
                .ok_or(Error::Malformed("redirect without a location"))?;
            self.redirects += 1;
            if self.redirects > MAX_REDIRECTS {
                return Err(Error::TooManyRedirects);
            }
            self.redirect = Some(loc);
            return Ok(());
        }
        self.redirect = None;
        self.redirects = 0;
        let state = core::mem::replace(&mut self.state, State::Done);
        if resp.status == 401
            && !matches!(state, State::Token { .. })
            && self.token.is_none()
            && let Some(url) = resp.header("www-authenticate").and_then(token_url)
        {
            self.state = State::Token {
                url,
                retry: Box::new(state),
            };
            return Ok(());
        }
        if resp.status != 200 {
            self.state = state;
            return Err(Error::Status(resp.status));
        }
        match state {
            State::Token { retry, .. } => {
                let v = json::parse(&resp.body).ok_or(Error::Malformed("token response"))?;
                let t = v
                    .get("token")
                    .or_else(|| v.get("access_token"))
                    .and_then(Value::as_str)
                    .ok_or(Error::Malformed("token response without a token"))?;
                self.token = Some(t.into());
                self.state = *retry;
                Ok(())
            }
            State::Manifest { expect, .. } => self.manifest(&resp.body, expect),
            State::Blob { i } => {
                let d = &self.blobs[i];
                let got = digest_of(&resp.body);
                if got != d.digest || (d.size != 0 && resp.body.len() as u64 != d.size) {
                    return Err(Error::Digest(d.digest.clone()));
                }
                self.data.push(resp.body);
                self.state = if i + 1 < self.blobs.len() {
                    State::Blob { i: i + 1 }
                } else {
                    State::Done
                };
                Ok(())
            }
            State::Done => Ok(()),
        }
    }

    fn manifest(&mut self, body: &[u8], expect: Option<String>) -> Result<(), Error> {
        let digest = digest_of(body);
        if let Some(e) = expect
            && e != digest
        {
            return Err(Error::Digest(e));
        }
        let v = json::parse(body).ok_or(Error::Malformed("manifest"))?;
        let media = v.get("mediaType").and_then(Value::as_str).unwrap_or("");
        if let Some(list) = v.get("manifests").and_then(Value::as_array) {
            if !media.is_empty() && !INDEX_TYPES.contains(&media) {
                return Err(Error::Unsupported(media.to_string()));
            }
            let chosen = list
                .iter()
                .find(|m| {
                    m.get("platform").is_some_and(|p| {
                        p.get("os").and_then(Value::as_str) == Some("linux")
                            && p.get("architecture").and_then(Value::as_str) == Some("amd64")
                    })
                })
                .ok_or(Error::NoPlatform)?;
            let d = descriptor(chosen)?;
            self.state = State::Manifest {
                reference: d.digest.clone(),
                expect: Some(d.digest),
            };
            return Ok(());
        }
        if !media.is_empty() && !MANIFEST_TYPES.contains(&media) {
            return Err(Error::Unsupported(media.to_string()));
        }
        let config = descriptor(
            v.get("config")
                .ok_or(Error::Malformed("manifest without a config"))?,
        )?;
        let mut blobs = alloc::vec![config];
        for l in v
            .get("layers")
            .and_then(Value::as_array)
            .ok_or(Error::Malformed("manifest without layers"))?
        {
            blobs.push(descriptor(l)?);
        }
        self.manifest_digest = digest;
        self.blobs = blobs;
        self.state = State::Blob { i: 0 };
        Ok(())
    }
}

/// The token URL from a `Bearer realm="...",service="...",scope="..."`
/// challenge.
fn token_url(challenge: &str) -> Option<Url> {
    let params = challenge
        .strip_prefix("Bearer ")
        .or_else(|| challenge.strip_prefix("bearer "))?;
    let mut realm = None;
    let mut query = Vec::new();
    for part in split_params(params) {
        let (k, v) = part.split_once('=')?;
        let v = v.trim_matches('"');
        match k.trim() {
            "realm" => realm = Some(v),
            k @ ("service" | "scope") => query.push(format!("{k}={}", encode(v))),
            _ => {}
        }
    }
    let mut url = Url::parse(realm?)?;
    if !query.is_empty() {
        url.path
            .push(if url.path.contains('?') { '&' } else { '?' });
        url.path.push_str(&query.join("&"));
    }
    Some(url)
}

/// Splits `a="x,y",b=z` at the commas outside quotes.
fn split_params(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(s[start..].trim());
    out
}

/// Percent-encodes a query value.
fn encode(v: &str) -> String {
    let mut s = String::new();
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:/".contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

/// The pulled layers as one Ichor image.
pub fn convert(p: &Pulled) -> Result<Vec<u8>, Error> {
    convert_with(&mut p.clone(), &[], layer::ANY)
}

/// A layer added on top of an image's own, already verified against its
/// pinned digest: a gzip'd or plain tar, of which only the entries under
/// `from` are taken, moved to `to` (both empty: the whole archive, as an
/// image layer, whiteouts included).
#[derive(Clone, Copy, Debug)]
pub struct Extra<'a> {
    pub data: &'a [u8],
    pub from: &'a str,
    pub to: &'a str,
}

/// The pulled layers, then `extras` above them, as one Ichor image, if what
/// that takes fits in `room`. Each layer is let go of once it is unpacked.
pub fn convert_with(
    p: &mut Pulled,
    extras: &[Extra<'_>],
    room: layer::Room<'_>,
) -> Result<Vec<u8>, Error> {
    let bad = |e: layer::Error| Error::Unsupported(e.0);
    let mut t = layer::Tree::new();
    for (d, data) in &mut p.layers {
        let data = core::mem::take(data);
        let tar = if d.media_type.ends_with("gzip") || data.starts_with(&[0x1f, 0x8b]) {
            let tar = layer::gunzip_within(&data, room).map_err(bad)?;
            drop(data);
            tar
        } else if d.media_type.ends_with(".tar") || d.media_type.is_empty() {
            data
        } else {
            return Err(Error::Unsupported(d.media_type.clone()));
        };
        t.add_tar_within(&tar, room).map_err(bad)?;
    }
    // Extras in a row from one archive: it is unpacked once.
    let mut last: (&[u8], Vec<u8>) = (&[], Vec::new());
    for x in extras {
        let tar = if !x.data.starts_with(&[0x1f, 0x8b]) {
            x.data
        } else {
            if !core::ptr::eq(last.0, x.data) {
                drop(core::mem::take(&mut last.1)); // before the next is made
                let tar = layer::gunzip_within(x.data, room).map_err(bad)?;
                last = (x.data, tar);
            }
            &last.1
        };
        let r = if x.from.is_empty() && x.to.is_empty() {
            t.add_tar_within(tar, room)
        } else {
            t.add_tar_at_within(tar, x.from, x.to, room)
        };
        r.map_err(bad)?;
    }
    drop(last);
    t.into_image(room).map_err(bad)
}

/// What the image config says to run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImageConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: String,
    pub user: String,
}

impl ImageConfig {
    pub fn parse(config: &[u8]) -> Result<ImageConfig, Error> {
        let v = json::parse(config).ok_or(Error::Malformed("image config"))?;
        let Some(c) = v.get("config") else {
            return Ok(ImageConfig::default());
        };
        let list = |k: &str| c.get(k).and_then(Value::strings).unwrap_or_default();
        let text = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Ok(ImageConfig {
            entrypoint: list("Entrypoint"),
            cmd: list("Cmd"),
            env: list("Env"),
            working_dir: text("WorkingDir"),
            user: text("User"),
        })
    }

    /// The process to run: the entrypoint, then `args` if given, else the
    /// image's command.
    pub fn argv(&self, args: &[String]) -> Vec<String> {
        let mut v = self.entrypoint.clone();
        v.extend_from_slice(if args.is_empty() { &self.cmd } else { args });
        v
    }

    /// The process's environment: the image's, with `set` over it (the last
    /// of one name counts), and what an image may rely on being there: a
    /// `PATH`, and root's `HOME`.
    pub fn environment(&self, set: &[String]) -> Vec<String> {
        const ALWAYS: [&str; 2] = [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=/root",
        ];
        let name = |e: &str| e.split_once('=').map_or(e.len(), |(n, _)| n.len());
        let mut env: Vec<String> = Vec::new();
        for e in ALWAYS
            .iter()
            .copied()
            .chain(self.env.iter().chain(set).map(String::as_str))
        {
            let n = &e[..name(e)];
            match env.iter_mut().find(|had| had[..name(had)] == *n) {
                Some(had) => *had = e.into(),
                None => env.push(e.into()),
            }
        }
        env
    }
}

#[cfg(test)]
mod tests;
