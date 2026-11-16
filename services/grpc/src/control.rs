//! `ichor.v1.Control` (`docs/abi/control.proto`): its methods' paths and
//! messages, encoded and decoded by hand.

use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::{Error, Reader, Writer};

pub const PULL_IMAGE: &str = "/ichor.v1.Control/PullImage";
pub const CREATE_CELL: &str = "/ichor.v1.Control/CreateCell";
pub const RUN: &str = "/ichor.v1.Control/Run";
pub const SIGNAL: &str = "/ichor.v1.Control/Signal";
pub const INSPECT: &str = "/ichor.v1.Control/Inspect";
pub const DESTROY: &str = "/ichor.v1.Control/Destroy";

/// A request naming one cell (`Inspect`, `Destroy`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CellRequest {
    pub cell_id: String,
}

impl CellRequest {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new().string(1, &self.cell_id).finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            if f == 1 {
                m.cell_id = v.as_string()?;
            }
            Ok(())
        })?;
        Ok(m)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignalRequest {
    pub cell_id: String,
    /// A Linux signal number (15: SIGTERM, 9: SIGKILL).
    pub signal: u32,
}

impl SignalRequest {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .string(1, &self.cell_id)
            .varint(2, u64::from(self.signal))
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            match f {
                1 => m.cell_id = v.as_string()?,
                2 => m.signal = u32::try_from(v.as_u64()?).map_err(|_| Error)?,
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

/// `Signal`'s answer: how many processes it reached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignalResponse {
    pub processes: u64,
}

impl SignalResponse {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new().varint(1, self.processes).finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            if f == 1 {
                m.processes = v.as_u64()?;
            }
            Ok(())
        })?;
        Ok(m)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InspectResponse {
    pub cell_id: String,
    pub address: String,
    pub image_id: String,
    pub memory_used_bytes: u64,
    pub memory_limit_bytes: u64,
    pub processes: u64,
    pub threads: u64,
}

impl InspectResponse {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .string(1, &self.cell_id)
            .string(2, &self.address)
            .string(3, &self.image_id)
            .varint(4, self.memory_used_bytes)
            .varint(5, self.memory_limit_bytes)
            .varint(6, self.processes)
            .varint(7, self.threads)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            match f {
                1 => m.cell_id = v.as_string()?,
                2 => m.address = v.as_string()?,
                3 => m.image_id = v.as_string()?,
                4 => m.memory_used_bytes = v.as_u64()?,
                5 => m.memory_limit_bytes = v.as_u64()?,
                6 => m.processes = v.as_u64()?,
                7 => m.threads = v.as_u64()?,
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

/// Reads every field of `b` with `f`, skipping the ones it does not know.
fn each<'a>(
    b: &'a [u8],
    mut f: impl FnMut(u32, crate::proto::Value<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut r = Reader::new(b);
    while let Some((field, v)) = r.field()? {
        f(field, v)?;
    }
    Ok(())
}

/// A layer added on top of a pulled image, pinned by digest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LayerSource {
    /// Where to fetch it (`https://` or `http://`: the digest, not the
    /// transport, makes it trustworthy).
    pub url: String,
    /// `sha256:<hex>` of the bytes as fetched; required.
    pub digest: String,
    /// Take only the archive's entries under this path...
    pub from: String,
    /// ...and put them under this one (empty: as they are).
    pub to: String,
}

impl LayerSource {
    fn encode(&self) -> Vec<u8> {
        Writer::new()
            .string(1, &self.url)
            .string(2, &self.digest)
            .string(3, &self.from)
            .string(4, &self.to)
            .finish()
    }

    fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            match f {
                1 => m.url = v.as_string()?,
                2 => m.digest = v.as_string()?,
                3 => m.from = v.as_string()?,
                4 => m.to = v.as_string()?,
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PullImageRequest {
    pub reference: String,
    /// Layers to add on top of the image's own, lowest first.
    pub layers: Vec<LayerSource>,
}

impl PullImageRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(1, &self.reference);
        for l in &self.layers {
            w.bytes(2, &l.encode());
        }
        w.finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            match f {
                1 => m.reference = v.as_string()?,
                2 => m.layers.push(LayerSource::decode(v.as_bytes()?)?),
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PullImageResponse {
    pub digest: String,
    pub image_id: String,
    pub size: u64,
    pub argv: Vec<String>,
    pub env: Vec<String>,
}

impl PullImageResponse {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .string(1, &self.digest)
            .string(2, &self.image_id)
            .varint(3, self.size)
            .strings(4, &self.argv)
            .strings(5, &self.env)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            match f {
                1 => m.digest = v.as_string()?,
                2 => m.image_id = v.as_string()?,
                3 => m.size = v.as_u64()?,
                4 => m.argv.push(v.as_string()?),
                5 => m.env.push(v.as_string()?),
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateCellRequest {
    pub image_id: String,
    pub memory_bytes: u64,
}

impl CreateCellRequest {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .string(1, &self.image_id)
            .varint(2, self.memory_bytes)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            match f {
                1 => m.image_id = v.as_string()?,
                2 => m.memory_bytes = v.as_u64()?,
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateCellResponse {
    pub cell_id: String,
    pub address: String,
}

impl CreateCellResponse {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .string(1, &self.cell_id)
            .string(2, &self.address)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            match f {
                1 => m.cell_id = v.as_string()?,
                2 => m.address = v.as_string()?,
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunRequest {
    pub cell_id: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
}

impl RunRequest {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .string(1, &self.cell_id)
            .strings(2, &self.argv)
            .strings(3, &self.env)
            .finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = Self::default();
        each(b, |f, v| {
            match f {
                1 => m.cell_id = v.as_string()?,
                2 => m.argv.push(v.as_string()?),
                3 => m.env.push(v.as_string()?),
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

/// One message of `Run`'s response stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEvent {
    Output(Vec<u8>),
    ExitStatus(u32),
}

impl RunEvent {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RunEvent::Output(b) => Writer::new().bytes(1, b).finish(),
            RunEvent::ExitStatus(s) => Writer::new().varint_always(2, u64::from(*s)).finish(),
        }
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let mut m = None;
        each(b, |f, v| {
            match f {
                1 => m = Some(RunEvent::Output(v.as_bytes()?.to_vec())),
                2 => {
                    m = Some(RunEvent::ExitStatus(
                        u32::try_from(v.as_u64()?).map_err(|_| Error)?,
                    ))
                }
                _ => {}
            }
            Ok(())
        })?;
        m.ok_or(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn messages_round_trip() {
        let p = PullImageResponse {
            digest: "sha256:ab".into(),
            image_id: "cd".into(),
            size: 1 << 33,
            argv: vec!["/hello".into()],
            env: vec!["PATH=/bin".into(), "A=b".into()],
        };
        assert_eq!(PullImageResponse::decode(&p.encode()), Ok(p));
        let r = RunRequest {
            cell_id: "7".into(),
            argv: vec!["sh".into(), "-c".into(), String::new()],
            env: vec![],
        };
        assert_eq!(RunRequest::decode(&r.encode()), Ok(r));
        let pull = PullImageRequest {
            reference: "alpine".into(),
            layers: vec![LayerSource {
                url: "https://example.com/l.tar.gz".into(),
                digest: "sha256:00".into(),
                from: "src/".into(),
                to: "/opt/".into(),
            }],
        };
        assert_eq!(PullImageRequest::decode(&pull.encode()), Ok(pull));
        let s = SignalRequest {
            cell_id: "2".into(),
            signal: 15,
        };
        assert_eq!(SignalRequest::decode(&s.encode()), Ok(s));
        let i = InspectResponse {
            cell_id: "2".into(),
            address: "10.88.0.13".into(),
            image_id: "ab".into(),
            memory_used_bytes: 1 << 20,
            memory_limit_bytes: 64 << 20,
            processes: 1,
            threads: 1,
        };
        assert_eq!(InspectResponse::decode(&i.encode()), Ok(i));
        for e in [
            RunEvent::Output(b"hi\n".to_vec()),
            RunEvent::ExitStatus(0),
            RunEvent::ExitStatus(256),
        ] {
            assert_eq!(RunEvent::decode(&e.encode()), Ok(e));
        }
        assert_eq!(RunEvent::decode(&[]), Err(Error));
        let c = CreateCellRequest {
            image_id: "x".into(),
            memory_bytes: 0,
        };
        assert_eq!(c.encode(), Writer::new().string(1, "x").finish());
        assert_eq!(CreateCellRequest::decode(&c.encode()), Ok(c));
    }
}
