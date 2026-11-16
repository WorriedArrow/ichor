//! Container layers into Ichor images (ADR-0012 §3): gzip and DEFLATE
//! decoding ([`inflate`]) and tar archives applied layer by layer into a
//! tree that becomes one image ([`Tree`]), with OCI whiteouts.
//!
//! Moved out of xtask, which builds its test images with it; the control
//! plane converts pulled images with the same code. Input is untrusted:
//! malformed data is an [`Error`], never a panic.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod inflate;
mod tar;

pub use inflate::{crc32, gunzip, gunzip_all};
pub use tar::Tree;

/// What was wrong with a layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub alloc::string::String);

impl Error {
    pub(crate) fn new(msg: &str) -> Error {
        Error(alloc::string::String::from(msg))
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Error {
        Error::new(s)
    }
}

impl From<alloc::string::String> for Error {
    fn from(s: alloc::string::String) -> Error {
        Error(s)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
