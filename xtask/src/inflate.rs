//! gzip and DEFLATE decoding: `services/layer`'s decoder (shared with the
//! control plane), with xtask's string errors. Its tests live there.

use crate::Result;

pub use layer::crc32;

/// Inflates a raw DEFLATE stream; returns the output and the bytes consumed.
pub fn inflate(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    layer::inflate::inflate(data).map_err(|e| e.to_string())
}

/// Decompresses a gzip file (one member), checking its CRC and length.
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    layer::gunzip(data).map_err(|e| e.to_string())
}

/// Decompresses every member of a multi-member gzip stream and joins them.
pub fn gunzip_all(data: &[u8]) -> Result<Vec<u8>> {
    layer::gunzip_all(data).map_err(|e| e.to_string())
}
