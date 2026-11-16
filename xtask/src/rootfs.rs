//! Turning root file system tarballs (OCI layers, Alpine's minirootfs, ...)
//! into Ichor images without extracting anything to the host's disk:
//! `services/layer`'s tree (shared with the control plane), with xtask's
//! string errors. Its tests live there.

use crate::Result;

/// A directory tree, assembled from tar layers.
#[derive(Debug, Default)]
pub struct Tree(layer::Tree);

impl Tree {
    pub fn new() -> Tree {
        Tree(layer::Tree::new())
    }

    /// Applies one uncompressed tar layer (OCI whiteouts included).
    pub fn add_tar(&mut self, tar: &[u8]) -> Result<()> {
        self.0.add_tar(tar).map_err(|e| e.to_string())
    }

    /// Adds a regular file at `path` (creating parent directories).
    pub fn add_file(&mut self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        self.0.add_file(path, data, mode).map_err(|e| e.to_string())
    }

    /// Builds the Ichor image (padded to whole 4 KiB blocks).
    pub fn image(&self) -> Vec<u8> {
        self.0.image()
    }
}
