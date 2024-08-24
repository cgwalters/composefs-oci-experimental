use std::fmt::Display;

use anyhow::Result;
use ocidir::oci_spec::image::Descriptor;

pub(crate) const SHA256_HEXLEN: usize = 64;

/// A string which has been validated as a hexadecimal 64 character string,
/// which is the most common format for sha-256.
pub(crate) struct Sha256Hex<'a>(&'a str);

fn is_ascii_hex_lowercase(c: char) -> bool {
    c.is_ascii_digit() | matches!(c, 'a'..='f')
}

impl<'a> Sha256Hex<'a> {
    pub(crate) fn new(digest: &'a str) -> Result<Self> {
        if digest.len() != SHA256_HEXLEN || !digest.chars().all(is_ascii_hex_lowercase) {
            anyhow::bail!("Invalid sha256: {}", digest);
        }
        Ok(Self(digest))
    }

    pub(crate) fn to_descriptor_digest(&self) -> String {
        format!("sha256:{self}")
    }
}

impl<'a> std::ops::Deref for Sha256Hex<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> Display for Sha256Hex<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

fn sha256_of_descriptor(descriptor: &Descriptor) -> Result<Sha256Hex> {
    let (alg, digest) = descriptor
        .digest()
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid descriptor digest: {}", descriptor.digest()))?;
    if alg != "sha256" {
        anyhow::bail!("Unexpected algorithm in descriptor: {}", alg);
    }
    Sha256Hex::new(digest)
}

pub(crate) trait DescriptorExt {
    fn sha256(&self) -> Result<Sha256Hex>;
}

impl DescriptorExt for Descriptor {
    fn sha256(&self) -> Result<Sha256Hex> {
        sha256_of_descriptor(self)
    }
}
