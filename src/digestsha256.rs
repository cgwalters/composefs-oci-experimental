//! A parser for the pair of "sha256:<digest>" as used
//! in image manifests.

use anyhow::Result;

pub(crate) const SHA256_HEXLEN: u16 = 64;

/// A validated
pub(crate) struct DigestSha256<'a>(&'a str);

impl<'a> DigestSha256<'a> {
    /// Parse a descriptor <algo>:<digest> pair.
    /// <algo> must be `sha256`.
    pub(crate) fn parse(s: &'a str) -> Result<Self> {
        let (alg, digest) = s
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Missing `:` in digest"))?;
        match alg {
            "sha256" => {
                if digest.len() != (usize::from(SHA256_HEXLEN)) {
                    anyhow::bail!("Invalid sha256 (length={})", digest.len());
                }
                for c in digest.chars() {
                    if !c.is_ascii_alphanumeric() {
                        anyhow::bail!("Invalid sha256 (non-alphanumeric {c})")
                    }
                }
                Ok(Self(digest))
            }
            o => anyhow::bail!("Unsupported digest algorithm: {o}"),
        }
    }

    /// Return the parsed and validated SHA-256 digest.
    pub(crate) fn sha256(&self) -> &str {
        self.0
    }
}
