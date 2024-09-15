use ocidir::oci_spec::image::{ImageConfiguration, ImageManifest};

/// Get the creation timestamp, which can be a manifest annotation or part of the config.
pub(crate) fn created<'a, 'b: 'a>(
    manifest: &'a ImageManifest,
    config: &'b ImageConfiguration,
) -> Option<&'a str> {
    manifest
        .annotations()
        .as_ref()
        .and_then(|a| {
            a.get(ocidir::oci_spec::image::ANNOTATION_CREATED)
                .map(|s| s.as_str())
        })
        .or_else(|| config.created().as_deref())
}
