# composefs-oci

The high level goal of this crate is to be an opinionated
generic storage layer using composefs, with direct support
for OCI.  Note not just OCI *containers* but also including
OCI artifacts too.
    
This crate is intended to be the successor to
the "storage core" of both ostree and containers/storage.

## Design

The composefs core just offers the primitive of creating
"superblocks" which can have regular file data point
to underlying "loose" objects stored in an arbitrary place.

cfs-oci (for short) roughly matches the goal of both
ostree and containers/storage in supporting multiple
versioned filesystem trees with associated metadata,
including support for e.g. garbage collection.

## composefs-mapped OCI image

A "cfs-oci image" is a mapping of a standard OCI image
into composefs. An OCI image is composed of 3 parts:

- manifest
- config
- rootfs (layers)

The mapping is simple; the manifest and config are JSON and are serialized
into the toplevel, and the full *squashed* rootfs is stored in /rootfs.

```
/manifest.json
/config.json
/rootfs
```

This is designed to allow directly (natively) mounting the composefs and using
the `/rootfs` subdirectory as the target root filesystem.

## composefs-mapped OCI artifact

OCI artifacts are more general, and are effectively

```
/manifest.json
/config.json
/layers/[0..n]
```

where each file in `layers/` is directory stored as a composefs
object.

### Layout

A cfs-ocidir has the following toplevel entries:

- `meta.json`: Metadata
- `images/`: A directory for OCI images (not generic artifacts) filled with composefs files (backed by `objects/`), named by their fsverity digest (split-checksum)
- `images/tags/`: A directory of hard links to `images/`, with the file name being a URL encoding of the image name
- `images/by-manifest-digest/`: A directory of hardlinks to `images/`, named by the sha256 digest of the manifest (split-checksum)
- `images/layers/`: A directory filled with composefs files (backed by `objects/`), named by their "diffid" (sha256) (split-checksum)
   Each composefs file has a set of xattrs `user.composefs.blobid.0..n` where each value is the sha256 digest
   of a corresponding compressed tar stream.
- `artifacts/`: A directory for OCI artifacts, filled with composefs files, named by their fsverity digest (split-checksum)
- `artifacts/tags`: A directory with hard links to `artifacts/`, with the file name being a URL encoding of the artifact name
- `artifacts/by-manifest/`: A directory of hardlinks to `artifacts/`, same as `images/by-manifest-digest` otherwise
- `objects/`: A "split-checksum" object directory, used as the shared backing store for all composefs
  files.
- `objects/by-sha256`: A split-checksum directory with hardlinks to objects named by sha256 (optional, not all objects have their
  plain sha256 calculated)

Note that an artifact may *also* be an OCI image; it is not required to store OCI images "unpacked".

#### "split-checksum" format

Side note: This follows a longstanding tradition of splitting up a checksum into (first two bytes, remaining bytes)
creating subdirectories for the first two bytes. It is used by composefs by default.

## CLI sketch: OCI container images

`cfs-oci --repo=/path/to/repo image list|pull|rm|mount`

## CLI sketch: OCI artifacts

`cfs-oci --repo=/path/to/repo artifact list|pull|rm`

## CLI sketch: Other

### Efficiently clone a repo

`cfs-oci clone /path/to/repo /path/to/clone`
This would use reflinks (if available) or hardlinks if not
for all the loose objects, but allow fully distinct namespacing/ownership
of images.

For example, it would probably make sense to have
bootc and podman use separate physical stores in
`/ostree` and `/var/lib/containers` - but if they're
on the same filesystem, we can efficiently and safely share
backing objects!

### Injecting "flattened" composefs digests

Another verb that should be supported here is:
`cfs-oci --repo=/path/to/repo image finalize <imagename>`

This would compute the *flattened* final filesystem tree
for the container image, and inject its metadata into
the manifest as an annotation e.g. `containers.composefs.digest`.

Then, a signature which covers the manifest such as Sigstore
can also cover verification of the filesystem tree. Of course,
one could use any signature scheme desired to sign images.
