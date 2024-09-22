# composefs-oci

The high level goal of this crate is to be an opinionated
generic storage layer using composefs, with direct support
for OCI.  Note not just OCI *containers* but also including
OCI artifacts too.
    
This crate is intended to be the successor to
the "storage core" of both ostree and containers/storage.

## Goal: efficient and complete chained fsverity-oriented OCI image

For more on this, see https://github.com/containers/storage/issues/2095

Basically the goal is to create efficient fsverity (composefs) oriented
storage layout such that a `manifest.json` (which points to everything
else, such as the `config.json` and especially the layers) can
be efficiently mounted and verified (incrementally/on-demand or upfront).

## Design

The composefs core just offers the primitive of creating
"superblocks" which can have regular file data point
to underlying "loose" objects stored in an arbitrary place.

cfs-oci (for short) roughly matches the goal of both
ostree and containers/storage in supporting multiple
versioned filesystem trees with associated metadata,
including support for e.g. garbage collection.

## A cfs-oci image

By default, a cfs-oci image is a bit like a generic
[OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md),
although there is no `index.json`, but instead a directory with URL-encoded
names.

A cfs-oci image can have two manifest forms: "native" and "imported".
A native image has all relevant annotations included in `manifest.json`.
The composefs manifest for an imported image can be found via an extended
attribute attached to the manifest.

Additionally, each non-artifact image (with tar layers) can be either "packed" or "unpacked", or both.

### packed vs unpacked

A very common use case for cfs-oci will be to fetch a non-artifact image and
unpack the layers and create the final merged rootfs, ready to be mounted.
The original compressed tar layers will not be stored.

However, we also aim to support fully generic use cases (OCI artifacts)
as well as storing *packed* images which allows mirroring offline, etc.
In this case, 

An image can be both an artifact *and* unpacked, i.e. both the compressed
layer tarballs and the final merged rootfs are stored. This can be useful
when one needs to be able to reliably re-push the full contents of an
image "bit for bit" (including compression), but also be able to
mount and inspect it.

### cfs-oci native annotations

#### The `containers.composefs.fsverity` annotation

The annotation `containers.composefs.fsverity` is the composefs
fsverity sha256 (as opposed to the default "content-sha256")
that can be applied to a [descriptor](https://github.com/opencontainers/image-spec/blob/main/descriptor.md).

A "native" image MUST have this annotation present on the image
configuration descriptor (even if it is the "empty descriptor"
value). This annotation signals that the manifest is a
"verity OCI" and that the following annotations are also
expected to be present (where relevant).

If this annotation is present on the configuration descriptor,
it MUST be present on all layers that are not a subtype of
`application/vnd.oci.image.layer.v1.tar`.

It MAY be present additionally on layers that are a subtype
of `application/vnd.oci.image.layer.v1.tar`, but this
is generally unnecessary as such types are expected to be
maintained in an unpacked (composefs) representation.

#### The `containers.composefs.layer.digest` annotation

The `containers.composefs.layer.digest` annotation
can be added to `application/vnd.oci.image.layer.v1.tar` or one
of its "sub-types" such as `application/vnd.oci.image.layer.v1.tar+gzip`.
This digest holds the "canonical composefs EROFS" digest of
the tarball mapped to an EROFS image. Consider this like a variant
of the "diffid" that instead allows efficient indexed access
to the changeset corresponding to a layer because a composefs
can be mounted instead.

When these annotations are pre-computed by a build server,
the signature covering the manifest hence covers both the
default "content-sha256:" digest as well as the optimized
fsverity digests.

#### The `containers.composefs.rootfs.digest` annotation

An image manifest should additionally have a `containers.composefs.rootfs.digest` annotation that contains the digest of the final flattened
image following the [applying changesets](https://github.com/opencontainers/image-spec/blob/main/layer.md#applying-changesets)
algorithm for all of its layers.

Note that computing this digest can be computed relatively cheaply assuming that the system has a cached composefs image corresponding to each layer (it will not involve recomputing the digest of content files).

This digest must match that for `rootfs.cfs`.

### Imported images

An image that does not already have these annotations 
as part of the `manifest.json` can still be imported.
The original manifest is linked via an annotation
`composefs.manifest-original.fsverity` that contains
the fsverity digest for the original manifest.

### Layout

A cfs-ocidir can contain multiple images, and includes its own metadata.
It has the following layout:

- `meta.json`: Metadata
- `objects/`: A "split-digest" object directory, used as the shared backing store for all composefs files.
   The digest here is the fsverity digest.
- `objects-by-sha256`: A split-digest object directory with symbolic links to `../../objects`, only used
   for images that don't have the annotation `containers.composefs.layer.digest`.
- `images/`: Directory of URL encoded hardlinks to `manifest.json` for artifacts
- `unpacked/`: Directory of URL encoded hardlinks to `manifest.json` for unpacked images

#### "split-digest" format

Side note: This follows a longstanding tradition of splitting up a digest into (first two bytes, remaining bytes)
creating subdirectories for the first two bytes. It is used by composefs by default.

### Runtime state

Each cfs-oci directory owned by root defaults to having a corresponding
`/run/composefs-oci/state/<device,inode>/` directory that holds e.g.
locks.

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

### Concurrency

Concurrent reads are trivially supportable; everything
is just a readonly file.

Writes come in three forms:

- Addition
- Unreferencing
- Garbage collection

Concurrent additions (e.g. two processes/threads
pulling two images that may share blobs, or even
the same image) are "easy"; most files are designed
to be an "object" which have natural idempotent
semantics. For example when we go to add an object,
that's a linkat() operation, and if we get EEXIST
that's OK - something else succeeded at adding
the object and we discard our copy.

An "unreference" operation is basically deleting
a tag. This can race with addition, but it
is unspecified which operation wins.

Garbage collection is removing objects which
are no longer referenced. Having GC run
concurrently with addition is the challenge.

The simplest solution is:

- A read-write lock
- Read operations claim read lock
- GC operates in "mark and sweep" model; mark
  phase holds a read lock; scan all roots and
  note live objects. When this finishes, grab
  write lock. Find any *new* roots added between
  those two phases, and scan them. Prune all
  unreferenced objects.



### Injecting "flattened" composefs digests

Another verb that should be supported here is:
`cfs-oci --repo=/path/to/repo image finalize <imagename>`

This would compute the *flattened* final filesystem tree
for the container image, and inject its metadata into
the manifest as an annotation e.g. `containers.composefs.digest`.

Then, a signature which covers the manifest such as Sigstore
can also cover verification of the filesystem tree. Of course,
one could use any signature scheme desired to sign images.

### Mounting composefs as non-root

In order to be able to use composefs *everywhere* we should
support a mechanism for runtimes like podman/flatpak to
be able to safely mount a composefs as non-root. Privileges
for mounting EROFS are currently restricted to root for
security reasons. A decent solution for this problem is
basically "mkcomposefs --from-file + mount" as a (DBus) service.
This accepts two things:

 - textual composefs dump file (as a sealed memfd)
 - file descriptor for mount namespace, which we can use
   as a mount target with https://people.kernel.org/brauner/mounting-into-mount-namespaces

The return value is a linkable O_TMPFILE fd with the
resulting composefs EROFS.

We can also have an optimized version where fsverity
is required, and we accept as input three things:

- textual composefs dump file (as sealed memfd)
- file descriptor for composefs EROFS
- file descriptor for mount namespace

Then the service synthesizes another copy of the EROFS,
and compares its fsverity digest with the provided one.
If they match, it's safe to mount because the Linux
kernel will deny writing to the user's copy of the EROFS
file. One optimization here would be to maintain a cache
in e.g. /run/composefs-mounts/verified/<fsverity digest>
since once we've verified a given EROFS (identified via fsverity digest)
it's safe to mount again.
