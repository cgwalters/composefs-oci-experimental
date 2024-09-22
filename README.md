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

## A cfs-oci image

By default, a cfs-oci image is a bit like a generic
[OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
in that it does not automatically unpack layers,
but stores content directly.

### cfs-oci native annotations

This project defines a annotation
`containers.composefs.fsverity` that is the composefs
fsverity-sha256 (as opposed to the default "content-sha256")
that can be applied to a descriptor.

Additionally, a `containers.composefs.layer.fsverity` annotation
can be added to `application/vnd.oci.image.layer.v1.tar` or one
of its "sub-types" such as `application/vnd.oci.image.layer.v1.tar+gzip`.
This digest holds the "canonical composefs tar fsverity" digest of
the tarball mapped to an EROFS image.

When these annotations are pre-computed by a build server,
the signature covering the manifest hence covers both the
default "content-sha256:" digest as well as the optimized
`fsverity-sha256` digest.

An image 

### Non-native images

An image that does not already have these annotations can
be imported; they will be computed client side and stored
as extended attributes instead. Each file stored in the
`blobs/sha256` directory will have a
`trusted.composefs.fsverity` xattr (when run as root,
otherwise `user.composefs.fsverity`). In order to
be robust against accidental corruption,
the value is actually a [HMAC](https://en.wikipedia.org/wiki/HMAC)
using the manifest's digest as a key.

Additionally, the manifest will have a `trusted.composefs.`

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
- `objects/`: A "split-digest" object directory, used as the shared backing store for all composefs files.
   The digest here is the fsverity digest.
- `objects/by-sha256`: A split-digest directory with hardlinks to objects named by their "plain" sha256. Note
   that not *every* object has its plain sha256 calculated.
- `artifacts/`: A directory for OCI artifacts, filled with composefs files, named by their fsverity digest (split-digest)
- `artifacts/tags`: A directory with hard links to `artifacts/`, with the file name being a URL encoding of the artifact name
- `images/`: A directory for OCI images (not generic artifacts) filled with composefs files (backed by `objects/`), named by their fsverity digest
- `images/tags/`: A directory of hard links to `images/`, with the file name being a URL encoding of the image name
- `images/layers/`: A directory filled with composefs files (backed by `objects/`), named by their "diffid" (sha256, split-digest)
   Each composefs file has a set of xattrs `user.composefs.blobid.0..n` where each value is the sha256 digest
   of a corresponding compressed tar stream.

Note that an artifact may *also* be an OCI image; it is not required to store OCI images "unpacked".

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
