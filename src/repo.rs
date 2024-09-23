use core::str;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::ops::{Add, ControlFlow};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std_ext::cap_tempfile::{TempDir, TempFile};
use cap_std_ext::dirext::CapStdExtDirExt;
use cap_std_ext::{cap_std, cap_tempfile};
use composefs::dumpfile::{DumpConfig, Entry, Item, Mtime, Xattr};
use composefs::fsverity::Digest as VerityDigest;
use fn_error_context::context;
use ocidir::cap_std::fs::MetadataExt;
use ocidir::oci_spec::image::{
    Descriptor, Digest as DescriptorDigest, DigestAlgorithm, ImageConfiguration, ImageManifest,
    ImageManifestBuilder, MediaType, Sha256Digest,
};
use openssl::hash::{Hasher, MessageDigest};
use rustix::fd::BorrowedFd;
use rustix::fs::{AtFlags, XattrFlags};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use crate::fileutils::{self, ignore_eexist, linkat_optional_allow_exists, map_rustix_optional};

/// Maximum length of a tag name
const TAG_MAX: usize = 255;
/// Maximum size of a manifest or config
const METADATA_MAX: usize = 5 * 1024 * 1024;

/// Standardized metadata
const REPOMETA: &str = "meta.json";
/// A composefs/ostree style object directory
const OBJECTS: &str = "objects";
/// A directory with symlinks to ../objects
const OBJECTS_BY_SHA256: &str = "objects-by-sha256";
/// OCI images, may be either packed (or an artifact) or "unpacked"
const IMAGES: &str = "images";
const UNPACKED: &str = "unpacked";

/// TODO remove this
const LAYERS: &str = "layers";

/// The directory with metadata for diffs associated with an unpacked
/// image.
const DIFFS: &str = "diffs";
/// The filename containing metadata for a tar stream sufficient
/// to reconstruct it bit-for-bit.
const TAR_SPLIT_EXT: &str = "tar-split";
/// The name of a composefs file for an unpacked root.
const ROOTFS_CFS: &str = "rootfs.cfs";

const TMP: &str = "tmp";

/// Filename for manifest inside composefs
const MANIFEST_NAME: &str = "manifest.json";
/// Filename for a locally generated composefs-augmented manifest.
const MANIFEST_CFS_LOCAL: &str = "manifest-cfs-local.json";

/// Annotation for a descriptor's fsverity
const ANNOTATION_DESCRIPTOR_VERITY: &str = "containers.composefs.fsverity";
const ANNOTATION_LAYER_VERITY: &str = "containers.composefs.layer.digest";
const ANNOTATION_ROOTFS_VERITY: &str = "containers.composefs.rootfs.digest";

const XATTR_PREFIX_TRUSTED: &str = "trusted.";
const XATTR_PREFIX_USER: &str = "user.";

/// Links imported manifest to original
const XATTR_MANIFEST_ORIG: &str = "composefs.manifest-original.digest";
/// The extended attribute with the original descriptor digest.
const XATTR_DESCRIPTOR_DIGEST: &str = "composefs.descriptor.digest";

const BOOTID_XATTR: &str = "user.cfs-oci.bootid";
const BY_SHA256_UPLINK: &str = "../../objects/";

/// Can be included in a manifest if the digest is pre-computed
const CFS_DIGEST_ANNOTATION: &str = "composefs.digest";

type SharedObjectDirs = Arc<Mutex<Vec<Dir>>>;
type ObjectDigest = String;
type ObjectPath = Utf8PathBuf;

/// Require that a descriptor's digest is sha256. Return the digest value.
fn sha256_of_descriptor(desc: &Descriptor) -> Result<&str> {
    sha256_of_digest(desc.digest())
}

/// If a descriptor has a standard composefs fsverity annotation, parse and return it.
fn fsverity_of_descriptor(desc: &Descriptor) -> Result<Option<Sha256Digest>> {
    let Some(v) = desc
        .annotations()
        .as_ref()
        .and_then(|a| a.get(ANNOTATION_DESCRIPTOR_VERITY))
    else {
        return Ok(None);
    };
    let v = Sha256Digest::from_str(v)?;
    Ok(Some(v))
}

/// Require that a descriptor digest is sha256. Return the digest value.
fn sha256_of_digest(digest: &DescriptorDigest) -> Result<&str> {
    if digest.algorithm() != &DigestAlgorithm::Sha256 {
        anyhow::bail!("Expected algorithm sha256, found {}", digest.algorithm())
    };
    Ok(digest.digest())
}

/// Given an object ID (sha256 digest), turn it into a path. A slash `/`
/// is inserted after the first two characters.
fn object_digest_to_path(objid: ObjectDigest) -> ObjectPath {
    object_digest_to_path_prefixed(objid, "")
}

/// Like [`object_digest_to_path()`] but also insert the provided prefix.
fn object_digest_to_path_prefixed(mut objid: ObjectDigest, prefix: &str) -> ObjectPath {
    // Ensure we are only passed an object id
    assert_eq!(objid.len(), 64, "Invalid object ID {objid}");
    objid.insert(2, '/');
    if !prefix.is_empty() && !prefix.ends_with('/') {
        objid.insert(0, '/');
    }
    objid.insert_str(0, prefix);
    objid.into()
}

/// Convert a relative path into an object identifier. For convenience/comprehensibility
/// things like tags are implemented as symbolic links to an object. But often we
/// want to precisely know which object is expected, and not just follow the link.
///
/// This trims all relative path components (`../`) as well as an `objects/` string.
#[context("Parsing object link")]
fn object_link_to_digest(buf: Vec<u8>) -> Result<ObjectDigest> {
    // It's an error if we find non-UTF8 content here
    let mut buf = String::from_utf8(buf).map_err(|_| anyhow::anyhow!("Invalid UTF-8"))?;
    while buf.starts_with("../") {
        buf.replace_range(0..3, "");
    }
    let objects = "objects/";
    if buf.starts_with(objects) {
        buf.replace_range(0..objects.len(), "");
    }
    if !matches!(buf.chars().nth(2), Some('/')) {
        anyhow::bail!("Expected object file path in {buf:?}");
    }
    // Trim the `/`
    buf.replace_range(2..3, "");
    // TODO avoid multiple allocations here
    let r = Sha256Digest::from_str(&buf)?;
    Ok(r.digest().into())
}

fn compare_digests(expected: &str, found: &str) -> Result<()> {
    if expected != found {
        anyhow::bail!("Expected digest {expected} but found {found}");
    }
    Ok(())
}

/// Given a tag name (arbitrary string), encode it in a way that is safe for a filename
/// and prepend the tag directory to it.
fn tag_path(name: &str) -> Utf8PathBuf {
    assert!(name.len() <= TAG_MAX);
    let tag_filename =
        percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    format!("{IMAGES}/{tag_filename}").into()
}

/// The extended attribute we attach with the target metadata
// const CFS_ENTRY_META_XATTR: &str = "user.cfs.entry.meta";
/// This records the virtual number of links (as opposed to
/// the physical, because we may share multiple regular files
/// by hardlinking into the object store).
// const CFS_ENTRY_META_NLINK: &str = "user.cfs.entry.nlink";

///
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RepoMetadata {
    // Must currently be 0.1
    version: String,
    // Set to true if and only if we detected the filesystem supports fs-verity
    // and all objects should have been initialized that way.
    verity: bool,
}

/// This metadata is serialized underneath the `CFS_ENTRY_META_XATTR`
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OverrideMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: Option<u32>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

fn get_bootid() -> &'static str {
    static BOOTID: OnceLock<String> = OnceLock::new();
    let bootid =
        BOOTID.get_or_init(|| std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap());
    bootid.as_str()
}

// fn create_entry(_h: tar::Header) -> Result<Entry<'static>> {
// let size = h.size()?;
// let path = &*h.path()?;
// let path = Utf8Path::from_path(path)
//     .ok_or_else(|| anyhow::anyhow!("Invalid non-UTF8 path: {path:?}"))?;
// let path: Cow<std::path::Path> = Cow::Owned(PathBuf::from("."));
// let mtime = dumpfile::Mtime {
//     sec: h.mtime()?,
//     nsec: 0,
// };
// // The data below are stubs, we'll fix it up after
// let nlink = 1;
// let inline_content = None;
// let fsverity_digest = None;

// use dumpfile::Item;
// let item = match h.entry_type() {
//     tar::EntryType::Regular => {}
//     tar::EntryType::Link => todo!(),
//     tar::EntryType::Symlink => todo!(),
//     tar::EntryType::Char => todo!(),
//     tar::EntryType::Block => todo!(),
//     tar::EntryType::Directory => todo!(),
//     tar::EntryType::Fifo => todo!(),
//     tar::EntryType::Continuous => todo!(),
//     tar::EntryType::GNULongName => todo!(),
//     tar::EntryType::GNULongLink => todo!(),
//     tar::EntryType::GNUSparse => todo!(),
//     tar::EntryType::XGlobalHeader => todo!(),
//     tar::EntryType::XHeader => todo!(),
//     _ => todo!(),
// };

// let entry = Entry {
//     path,
//     uid: h.uid().context("uid")?.try_into()?,
//     gid: h.gid().context("gid")?.try_into()?,
//     mode: h.mode().context("mode")?,
//     mtime,
//     item: todo!(),
//     xattrs: todo!(),
// };
//     todo!()
// }

/// A writer which writes an object identified by sha256.
pub struct DescriptorWriter<'a> {
    /// Compute checksum
    sha256hasher: Hasher,
    /// Target file
    target: Option<cap_tempfile::TempFile<'a>>,
    size: u64,
}

impl<'a> std::fmt::Debug for DescriptorWriter<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DescriptorWRiter")
            .field("target", &self.target)
            .field("size", &self.size)
            .finish()
    }
}

impl<'a> std::io::Write for DescriptorWriter<'a> {
    fn write(&mut self, srcbuf: &[u8]) -> std::io::Result<usize> {
        self.sha256hasher.update(srcbuf)?;
        self.target
            .as_mut()
            .unwrap()
            .as_file_mut()
            .write_all(srcbuf)?;
        self.size += srcbuf.len() as u64;
        Ok(srcbuf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> DescriptorWriter<'a> {
    fn new(tmpf: TempFile<'a>) -> Result<Self> {
        Ok(Self {
            sha256hasher: Hasher::new(MessageDigest::sha256())?,
            // FIXME add ability to choose filename after completion
            target: Some(tmpf),
            size: 0,
        })
    }

    #[allow(dead_code)]
    fn finish(mut self, media_type: MediaType) -> Result<(Descriptor, TempFile<'a>)> {
        // SAFETY: Nothing else should have taken the target
        let tempfile = self.target.take().unwrap();
        let sha256 = hex::encode(self.sha256hasher.finish()?);
        let desc = Descriptor::new(
            media_type,
            self.size.try_into().unwrap(),
            Sha256Digest::from_str(&sha256).unwrap(),
        );
        Ok((desc, tempfile))
    }

    #[context("Validating descriptor {}", descriptor.digest())]
    fn finish_validate(mut self, descriptor: &Descriptor) -> Result<TempFile<'a>> {
        let expected_sha256 = sha256_of_descriptor(descriptor)?;
        let descriptor_size: u64 = descriptor.size().try_into()?;
        if descriptor_size != self.size {
            anyhow::bail!(
                "Corrupted object, expected size {descriptor_size}, got size {}",
                self.size
            );
        }
        let found_sha256 = hex::encode(self.sha256hasher.finish()?);
        if found_sha256 != expected_sha256 {
            anyhow::bail!(
                "Corrupted object, expected sha256:{expected_sha256} got sha256:{found_sha256}"
            );
        }
        // SAFETY: Nothing else should have taken this value
        Ok(self.target.take().unwrap())
    }
}

#[context("Initializing object dir")]
fn init_object_dir(objects: &Dir) -> Result<()> {
    for prefix in 0..=0xFFu8 {
        let path = format!("{:02x}", prefix);
        objects.ensure_dir_with(path, &fileutils::default_dirbuilder())?;
    }
    Ok(())
}

#[context("Checking fsverity")]
fn test_fsverity_in(d: &Dir) -> Result<bool> {
    let mut tf = TempFile::new(&d)?;
    tf.write_all(b"test")?;
    fileutils::reopen_tmpfile_ro(&mut tf)?;
    Ok(composefs::fsverity::fsverity_enable(tf.as_file().as_fd()).is_ok())
}

fn fsverity_hexdigest_from_fd(fd: impl AsFd) -> Result<String> {
    let mut digest = VerityDigest::new();
    composefs::fsverity::fsverity_digest_from_fd(fd.as_fd(), &mut digest)
        .context("Computing fsverity digest")?;
    Ok(hex::encode(digest.get()))
}

// Rename all regular files from -> to. Non-regular and non-symlink files will be ignored.
// If a target file with the given name already exists in "to", the file is left
// in the "from" directory.
async fn merge_dir_to(from: Dir, to: Dir) -> Result<u64> {
    let from_to = Arc::new((from, to));
    let mut tasks = tokio::task::JoinSet::new();
    let mut merged = 0u64;
    for ent in from_to.0.entries()? {
        let ent = ent?;
        let ftype = ent.file_type()?;
        if !(ftype.is_file() || ftype.is_symlink()) {
            continue;
        }
        merged += 1;
        let name = ent.file_name();
        let from_to = Arc::clone(&from_to);
        tasks.spawn_blocking(move || -> Result<()> {
            let from = &from_to.0;
            let to = &from_to.1;
            if ftype.is_file() {
                let f = from.open(&name)?;
                f.sync_all().context("fsync")?;
            }
            ignore_eexist(rustix::fs::renameat(from, &name, &to, &name).map_err(|e| e.into()))?;
            Ok(())
        });
    }
    while let Some(r) = tasks.join_next().await {
        r.context("join")?.context("Renaming into global")?;
    }
    Ok(merged)
}

/// An opaque object representing an active transaction on the repository.
#[derive(Debug)]
pub struct RepoTransaction {
    parent: Arc<RepoInner>,
    // Our temporary directory
    workdir: TempDir,
    // A transaction is really just a temporary repository, that gets
    // merged into our parent on commit
    repo: Repo,
    stats: Mutex<TransactionStats>,
}

impl RepoTransaction {
    const TMPROOT: &'static str = "tmp/root";

    fn new(repo: &Repo) -> Result<Self> {
        let parent = Arc::clone(&repo.0);
        let global_tmp = &repo.0.dir.open_dir(TMP).context(TMP)?;
        let workdir = {
            let d = TempDir::new_in(global_tmp)?;
            fileutils::fsetxattr(
                d.as_fd(),
                BOOTID_XATTR,
                repo.0.bootid.as_bytes(),
                rustix::fs::XattrFlags::empty(),
            )
            .context("setting bootid xattr")?;
            d
        };
        let reuse_object_dirs = Arc::clone(&repo.0.reuse_object_dirs);
        let temp_repo = Repo::init_full(&workdir, repo.has_verity(), reuse_object_dirs)?;
        workdir.create_dir(Self::TMPROOT).context(Self::TMPROOT)?;
        let r = RepoTransaction {
            parent,
            workdir,
            repo: temp_repo,
            stats: Default::default(),
        };
        Ok(r)
    }

    #[context("Creating new object")]
    fn new_object(&self) -> Result<TempFile> {
        TempFile::new(&self.repo.0.objects).map_err(Into::into)
    }

    fn new_descriptor_with_bytes(&self, buf: &[u8]) -> Result<DescriptorWriter> {
        let mut desc = DescriptorWriter::new(self.new_object()?)?;
        desc.write_all(buf)?;
        Ok(desc)
    }

    fn import_object_from_fn<F>(&self, f: F) -> Result<ObjectDigest>
    where
        F: FnOnce(&mut cap_std::fs::File) -> Result<()>,
    {
        let mut tmpf = self.new_object()?;
        f(tmpf.as_file_mut())?;
        self.import_object(tmpf)
    }

    fn import_tar(&self, src: File) -> Result<()> {
        let src = std::io::BufReader::new(src);
        let mut archive = tar::Archive::new(src);

        let layer_root = fileutils::openat_rooted(self.workdir.as_fd(), Self::TMPROOT)
            .context("Opening sandboxed layer dir")?;

        for entry in archive.entries()? {
            let entry = entry?;

            let etype = entry.header().entry_type();
            let path = entry.header().path()?;
            if let Some(parent) = fileutils::parent_nonempty(&path) {
                fileutils::ensure_dir_recursive(layer_root.as_fd(), parent, true)
                    .with_context(|| format!("Creating parents for {path:?}"))?;
            };

            match etype {
                tar::EntryType::Regular => {
                    // Copy as we need to refer to it after processing the entry
                    let path = path.into_owned();
                    self.unpack_regfile(entry, layer_root.as_fd(), &path)?;
                }
                tar::EntryType::Link => {
                    let target = entry
                        .link_name()
                        .context("linkname")?
                        .ok_or_else(|| anyhow::anyhow!("Missing hardlink target"))?;
                    rustix::fs::linkat(
                        layer_root.as_fd(),
                        &*path,
                        layer_root.as_fd(),
                        &*target,
                        AtFlags::empty(),
                    )
                    .with_context(|| format!("hardlinking {path:?} to {target:?}"))?;
                    let mut stats = self.stats.lock().unwrap();
                    stats.meta_count += 1;
                }
                tar::EntryType::Symlink => {
                    let target = entry
                        .link_name()
                        .context("linkname")?
                        .ok_or_else(|| anyhow::anyhow!("Missing hardlink target"))?;
                    rustix::fs::symlinkat(&*target, layer_root.as_fd(), &*path)
                        .with_context(|| format!("symlinking {path:?} to {target:?}"))?;
                    let mut stats = self.stats.lock().unwrap();
                    stats.meta_count += 1;
                }
                tar::EntryType::Char | tar::EntryType::Block => {
                    todo!()
                }
                tar::EntryType::Directory => {
                    fileutils::ensure_dir(layer_root.as_fd(), &path)?;
                }
                tar::EntryType::Fifo => todo!(),
                o => anyhow::bail!("Unhandled entry type: {o:?}"),
            }
        }
        Ok(())
    }

    #[context("Committing objects")]
    // Given two "split checksum" directories, rename all files from -> to
    async fn commit_objects(from: &Dir, to: &Dir) -> Result<()> {
        let mut merged = 0u64;
        for d in from.entries()? {
            let d = d?;
            if !d.file_type()?.is_dir() {
                continue;
            }
            let name = d.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let from = from.open_dir(&name).context("tmp objects")?;
            let to = to.open_dir(&name).context("global objects")?;
            merged += merge_dir_to(from, to).await?;
        }
        tracing::debug!("Merged: {merged}");
        Ok(())
    }

    #[context("Importing object")]
    fn import_object(&self, mut tmpfile: TempFile) -> Result<ObjectDigest> {
        // Rewind to ensure we read from the start
        tmpfile.as_file_mut().seek(std::io::SeekFrom::Start(0))?;
        // Gather state
        let size = tmpfile.as_file().metadata()?.size();
        let my_objects = &self.repo.0.objects;
        // Compute its composefs digest.  This can be an expensive operation,
        // so in the future it'd be nice to do this is a helper thread.  However
        // doing so would significantly complicate the flow.
        if self.repo.has_verity() {
            fileutils::reopen_tmpfile_ro(&mut tmpfile).context("Reopening tmpfile")?;
            composefs::fsverity::fsverity_enable(tmpfile.as_file().as_fd())
                .context("Failed to enable fsverity")?;
        };
        let digest = fsverity_hexdigest_from_fd(tmpfile.as_file().as_fd())
            .context("Computing fsverity digest")?;
        let mut buf = digest.clone();
        buf.insert(2, '/');
        let buf = Utf8PathBuf::from(buf);
        let objpath = buf.as_std_path();
        let exists_globally = self.parent.objects.try_exists(&buf)?;
        let exists_locally = !exists_globally && my_objects.try_exists(&buf)?;
        if !(exists_globally || exists_locally) {
            let reuse_dirs = self.repo.0.reuse_object_dirs.lock().unwrap();
            for d in reuse_dirs.iter() {
                if linkat_optional_allow_exists(d, &buf, &my_objects, &buf)? {
                    let mut stats = self.stats.lock().unwrap();
                    stats.external_objects_count += 1;
                    stats.external_objects_size += size;
                    return Ok(digest);
                }
            }
        };
        if exists_globally {
            let mut stats = self.stats.lock().unwrap();
            stats.extant_objects_count += 1;
            stats.extant_objects_size += size;
            ignore_eexist(
                rustix::fs::linkat(
                    &self.parent.objects.as_fd(),
                    objpath,
                    &my_objects,
                    objpath,
                    AtFlags::empty(),
                )
                .map_err(|e| e.into()),
            )
            .with_context(|| format!("Linking extant object {buf}"))?;
        } else if !exists_locally {
            ignore_eexist(tmpfile.replace(&buf)).context("tmpfile replace")?;
            let mut stats = self.stats.lock().unwrap();
            stats.imported_objects_count += 1;
            stats.imported_objects_size += size;
        }
        let mut buf = buf.into_string();
        buf.remove(2);
        Ok(buf)
    }

    /// Import an object which also has a known descriptor, and if
    /// it does not have a native composefs digest as an annotation,
    /// then include a symlink mapping the content-sha256 digest
    /// to the fsverity object.
    /// The descriptor will be validated (size and content-sha256).
    fn import_descriptor(
        &self,
        tmpf: DescriptorWriter,
        descriptor: &Descriptor,
    ) -> Result<ObjectDigest> {
        let expected_sha256 = sha256_of_descriptor(descriptor)?;
        let expected_fsverity = fsverity_of_descriptor(descriptor)?;
        let tmpf = tmpf.finish_validate(&descriptor)?;
        // Attach the descriptor digest as an xattr so it
        // can be efficiently looked up.
        {
            let full_digest = descriptor.digest().to_string();
            let xattr_key = self.repo.prefix_xattr(XATTR_DESCRIPTOR_DIGEST);
            rustix::fs::fsetxattr(
                tmpf.as_file().as_fd(),
                xattr_key,
                full_digest.as_bytes(),
                rustix::fs::XattrFlags::empty(),
            )?;
        }
        let objid = self.import_object(tmpf)?;
        if let Some(expected_fsverity) = expected_fsverity {
            compare_digests(expected_fsverity.digest(), &objid)?;
            // No need to make the by-sha256 link
            return Ok(objid);
        }
        let descriptor_path =
            object_digest_to_path_prefixed(expected_sha256.to_string(), OBJECTS_BY_SHA256);
        let target_path = object_digest_to_path_prefixed(objid.clone(), BY_SHA256_UPLINK);
        ignore_eexist(
            rustix::fs::symlinkat(
                target_path.as_std_path(),
                &self.repo.0.dir,
                descriptor_path.as_std_path(),
            )
            .map_err(|e| e.into()),
        )?;
        Ok(objid)
    }

    /// Import bytes which also has a known descriptor. The descriptor will be validated (size and content-sha256).
    /// A mapping by-sha256 symlink is not added.
    fn import_descriptor_from_bytes(
        &self,
        descriptor: &Descriptor,
        buf: &[u8],
    ) -> Result<ObjectDigest> {
        let tmpf = self.new_descriptor_with_bytes(buf)?;
        self.import_descriptor(tmpf, descriptor)
    }

    #[context("Unpacking regfile")]
    fn unpack_regfile<E: std::io::Read>(
        &self,
        mut entry: tar::Entry<E>,
        layer_root: BorrowedFd,
        path: &Path,
    ) -> Result<()> {
        // First, spool the file content to a temporary file
        let mut tmpfile = self.new_object()?;
        let wrote_size = std::io::copy(&mut entry, &mut tmpfile)?;
        tmpfile.seek(std::io::SeekFrom::Start(0))?;

        // Load metadata
        let header = entry.header();
        let size = header.size().context("header size")?;
        // This should always be true, but just in case
        anyhow::ensure!(size == wrote_size);

        let objid = self.import_object(tmpfile)?;
        self.link_object_at(&objid, layer_root, path)
    }

    /// Create a hardlink from an object to the target path, which must
    /// be a subdirectory of the repo.
    fn link_object_at(
        &self,
        objid: &str,
        destdir: impl AsFd,
        destname: impl AsRef<Path>,
    ) -> Result<()> {
        let objpath = object_digest_to_path(objid.into());
        rustix::fs::linkat(
            &self.repo.0.objects,
            objpath.as_std_path(),
            destdir,
            destname.as_ref(),
            AtFlags::empty(),
        )?;
        Ok(())
    }

    // Commit this transaction, returning statistics
    #[context("Committing")]
    async fn commit(self) -> Result<TransactionStats> {
        // First, handle the objects
        Self::commit_objects(&self.repo.0.objects, &self.parent.objects).await?;
        // Then all the derived data and links
        let from_basedir = &self.repo.0.dir;
        let to_basedir = &self.parent.dir;
        {
            let from_by_sha256 = from_basedir
                .open_dir(OBJECTS_BY_SHA256)
                .context(OBJECTS_BY_SHA256)?;
            let to_by_sha256 = to_basedir
                .open_dir(OBJECTS_BY_SHA256)
                .context(OBJECTS_BY_SHA256)?;
            Self::commit_objects(&from_by_sha256, &to_by_sha256).await?;
        }
        for name in [IMAGES, UNPACKED] {
            let from_tags = from_basedir
                .open_dir(&name)
                .with_context(|| format!("Opening {name}"))?;
            let to_tags = to_basedir
                .open_dir(&name)
                .with_context(|| format!("Opening {name}"))?;
            merge_dir_to(from_tags, to_tags)
                .await
                .with_context(|| format!("Committing {name}"))?;
        }
        // SAFETY: This just propagates panics, which is OK
        Ok(self.stats.into_inner().unwrap())
    }

    /// Abort this transaction; no changes will be made to the underlying repository.
    pub fn discard(self) -> Result<()> {
        self.workdir.close()?;
        Ok(())
    }
}

/// Metadata contained inside the composefs file.
/// Note that the manifest has a descriptor for the config.
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    /// The fsverity object ID for the composefs itself
    // pub objectid: String,
    /// The descriptor for the manifest.
    pub manifest_descriptor: Descriptor,
    /// The parsed manifest
    pub manifest: ImageManifest,
    /// The parsed config
    pub config: ImageConfiguration,
}

/// Repository corruption was detected
pub enum CorruptionEvent {
    /// A fsverity object was corrupted
    FsVerity(Box<str>),
    /// An unexpected error occurred
    InternalError(Box<str>),
}

#[derive(Debug)]
struct RepoInner {
    dir: Dir,
    bootid: &'static str,
    /// Whether or not we had CAP_SYS_ADMIN
    privileged: bool,
    objects: Dir,
    reuse_object_dirs: Arc<Mutex<Vec<Dir>>>,
    meta: RepoMetadata,
}

#[derive(Debug, Clone)]
pub struct Repo(Arc<RepoInner>);

impl Repo {
    #[context("Initializing repo")]
    pub fn init(dir: &Dir, require_verity: bool) -> Result<Self> {
        let reuse_object_dirs = Arc::new(Mutex::new(Vec::new()));
        Self::init_full(dir, require_verity, reuse_object_dirs)
    }

    fn init_full(
        dir: &Dir,
        require_verity: bool,
        reuse_object_dirs: SharedObjectDirs,
    ) -> Result<Self> {
        let supports_verity = test_fsverity_in(&dir)?;
        if require_verity && !supports_verity {
            anyhow::bail!("Requested fsverity, but target does not support it");
        }
        let dirbuilder = &fileutils::default_dirbuilder();
        let meta = RepoMetadata {
            version: String::from("0.5"),
            verity: supports_verity,
        };
        if !dir.try_exists(REPOMETA)? {
            dir.atomic_replace_with(REPOMETA, |w| {
                serde_json::to_writer(w, &meta).map_err(anyhow::Error::msg)
            })?;
        }
        for name in [IMAGES, UNPACKED] {
            dir.ensure_dir_with(name, dirbuilder).context(name)?;
        }
        // We maintain indicies by both fsverity and sha256
        for name in [OBJECTS, OBJECTS_BY_SHA256] {
            dir.ensure_dir_with(name, dirbuilder).context(name)?;
            let objects = dir.open_dir(name)?;
            init_object_dir(&objects)?;
        }

        dir.ensure_dir_with(TMP, dirbuilder)?;
        Self::impl_open(dir.try_clone()?, reuse_object_dirs)
    }

    fn impl_open(dir: Dir, reuse_object_dirs: SharedObjectDirs) -> Result<Self> {
        let bootid = get_bootid();
        let meta = serde_json::from_reader(
            dir.open(REPOMETA)
                .map(std::io::BufReader::new)
                .with_context(|| format!("Opening {REPOMETA}"))?,
        )?;
        let objects = dir.open_dir(OBJECTS).context(OBJECTS)?;
        let process_uid = rustix::process::getuid();
        let privileged =
            rustix::thread::capability_is_in_ambient_set(rustix::thread::Capability::SystemAdmin)?;
        let inner = Arc::new(RepoInner {
            dir,
            objects,
            bootid,
            privileged,
            meta,
            reuse_object_dirs,
        });
        Ok(Self(inner))
    }

    /// Open a repository
    #[context("Opening composefs-oci repo")]
    pub fn open(dir: Dir) -> Result<Self> {
        Self::impl_open(dir, Default::default())
    }

    /// Create a new transaction
    pub fn new_transaction(&self) -> Result<RepoTransaction> {
        RepoTransaction::new(&self)
    }

    /// Path to a directory with a composefs objects/ directory
    /// that will be used opportunistically as a source of objects.
    ///
    /// The directory must be on the same filesystem (so that hardlinks)
    /// are available.
    ///
    /// This need not specifically be a cfs-oci directory.
    pub fn add_external_objects_dir(&self, fd: Dir) -> Result<()> {
        let mut dirs = self.0.reuse_object_dirs.lock().unwrap();
        dirs.push(fd);
        Ok(())
    }

    /// Return true if fsverity was enabled and supported by the kernel
    /// and filesystem when this repository was created.
    pub fn has_verity(&self) -> bool {
        self.0.meta.verity
    }

    #[context("Reading object path of descriptor {digest}")]
    fn lookup_object_by_descriptor_digest(&self, digest: &str) -> Result<Option<ObjectDigest>> {
        let path = object_digest_to_path_prefixed(digest.to_string(), OBJECTS_BY_SHA256);
        let Some(buf) = map_rustix_optional(rustix::fs::readlinkat(
            &self.0.dir,
            path.as_std_path(),
            Vec::new(),
        ))?
        else {
            return Ok(None);
        };
        let objid = object_link_to_digest(buf.into_bytes())?;
        Ok(Some(objid))
    }

    #[context("Looking up descriptor")]
    fn lookup_descriptor(&self, descriptor: &Descriptor) -> Result<Option<ObjectDigest>> {
        self.lookup_object_by_descriptor_digest(sha256_of_descriptor(descriptor)?)
    }

    #[context("Looking up descriptor")]
    fn require_descriptor(&self, descriptor: &Descriptor) -> Result<ObjectDigest> {
        self.lookup_object_by_descriptor_digest(sha256_of_descriptor(descriptor)?)?
            .ok_or_else(|| {
                anyhow::anyhow!("Missing object for descriptor: {}", descriptor.digest())
            })
    }

    fn read_all_validate_sha256(
        mut f: impl Read,
        digest: &Sha256Digest,
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        f.read_to_end(buf)?;
        let mut h = Hasher::new(MessageDigest::sha256())?;
        h.update(&buf)?;
        let found_sha256 = hex::encode(h.finish()?);
        compare_digests(digest.digest(), &found_sha256)?;
        Ok(())
    }

    fn read_verity_object(&self, digest: &Sha256Digest) -> Result<Vec<u8>> {
        let path = object_digest_to_path(digest.digest().into());
        let f = self.0.objects.open(&path)?;
        let size = f.metadata()?.size();
        if size > (METADATA_MAX as u64) {
            anyhow::bail!("Descriptor size={size} exceeded max={METADATA_MAX}");
        }
        let found_digest = fsverity_hexdigest_from_fd(&f)?;
        compare_digests(digest.digest(), &found_digest)?;
        let mut buf = Vec::with_capacity(size as usize);
        Self::read_all_validate_sha256(f, digest, &mut buf)?;
        Ok(buf)
    }

    /// Read the complete content of a descriptor
    #[context("Reading descriptor {}", descriptor.digest())]
    fn read_descriptor_all(&self, descriptor: &Descriptor) -> Result<Vec<u8>> {
        // TODO also handle fsverity case
        let digest = sha256_of_descriptor(descriptor)?;
        let path = object_digest_to_path_prefixed(digest.to_string(), OBJECTS_BY_SHA256);
        let mut f = self.0.dir.open(&path)?;
        let meta = f.metadata()?;
        let expected_size = descriptor.size();
        let found_size = meta.size();
        if expected_size != meta.size() {
            anyhow::bail!("Expected size={expected_size} but found {found_size}");
        }
        if descriptor.size() > (METADATA_MAX as u64) {
            anyhow::bail!("Descriptor size={found_size} exceeded max={METADATA_MAX}");
        }
        let mut r = Vec::with_capacity(found_size as usize);

        Ok(r)
    }

    pub(crate) fn prefix_xattr(&self, key: &str) -> String {
        if self.0.privileged {
            format!("{XATTR_PREFIX_TRUSTED}{key}")
        } else {
            format!("{XATTR_PREFIX_USER}{key}")
        }
    }

    fn parse_digest_xattr(f: &File, xattr: &str) -> Result<Sha256Digest> {
        let digest = fileutils::fgetxattr(&f, xattr, rustix::fs::XattrFlags::empty())?;
        let digest = String::from_utf8(digest)?;
        Sha256Digest::from_str(&digest).map_err(Into::into)
    }

    fn image_metadata_from_path(&self, path: &Utf8Path) -> Result<Option<Metadata>> {
        let Some(f) = self.0.dir.open_optional(&path)? else {
            return Ok(None);
        };
        let mut f = f.into_std();
        let manifest_meta = f.metadata()?;
        let cfs_manifest: ImageManifest = serde_json::from_reader(BufReader::new(&mut f))?;

        let config_descriptor = cfs_manifest.config();
        // TODO read descriptor via fsverity instead
        let is_native = fsverity_of_descriptor(config_descriptor)?.is_some();

        let (manifest, manifest_digest) = if !is_native {
            let xattr_key = self.prefix_xattr(XATTR_MANIFEST_ORIG);
            let orig_digest = Self::parse_digest_xattr(&f, &xattr_key)?;
            let manifest = self.read_verity_object(&orig_digest)?;
            let manifest = serde_json::from_slice(&manifest)?;
            (manifest, orig_digest)
        } else {
            let xattr_key = self.prefix_xattr(XATTR_DESCRIPTOR_DIGEST);
            let digest = Self::parse_digest_xattr(&f, &xattr_key)?;
            (cfs_manifest, digest)
        };

        let config = self.read_descriptor_all(manifest.config())?;
        let config = serde_json::from_slice(&config)?;

        let size = manifest_meta.size();
        let manifest_descriptor = Descriptor::new(MediaType::ImageManifest, size, manifest_digest);

        let r = Metadata {
            manifest: manifest,
            config,
            manifest_descriptor,
        };
        Ok(Some(r))
    }

    pub fn image_metadata_via_digest(
        &self,
        manifest_digest: &Sha256Digest,
    ) -> Result<Option<Metadata>> {
        let path = object_digest_to_path_prefixed(manifest_digest.digest().into(), "{IMAGES}/");
        self.image_metadata_from_path(&path)
    }

    #[context("Reading tag {tag}")]
    pub fn image_metadata_from_tag(&self, tag: &str) -> Result<Option<Metadata>> {
        let tagpath = tag_path(&tag);
        self.image_metadata_from_path(&tagpath)
    }

    #[context("Reading tag {tag}")]
    pub async fn require_image_metadata_from_tag(&self, tag: &str) -> Result<Metadata> {
        self.image_metadata_from_tag(tag)?
            .ok_or_else(|| anyhow::anyhow!("No such tag {tag}"))
    }

    #[context("Importing layer")]
    pub async fn import_layer(
        &self,
        txn: RepoTransaction,
        src: File,
        diffid: &Sha256Digest,
    ) -> Result<RepoTransaction> {
        let objid = diffid.digest().to_string();
        let layer_path = object_digest_to_path_prefixed(objid, &format!("{IMAGES}/{LAYERS}"));
        // If we've already fetched the layer, then assume the caller is forcing a re-import
        // to e.g. repair missing files.
        if self.0.dir.try_exists(&layer_path)? {
            self.0
                .dir
                .remove_dir_all(&layer_path)
                .context("removing extant layerdir")?;
        }
        // SAFETY: Panic if we can't join the thread
        tokio::task::spawn_blocking(move || {
            txn.import_tar(src)?;
            Ok(txn)
        })
        .await
        .unwrap()
    }

    /// Pull the target image, and add the provided tag. If this is a mountable
    /// image (i.e. not an artifact), it is *not* unpacked by default.
    pub async fn pull(
        &self,
        txn: RepoTransaction,
        proxy: &containers_image_proxy::ImageProxy,
        imgref: &str,
    ) -> Result<(RepoTransaction, Descriptor)> {
        // if let Some(meta) = self.read_artifact_metadata(imgref).await? {
        //     return Ok((txn, meta.manifest_descriptor));
        // }

        let img = proxy.open_image(&imgref).await.context("Opening image")?;
        let (manifest_digest, raw_manifest) = proxy
            .fetch_manifest_raw_oci(&img)
            .await
            .context("Fetching manifest")?;
        let manifest_digest = DescriptorDigest::from_str(&manifest_digest)?;
        let manifest_digest_sha256 = sha256_of_digest(&manifest_digest)?.to_string();
        let manifest_descriptor = Descriptor::new(
            MediaType::ImageManifest,
            raw_manifest.len().try_into().unwrap(),
            manifest_digest,
        );
        let manifest_fsverity = {
            let tmpf = txn.new_descriptor_with_bytes(&raw_manifest)?;
            txn.import_descriptor(tmpf, &manifest_descriptor)
                .context("Importing manifest")?
        };

        let manifest = ImageManifest::from_reader(io::Cursor::new(&raw_manifest))?;
        let mut augmented_manifest = manifest.clone();

        let txn = Arc::new(txn);
        let config_descriptor = manifest.config();
        // Import the config
        let (mut config, driver) = proxy.get_descriptor(&img, config_descriptor).await?;
        let config = async move {
            let mut s = Vec::new();
            config.read_to_end(&mut s).await?;
            anyhow::Ok(s)
        };
        let (config, driver) = tokio::join!(config, driver);
        let _: () = driver?;
        let config = config?;
        let config_fsverity = txn
            .import_descriptor_from_bytes(&config_descriptor, &config)
            .context("Importing config")?;

        let mut layers_by_digest = HashMap::new();
        let (mut existing_layers, to_fetch_layers) = manifest.layers().iter().try_fold(
            (HashMap::new(), HashSet::new()),
            |(mut existing, mut to_fetch), layer| -> Result<_> {
                let layer_sha256 = sha256_of_descriptor(layer)?;
                layers_by_digest.insert(layer_sha256, layer);
                if let Some(objid) = self.lookup_descriptor(layer)? {
                    existing.insert(layer_sha256, objid);
                } else {
                    to_fetch.insert(layer_sha256);
                }
                Ok((existing, to_fetch))
            },
        )?;

        tracing::debug!("Layers to fetch: {}", to_fetch_layers.len());
        for layer_digest in to_fetch_layers.iter() {
            // SAFETY: Must exist
            let layer = *layers_by_digest.get(layer_digest).unwrap();
            // Must have been validated earlier
            let layer_sha256 = sha256_of_descriptor(layer).unwrap();
            let (blob_reader, driver) = proxy.get_descriptor(&img, &layer).await?;
            let mut sync_blob_reader = tokio_util::io::SyncIoBridge::new(blob_reader);
            // Clone to move into worker thread
            let layer_copy = layer.clone();
            let txn2 = Arc::clone(&txn);
            let import_task = tokio::task::spawn_blocking(move || -> Result<_> {
                let mut tmpf = DescriptorWriter::new(txn2.new_object()?)?;
                let _n: u64 = std::io::copy(&mut sync_blob_reader, &mut tmpf)?;
                let objid = txn2.import_descriptor(tmpf, &layer_copy)?;
                Ok(objid)
            });
            let (import_task, driver) = tokio::join!(import_task, driver);
            let _: () = driver?;
            let objid = import_task.unwrap()?;
            existing_layers.insert(layer_sha256, objid);
        }
        tracing::debug!("Imported all layers");

        for (i, layer) in manifest.layers().iter().enumerate() {
            let digest = sha256_of_descriptor(layer)?;
            let objid = existing_layers.get(digest).unwrap();
            let augmented_layer = augmented_manifest.layers_mut().get_mut(i).unwrap();
            let mut annos = augmented_layer.annotations().clone().unwrap_or_default();
            annos.insert(ANNOTATION_LAYER_VERITY.to_string(), objid.clone());
            augmented_layer.set_annotations(Some(annos));
        }

        let augmented_manifest_objid = txn.import_object_from_fn(move |f| -> Result<()> {
            let xattr_key = self.prefix_xattr(XATTR_MANIFEST_ORIG);
            rustix::fs::fsetxattr(
                f.as_fd(),
                &xattr_key,
                manifest_fsverity.as_bytes(),
                rustix::fs::XattrFlags::empty(),
            )?;
            serde_json::to_writer(f, &manifest)?;
            Ok(())
        })?;
        let path = tag_path(&imgref);
        txn.link_object_at(&augmented_manifest_objid, &self.0.dir, &path)?;

        // SAFETY: We joined all the threads
        let txn = Arc::into_inner(txn).unwrap();
        Ok((txn, manifest_descriptor))
    }

    pub async fn list_tags(&self, starting_with: Option<&str>) -> Result<Vec<String>> {
        let repo = Arc::clone(&self.0);
        let starting_with = starting_with.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || -> Result<_> {
            let mut r = Vec::new();
            for e in repo.dir.read_dir(IMAGES)? {
                let e = e?;
                let name = e.file_name();
                let name =
                    percent_encoding::percent_decode(name.as_encoded_bytes()).decode_utf8()?;
                if let Some(starting_with) = starting_with.as_deref() {
                    if !name.starts_with(starting_with) {
                        continue;
                    }
                }
                r.push(name.into_owned());
            }
            anyhow::Ok(r)
        })
        .await
        .unwrap()
    }

    fn fsck_one_object(&self, objid: &str) -> Result<Option<CorruptionEvent>> {
        let path = object_digest_to_path(objid.to_string());
        let f = self.0.objects.open(&path)?;
        let found_digest = fsverity_hexdigest_from_fd(f)?;
        let r = if found_digest != objid {
            Some(CorruptionEvent::FsVerity(objid.into()))
        } else {
            None
        };
        Ok(r)
    }

    /// Verify integrity of all objects; a callback is invoked for each corrupted object
    /// or when an unexpected other error is encountered.
    ///
    /// The total count of all verified objects is returned.
    pub async fn fsck<F>(&self, mut f: F) -> Result<u64>
    where
        F: FnMut(CorruptionEvent) -> ControlFlow<()>,
    {
        let mut n_verified = 0u64;
        let tags = self.list_tags(None).await?;
        for tag in tags {
            let metadata = self.require_image_metadata_from_tag(&tag).await?;
            for desc in metadata.manifest.layers() {
                let expected_digest = self.require_descriptor(desc)?;
                if let Some(event) = self.fsck_one_object(&expected_digest)? {
                    match f(event) {
                        ControlFlow::Continue(()) => {}
                        ControlFlow::Break(()) => {
                            return Ok(n_verified);
                        }
                    }
                } else {
                    n_verified += 1;
                }
            }
        }
        Ok(n_verified)
    }

    /// Verify integrity of all objects. The total count of all verified
    /// objects is returned.
    pub async fn fsck_simple(&self) -> Result<u64> {
        let mut n_corrupted = 0u64;
        let mut err = None;
        let r = self
            .fsck(|event| {
                match event {
                    CorruptionEvent::FsVerity(_) => {
                        n_corrupted += 1;
                    }
                    CorruptionEvent::InternalError(msg) => {
                        err = Some(msg);
                        return ControlFlow::Break(());
                    }
                }
                ControlFlow::Continue(())
            })
            .await?;
        match (err, n_corrupted) {
            (Some(e), 0) => {
                anyhow::bail!("{e}");
            }
            (Some(e), n) => {
                anyhow::bail!("corrupted objects: {n}, and encountered error: {e}");
            }
            (None, 0) => Ok(r),
            (None, n) => {
                anyhow::bail!("corruption detected");
            }
        }
    }

    /// Ensure that a downloaded OCI image is "expanded" (unpacked)
    /// into the composefs-native store.
    pub async fn expand(&self, _manifest_desc: &Descriptor) -> Result<TransactionStats> {
        todo!()
        // let repo = self.clone();
        // let manifest_desc = manifest_desc.clone();
        // // Read and parse the manifest in a helper thread, also retaining its fd
        // let (manifest_fd, manifest) = tokio::task::spawn_blocking(move || -> Result<_> {
        //     let mut bufr = repo
        //         .as_oci()
        //         .read_blob(&manifest_desc)
        //         .map(BufReader::new)?;
        //     let parsed = serde_json::from_reader::<_, ImageManifest>(&mut bufr)?;
        //     let mut f = bufr.into_inner();
        //     f.seek(std::io::SeekFrom::Start(0))?;
        //     Ok((f, parsed))
        // })
        // .await
        // .unwrap()
        // .context("Reading manifest")?;
        // // Read and parse the config in a helper thread
        // let repo = self.clone();
        // let config = manifest.config().clone();
        // let config: ImageConfiguration = tokio::task::spawn_blocking(move || -> Result<_> {
        //     repo.as_oci().read_json_blob(&config)
        // })
        // .await
        // .unwrap()?;

        // // Walk the diffids, and find the ones we don't already have
        // let needed_diffs = manifest.layers().iter().enumerate().try_fold(
        //     Vec::new(),
        //     |mut acc, (i, layer)| -> Result<_> {
        //         let diffid = config
        //             .rootfs()
        //             .diff_ids()
        //             .get(i)
        //             .ok_or_else(|| anyhow::anyhow!("Missing diffid {i}"))?;
        //         let diffid = DigestSha256::parse(&diffid)?;
        //         if !self.has_layer(diffid.sha256())? {
        //             acc.push((layer, diffid));
        //         }
        //         Ok(acc)
        //     },
        // )?;

        // let mut stats = ImportLayerStats::default();
        // for (layer, diffid) in needed_diffs {
        //     let blobsrc = self.as_oci().read_blob(layer)?;
        //     stats = stats + self.import_layer(blobsrc, diffid.sha256()).await?;
        // }

        // if let Some(expected_digest) = manifest
        //     .annotations()
        //     .as_ref()
        //     .and_then(|a| a.get(CFS_DIGEST_ANNOTATION))
        // {
        //     // Handle verified manifests later
        //     todo!()
        // } else {
        // }

        // Ok(stats)
    }

    // Commit this transaction, returning statistics
    pub async fn commit(&self, txn: RepoTransaction) -> Result<TransactionStats> {
        txn.commit().await
    }
}

#[derive(Debug, Default)]
pub struct TransactionStats {
    /// Existing regular file count
    extant_objects_count: usize,
    /// Existing regular file size
    extant_objects_size: u64,

    /// Objects imported from external
    external_objects_count: usize,
    /// Objects imported from external
    external_objects_size: u64,

    /// Imported regular file count
    imported_objects_count: usize,
    /// Imported regular file size
    imported_objects_size: u64,

    /// Imported metadata
    meta_count: u64,
}

impl Add for TransactionStats {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            extant_objects_count: self.extant_objects_count + rhs.extant_objects_count,
            extant_objects_size: self.extant_objects_size + rhs.extant_objects_size,
            external_objects_count: self.external_objects_count + rhs.external_objects_count,
            external_objects_size: self.external_objects_size + rhs.external_objects_size,
            imported_objects_count: self.imported_objects_count + rhs.imported_objects_count,
            imported_objects_size: self.imported_objects_size + rhs.imported_objects_size,
            meta_count: self.meta_count + rhs.meta_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;
    use std::process::Command;

    use ocidir::oci_spec::image::{ImageConfigurationBuilder, Platform};

    use super::*;

    const EMPTY_DIFFID: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn test_object_link_to_digest() {
        let failing = &["", "foo", "../../blah"];
        for case in failing {
            assert!(object_link_to_digest(case.as_bytes().into()).is_err());
        }
        assert_eq!(
            object_link_to_digest(
                b"../../e3/b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()
            )
            .unwrap(),
            EMPTY_DIFFID
        );
    }

    fn new_memfd(buf: &[u8]) -> Result<File> {
        use rustix::fs::MemfdFlags;
        let f: File = rustix::fs::memfd_create("test memfd", MemfdFlags::CLOEXEC)?.into();
        let mut bufw = std::io::BufWriter::new(f);
        std::io::copy(&mut std::io::Cursor::new(buf), &mut bufw)?;
        bufw.into_inner().map_err(Into::into)
    }

    #[tokio::test]
    async fn test_import_layer() -> Result<()> {
        let td = TempDir::new(cap_std::ambient_authority())?;
        let td = &*td;

        td.create_dir("repo")?;
        let repo = Repo::init(&td.open_dir("repo")?, false).unwrap();
        eprintln!("verity={}", repo.has_verity());

        // A no-op import
        let txn = repo.new_transaction()?;
        let txn = repo
            .import_layer(
                txn,
                new_memfd(b"")?,
                &Sha256Digest::from_str(EMPTY_DIFFID).unwrap(),
            )
            .await
            .unwrap();
        let r = txn.commit().await.unwrap();
        assert_eq!(r.extant_objects_count, 0);
        assert_eq!(r.imported_objects_count, 0);
        assert_eq!(r.imported_objects_size, 0);

        // Serialize our own source code
        let testtar = td.create("test.tar").map(BufWriter::new)?;
        let mut testtar = tar::Builder::new(testtar);
        testtar.follow_symlinks(false);
        testtar
            .append_dir_all("./", "src")
            .context("creating tar")
            .unwrap();
        drop(testtar.into_inner()?.into_inner()?);
        let digest_o = Command::new("sha256sum")
            .stdin(td.open("test.tar")?)
            .stdout(std::process::Stdio::piped())
            .output()?;
        assert!(digest_o.status.success());
        let digest = String::from_utf8(digest_o.stdout).unwrap();
        let digest = digest.split_ascii_whitespace().next().unwrap().trim();
        let digest = Sha256Digest::from_str(digest).unwrap();
        let testtar = td.open("test.tar")?;

        let txn = repo.new_transaction()?;
        let txn = repo
            .import_layer(txn, testtar.into_std(), &digest)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn test_import_ocidir() -> Result<()> {
        let td_abs = tempfile::tempdir()?;
        let td_path = <&Utf8Path>::try_from(td_abs.path())?;
        let td = &Dir::open_ambient_dir(td_abs.path(), cap_std::ambient_authority())?;

        td.create_dir("oci")?;
        let ocipath = &td_path.join("oci");
        let ocidir = ocidir::OciDir::ensure(&td.open_dir("oci")?)?;

        // A dummy layer
        let mut blobw = ocidir.create_gzip_layer(Default::default())?;
        blobw.write_all(b"pretend this is a tarball")?;
        let blob = blobw.complete()?;
        let blobsize = blob.blob.size;
        let mut manifest = ocidir::new_empty_manifest().build().unwrap();
        let mut config = ImageConfigurationBuilder::default().build().unwrap();
        ocidir.push_layer(
            &mut manifest,
            &mut config,
            blob,
            "empty blob",
            Default::default(),
        );

        let orig_desc = ocidir.insert_manifest_and_config(
            manifest,
            config,
            Some("latest"),
            Platform::default(),
        )?;
        ocidir.fsck()?;
        let imgref = &format!("oci:{ocipath}:latest");

        td.create_dir("repo")?;
        let repo = Repo::init(&td.open_dir("repo")?, false).unwrap();
        let proxy = containers_image_proxy::ImageProxy::new().await?;

        let txn = repo.new_transaction()?;
        let (txn, desc) = repo.pull(txn, &proxy, &imgref).await.unwrap();
        assert_eq!(orig_desc.digest(), desc.digest());
        assert_eq!(orig_desc.size(), desc.size());
        let r = txn.commit().await.unwrap();
        assert_eq!(r.extant_objects_count, 0);
        assert_eq!(r.imported_objects_count, 4);
        // Can't strictly assert on size as it depends on compression
        assert_eq!(r.imported_objects_size, 16951 + blobsize);

        let tags = repo.list_tags(None).await?;
        assert_eq!(tags.len(), 1);
        similar_asserts::assert_eq!(tags[0].as_str(), imgref);

        let found_desc = repo.image_metadata_from_tag(&imgref).unwrap().unwrap();
        assert_eq!(&found_desc.manifest_descriptor, &desc);

        // TODO fix fsck to also verify metadata
        let n = repo.fsck_simple().await?;
        assert_eq!(n, 1);

        Ok(())
    }
}
