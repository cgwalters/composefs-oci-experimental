use std::collections::hash_map::VacantEntry;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Seek, Write};
use std::ops::Add;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std_ext::cap_tempfile::{TempDir, TempFile};
use cap_std_ext::cmdext::CapStdExtCommandExt;
use cap_std_ext::dirext::CapStdExtDirExt;
use cap_std_ext::{cap_std, cap_tempfile};
use composefs::dumpfile::{Entry, Item, Mtime};
use composefs::fsverity::Digest;
use fn_error_context::context;
use ocidir::cap_std::fs::MetadataExt;
use ocidir::oci_spec::image::{Descriptor, MediaType};
use openssl::hash::{Hasher, MessageDigest};
use rustix::fd::BorrowedFd;
use rustix::fs::AtFlags;
use serde::{Deserialize, Serialize};

use crate::fileutils::{self, default_dirbuilder};
use crate::sha256descriptor::{DescriptorExt, Sha256Hex};

/// Standardized metadata
const REPOMETA: &str = "meta.json";
/// A composefs/ostree style object directory
const OBJECTS: &str = "objects";
/// A split-checksum hardlink set into OBJECTS
const OBJECTS_BY_SHA256: &str = "objects/by-sha256";
/// OCI container images, stored in a ready-to-run format
const IMAGES: &str = "images";
/// A subdirectory of images/ or artifacts/, hardlink farm
const TAGS: &str = "tags";
/// /descriptor/<url encoded MIME type>/<object id>
const DESCRIPTOR: &str = "descriptor";
/// A subdirectory of images/
const LAYERS: &str = "layers";
/// Generic OCI artifacts (may be container images, or may not be)
/// /artifacts
///   /tags/<urlencoded>
///   /descriptor/<sha256>
const ARTIFACTS: &str = "artifacts";
const TMP: &str = "tmp";
const BOOTID_XATTR: &str = "user.cfs-oci.bootid";
const BY_SHA256_UPLINK: &'static str = "../../";
const DESCRIPTOR_UPLINK: &'static str = "../../objects/";
const TAG_UPLINK: &'static str = "../../objects/";

/// Can be included in a manifest if the digest is pre-computed
const CFS_DIGEST_ANNOTATION: &str = "composefs.rootfs.digest";

type SharedObjectDirs = Arc<Mutex<Vec<Dir>>>;
type ObjectDigest = String;
type DescriptorDigest = String;
type ObjectPath = Utf8PathBuf;

fn object_digest_to_path(mut objid: ObjectDigest) -> ObjectPath {
    object_digest_to_path_prefixed(objid, "")
}

fn object_digest_to_path_prefixed(mut objid: ObjectDigest, prefix: &str) -> ObjectPath {
    // Ensure we are only passed an object id
    assert_eq!(objid.len(), 64);
    objid.insert(2, '/');
    objid.insert_str(0, prefix);
    objid.into()
}

#[context("Parsing object link")]
fn object_link_to_digest(buf: Vec<u8>) -> Result<ObjectDigest> {
    // It's an error if we find non-UTF8 content here
    let mut buf = String::from_utf8(buf)
        .map_err(|_| anyhow::anyhow!("Invalid UTF-8"))?;
    while buf.starts_with("../") {
        buf.replace_range(0..3, "");
    }
    // Trim the `/`
    buf.replace_range(2..3, "");
    let _ = Sha256Hex::new(buf.as_str());
    Ok(buf)
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

/// Given a sha256 checksum, return its path for an object directory.
/// This also verifies the validity of the checksum, disallowing unsafe
/// characters such as `/` in the value.
///
/// It's expected that the string does *not* have a trailing `/`; one
/// is inserted.
pub(crate) fn append_object_path(s: &mut String, checksum: &str) -> Result<()> {
    if checksum.len() != usize::from(crate::digestsha256::SHA256_HEXLEN) {
        anyhow::bail!("Invalid checksum (expected 64 characters): {checksum}");
    }
    s.push('/');
    for (i, c) in checksum.chars().enumerate() {
        if !c.is_ascii_alphanumeric() {
            anyhow::bail!("Invalid checksum (non-alphanumeric {c}): {checksum}");
        }
        if i == 2 {
            s.push('/');
        }
        s.push(c);
    }
    Ok(())
}

fn get_bootid() -> &'static str {
    static BOOTID: OnceLock<String> = OnceLock::new();
    let bootid =
        BOOTID.get_or_init(|| std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap());
    bootid.as_str()
}

fn create_entry(_h: tar::Header) -> Result<Entry<'static>> {
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

    todo!()
}

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

    fn finish(mut self, media_type: MediaType) -> Result<(Descriptor, TempFile<'a>)> {
        // SAFETY: Nothing else should have taken the target
        let tempfile = self.target.take().unwrap();
        let sha256 = hex::encode(self.sha256hasher.finish()?);
        let desc = Descriptor::new(
            media_type,
            self.size.try_into().unwrap(),
            format!("sha256:{sha256}"),
        );
        Ok((desc, tempfile))
    }

    fn finish_validate(mut self, descriptor: &Descriptor) -> Result<TempFile<'a>> {
        let descriptor_size: u64 = descriptor.size().try_into()?;
        if descriptor_size != self.size {
            anyhow::bail!(
                "Corrupted object, expected size {descriptor_size}, got size {}",
                self.size
            );
        }
        let found_sha256 = hex::encode(self.sha256hasher.finish()?);
        let expected_sha256 = &*descriptor.sha256()?;
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

fn linkat_optional_allow_exists(
    old_dirfd: &Dir,
    old_path: impl AsRef<Path>,
    new_dirfd: &Dir,
    new_path: impl AsRef<Path>,
) -> Result<bool> {
    match rustix::fs::linkat(
        old_dirfd.as_fd(),
        old_path.as_ref(),
        new_dirfd.as_fd(),
        new_path.as_ref(),
        AtFlags::empty(),
    ) {
        // We successfully linked
        Ok(()) => Ok(true),
        // We're idempotent; it's ok if the target already exists
        Err(e) if e == rustix::io::Errno::EXIST => Ok(true),
        // Not finding it is just a cache miss
        Err(e) if e == rustix::io::Errno::NOENT => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn ignore_rustix_eexist(r: rustix::io::Result<()>) -> Result<()> {
    match r {
        Ok(()) => Ok(()),
        Err(e) if e == rustix::io::Errno::EXIST => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn ignore_std_eexist(r: io::Result<()>) -> Result<()> {
    match r {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn linkat_allow_exists(
    old_dirfd: impl AsFd,
    old_path: impl AsRef<Path>,
    new_dirfd: impl AsFd,
    new_path: impl AsRef<Path>,
) -> Result<()> {
    ignore_rustix_eexist(rustix::fs::linkat(
        old_dirfd.as_fd(),
        old_path.as_ref(),
        new_dirfd.as_fd(),
        new_path.as_ref(),
        AtFlags::empty(),
    ))
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
            ignore_rustix_eexist(rustix::fs::renameat(from, &name, &to, &name))?;
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

    fn new_object(&self) -> Result<TempFile> {
        TempFile::new(&self.repo.0.objects).map_err(Into::into)
    }

    fn new_descriptor_with_bytes(&self, buf: &[u8]) -> Result<DescriptorWriter> {
        let mut desc = DescriptorWriter::new(self.new_object()?)?;
        desc.write_all(buf)?;
        Ok(desc)
    }

    fn import_tar(&self, src: File) -> Result<()> {
        let src = std::io::BufReader::new(src);
        let mut archive = tar::Archive::new(src);

        let layer_root = fileutils::openat_rooted(self.workdir.as_fd(), Self::TMPROOT)
            .context("Opening sandboxed layer dir")?;

        for entry in archive.entries()? {
            let entry = entry?;

            let etype = entry.header().entry_type();
            // Make a copy because it may refer into the header, but we need it
            // after we process the entry too.
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
        let mut digest = Digest::new();
        composefs::fsverity::fsverity_digest_from_fd(tmpfile.as_file().as_fd(), &mut digest)
            .context("Computing fsverity digest")?;
        let digest = hex::encode(digest.get());
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
            linkat_allow_exists(&self.parent.objects.as_fd(), objpath, &my_objects, objpath)
                .with_context(|| format!("Linking extant object {buf}"))?;
        } else {
            if !exists_locally {
                ignore_std_eexist(tmpfile.replace(&buf)).context("tmpfile replace")?;
                let mut stats = self.stats.lock().unwrap();
                stats.imported_objects_count += 1;
                stats.imported_objects_size += size;
            }
        }
        let mut buf = buf.into_string();
        buf.remove(2);
        Ok(buf)
    }

    /// Import an object which also has a known descriptor. The descriptor will be validated (size and content-sha256),
    /// and upon success a symlink will be added in objects/by-sha256 with the descriptor's content-sha256.
    fn import_descriptor(
        &self,
        tmpf: DescriptorWriter,
        descriptor: &Descriptor,
    ) -> Result<ObjectDigest> {
        let tmpf = tmpf.finish_validate(&descriptor)?;
        let objid = self.import_object(tmpf)?;
        let (parent, digest) = path_components_for_descriptor(descriptor)?;
        let basepath = format!("{ARTIFACTS}/{DESCRIPTOR}/{parent}");
        self.repo
            .0
            .dir
            .ensure_dir_with(&basepath, &default_dirbuilder())
            .with_context(|| format!("Creating descriptor dir {basepath}"))?;
        let objpath = object_digest_to_path_prefixed(objid, &DESCRIPTOR_UPLINK);
        let target_path = format!("{basepath}/{digest}");
        ignore_rustix_eexist(rustix::fs::symlinkat(
            objpath.as_std_path(),
            &self.repo.0.dir,
            &target_path,
        ))?;
        tracing::debug!("Added descriptor {target_path}",);
        Ok(objid)
    }

    fn add_artifact_tag(&self, descriptor: &Descriptor, name: &str) -> Result<()> {
        let quoted = percent_encoding::percent_encode(name.as_bytes(), percent_encoding::NON_ALPHANUMERIC);
        let (parent, digest) = path_components_for_descriptor(descriptor)?;
        let descriptor_path = format!("../");
        ignore_rustix_eexist(rustix::fs::symlinkat(
            objpath.as_std_path(),
            &self.repo.0.dir,
            tagpath.as_std_path(),
        ))
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
        let wrote_size = std::io::copy(&mut entry, &mut tmpfile)
            .with_context(|| format!("Copying tar entry {:?} to tmpfile", path))?;
        tmpfile.seek(std::io::SeekFrom::Start(0))?;

        // Load metadata
        let header = entry.header();
        let size = header.size().context("header size")?;
        // This should always be true, but just in case
        anyhow::ensure!(size == wrote_size);

        let objpath = object_digest_to_path(self.import_object(tmpfile)?);
        rustix::fs::linkat(
            &self.repo.0.objects,
            objpath.as_std_path(),
            layer_root,
            path,
            AtFlags::empty(),
        )?;
        Ok(())
    }

    // Commit this transaction, returning statistics
    async fn commit(self) -> Result<TransactionStats> {
        std::process::Command::new("find")
            .args(["-type", "f"])
            .cwd_dir(self.repo.0.dir.try_clone()?)
            .status()?;
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
        for name in [ARTIFACTS, IMAGES] {
            let tags_name = format!("{name}/{TAGS}");
            let from_tags = from_basedir
                .open_dir(&tags_name)
                .with_context(|| format!("Opening {tags_name}"))?;
            let to_tags = to_basedir
                .open_dir(&tags_name)
                .with_context(|| format!("Opening {tags_name}"))?;
            merge_dir_to(from_tags, to_tags)
                .await
                .context("Committing tags")?;
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

fn dir_cfs_entry(path: &Utf8Path) -> Entry<'_> {
    let item = Item::Directory { size: 0, nlink: 1 };
    Entry {
        path: path.into(),
        uid: 0,
        gid: 0,
        mode: libc::S_IFDIR | 0700,
        mtime: Mtime { sec: 0, nsec: 0 },
        item,
        xattrs: Default::default(),
    }
}

fn cfs_entry_for_descriptor(
    d: &Descriptor,
    fsverity_digest: &str,
    path: &Utf8Path,
) -> Result<Entry<'static>> {
    let size = d.size().try_into()?;
    let item = Item::Regular {
        size,
        nlink: 1,
        inline_content: None,
        fsverity_digest: Some(fsverity_digest.to_string()),
    };
    let path = std::path::PathBuf::from(path);
    let e = Entry {
        path: path.into(),
        uid: 0,
        gid: 0,
        mode: 0400,
        mtime: Mtime { sec: 0, nsec: 0 },
        item,
        xattrs: Default::default(),
    };
    Ok(e)
}

fn path_components_for_descriptor(descriptor: &Descriptor) -> Result<(String, Sha256Hex)> {
    // TODO https://github.com/containers/oci-spec-rs/pull/200
    let media_type = descriptor.media_type().to_string();
    let mtype =
        percent_encoding::percent_encode(media_type.as_bytes(), percent_encoding::NON_ALPHANUMERIC);
    let sha256 = descriptor.sha256()?;
    Ok((mtype.to_string(), sha256))
}

fn path_for_descriptor(descriptor: &Descriptor) -> Result<Utf8PathBuf> {
    let (parent, sha256) = path_components_for_descriptor(descriptor)?;
    Ok(format!("{parent}/{sha256}").into())
}

#[derive(Debug)]
struct RepoInner {
    dir: Dir,
    bootid: &'static str,
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
        // Images and artifacts
        for name in [ARTIFACTS, IMAGES] {
            dir.ensure_dir_with(name, dirbuilder).context(name)?;
            dir.ensure_dir_with(format!("{name}/{TAGS}"), dirbuilder)
                .context(TAGS)?;
            dir.ensure_dir_with(format!("{name}/{DESCRIPTOR}"), dirbuilder)
                .context(DESCRIPTOR)?;
        }
        // A special subdir for images/
        dir.ensure_dir_with(format!("{IMAGES}/{LAYERS}"), dirbuilder)
            .context("Creating layers dir")?;
        // The overall object dir, and its child by-sha256
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
        let inner = Arc::new(RepoInner {
            dir,
            objects,
            bootid,
            meta,
            reuse_object_dirs,
        });
        Ok(Self(inner))
    }

    #[context("Opening composefs-oci repo")]
    pub fn open(dir: Dir) -> Result<Self> {
        Self::impl_open(dir, Default::default())
    }

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

    pub fn has_verity(&self) -> bool {
        self.0.meta.verity
    }

    #[context("Reading object path of descriptor {digest}")]
    fn descriptor_digest_to_objid(&self, digest: Sha256Hex) -> Result<Option<ObjectDigest>> {
        let mut by_sha256_path = String::from(OBJECTS_BY_SHA256);
        append_object_path(&mut by_sha256_path, &digest)?;
        let buf = match rustix::fs::readlinkat(&self.0.dir, &by_sha256_path, Vec::new()) {
            Ok(r) => r,
            Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut buf = buf.into_string()?;
        if !(buf.chars().all(|c| c.is_ascii())
            && buf.starts_with(BY_SHA256_UPLINK)
            && buf.bytes().nth(2) == Some(b'/'))
        {
            anyhow::bail!("Invalid descriptor symlink: {buf}");
        }
        buf.replace_range(0..BY_SHA256_UPLINK.len(), "");
        buf.remove(2);
        // Verify
        let _ = Sha256Hex::new(&buf);
        Ok(Some(buf))
    }

    fn lookup_descriptor(&self, descriptor: &Descriptor) -> Result<Option<ObjectDigest>> {
        let path = path_for_descriptor(descriptor)?;
        let buf = match rustix::fs::readlinkat(&self.0.dir, path.as_std_path(), Vec::new()) {
            Ok(r) => r,
            Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut buf = buf.into_string()?;
        if !(buf.chars().all(|c| c.is_ascii())
            && buf.starts_with(BY_SHA256_UPLINK)
            && buf.bytes().nth(2) == Some(b'/'))
        {
            anyhow::bail!("Invalid descriptor symlink: {buf}");
        }
        buf.replace_range(0..BY_SHA256_UPLINK.len(), "");
        buf.remove(2);
        // Verify
        let _ = Sha256Hex::new(&buf);
        Ok(Some(buf))
    }

    #[context("Reading descriptor sha256:{}", descriptor.digest())]
    fn read_descriptor(&self, descriptor: &Descriptor) -> Result<Option<File>> {
        let path = path_for_descriptor(descriptor)?;
        let f = self.0.dir.open_optional(&path)?;
        Ok(f.map(|f| f.into_std()))
    }

    #[context("Reading tag {:?}", tag)]
    fn lookup_artifact_tag(&self, tag: &str) -> Result<Option<Descriptor>> {
        let tag_filename =
            percent_encoding::utf8_percent_encode(tag, percent_encoding::NON_ALPHANUMERIC);
        let tagpath: Utf8PathBuf = format!("{ARTIFACTS}/{TAGS}/{tag_filename}").into();
        let buf = match rustix::fs::readlinkat(&self.0.dir, tagpath.as_std_path(), Vec::new()) {
            Ok(r) => r,
            Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut buf = buf.into_string()?;
        todo!()
    }

    /// Returns true if this layer is stored in expanded form.
    fn has_layer(&self, diffid: &str) -> Result<bool> {
        let mut layer_path = format!("{IMAGES}/{LAYERS}");
        append_object_path(&mut layer_path, diffid)?;
        self.0.dir.try_exists(layer_path).map_err(Into::into)
    }

    /// Returns true if descriptor is stored as an object
    fn has_descriptor_object(&self, descriptor: &Descriptor) -> Result<bool> {
        let mut layer_path = String::from(OBJECTS_BY_SHA256);
        append_object_path(&mut layer_path, &descriptor.sha256()?)?;
        self.0.dir.try_exists(layer_path).map_err(Into::into)
    }

    /// Returns true if this manifest digest is stored as an image
    pub fn has_image_manifest(&self, descriptor: &Descriptor) -> Result<bool> {
        let mut path = format!("{IMAGES}/{DESCRIPTOR}");
        append_object_path(&mut path, &descriptor.sha256()?)?;
        self.0.dir.try_exists(path).map_err(Into::into)
    }

    /// Returns true if this manifest digest is stored as an artifact
    pub fn has_artifact_manifest(&self, descriptor: &Descriptor) -> Result<bool> {
        let mut path = format!("{ARTIFACTS}/{DESCRIPTOR}");
        append_object_path(&mut path, &descriptor.sha256()?)?;
        self.0.dir.try_exists(path).map_err(Into::into)
    }

    #[context("Importing layer")]
    pub async fn import_layer(
        &self,
        txn: RepoTransaction,
        src: File,
        diffid: &str,
    ) -> Result<RepoTransaction> {
        let mut layer_path = format!("{IMAGES}/{LAYERS}");
        append_object_path(&mut layer_path, diffid)?;
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

    /// Pull the target artifact
    pub async fn pull_artifact(
        &self,
        txn: RepoTransaction,
        proxy: &containers_image_proxy::ImageProxy,
        imgref: &str,
    ) -> Result<(RepoTransaction, Descriptor)> {
        if let Some(d) = self.lookup_artifact_tag(imgref)? {
            return Ok((txn, d));
        }

        let img = proxy.open_image(&imgref).await?;
        let (manifest_digest, raw_manifest) = proxy.fetch_manifest_raw_oci(&img).await?;
        let manifest_descriptor = Descriptor::new(
            ocidir::oci_spec::image::MediaType::ImageManifest,
            raw_manifest.len().try_into().unwrap(),
            &manifest_digest,
        );
        let manifest_fsverity = if let Some(v) = self.lookup_descriptor(&manifest_descriptor)? {
            v
        } else {
            let tmpf = txn.new_descriptor_with_bytes(&raw_manifest)?;
            txn.import_descriptor(tmpf, &manifest_descriptor)?
        };

        let manifest =
            ocidir::oci_spec::image::ImageManifest::from_reader(io::Cursor::new(&raw_manifest))?;
        let txn = Arc::new(txn);
        let config_descriptor = manifest.config();
        let config_fsverity = if let Some(v) = self.lookup_descriptor(&config_descriptor)? {
            v
        } else {
            let config_raw = proxy.fetch_config_raw(&img).await?;
            // Import the config
            let tmpf = txn.new_descriptor_with_bytes(&config_raw)?;
            txn.import_descriptor(tmpf, &config_descriptor)?
        };

        let layers_to_fetch =
            manifest
                .layers()
                .iter()
                .try_fold(Vec::new(), |mut acc, layer| -> Result<_> {
                    if !self.has_descriptor_object(layer)? {
                        acc.push(layer);
                    }
                    Ok(acc)
                })?;

        tracing::debug!("Layers to fetch: {}", layers_to_fetch.len());
        for layer in layers_to_fetch {
            let size = layer.size().try_into().context("Invalid size")?;
            let (blob_reader, driver) = proxy.get_blob(&img, layer.digest(), size).await?;
            let mut sync_blob_reader = tokio_util::io::SyncIoBridge::new(blob_reader);
            // Clone to move into worker thread
            let layer = layer.clone();
            let txn = Arc::clone(&txn);
            let import_task = tokio::task::spawn_blocking(move || -> Result<_> {
                let mut tmpf = DescriptorWriter::new(txn.new_object()?)?;
                let _n: u64 = std::io::copy(&mut sync_blob_reader, &mut tmpf)?;
                txn.import_descriptor(tmpf, &layer)?;
                Ok(())
            });
            let (import_task, driver) = tokio::join!(import_task, driver);
            let _: () = driver?;
            let _: () = import_task.unwrap()?;
        }
        tracing::debug!("Imported all layers");

        // Map from a layer sha256:<hash> to a fsverity digest
        let layer_digest_to_objid =
            manifest
                .layers()
                .iter()
                .try_fold(HashMap::new(), |mut acc, layer| {
                    use std::collections::hash_map::Entry;
                    if let Entry::Vacant(v) = acc.entry(layer.digest()) {
                        let objid = txn
                            .repo
                            .lookup_descriptor(layer)?
                            .expect("Should have fetched descriptor");
                        v.insert(objid);
                    }
                    anyhow::Ok(acc)
                })?;

        let (send_entries, recv_entries) = std::sync::mpsc::sync_channel(5);
        let txn_clone = Arc::clone(&txn);
        let cfs_worker = tokio::task::spawn_blocking(move || -> Result<_> {
            let cfs_object = txn_clone.new_object()?;
            let cfs_object_file = cfs_object.as_file().try_clone()?.into_std();
            composefs::mkcomposefs::mkcomposefs(Default::default(), recv_entries, cfs_object_file)?;
            let cfs_path = txn_clone.import_object(cfs_object)?;
            tracing::debug!("Committed artifact: {cfs_path}");
            Ok(cfs_path)
        });
        let manifest_desc_ref = &manifest_descriptor;
        let manifest_ref = &manifest;
        let send_task = async move {
            // If we fail to send on the channel, then we should get an error from the mkcomposefs job
            if let Err(_) = send_entries.send(dir_cfs_entry("/".into())) {
                return Ok(());
            }
            let path = Utf8Path::new("/manifest.json");
            if let Err(_) = send_entries.send(cfs_entry_for_descriptor(
                &manifest_desc_ref,
                &manifest_fsverity,
                path,
            )?) {
                return Ok(());
            }
            let path = Utf8Path::new("/config.json");
            if let Err(_) = send_entries.send(cfs_entry_for_descriptor(
                &config_descriptor,
                &config_fsverity,
                path,
            )?) {
                return Ok(());
            }
            if let Err(_) = send_entries.send(dir_cfs_entry("/layers".into())) {
                return Ok(());
            }
            for (i, layer) in manifest_ref.layers().iter().enumerate() {
                let digest = layer_digest_to_objid
                    .get(layer.digest())
                    .expect("Should have objid for layer");
                let path = &format!("/layers/{i}");
                if let Err(_) =
                    send_entries.send(cfs_entry_for_descriptor(&layer, &digest, path.as_ref())?)
                {
                    return Ok(());
                }
            }
            tracing::debug!("Wrote all cfs entries");
            drop(send_entries);
            anyhow::Ok(())
        };

        let (mkcfs_result, send_result) = tokio::join!(cfs_worker, send_task);
        let mut cfs_objid = mkcfs_result.unwrap()?;
        let _: () = send_result?;

        //txn.add_tag(cfs_objid, &img_path)?;

        // let repo = self.clone();
        // tokio::task::spawn_blocking(move || -> Result<_> {
        //     repo.as_oci().insert_manifest(manifest, Some("default"), platform)
        // })
        // .await
        // .unwrap()
        // SAFETY: We joined all the threads
        let txn = Arc::into_inner(txn).unwrap();
        Ok((txn, manifest_descriptor))
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

    use ocidir::oci_spec::image::{
        ImageConfigurationBuilder, ImageManifest, ImageManifestBuilder, Platform,
    };

    use super::*;

    const EMPTY_DIFFID: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn new_memfd(buf: &[u8]) -> Result<File> {
        use rustix::fs::MemfdFlags;
        let f = rustix::fs::memfd_create("test memfd", MemfdFlags::CLOEXEC)?;
        let f = File::from(f);
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

        assert!(!repo.has_layer(EMPTY_DIFFID).unwrap());

        // A no-op import
        let txn = repo.new_transaction()?;
        let txn = repo
            .import_layer(txn, new_memfd(b"")?, EMPTY_DIFFID)
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
            .append_dir_all("./", "../../tests")
            .context("creating tar")?;
        drop(testtar.into_inner()?.into_inner()?);
        let digest_o = Command::new("sha256sum")
            .stdin(td.open("test.tar")?)
            .stdout(std::process::Stdio::piped())
            .output()?;
        assert!(digest_o.status.success());
        let digest = String::from_utf8(digest_o.stdout).unwrap();
        let digest = digest.split_ascii_whitespace().next().unwrap().trim();
        let testtar = td.open("test.tar")?;

        let txn = repo.new_transaction()?;
        let txn = repo
            .import_layer(txn, testtar.into_std(), digest)
            .await
            .unwrap();
        txn.commit().await.unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn test_import_ocidir() -> Result<()> {
        let td = TempDir::new(cap_std::ambient_authority())?;
        let td = &*td;

        // td.create_dir("oci")?;
        // let ocidir = ocidir::OciDir::ensure(&td.open_dir("oci")?)?;

        // // A dummy layer
        // let mut blobw = ocidir.create_gzip_layer(Default::default())?;
        // blobw.write_all(b"pretend this is a tarball")?;
        // let blob = blobw.complete()?;
        // let mut manifest = ocidir::new_empty_manifest().build().unwrap();
        // let mut config = ImageConfigurationBuilder::default().build().unwrap();
        // ocidir.push_layer(&mut manifest, &mut config, blob, "empty blob", Default::default());

        // ocidir.insert_manifest_and_config(manifest, config, Some("latest"), Platform::default())?;

        td.create_dir("repo")?;
        let repo = Repo::init(&td.open_dir("repo")?, false).unwrap();
        let proxy = containers_image_proxy::ImageProxy::new().await?;

        let txn = repo.new_transaction()?;
        let (txn, desc) = repo
            .pull_artifact(txn, &proxy, "docker://quay.io/fedora/fedora:40")
            .await
            .unwrap();
        let r = txn.commit().await.unwrap();
        assert_eq!(r.extant_objects_count, 0);
        assert_eq!(r.imported_objects_count, 0);
        assert_eq!(r.imported_objects_size, 0);

        Ok(())
    }
}
