use std::{borrow::Cow, ffi::OsString, time::Duration};

use anyhow::{anyhow, Context, Result};
use camino::Utf8PathBuf;

use cap_std::fs::Dir;
use clap::Parser;
use comfy_table::Cell;
use ocidir::cap_std;

mod cli;
mod fileutils;
mod ociutil;
pub mod repo;

/// Options for specifying the repository
#[derive(Debug, Parser)]
pub(crate) struct RepoOpts {
    /// Path to the repository
    #[clap(long, value_parser)]
    repo: Utf8PathBuf,
}

impl RepoOpts {
    pub(crate) fn open(&self) -> Result<crate::repo::Repo> {
        let repo = self.repo.as_path();
        let d = Dir::open_ambient_dir(repo, cap_std::ambient_authority())
            .with_context(|| format!("Opening {repo}"))?;
        crate::repo::Repo::open(d)
    }
}

/// Options for importing container.
#[derive(Debug, Parser)]
pub(crate) struct PullOpts {
    #[clap(flatten)]
    repo_opts: RepoOpts,

    /// Image reference
    image: String,
}

/// Options for importing container.
#[derive(Debug, Parser)]
pub(crate) struct UnpackOpts {
    #[clap(flatten)]
    repo_opts: RepoOpts,

    /// Image reference
    image: String,
}

/// Options for creating a repo
#[derive(Debug, Parser)]
pub(crate) struct CreateOpts {
    #[clap(flatten)]
    repo_opts: RepoOpts,

    /// Require fsverity
    #[clap(long)]
    require_verity: bool,
}

/// Toplevel options
#[derive(Debug, Parser)]
#[clap(name = "composefs-oci")]
#[clap(rename_all = "kebab-case")]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Opt {
    /// Initialize a repo
    Create(CreateOpts),
    /// List all images
    List(RepoOpts),
    /// Query a tag
    Inspect {
        #[clap(flatten)]
        repo_opts: RepoOpts,

        /// Query this tag
        name: String,
    },
    /// Pull an image
    Pull(PullOpts),
    /// Verify integrity
    Fsck(RepoOpts),
    Unpack(UnpackOpts),
}

/// Parse the provided arguments and execute.
/// Calls [`clap::Error::exit`] on failure, printing the error message and aborting the program.
pub async fn run_from_iter<I>(args: I) -> Result<()>
where
    I: IntoIterator,
    I::Item: Into<OsString> + Clone,
{
    run_from_opt(Opt::parse_from(args)).await
}

async fn run_from_opt(opt: Opt) -> Result<()> {
    match opt {
        Opt::Create(opts) => {
            let repopath = opts.repo_opts.repo.as_path();
            std::fs::create_dir_all(repopath)
                .with_context(|| format!("Creating target dir: {repopath}"))?;
            let repodir = Dir::open_ambient_dir(repopath, cap_std::ambient_authority())?;
            let repo = crate::repo::Repo::init(&repodir, opts.require_verity)?;
            drop(repo);
            Ok(())
        }
        Opt::List(opts) => {
            let repo = opts.open()?;
            let now = chrono::Utc::now();
            let mut table = comfy_table::Table::new();
            table.set_header(vec!["NAME", "TYPE", "CREATED", "SIZE"]);
            for tag in repo.list_tags(None).await? {
                let metadata = repo
                    .read_artifact_metadata(&tag)
                    .await?
                    .ok_or_else(|| anyhow!("Expected metadata for {tag}"))?;
                let ty = metadata
                    .manifest
                    .artifact_type()
                    .as_ref()
                    .map(|c| c.as_ref())
                    .unwrap_or("image");
                let created_delta = ociutil::created(&metadata.manifest, &metadata.config)
                    .and_then(|c| chrono::DateTime::parse_from_rfc3339(c).ok())
                    .map(|c| now.signed_duration_since(&c));
                let created = if let Some(delta) = created_delta {
                    if delta < chrono::Duration::zero() {
                        Cow::Borrowed("in the future")
                    } else {
                        if let Ok(delta) = delta.abs().to_std() {
                            Cow::Owned(format!("{} ago", indicatif::HumanDuration(delta)))
                        } else {
                            Cow::Borrowed("<invalid timestamp>")
                        }
                    }
                } else {
                    Cow::Borrowed("unknown")
                };
                let size = metadata
                    .manifest
                    .layers()
                    .iter()
                    .fold(0u64, |mut acc, layer| {
                        acc += layer.size() as u64;
                        acc
                    });
                let size = indicatif::HumanBytes(size);
                table.add_row([Cell::new(tag.as_str()), Cell::new(created), Cell::new(size)]);
            }
            println!("{table}");
            Ok(())
        }
        Opt::Inspect { repo_opts, name } => {
            let repo = repo_opts.open()?;
            if let Some(meta) = repo.read_artifact_metadata(&name).await? {
                let mut stdout = std::io::stdout().lock();
                serde_json::to_writer(&mut stdout, &meta)?;
            } else {
                println!(r"{{}}");
            }
            Ok(())
        }
        Opt::Pull(opts) => cli::pull(opts).await,
        Opt::Fsck(opts) => cli::fsck(opts).await,
        Opt::Unpack(opts) => cli::unpack(opts).await,
    }
}
