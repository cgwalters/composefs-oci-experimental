use std::ops::ControlFlow;

use anyhow::Result;

pub(crate) async fn pull(opts: crate::PullOpts) -> Result<()> {
    let repo = opts.repo_opts.open()?;
    let proxy = containers_image_proxy::ImageProxy::new().await?;

    let txn = repo.new_transaction()?;
    let (txn, descriptor) = repo.pull(txn, &proxy, &opts.image).await?;
    repo.commit(txn).await?;
    println!("Imported: {}", descriptor.digest());

    Ok(())
}

pub(crate) async fn unpack(opts: crate::UnpackOpts) -> Result<()> {
    let _repo = opts.repo_opts.open()?;
    let _proxy = containers_image_proxy::ImageProxy::new().await?;

    todo!();
}

pub(crate) async fn fsck(opts: crate::RepoOpts) -> Result<()> {
    use crate::repo::CorruptionEvent;
    let repo = opts.open()?;
    let mut found_corruption = false;
    let mut err = None;
    repo.fsck(|event| {
        match event {
            CorruptionEvent::FsVerity(digest) => {
                eprintln!("Corrupted object: {digest}");
            }
            CorruptionEvent::InternalError(msg) => {
                err = Some(msg);
                return ControlFlow::Break(());
            }
        }
        found_corruption = true;
        ControlFlow::Continue(())
    })
    .await?;
    match (err, found_corruption) {
        (Some(e), true) => {
            anyhow::bail!("corruption detected, and encountered error: {e}");
        }
        (Some(e), false) => {
            anyhow::bail!("{e}");
        }
        (None, true) => {
            anyhow::bail!("corruption detected");
        }
        (None, false) => Ok(()),
    }
}
