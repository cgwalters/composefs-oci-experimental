use anyhow::Result;

pub(crate) async fn pull(opts: crate::PullOpts) -> Result<()> {
    let repo = opts.repo_opts.open()?;
    let proxy = containers_image_proxy::ImageProxy::new().await?;

    let txn = repo.new_transaction()?;
    let (txn, descriptor) = repo.pull_artifact(txn, &proxy, &opts.image).await?;
    repo.commit(txn).await?;
    println!("Imported: {}", descriptor.digest());

    Ok(())
}

pub(crate) async fn unpack(opts: crate::UnpackOpts) -> Result<()> {
    let _repo = opts.repo_opts.open()?;
    let _proxy = containers_image_proxy::ImageProxy::new().await?;

    todo!();
}
