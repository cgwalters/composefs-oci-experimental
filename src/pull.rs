use anyhow::Result;

use crate::PullOpts;

pub(crate) async fn cli_pull(opts: PullOpts) -> Result<()> {
    let repo = opts.repo_opts.open()?;
    let proxy = containers_image_proxy::ImageProxy::new().await?;

    let txn = repo.new_transaction()?;
    let (txn, descriptor) = repo.pull_artifact(txn, &proxy, &opts.image).await?;
    repo.commit(txn).await?;
    println!("Imported: {}", descriptor.digest());

    Ok(())
}
