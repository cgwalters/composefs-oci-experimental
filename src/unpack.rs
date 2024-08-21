use anyhow::Result;

pub(crate) async fn cli_unpack(opts: crate::UnpackOpts) -> Result<()> {
    let _repo = opts.repo_opts.open()?;
    let _proxy = containers_image_proxy::ImageProxy::new().await?;

    todo!();
}
