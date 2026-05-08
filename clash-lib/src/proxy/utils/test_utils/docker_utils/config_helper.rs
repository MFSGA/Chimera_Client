use std::path::PathBuf;

use std::sync::Arc;

use crate::{
    app::dns::ThreadSafeDNSResolver, proxy::utils::test_utils::noop::NoopResolver,
};

pub fn root_dir() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root
}

pub fn test_config_base_dir() -> PathBuf {
    root_dir().join("clash-lib/tests/data/config")
}

pub async fn build_dns_resolver() -> anyhow::Result<ThreadSafeDNSResolver> {
    Ok(Arc::new(NoopResolver))
}
