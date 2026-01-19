use std::sync::Arc;

use tracing::debug;

use crate::{
    Runner,
    app::dispatcher::Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    config::internal::listener::InboundOpts,
};

pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    _dispatcher: Arc<Dispatcher>,
    _authenticator: ThreadSafeAuthenticator,
) -> Option<Vec<Runner>> {
    let name = &inbound_opts.common_opts().name;
    debug!("todo inbound listener {} is not implemented in this build", name);
    None
}
