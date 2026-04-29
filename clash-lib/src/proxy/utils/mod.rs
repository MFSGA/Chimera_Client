pub mod socket_helpers;

#[allow(unused_imports)]
pub use platform::{
    SocketProtector, clear_socket_protector, install_default_socket_protector,
    set_socket_protector,
};
pub use socket_helpers::*;

/// 2
mod platform;

mod proxy_connector;

pub mod provider_helper;
mod shared_handler;

pub use proxy_connector::*;

pub use shared_handler::{
    OutboundHandlerRegistry, SharedOutboundHandler, direct_only_registry,
};
