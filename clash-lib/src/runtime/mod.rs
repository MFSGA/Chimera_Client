//! Internal runtime boundaries: lifecycle orchestration, component assembly and
//! health, configuration construction, and network ownership/recovery.

mod components;
mod factory;
mod lifecycle;
mod network;

#[cfg(test)]
use self::{
    factory::create_components,
    lifecycle::{
        RuntimeExit, SHUTDOWN_TOKEN, ShutdownTokenRegistration, catch_control_panic,
        wait_for_control_or_shutdown,
    },
    network::{NetworkRecoveryRequest, recover_to_latest_environment},
};
#[cfg(all(test, feature = "tun"))]
use network::NetworkRuntimeLease;

#[cfg(test)]
pub(crate) mod tests;

pub use lifecycle::{
    setup_default_crypto_provider, shutdown, start, start_scaffold,
    start_scaffold_instance,
};
