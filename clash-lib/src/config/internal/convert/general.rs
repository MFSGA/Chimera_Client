use crate::config::{
    def,
    internal::config::{BindAddress, Controller, General},
};

pub(super) fn convert(c: &def::Config) -> Result<General, crate::Error> {
    /* let bind_address = if c.bind_address == BindAddress::default() && c.ipv6 {
        BindAddress::dual_stack()
    } else {
        c.bind_address
    }; */
    Ok(General {
        log_level: c.log_level,
        controller: Controller {
            external_controller: c.external_controller.clone(),
            external_ui: c.external_ui.clone(),
            secret: c.secret.clone(),
            cors_allow_origins: c.cors_allow_origins.clone(),
            external_controller_ipc: c.external_controller_ipc.clone(),
        },
        mmdb: c.mmdb.clone(),
        mmdb_download_url: c.mmdb_download_url.clone(),
    })
}
