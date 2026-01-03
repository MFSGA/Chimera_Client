use crate::config::{
    def,
    internal::config::{BindAddress, General},
};

pub(super) fn convert(c: &def::Config) -> Result<General, crate::Error> {
    /* let bind_address = if c.bind_address == BindAddress::default() && c.ipv6 {
        BindAddress::dual_stack()
    } else {
        c.bind_address
    }; */
    Ok(General {
        log_level: c.log_level,
    })
}
