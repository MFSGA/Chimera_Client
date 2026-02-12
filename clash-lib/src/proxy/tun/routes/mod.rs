#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::add_route;
#[cfg(target_os = "linux")]
pub use linux::maybe_routes_clean_up;

#[cfg(not(target_os = "linux"))]
mod other;
#[cfg(not(target_os = "linux"))]
use other::add_route;
#[cfg(not(target_os = "linux"))]
pub use other::maybe_routes_clean_up;

use tracing::warn;

use crate::{app::net::get_interface_by_name, config::internal::config::TunConfig};

pub fn maybe_add_routes(cfg: &TunConfig, tun_name: &str) -> std::io::Result<()> {
    if cfg.route_all || !cfg.routes.is_empty() {
        #[cfg(target_os = "linux")]
        linux::check_ip_command_installed()?;

        let tun_iface = get_interface_by_name(tun_name)
            .ok_or_else(|| std::io::Error::other("tun interface not found"))?;

        if cfg.route_all {
            warn!("route_all is enabled, all traffic will be routed through the tun interface");

            #[cfg(target_os = "linux")]
            {
                linux::setup_policy_routing(cfg, &tun_iface)?;
            }
        } else {
            for route in &cfg.routes {
                add_route(&tun_iface, route)?;
            }
        }
    }

    Ok(())
}
