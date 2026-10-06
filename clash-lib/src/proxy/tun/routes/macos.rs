use std::{net::Ipv4Addr, sync::Mutex};

use ipnet::IpNet;
use tracing::warn;

use crate::{
    app::net::{DEFAULT_OUTBOUND_INTERFACE, OutboundInterface},
    common::errors::new_io_error,
    config::internal::config::TunConfig,
};

/// let's assume that the `route` command is available on macOS
pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let mut cmd = std::process::Command::new("route");
    cmd.arg("add");

    match dest {
        IpNet::V4(_) => {
            cmd.arg("-net")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!("executing: route add -net {} -interface {}", dest, via.name);
        }
        IpNet::V6(_) => {
            cmd.arg("-inet6")
                .arg(dest.to_string())
                .arg("-interface")
                .arg(&via.name);
            warn!(
                "executing: route add -inet6 {} -interface {}",
                dest, via.name
            );
        }
    }

    let output = cmd.output()?;

    if !output.status.success() {
        Err(new_io_error("add route failed"))
    } else {
        Ok(())
    }
}

fn get_default_gateway(
    interface: &str,
) -> std::io::Result<(Option<Ipv4Addr>, Option<std::net::Ipv6Addr>)> {
    // IPv4
    let cmd_v4 = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("-ifscope")
        .arg(interface)
        .arg("default")
        .output()?;

    let mut gateway_v4 = None;
    if cmd_v4.status.success() {
        let output = String::from_utf8_lossy(&cmd_v4.stdout);
        for line in output.lines() {
            if line.trim().contains("gateway:") {
                gateway_v4 = line
                    .split_whitespace()
                    .last()
                    .and_then(|x| x.parse::<Ipv4Addr>().ok());
                break;
            }
        }
    }

    // IPv6
    let cmd_v6 = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("-inet6")
        .arg("-ifscope")
        .arg(interface)
        .arg("default")
        .output()?;

    let mut gateway_v6 = None;
    if cmd_v6.status.success() {
        let output = String::from_utf8_lossy(&cmd_v6.stdout);
        for line in output.lines() {
            if line.trim().contains("gateway:") {
                gateway_v6 = line
                    .split_whitespace()
                    .last()
                    .and_then(|value| value.split('%').next())
                    .and_then(|x| x.parse::<std::net::Ipv6Addr>().ok());
                break;
            }
        }
    }

    Ok((gateway_v4, gateway_v6))
}

// Only routes successfully installed by this runtime may be removed on stop.
// A network switch must never make cleanup rediscover and delete the new
// system-owned default route.
static OWNED_DEFAULTS: Mutex<Vec<(String, IpNet, String)>> = Mutex::new(Vec::new());

pub async fn maybe_add_default_route() -> std::io::Result<()> {
    let interface = DEFAULT_OUTBOUND_INTERFACE
        .read()
        .await
        .clone()
        .ok_or_else(|| new_io_error("get configured physical interface"))?;
    let (v4, v6) = get_default_gateway(&interface.name)?;
    let mut gateways = Vec::new();
    if let Some(gateway) = v4 {
        gateways.push((
            "0.0.0.0/0".parse::<IpNet>().map_err(new_io_error)?,
            gateway.to_string(),
        ));
    }
    if let Some(gateway) = v6 {
        gateways.push((
            "::/0".parse::<IpNet>().map_err(new_io_error)?,
            gateway.to_string(),
        ));
    }
    if gateways.is_empty() {
        return Err(new_io_error("physical default gateway not found"));
    }
    for (network, gateway) in gateways {
        let output =
            scoped_route_command("add", &interface.name, &network, &gateway)
                .output()?;
        if output.status.success() {
            OWNED_DEFAULTS
                .lock()
                .map_err(|_| new_io_error("route ownership lock poisoned"))?
                .push((interface.name.clone(), network, gateway));
        } else if !String::from_utf8_lossy(&output.stderr).contains("File exists") {
            return Err(new_io_error("add physical scoped default route failed"));
        }
    }
    Ok(())
}

fn scoped_route_command(
    action: &str,
    interface: &str,
    network: &IpNet,
    gateway: &str,
) -> std::process::Command {
    let mut command = std::process::Command::new("route");
    command.arg(action);
    if matches!(network, IpNet::V6(_)) {
        command.arg("-inet6");
    }
    command
        .arg("-ifscope")
        .arg(interface)
        .arg(network.to_string())
        .arg(gateway);
    command
}

pub fn maybe_routes_clean_up(cfg: &TunConfig) -> std::io::Result<()> {
    if !cfg.route_all {
        return Ok(());
    }
    let routes = std::mem::take(
        &mut *OWNED_DEFAULTS
            .lock()
            .map_err(|_| new_io_error("route ownership lock poisoned"))?,
    );
    let mut errors = Vec::new();
    for (interface, network, gateway) in routes {
        // If the system replaced this route, ownership no longer applies.
        let current = get_default_gateway(&interface);
        let unchanged = match &current {
            Ok((v4, _)) if matches!(network, IpNet::V4(_)) => {
                v4.map(|ip| ip.to_string()).as_deref() == Some(gateway.as_str())
            }
            Ok((_, v6)) => {
                v6.map(|ip| ip.to_string()).as_deref() == Some(gateway.as_str())
            }
            Err(_) => false,
        };
        if !unchanged {
            continue;
        }
        match scoped_route_command("delete", &interface, &network, &gateway).output()
        {
            Ok(output) if output.status.success() => {}
            Ok(_) => errors
                .push(format!("delete owned scoped route on {interface} failed")),
            Err(error) => errors.push(error.to_string()),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(new_io_error(errors.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_targets_recorded_interface_and_gateway() {
        let command = scoped_route_command(
            "delete",
            "en7",
            &"::/0".parse().unwrap(),
            "fe80::1",
        );
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(
            args,
            ["delete", "-inet6", "-ifscope", "en7", "::/0", "fe80::1"]
        );
    }
}
