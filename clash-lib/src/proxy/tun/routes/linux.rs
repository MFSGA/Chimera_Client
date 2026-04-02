use ipnet::{IpNet, Ipv4Net};
use tracing::warn;

use crate::{
    app::net::OutboundInterface, common::errors::new_io_error,
    config::internal::config::TunConfig,
};

fn is_missing_ip_state(stderr: &str) -> bool {
    matches!(
        stderr.trim(),
        msg if msg.contains("No such file or directory")
            || msg.contains("No such process")
    )
}

/// TODO: get rid of command execution
pub fn check_ip_command_installed() -> std::io::Result<()> {
    std::process::Command::new("ip")
        .arg("route")
        .output()
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                Err(std::io::Error::other("ip command not found"))
            }
        })
}

pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> std::io::Result<()> {
    let cmd = std::process::Command::new("ip")
        .arg("route")
        .arg("add")
        .arg(dest.to_string())
        .arg("dev")
        .arg(&via.name)
        .output()?;
    warn!("executing: ip route add {} dev {}", dest, via.name);
    if !cmd.status.success() {
        return Err(new_io_error(format!(
            "add route failed: {}",
            String::from_utf8_lossy(&cmd.stderr)
        )));
    }
    Ok(())
}

pub fn delete_interface(name: &str) -> std::io::Result<()> {
    let cmd_str = format!("ip link del dev {name}");
    let args = ["link", "del", "dev", name];
    let deleted = run_ip_cmd_single(&cmd_str, &args, true)?;
    if deleted {
        warn!("deleted stale tun interface {}", name);
    }
    Ok(())
}

pub fn ensure_interface_address(
    name: &str,
    addr: Ipv4Net,
) -> std::io::Result<()> {
    let cidr = addr.to_string();
    let cmd = std::process::Command::new("ip")
        .args(["addr", "add", &cidr, "dev", name])
        .output()?;
    warn!("executing: ip addr add {} dev {}", cidr, name);

    if cmd.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&cmd.stderr);
    if stderr.contains("File exists") {
        warn!(
            "address {} already configured on {}, continuing",
            cidr, name
        );
        return Ok(());
    }

    Err(new_io_error(format!(
        "ip addr add {} dev {} failed: {}",
        cidr, name, stderr
    )))
}

fn run_ip_cmd_single(
    cmd_str: &str,
    args: &[&str],
    allow_missing: bool,
) -> std::io::Result<bool> {
    let cmd = std::process::Command::new("ip").args(args).output()?;
    warn!("executing: {}", cmd_str);
    if cmd.status.success() {
        return Ok(true);
    }

    let stderr = String::from_utf8_lossy(&cmd.stderr);
    if allow_missing && is_missing_ip_state(&stderr) {
        warn!("{} already absent: {}", cmd_str, stderr.trim());
        return Ok(false);
    }

    Err(new_io_error(format!("{} failed: {}", cmd_str, stderr)))
}

fn run_ip_cmd_with_mode(
    args: &[&str],
    enable_v6: bool,
    allow_missing: bool,
) -> std::io::Result<bool> {
    let cmd_str = format!("ip {}", args.join(" "));
    let mut changed = run_ip_cmd_single(&cmd_str, args, allow_missing)?;

    if enable_v6 {
        let mut v6_args = vec!["-6"];
        v6_args.extend_from_slice(args);
        let v6_cmd_str = format!("ip -6 {}", args.join(" "));
        changed |= run_ip_cmd_single(&v6_cmd_str, &v6_args, allow_missing)?;
    }

    Ok(changed)
}

fn run_ip_cmd(args: &[&str], enable_v6: bool) -> std::io::Result<()> {
    run_ip_cmd_with_mode(args, enable_v6, false).map(|_| ())
}

fn delete_ip_cmd_all(args: &[&str], enable_v6: bool) -> std::io::Result<()> {
    while run_ip_cmd_with_mode(args, enable_v6, true)? {}
    Ok(())
}

/// three rules are added:
/// # ip route add default dev wg0 table 2468
/// # ip rule add not fwmark 1234 table 2468
/// # ip rule add table main suppress_prefixlength 0
/// for ipv6
/// # ip -6 ...
pub fn setup_policy_routing(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    let table = tun_cfg.route_table.to_string();
    let dev = via.name.as_str();
    let enable_v6 = tun_cfg.gateway_v6.is_some();

    run_ip_cmd(
        &["route", "add", "default", "dev", dev, "table", &table],
        enable_v6,
    )?;

    if let Some(so_mark) = tun_cfg.so_mark {
        run_ip_cmd(
            &[
                "rule",
                "add",
                "not",
                "fwmark",
                &so_mark.to_string(),
                "table",
                &table,
            ],
            enable_v6,
        )?;
    }

    run_ip_cmd(
        &["rule", "add", "table", "main", "suppress_prefixlength", "0"],
        enable_v6,
    )?;

    if tun_cfg.dns_hijack {
        run_ip_cmd(&["rule", "add", "dport", "53", "table", &table], enable_v6)?;
    }

    Ok(())
}

/// three rules to clean up:
/// # ip rule del not fwmark $SO_MARK table $TABLE
/// # ip rule del table main suppress_prefixlength 0
/// # ip rule del dport 53 table $TABLE
/// for v6
/// # ip -6 ...
pub fn maybe_routes_clean_up(tun_cfg: &TunConfig) -> std::io::Result<()> {
    if !(tun_cfg.enable && tun_cfg.route_all) {
        return Ok(());
    }

    let table = tun_cfg.route_table.to_string();
    let enable_v6 = tun_cfg.gateway_v6.is_some();

    delete_ip_cmd_all(&["route", "del", "default", "table", &table], enable_v6)?;

    if let Some(so_mark) = tun_cfg.so_mark {
        delete_ip_cmd_all(
            &[
                "rule",
                "del",
                "not",
                "fwmark",
                &so_mark.to_string(),
                "table",
                &table,
            ],
            enable_v6,
        )?;
    }
    delete_ip_cmd_all(
        &["rule", "del", "table", "main", "suppress_prefixlength", "0"],
        enable_v6,
    )?;

    delete_ip_cmd_all(
        &["rule", "del", "dport", "53", "table", &table],
        enable_v6,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_missing_ip_state;

    #[test]
    fn detect_missing_ip_rule_errors() {
        assert!(is_missing_ip_state("RTNETLINK answers: No such file or directory"));
        assert!(is_missing_ip_state("RTNETLINK answers: No such process"));
        assert!(!is_missing_ip_state("RTNETLINK answers: File exists"));
    }
}
