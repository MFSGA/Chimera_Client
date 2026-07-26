use std::net::IpAddr;

use ipnet::IpNet;
use tracing::warn;

use crate::{
    app::net::OutboundInterface, common::errors::new_io_error,
    config::internal::config::TunConfig,
};

const FWMARK_MAIN_RULE_PREF: &str = "88";
// DNS must be selected before the main-table lookup at preference 90.
// Chimera's SO_MARK-to-main rule at preference 88 prevents its own upstream
// DNS traffic from looping back into the TUN.
const DNS_HIJACK_RULE_PREF: &str = "89";
const ROUTE_ALL_RULE_PREF: &str = "102";
// Resolve connected, LAN, VPN, and other specific main-table routes before the
// catch-all TUN rule, while suppressing only the physical default route.
const MAIN_SUPPRESS_RULE_PREF: &str = "90";

fn is_missing_ip_state(stderr: &str) -> bool {
    matches!(
        stderr.trim(),
        msg if msg.contains("No such file or directory")
            || msg.contains("No such process")
            || msg.contains("FIB table does not exist")
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
    run_ip_cmd_for_family(
        &["route", "add", &dest.to_string(), "dev", &via.name],
        dest.addr().is_ipv6(),
        false,
    )
    .map(|_| ())
}

fn best_route_for(dest: IpAddr) -> std::io::Result<(Option<IpAddr>, String)> {
    let destination = dest.to_string();
    let mut args = Vec::new();
    if dest.is_ipv6() {
        args.push("-6");
    }
    args.extend(["route", "get", &destination]);
    let output = std::process::Command::new("ip").args(&args).output()?;
    warn!("executing: ip {}", args.join(" "));
    if !output.status.success() {
        return Err(new_io_error(format!(
            "query best route for {} failed: {}",
            dest,
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(line) = stdout.lines().next() else {
        return Err(new_io_error(format!("no best route found for {dest}")));
    };

    let mut gateway = None;
    let mut dev = None;
    let mut parts = line.split_whitespace();
    while let Some(part) = parts.next() {
        match part {
            "via" => gateway = parts.next().and_then(|gateway| gateway.parse().ok()),
            "dev" => {
                dev = parts.next().map(ToOwned::to_owned);
            }
            _ => {}
        }
    }

    let dev = dev
        .ok_or_else(|| new_io_error(format!("no route device found for {dest}")))?;
    Ok((gateway, dev))
}

fn add_excluded_route(
    table: &str,
    dest: &IpNet,
    transaction: &mut RouteTransaction,
) -> std::io::Result<()> {
    let ipv6 = dest.addr().is_ipv6();
    let cidr = dest.to_string();
    let (gateway, dev) = best_route_for(dest.addr())?;

    let mut args = vec!["route", "add", &cidr];
    if let Some(gateway) = gateway {
        let gateway = gateway.to_string();
        args.extend(["via", &gateway, "dev", &dev, "table", table]);
        transaction.apply(
            &args,
            &[
                "route", "del", &cidr, "via", &gateway, "dev", &dev, "table", table,
            ],
            ipv6,
        )
    } else {
        args.extend(["dev", &dev, "table", table]);
        transaction.apply(
            &args,
            &["route", "del", &cidr, "dev", &dev, "table", table],
            ipv6,
        )
    }
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

fn run_ip_cmd_for_family(
    args: &[&str],
    ipv6: bool,
    allow_missing: bool,
) -> std::io::Result<bool> {
    if ipv6 {
        let mut family_args = vec!["-6"];
        family_args.extend_from_slice(args);
        run_ip_cmd_single(
            &format!("ip {}", family_args.join(" ")),
            &family_args,
            allow_missing,
        )
    } else {
        run_ip_cmd_single(&format!("ip {}", args.join(" ")), args, allow_missing)
    }
}

#[derive(Default)]
struct RouteTransaction {
    applied: Vec<Vec<String>>,
}

impl RouteTransaction {
    fn apply(
        &mut self,
        add_args: &[&str],
        delete_args: &[&str],
        ipv6: bool,
    ) -> std::io::Result<()> {
        run_ip_cmd_for_family(add_args, ipv6, false)?;
        let mut inverse = Vec::new();
        if ipv6 {
            inverse.push("-6".to_owned());
        }
        inverse.extend(delete_args.iter().map(|arg| (*arg).to_owned()));
        self.applied.push(inverse);
        Ok(())
    }

    fn rollback(&mut self) {
        while let Some(args) = self.applied.pop() {
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();
            let cmd = format!("ip {}", args.join(" "));
            if let Err(error) = run_ip_cmd_single(&cmd, &args, true) {
                warn!(command = %cmd, %error, "failed to roll back TUN route operation");
            }
        }
    }
}

fn delete_ip_cmd_all(args: &[&str], ipv6: bool) -> std::io::Result<()> {
    while run_ip_cmd_for_family(args, ipv6, true)? {}
    Ok(())
}

/// three rules are added:
/// # ip route add default dev wg0 table 2468
/// # ip rule add pref 88 fwmark 1234 table main
/// # ip rule add pref 90 table main suppress_prefixlength 0
/// # ip rule add pref 102 not fwmark 1234 table 2468
/// for ipv6
/// # ip -6 ...
pub fn setup_policy_routing(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
) -> std::io::Result<()> {
    let mut transaction = RouteTransaction::default();
    let result = setup_policy_routing_inner(tun_cfg, via, &mut transaction);
    if result.is_err() {
        transaction.rollback();
    }
    result
}

fn setup_policy_routing_inner(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
    transaction: &mut RouteTransaction,
) -> std::io::Result<()> {
    setup_policy_family(
        tun_cfg,
        via,
        &tun_cfg.route_table.to_string(),
        false,
        transaction,
    )?;
    if tun_cfg.gateway_v6.is_some() {
        setup_policy_family(
            tun_cfg,
            via,
            &tun_cfg.route_table_v6.to_string(),
            true,
            transaction,
        )?;
    }
    Ok(())
}

fn setup_policy_family(
    tun_cfg: &TunConfig,
    via: &OutboundInterface,
    table: &str,
    ipv6: bool,
    transaction: &mut RouteTransaction,
) -> std::io::Result<()> {
    let dev = via.name.as_str();

    transaction.apply(
        &["route", "add", "default", "dev", dev, "table", table],
        &["route", "del", "default", "dev", dev, "table", table],
        ipv6,
    )?;

    for route in tun_cfg
        .route_exclude_address
        .iter()
        .filter(|route| route.addr().is_ipv6() == ipv6)
    {
        add_excluded_route(table, route, transaction)?;
    }

    if let Some(so_mark) = tun_cfg.so_mark {
        transaction.apply(
            &[
                "rule",
                "add",
                "pref",
                FWMARK_MAIN_RULE_PREF,
                "fwmark",
                &so_mark.to_string(),
                "table",
                "main",
            ],
            &[
                "rule",
                "del",
                "pref",
                FWMARK_MAIN_RULE_PREF,
                "fwmark",
                &so_mark.to_string(),
                "table",
                "main",
            ],
            ipv6,
        )?;

        transaction.apply(
            &[
                "rule",
                "add",
                "pref",
                ROUTE_ALL_RULE_PREF,
                "not",
                "fwmark",
                &so_mark.to_string(),
                "table",
                table,
            ],
            &[
                "rule",
                "del",
                "pref",
                ROUTE_ALL_RULE_PREF,
                "not",
                "fwmark",
                &so_mark.to_string(),
                "table",
                table,
            ],
            ipv6,
        )?;
    }

    transaction.apply(
        &[
            "rule",
            "add",
            "pref",
            MAIN_SUPPRESS_RULE_PREF,
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ],
        &[
            "rule",
            "del",
            "pref",
            MAIN_SUPPRESS_RULE_PREF,
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ],
        ipv6,
    )?;

    for port in tun_cfg.dns_hijack_udp_ports() {
        transaction.apply(
            &[
                "rule",
                "add",
                "pref",
                DNS_HIJACK_RULE_PREF,
                "ipproto",
                "udp",
                "dport",
                &port.to_string(),
                "table",
                table,
            ],
            &[
                "rule",
                "del",
                "pref",
                DNS_HIJACK_RULE_PREF,
                "ipproto",
                "udp",
                "dport",
                &port.to_string(),
                "table",
                table,
            ],
            ipv6,
        )?;
    }

    Ok(())
}

/// policy rules to clean up:
/// # ip rule del pref 88 fwmark $SO_MARK table main
/// # ip rule del pref 90 table main suppress_prefixlength 0
/// # ip rule del pref 102 not fwmark $SO_MARK table $TABLE
/// for v6
/// # ip -6 ...
pub fn maybe_routes_clean_up(tun_cfg: &TunConfig) -> std::io::Result<()> {
    if !(tun_cfg.enable && tun_cfg.route_all) {
        return Ok(());
    }

    clean_up_policy_family(tun_cfg, &tun_cfg.route_table.to_string(), false)?;
    if tun_cfg.gateway_v6.is_some() {
        clean_up_policy_family(tun_cfg, &tun_cfg.route_table_v6.to_string(), true)?;
    }
    Ok(())
}

fn clean_up_policy_family(
    tun_cfg: &TunConfig,
    table: &str,
    ipv6: bool,
) -> std::io::Result<()> {
    delete_ip_cmd_all(&["route", "del", "default", "table", table], ipv6)?;

    for route in tun_cfg
        .route_exclude_address
        .iter()
        .filter(|route| route.addr().is_ipv6() == ipv6)
    {
        delete_ip_cmd_all(
            &["route", "del", &route.to_string(), "table", table],
            ipv6,
        )?;
    }

    if let Some(so_mark) = tun_cfg.so_mark {
        delete_ip_cmd_all(
            &[
                "rule",
                "del",
                "pref",
                FWMARK_MAIN_RULE_PREF,
                "fwmark",
                &so_mark.to_string(),
                "table",
                "main",
            ],
            ipv6,
        )?;

        delete_ip_cmd_all(
            &[
                "rule",
                "del",
                "pref",
                ROUTE_ALL_RULE_PREF,
                "not",
                "fwmark",
                &so_mark.to_string(),
                "table",
                table,
            ],
            ipv6,
        )?;
    }
    delete_ip_cmd_all(
        &[
            "rule",
            "del",
            "pref",
            MAIN_SUPPRESS_RULE_PREF,
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ],
        ipv6,
    )?;

    for port in tun_cfg.dns_hijack_udp_ports() {
        delete_ip_cmd_all(
            &[
                "rule",
                "del",
                "pref",
                DNS_HIJACK_RULE_PREF,
                "ipproto",
                "udp",
                "dport",
                &port.to_string(),
                "table",
                table,
            ],
            ipv6,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_missing_ip_state;

    #[test]
    fn detect_missing_ip_rule_errors() {
        assert!(is_missing_ip_state(
            "RTNETLINK answers: No such file or directory"
        ));
        assert!(is_missing_ip_state("RTNETLINK answers: No such process"));
        assert!(is_missing_ip_state("Error: FIB table does not exist."));
        assert!(!is_missing_ip_state("RTNETLINK answers: File exists"));
    }
}
