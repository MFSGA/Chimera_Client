use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use tracing::{debug, error, info, trace, warn};
use url::Url;

use crate::{
    Error, Result, Runner,
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::internal::config::TunConfig,
    proxy::tun::{routes, stream::handle_inbound_stream},
};

#[derive(Default)]
struct TunInitializationConfig {
    fd: Option<u32>,
    tun_name: Option<String>,
}

struct RouteCleanupGuard {
    tun_cfg: TunConfig,
}

impl RouteCleanupGuard {
    fn new(tun_cfg: TunConfig) -> Self {
        Self { tun_cfg }
    }
}

impl Drop for RouteCleanupGuard {
    fn drop(&mut self) {
        warn!("cleaning up tun routes");
        if let Err(e) = routes::maybe_routes_clean_up(&self.tun_cfg) {
            error!("failed to clean up routes: {}", e);
        }
    }
}

pub fn get_runner(
    cfg: TunConfig,
    dispatcher: Arc<Dispatcher>,
    _resolver: ThreadSafeDNSResolver,
) -> Result<Option<Runner>> {
    if !cfg.enable {
        trace!("tun is disabled");
        return Ok(None);
    }

    let mut tun_init_config = TunInitializationConfig::default();
    match Url::parse(&cfg.device_id) {
        Ok(url) => match url.scheme() {
            "fd" => {
                let fd = url
                    .host()
                    .ok_or_else(|| Error::InvalidConfig("tun fd must be provided".to_string()))?
                    .to_string()
                    .parse()
                    .map_err(|e| Error::InvalidConfig(format!("tun fd {e}")))?;
                tun_init_config.fd = Some(fd);
            }
            "dev" => {
                let dev = url
                    .host()
                    .ok_or_else(|| Error::InvalidConfig("tun dev must be provided".to_string()))?
                    .to_string();
                tun_init_config.tun_name = Some(dev);
            }
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "invalid device id: {}",
                    cfg.device_id
                )));
            }
        },
        Err(_) => {
            tun_init_config.tun_name = Some(cfg.device_id.clone());
        }
    }

    let tun = if let Some(fd) = tun_init_config.fd {
        #[cfg(target_family = "unix")]
        {
            info!("tun started with fd {}", fd);
            // SAFETY: tun-rs expects a valid fd handed in by caller.
            unsafe { tun_rs::AsyncDevice::from_fd(fd as _) }?
        }

        #[cfg(not(target_family = "unix"))]
        {
            return Err(Error::InvalidConfig(format!(
                "tun fd({fd}) is only supported on Unix-like systems"
            )));
        }
    } else {
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            use network_interface::NetworkInterfaceConfig;
            use tun_rs::DeviceBuilder;

            let tun_name = tun_init_config
                .tun_name
                .ok_or_else(|| Error::InvalidConfig("tun name must be provided".to_string()))?;
            let tun_exist = network_interface::NetworkInterface::show()
                .map(|ifs| ifs.into_iter().any(|iface| iface.name == tun_name))
                .unwrap_or_default();

            if tun_exist {
                info!("tun device {} already exists, using it", tun_name);
            } else {
                info!("tun device {} does not exist, creating", tun_name);
            }

            let mut tun_builder = DeviceBuilder::new();
            tun_builder = tun_builder
                .name(&tun_name)
                .mtu(cfg.mtu.unwrap_or(if cfg!(windows) { 65535 } else { 1500 }));

            if !tun_exist {
                debug!("setting tun ipv4 addr: {:?}", cfg.gateway);
                tun_builder = tun_builder.ipv4(cfg.gateway.addr(), cfg.gateway.netmask(), None);

                if let Some(gateway_v6) = cfg.gateway_v6.as_ref() {
                    debug!("setting tun ipv6 addr: {:?}", cfg.gateway_v6);
                    tun_builder = tun_builder.ipv6(gateway_v6.addr(), gateway_v6.netmask());
                }
            }

            let dev = tun_builder.build_async()?;

            if !tun_exist {
                info!("setting up routes for tun {}", tun_name);
                routes::maybe_add_routes(&cfg, &tun_name)?;
            } else {
                info!("skipping route setup for existing tun {}", tun_name);
            }

            dev
        }
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            return Err(Error::InvalidConfig(
                "only fd:// is supported on mobile platforms".to_string(),
            ));
        }
    };

    let (stack, mut tcp_listener, _udp_socket) = watfaq_netstack::NetStack::new();

    Ok(Some(Box::pin(async move {
        let so_mark = cfg.so_mark;
        let _route_cleanup_guard = RouteCleanupGuard::new(cfg);

        let framed =
            tun_rs::async_framed::DeviceFramed::new(tun, tun_rs::async_framed::BytesCodec::new());

        let (mut tun_sink, mut tun_stream) = framed.split::<bytes::Bytes>();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = Vec::new();

        // dispatcher -> stack -> tun
        futs.push(Box::pin(async move {
            while let Some(pkt) = stack_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = tun_sink.send(pkt.into_bytes()).await {
                            error!("failed to send pkt to tun: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("tun stack error: {}", e);
                        break;
                    }
                }
            }

            Err(Error::Operation("tun stopped unexpectedly 0".to_string()))
        }));

        // tun -> stack -> dispatcher
        futs.push(Box::pin(async move {
            while let Some(pkt) = tun_stream.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = stack_sink.send(watfaq_netstack::Packet::new(pkt)).await {
                            error!("failed to send pkt to stack: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("tun stream error: {}", e);
                        break;
                    }
                }
            }

            Err(Error::Operation("tun stopped unexpectedly 1".to_string()))
        }));

        let dispatcher_for_stream = dispatcher.clone();
        futs.push(Box::pin(async move {
            while let Some(stream) = tcp_listener.next().await {
                debug!(
                    "new tun TCP connection: {} -> {}",
                    stream.local_addr(),
                    stream.remote_addr()
                );

                tokio::spawn(handle_inbound_stream(
                    stream,
                    dispatcher_for_stream.clone(),
                    so_mark,
                ));
            }

            Err(Error::Operation("tun stopped unexpectedly 2".to_string()))
        }));

        futures::future::select_all(futs).await.0.map_err(|e| {
            error!("tun error: {}. stopped", e);
            e
        })
    })))
}
