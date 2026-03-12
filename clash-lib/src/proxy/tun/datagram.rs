use crate::app::dns::{ThreadSafeDNSResolver, exchange_with_resolver};
use tracing::{debug, trace, warn};

pub(crate) async fn handle_inbound_datagram(
    socket: watfaq_netstack::UdpSocket,
    resolver: ThreadSafeDNSResolver,
    dns_hijack: bool,
) {
    let (mut rx, mut tx) = socket.split();

    debug!("tun UDP ready");

    while let Some(watfaq_netstack::UdpPacket {
        data,
        local_addr,
        remote_addr,
    }) = rx.recv().await
    {
        if remote_addr.ip().is_multicast() {
            continue;
        }

        if dns_hijack && remote_addr.port() == 53 {
            trace!(
                "hijack dns request: {} -> {} ({} bytes)",
                local_addr,
                remote_addr,
                data.data().len()
            );

            let msg = match hickory_proto::op::Message::from_vec(data.data()) {
                Ok(msg) => msg,
                Err(error) => {
                    warn!("failed to parse dns packet: {}", error);
                    continue;
                }
            };

            let mut resp = match exchange_with_resolver(&resolver, &msg, true).await
            {
                Ok(resp) => resp,
                Err(error) => {
                    warn!("failed to exchange dns message: {}", error);
                    continue;
                }
            };

            resp.set_id(msg.id());

            let data = match resp.to_vec() {
                Ok(data) => data,
                Err(error) => {
                    warn!("failed to serialize dns response: {}", error);
                    continue;
                }
            };

            if let Err(error) = tx.send((data, remote_addr, local_addr).into()).await
            {
                warn!("failed to send dns response to netstack: {}", error);
            }

            continue;
        }

        trace!(
            "dropping tun UDP packet: {} -> {} (dns_hijack={})",
            local_addr, remote_addr, dns_hijack
        );
    }
}
