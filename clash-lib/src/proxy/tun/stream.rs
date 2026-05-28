use std::sync::Arc;

use tracing::debug;

use crate::{
    app::{dispatcher::Dispatcher, net::DEFAULT_OUTBOUND_INTERFACE},
    session::{Network, Session, Type, find_process_name},
};

pub(crate) async fn handle_inbound_stream(
    stream: watfaq_netstack::TcpStream,

    dispatcher: Arc<Dispatcher>,
    so_mark: Option<u32>,
) {
    let source = stream.local_addr();
    let destination = stream.remote_addr();
    let process_name = find_process_name(source, Some(destination), Network::Tcp);

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Tun,
        source,
        destination: destination.into(),
        iface: DEFAULT_OUTBOUND_INTERFACE
            .read()
            .await
            .clone()
            .inspect(|x| {
                debug!(
                    "selecting outbound interface: {:?} for tun TCP connection",
                    x
                );
            }),
        so_mark,
        process_name,
        ..Default::default()
    };

    debug!("new tun TCP session assigned: {}", sess);
    dispatcher.dispatch_stream(sess, Box::new(stream)).await;
}
