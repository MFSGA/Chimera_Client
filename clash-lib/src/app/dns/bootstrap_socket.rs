//! S04b-m: local socket-path *evidence* carried by a chained connection.
//! These IDs come from the socket connector, not from routing intent. They
//! identify local physical sockets only, NOT a proxy's remote forwarding path.
//! The existing strict DNS wire client does not expose socket identities;
//! it cannot implement the attested transport boundary below.

use std::{collections::HashSet, io, sync::Arc};

use async_trait::async_trait;
use hickory_proto::op::Message;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::{config::NameServer, execution::DnsStrictTransport},
        flow::{AddressFamily, NetworkPathId},
        network::BindingStatus,
        outbound::manager::OutboundManager,
    },
    proxy::{AnyOutboundHandler, utils::SharedNetworkStatus},
};

/// Private fields prevent callers from passing an arbitrary planned path.
/// Providers must take this from a connection's `network_path_ids` and keep
/// it bound to that connection; test wrappers can synthesize it deliberately.
pub(crate) struct StrictDnsSocketPathEvidence {
    paths: Vec<NetworkPathId>,
}

impl StrictDnsSocketPathEvidence {
    /// Only the freshly created S04b-n DNS wire client uses this adapter;
    /// the runtime captured these IDs from its chained physical connection.
    pub(in crate::app::dns) fn from_dns_client_socket_paths(
        paths: Vec<NetworkPathId>,
    ) -> io::Result<Self> {
        Self::from_reported(paths)
    }

    pub(crate) fn from_stream(stream: &BoxedChainedStream) -> io::Result<Self> {
        Self::from_reported(stream.network_path_ids())
    }

    pub(crate) fn from_datagram(
        datagram: &BoxedChainedDatagram,
    ) -> io::Result<Self> {
        Self::from_reported(datagram.network_path_ids())
    }

    fn from_reported(paths: Vec<NetworkPathId>) -> io::Result<Self> {
        if paths.is_empty() || paths.len() > 16 {
            return Err(io::Error::other(
                "strict DNS socket path missing or exceeds maximum reported hops",
            ));
        }
        let mut unique = HashSet::new();
        for path in &paths {
            if path.interface.name.is_empty()
                || path.interface.index == 0
                || path.source_address.is_none_or(|ip| {
                    AddressFamily::from(ip) != path.family
                        || ip.is_unspecified()
                        || ip.is_multicast()
                })
                || !unique.insert(path)
            {
                return Err(io::Error::other(
                    "strict DNS socket path contains invalid or duplicate physical path identities",
                ));
            }
        }
        Ok(Self { paths })
    }

    pub(crate) async fn verify(
        &self,
        manager: &Arc<OutboundManager>,
        status: &SharedNetworkStatus,
    ) -> io::Result<()> {
        let generation = manager.strict_dns_path_generation(status).await?;
        let (snapshot_generation, observed, _, _) = status
            .write()
            .await
            .path_planning_snapshot()
            .ok_or_else(|| {
                io::Error::other(
                    "strict DNS socket path has no observed path candidates",
                )
            })?;
        if snapshot_generation != generation {
            return Err(io::Error::other(
                "strict DNS socket path generation changed during evidence verification",
            ));
        }
        for path in &self.paths {
            if path.network_generation != generation {
                return Err(io::Error::other(
                    "strict DNS socket path reported a stale network generation",
                ));
            }
            if !observed.iter().any(|candidate| {
                candidate.binding == BindingStatus::Verified
                    && candidate.interface == path.interface
                    && candidate.family == path.family
                    && Some(candidate.source_address) == path.source_address
            }) {
                return Err(io::Error::other(format!(
                    "strict DNS socket path '{}' is not a verified current local candidate",
                    path.interface.name
                )));
            }
        }
        let completed_generation =
            manager.strict_dns_path_generation(status).await?;
        if completed_generation != generation {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "strict DNS socket path generation changed during evidence verification",
            ));
        }
        Ok(())
    }
}

/// A DNS transport that can return the *connection's* local socket path
/// evidence with every DNS response. The S04b-n UDP/TCP wire clients now
/// implement it when their outbound connector actually reports socket IDs;
/// absent IDs remain a hard error and production policy-rules stay gated.
#[async_trait]
pub(crate) trait DnsStrictSocketPathTransport: DnsStrictTransport {
    async fn exchange_with_socket_evidence(
        &self,
        server: &NameServer,
        outbound: AnyOutboundHandler,
        request: &Message,
    ) -> io::Result<(Message, StrictDnsSocketPathEvidence)>;
}

/// Adapt an explicitly evidence-bearing DNS transport to the normal guarded
/// retry loop. The proxy identity and runtime epochs are checked by the outer
/// S04b-l leased guard on both sides of this proof verification.
pub(crate) struct StrictDnsEvidenceCheckedTransport<'a, T> {
    transport: &'a T,
    manager: &'a Arc<OutboundManager>,
    status: &'a SharedNetworkStatus,
}

impl<'a, T: DnsStrictSocketPathTransport> StrictDnsEvidenceCheckedTransport<'a, T> {
    pub(crate) fn new(
        transport: &'a T,
        manager: &'a Arc<OutboundManager>,
        status: &'a SharedNetworkStatus,
    ) -> Self {
        Self {
            transport,
            manager,
            status,
        }
    }
}

#[async_trait]
impl<T: DnsStrictSocketPathTransport> DnsStrictTransport
    for StrictDnsEvidenceCheckedTransport<'_, T>
{
    fn terminal_on_exchange_error(&self) -> bool {
        // A bad or missing socket path must NEVER be interpreted as an
        // upstream failure that can be bypassed via another DNS server.
        true
    }

    fn validate_server(&self, server: &NameServer) -> io::Result<()> {
        self.transport.validate_server(server)
    }

    fn validate_profile(&self, servers: &[NameServer]) -> io::Result<()> {
        self.transport.validate_profile(servers)
    }

    async fn exchange(
        &self,
        server: &NameServer,
        outbound: AnyOutboundHandler,
        request: &Message,
    ) -> io::Result<Message> {
        // The wire DNS client may not have its own NetworkPathSource.
        // Bind this *attempt* to the manager's observed epoch before sending
        // packets, not just the network that exists when the reply arrives.
        let started_generation =
            self.manager.strict_dns_path_generation(self.status).await?;
        let result = self
            .transport
            .exchange_with_socket_evidence(server, outbound, request)
            .await;
        // Check even after an upstream error: an epoch change must never
        // be mistaken for a normal DNS failure eligible for another server.
        let completed_generation =
            self.manager.strict_dns_path_generation(self.status).await?;
        if completed_generation != started_generation {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "strict DNS network changed during socket-evidence exchange",
            ));
        }
        let (answer, evidence) = result?;
        evidence.verify(self.manager, self.status).await?;
        Ok(answer)
    }
}
