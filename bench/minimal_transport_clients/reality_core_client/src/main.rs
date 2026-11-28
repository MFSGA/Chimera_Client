use std::net::SocketAddr;

use clash_lib::transport_bench::Client;

fn main() {
    chimera_transport_bench_bootstrap::run_or_exit(
        Client::vless_reality_from_config,
        SocketAddr::from(([127, 0, 0, 1], 59806)),
    );
}
