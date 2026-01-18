use std::sync::{Arc, LazyLock};

use rustls::RootCertStore;

pub static GLOBAL_ROOT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let store = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Arc::new(store)
});
