use tracing::warn;

use crate::{
    common::mmdb::MmdbLookup,
    session::{self, Session},
};

use super::RuleMatcher;

#[derive(Clone)]
pub struct GeoIP {
    pub target: String,
    pub country_code: String,
    pub no_resolve: bool,
    pub mmdb: Option<MmdbLookup>,
}

impl std::fmt::Display for GeoIP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GeoIP({} - {})", self.target, self.country_code)
    }
}

impl RuleMatcher for GeoIP {
    fn payload(&self) -> String {
        self.country_code.clone()
    }

    fn apply(&self, sess: &Session) -> bool {
        match &sess.destination {
            session::SocksAddr::Ip(addr) => {
                if let Some(mmdb) = &self.mmdb {
                    mmdb.lookup_country(addr.ip()).is_ok_and(|country| {
                        country.country_code == self.country_code
                    })
                } else {
                    warn!(
                        "GeoIP lookup failed: MMDB not available. Maybe config.mmdb is not set?"
                    );
                    false
                }
            }
            session::SocksAddr::Domain(_, _) => false,
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn type_name(&self) -> &str {
        "GeoIP"
    }

    /* todo
    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    } */
}
