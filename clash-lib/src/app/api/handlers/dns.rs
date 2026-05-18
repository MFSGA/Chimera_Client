use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use hickory_proto::{op::Message, rr::RecordType};
use http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::app::{api::AppState, dns::ThreadSafeDNSResolver};

#[derive(Clone)]
struct DNSState {
    resolver: ThreadSafeDNSResolver,
}

pub fn routes(resolver: ThreadSafeDNSResolver) -> Router<Arc<AppState>> {
    Router::new()
        .route("/query", get(query_dns))
        .with_state(DNSState { resolver })
}

#[derive(Deserialize)]
struct DnsQuery {
    name: String,
    #[serde(rename = "type")]
    typ: String,
}

async fn query_dns(
    State(state): State<DNSState>,
    q: Query<DnsQuery>,
) -> impl IntoResponse {
    if let crate::app::dns::ResolverKind::System = state.resolver.kind() {
        return (StatusCode::BAD_REQUEST, "Clash resolver is not enabled.")
            .into_response();
    }

    let typ: RecordType = q.typ.parse().unwrap_or(RecordType::A);
    let name = hickory_proto::rr::Name::from_str_relaxed(q.name.as_str());
    let Ok(name) = name else {
        return (StatusCode::BAD_REQUEST, "Invalid name").into_response();
    };

    let mut message = Message::query();
    message.add_query(hickory_proto::op::Query::query(name, typ));

    match state.resolver.exchange(&message).await {
        Ok(response) => {
            let mut resp = Map::new();
            resp.insert(
                "Status".to_owned(),
                response.metadata.response_code.low().into(),
            );
            resp.insert(
                "Question".to_owned(),
                response
                    .queries
                    .iter()
                    .map(|query| {
                        let mut data = Map::new();
                        data.insert(
                            "name".to_owned(),
                            query.name().to_string().into(),
                        );
                        data.insert(
                            "qtype".to_owned(),
                            u16::from(query.query_type()).into(),
                        );
                        data.insert(
                            "qclass".to_owned(),
                            u16::from(query.query_class()).into(),
                        );
                        data.into()
                    })
                    .collect::<Vec<Value>>()
                    .into(),
            );
            resp.insert("TC".to_owned(), response.metadata.truncation.into());
            resp.insert("RD".to_owned(), response.metadata.recursion_desired.into());
            resp.insert(
                "RA".to_owned(),
                response.metadata.recursion_available.into(),
            );
            resp.insert("AD".to_owned(), response.metadata.authentic_data.into());
            resp.insert("CD".to_owned(), response.metadata.checking_disabled.into());

            let rr_to_json = |rr: &hickory_proto::rr::Record| -> Value {
                let mut data = Map::new();
                data.insert("name".to_owned(), rr.name.to_string().into());
                data.insert("type".to_owned(), u16::from(rr.record_type()).into());
                data.insert("ttl".to_owned(), rr.ttl.into());
                data.insert("data".to_owned(), rr.data.to_string().into());
                data.into()
            };

            if !response.answers.is_empty() {
                resp.insert(
                    "Answer".to_owned(),
                    response.answers.iter().map(rr_to_json).collect(),
                );
            }

            if !response.authorities.is_empty() {
                resp.insert(
                    "Authority".to_owned(),
                    response.authorities.iter().map(rr_to_json).collect(),
                );
            }

            if !response.additionals.is_empty() {
                resp.insert(
                    "Additional".to_owned(),
                    response.additionals.iter().map(rr_to_json).collect(),
                );
            }

            Json(resp).into_response()
        }
        Err(err) => {
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}
