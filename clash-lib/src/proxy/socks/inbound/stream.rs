use std::{io, sync::Arc};

use tokio::net::TcpStream;
use tracing::instrument;

use crate::{app::dispatcher::Dispatcher, common::auth::ThreadSafeAuthenticator, session::Session};

#[instrument(skip(sess, s, dispatcher, authenticator))]
pub async fn handle_tcp(
    sess: &mut Session,
    mut s: TcpStream,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> io::Result<()> {
    todo!()
}
