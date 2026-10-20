pub(crate) fn pre_condition(
    src: Option<std::net::SocketAddr>,
    dst: Option<std::net::SocketAddr>,
) -> bool {
    match (src, dst) {
        (None, None) => false,
        (Some(_), None) => true,
        (None, Some(_)) => true,
        (Some(left), Some(right)) => {
            // it was         (inner1.is_ipv4() && inner2.is_ipv6()) || (inner2.is_ipv4() && inner1.is_ipv6())
            (left.is_ipv4() && right.is_ipv4())
                || (left.is_ipv6() && right.is_ipv6())
        }
    }
}

pub(crate) fn is_ipv6(
    src: Option<std::net::SocketAddr>,
    dst: Option<std::net::SocketAddr>,
) -> bool {
    match (src, dst) {
        (Some(addr), None) => addr.is_ipv6(),
        (None, Some(addr)) => addr.is_ipv6(),
        (Some(left), Some(right)) => left.is_ipv6() || right.is_ipv6(),
        _ => false,
    }
}
