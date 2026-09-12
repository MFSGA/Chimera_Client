pub(crate) fn ipv6_fragment_next_header(
    packet: &[u8],
) -> std::io::Result<Option<etherparse::IpNumber>> {
    let header = etherparse::Ipv6HeaderSlice::from_slice(packet)
        .map_err(std::io::Error::other)?;
    let payload_len = usize::from(header.payload_length());
    let end = etherparse::Ipv6Header::LEN
        .checked_add(payload_len)
        .ok_or_else(|| std::io::Error::other("IPv6 payload length overflow"))?;
    if packet.len() < end {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "truncated IPv6 packet",
        ));
    }

    let mut next = header.next_header();
    let mut rest = &packet[etherparse::Ipv6Header::LEN..end];
    loop {
        match next {
            etherparse::ip_number::IPV6_FRAG => {
                let fragment = etherparse::Ipv6FragmentHeaderSlice::from_slice(rest)
                    .map_err(std::io::Error::other)?;
                return if fragment.is_fragmenting_payload() {
                    Ok(Some(fragment.next_header()))
                } else {
                    Ok(None)
                };
            }
            etherparse::ip_number::IPV6_HOP_BY_HOP
            | etherparse::ip_number::IPV6_DEST_OPTIONS
            | etherparse::ip_number::IPV6_ROUTE => {
                let extension = etherparse::Ipv6RawExtHeaderSlice::from_slice(rest)
                    .map_err(std::io::Error::other)?;
                next = extension.next_header();
                rest = &rest[extension.slice().len()..];
            }
            etherparse::ip_number::AUTH => {
                let extension = etherparse::IpAuthHeaderSlice::from_slice(rest)
                    .map_err(std::io::Error::other)?;
                next = extension.next_header();
                rest = &rest[extension.slice().len()..];
            }
            _ => return Ok(None),
        }
    }
}
