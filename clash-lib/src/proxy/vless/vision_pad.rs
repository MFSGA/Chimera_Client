use bytes::{BufMut, Bytes, BytesMut};
use rand::RngExt;

const LONG_PADDING_MIN: usize = 900;
const LONG_PADDING_RANDOM_MAX: usize = 500;
const SHORT_PADDING_RANDOM_MAX: usize = 256;
const MAX_PADDING_SIZE: usize = 8171;

pub fn pad_with_uuid_and_command(
    data: &[u8],
    uuid: &[u8; 16],
    command: u8,
    is_tls: bool,
) -> Bytes {
    pad(data, Some(uuid), command, is_tls)
}

pub fn pad_with_command(data: &[u8], command: u8, is_tls: bool) -> Bytes {
    pad(data, None, command, is_tls)
}

fn pad(data: &[u8], uuid: Option<&[u8; 16]>, command: u8, is_tls: bool) -> Bytes {
    let content_len = data.len() as u16;
    let padding_len = calculate_padding_length(content_len as usize, is_tls);
    let uuid_len = if uuid.is_some() { 16 } else { 0 };
    let mut output =
        BytesMut::with_capacity(uuid_len + 5 + data.len() + padding_len);

    if let Some(uuid) = uuid {
        output.put_slice(uuid);
    }

    output.put_u8(command);
    output.put_u16(content_len);
    output.put_u16(padding_len as u16);
    output.put_slice(data);

    if padding_len > 0 {
        let padding_start = output.len();
        output.resize(padding_start + padding_len, 0);
        rand::rng().fill(&mut output[padding_start..]);
    }

    output.freeze()
}

fn calculate_padding_length(content_len: usize, is_tls: bool) -> usize {
    let max_allowable = MAX_PADDING_SIZE.saturating_sub(content_len);
    let padding = if is_tls && content_len < LONG_PADDING_MIN {
        LONG_PADDING_MIN
            .saturating_sub(content_len)
            .saturating_add(rand::rng().random_range(0..LONG_PADDING_RANDOM_MAX))
    } else {
        rand::rng().random_range(0..SHORT_PADDING_RANDOM_MAX)
    };
    padding.min(max_allowable)
}
