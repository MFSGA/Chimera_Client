mod platform;
mod utils;

#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum NetworkProtocol {
    TCP = 6,
    UDP = 17,
}
pub use platform::find_process_name;
