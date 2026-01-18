#[cfg(not(all(target_feature = "crt-static", target_env = "gnu")))]
#[path = "system.rs"]
mod system;

pub use system::SystemResolver;
