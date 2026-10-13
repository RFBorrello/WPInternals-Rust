#[cfg(not(target_arch = "wasm32"))]
pub mod artifacts;
#[cfg(not(target_arch = "wasm32"))]
pub mod backup_replay;
pub mod inspection;
pub mod operations;
pub mod profiles;
pub mod recovery_prepare;
pub mod recovery_replay;
pub use profiles::{capabilities, classify_usb, known_models};
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
