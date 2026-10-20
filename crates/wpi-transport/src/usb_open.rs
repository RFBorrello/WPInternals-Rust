//! Only a missing Windows WinUSB path BEFORE any protocol transfer is waitable.
//! Permission, driver, descriptor, transfer and post-open errors remain terminal.
#[derive(Debug)]
pub(super) enum OpenError {
    PathNotReady(String),
    Fatal(String),
}
impl OpenError {
    pub(super) fn message(self) -> String {
        match self {
            Self::PathNotReady(message) | Self::Fatal(message) => message,
        }
    }
    pub(super) fn claim(error: nusb::Error) -> Self {
        let message = error.to_string();
        let waitable =
            cfg!(windows) && missing_interface_path(error.kind(), error.os_error(), &message);
        let message = format!("Cannot claim USB interface: {message}");
        if waitable {
            Self::PathNotReady(message)
        } else {
            Self::Fatal(message)
        }
    }
}
impl From<String> for OpenError {
    fn from(message: String) -> Self {
        Self::Fatal(message)
    }
}
impl From<&str> for OpenError {
    fn from(message: &str) -> Self {
        Self::Fatal(message.into())
    }
}
fn missing_interface_path(kind: nusb::ErrorKind, code: Option<u32>, message: &str) -> bool {
    // nusb 0.2.7 windows_winusb/enumeration.rs emits this exact synthetic error
    // after driver/GUID resolution but before opening the interface path. It
    // reports Unsupported, so that broad kind alone must NEVER permit a retry.
    kind == nusb::ErrorKind::Unsupported
        && code.is_none()
        && message == "failed to find device path for WinUSB interface"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_preopen_missing_child_path_is_waitable() {
        let message = "failed to find device path for WinUSB interface";
        assert!(missing_interface_path(
            nusb::ErrorKind::Unsupported,
            None,
            message
        ));
        for kind in [
            nusb::ErrorKind::PermissionDenied,
            nusb::ErrorKind::Busy,
            nusb::ErrorKind::Disconnected,
            nusb::ErrorKind::NotFound,
            nusb::ErrorKind::Other,
        ] {
            assert!(!missing_interface_path(kind, None, message));
        }
        assert!(!missing_interface_path(
            nusb::ErrorKind::Unsupported,
            Some(5),
            message
        ));
        for message in ["incompatible driver is installed for this interface",
            "Could not find DeviceInterfaceGUIDs in registry. WinUSB driver may not be correctly installed for this interface.",
            "failed to find device path for WinUSB device", "Interface not found"] {
            assert!(!missing_interface_path(nusb::ErrorKind::Unsupported, None, message));
        }
    }
}
