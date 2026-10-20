//! A successful arrival claim stays open through classification and its callback.
use crate::usb_open::OpenError;
use wpi_protocol::{flash::FlashInfo, preflight, MessageTransport};
use wpi_types::DeviceMode;

pub(super) struct Application<'a, T> {
    pub(super) info: Option<FlashInfo>,
    pub(super) channel: &'a mut T,
}

/// None means no protocol request was submitted: only path discovery may wait.
/// Once open succeeds, every failure is terminal, including a failed NOKV.
pub(super) fn inspect<T: MessageTransport>(
    mode: DeviceMode,
    open: impl FnOnce() -> Result<T, OpenError>,
    mut boundary: impl FnMut() -> Result<(), String>,
    inspect: impl FnOnce(Option<Application<'_, T>>) -> Result<bool, String>,
) -> Result<Option<(DeviceMode, bool)>, String> {
    boundary()?;
    if !matches!(mode, DeviceMode::Flash | DeviceMode::Normal) {
        let accepted = inspect(None)?;
        boundary()?;
        return Ok(Some((mode, accepted)));
    }
    let mut channel = match open() {
        Ok(channel) => channel,
        Err(OpenError::PathNotReady(_)) => {
            boundary()?;
            return Ok(None);
        }
        Err(error) => return Err(error.message()),
    };
    boundary()?;
    let info = if mode == DeviceMode::Flash {
        Some(
            preflight::parse_application(
                &channel
                    .exchange(b"NOKV", 65536)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?
            .0,
        )
    } else {
        None // Normal uses its own guarded five-query protocol on this handle.
    };
    boundary()?;
    let actual = info.as_ref().map_or(mode, |info| info.mode);
    let accepted = inspect(Some(Application {
        info,
        channel: &mut channel,
    }))?;
    boundary()?;
    Ok(Some((actual, accepted)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::VecDeque};
    use wpi_protocol::ProtocolError;

    struct Fake<'a> {
        requests: &'a Cell<usize>,
        replies: VecDeque<wpi_protocol::Result<Vec<u8>>>,
    }
    impl MessageTransport for Fake<'_> {
        fn exchange(&mut self, request: &[u8], _: usize) -> wpi_protocol::Result<Vec<u8>> {
            let at = self.requests.get();
            assert_eq!(request, if at == 0 { b"NOKV" } else { b"NOKT" });
            self.requests.set(at + 1);
            self.replies.pop_front().expect("unexpected extra request")
        }
    }
    fn boot() -> Vec<u8> {
        b"NOKV\0\x01\x01\x01\x01\x10\x00".to_vec()
    }
    #[test]
    fn missing_path_waits_without_a_query_then_reuses_the_single_successful_claim() {
        let requests = Cell::new(0);
        let opens = Cell::new(0);
        for _ in 0..3 {
            let result = inspect::<Fake<'_>>(
                DeviceMode::Flash,
                || {
                    opens.set(opens.get() + 1);
                    Err(OpenError::PathNotReady("missing path".into()))
                },
                || Ok(()),
                |_| panic!("unopened callback"),
            );
            assert_eq!(result.unwrap(), None);
        }
        assert_eq!(requests.get(), 0);
        let result = inspect(
            DeviceMode::Flash,
            || {
                opens.set(opens.get() + 1);
                Ok(Fake {
                    requests: &requests,
                    replies: [Ok(boot()), Ok(b"GPT read".to_vec())].into(),
                })
            },
            || Ok(()),
            |application| {
                let application = application.unwrap();
                assert_eq!(application.info.unwrap().mode, DeviceMode::BootManager);
                assert_eq!(
                    application.channel.exchange(b"NOKT", 65536).unwrap(),
                    b"GPT read"
                );
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(result, Some((DeviceMode::BootManager, true)));
        assert_eq!(opens.get(), 4); // Three path lookups, only one successful claim.
        assert_eq!(requests.get(), 2);
    }
    #[test]
    fn permission_or_driver_error_is_terminal_without_a_query() {
        for message in ["permission denied", "incompatible driver"] {
            assert!(inspect::<Fake<'_>>(
                DeviceMode::Flash,
                || Err(OpenError::Fatal(message.into())),
                || Ok(()),
                |_| panic!("failed claim callback")
            )
            .unwrap_err()
            .contains(message));
        }
    }
    #[test]
    fn failed_or_malformed_query_never_becomes_path_readiness() {
        for reply in [
            Err(ProtocolError::Transport("disconnect after OUT".into())),
            Ok(b"NOKU".to_vec()),
            Ok(vec![]),
        ] {
            let requests = Cell::new(0);
            assert!(inspect(
                DeviceMode::Flash,
                || Ok(Fake {
                    requests: &requests,
                    replies: [reply].into()
                }),
                || Ok(()),
                |_| panic!("failed query callback")
            )
            .is_err());
            assert_eq!(requests.get(), 1);
        }
    }
    #[test]
    fn callback_failure_is_terminal_after_one_claim_and_classification() {
        let requests = Cell::new(0);
        assert!(inspect(
            DeviceMode::Flash,
            || Ok(Fake {
                requests: &requests,
                replies: [Ok(boot())].into()
            }),
            || Ok(()),
            |_| Err("GPT failure".into())
        )
        .unwrap_err()
        .contains("GPT failure"));
        assert_eq!(requests.get(), 1);
    }
    #[test]
    fn cancellation_or_deadline_after_open_prevents_the_first_protocol_request() {
        for fail_at in [1, 2] {
            let requests = Cell::new(0);
            let checks = Cell::new(0);
            assert!(inspect(
                DeviceMode::Flash,
                || Ok(Fake {
                    requests: &requests,
                    replies: VecDeque::new()
                }),
                || {
                    checks.set(checks.get() + 1);
                    if checks.get() == fail_at {
                        Err("cancelled or expired".into())
                    } else {
                        Ok(())
                    }
                },
                |_| panic!("late callback")
            )
            .is_err());
            assert_eq!(requests.get(), 0);
        }
    }
    #[test]
    fn late_classification_prevents_followup_and_emergency_never_opens() {
        let requests = Cell::new(0);
        let checks = Cell::new(0);
        assert!(inspect(
            DeviceMode::Flash,
            || Ok(Fake {
                requests: &requests,
                replies: [Ok(boot())].into()
            }),
            || {
                checks.set(checks.get() + 1);
                if checks.get() == 3 {
                    Err("expired".into())
                } else {
                    Ok(())
                }
            },
            |_| panic!("late callback")
        )
        .is_err());
        assert_eq!(requests.get(), 1);
        let result = inspect::<Fake<'_>>(
            DeviceMode::Emergency,
            || panic!("Emergency arrival must use its separate driver checkpoint"),
            || Ok(()),
            |application| {
                assert!(application.is_none());
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(result, Some((DeviceMode::Emergency, true)));
    }
    #[test]
    fn normal_arrival_waits_for_path_and_hands_over_the_same_handle_without_nokv() {
        assert_eq!(
            inspect::<Fake<'_>>(
                DeviceMode::Normal,
                || Err(OpenError::PathNotReady("missing path".into())),
                || Ok(()),
                |_| panic!("unopened Normal callback")
            )
            .unwrap(),
            None
        );
        let requests = Cell::new(0);
        let result = inspect(
            DeviceMode::Normal,
            || {
                Ok(Fake {
                    requests: &requests,
                    replies: VecDeque::new(),
                })
            },
            || Ok(()),
            |application| {
                let application = application.unwrap();
                assert!(application.info.is_none());
                assert_eq!(application.channel.requests.get(), 0);
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(result, Some((DeviceMode::Normal, true)));
        assert_eq!(requests.get(), 0);
    }
}
