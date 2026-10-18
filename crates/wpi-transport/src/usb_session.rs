//! Private bounded transaction policy shared by USB/serial adapters and fault tests.
//! A failed transaction retires the session; cancelled completions are never reused.
use std::time::{Duration, Instant};
use wpi_protocol::qualcomm::{dload::ReplyDecoder, v1::MAX_REPLY_FRAME};
use wpi_protocol::{ProtocolError, Result};

const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) trait Io {
    fn packet_size(&self) -> usize;
    fn write(&mut self, bytes: &[u8], timeout: Duration) -> Result<usize>;
    fn read(&mut self, length: usize, timeout: Duration) -> Result<Vec<u8>>;
    fn cancel(&mut self);
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub(super) struct Session<T> {
    io: T,
    retired: bool,
}
impl<T: Io> Session<T> {
    pub(super) fn new(io: T) -> Self {
        Self { io, retired: false }
    }
    fn check(&self, request: &[u8], deadline: Option<Instant>) -> Result<Instant> {
        if self.retired {
            return Err(ProtocolError::Transport(
                "Native session retired after a failed transfer; inspect device state and reopen"
                    .into(),
            ));
        }
        if request.is_empty() || request.len() > 65536 {
            return Err(ProtocolError::Invalid(
                "invalid native request bound".into(),
            ));
        }
        let end = self.io.now() + TRANSACTION_TIMEOUT;
        let end = deadline.map_or(end, |d| d.min(end));
        self.remaining(end)?;
        Ok(end)
    }
    fn remaining(&self, end: Instant) -> Result<Duration> {
        let remaining = end.saturating_duration_since(self.io.now());
        if remaining.is_zero() {
            return Err(ProtocolError::Transport(
                "Native transaction deadline expired".into(),
            ));
        }
        Ok(remaining)
    }
    fn finish<R>(&mut self, result: Result<R>) -> Result<R> {
        if result.is_err() {
            self.retired = true;
            self.io.cancel();
        }
        result
    }
    fn write(&mut self, request: &[u8], end: Instant) -> Result<()> {
        let actual = self.io.write(request, self.remaining(end)?)?;
        if actual != request.len() {
            return Err(ProtocolError::Transport(
                "Incomplete native output transfer; delivery is uncertain and no retry was sent"
                    .into(),
            ));
        }
        self.remaining(end)?;
        Ok(())
    }
    /// Send-only mode commands intentionally have no IN transaction.
    pub(super) fn send_once(&mut self, request: &[u8], deadline: Option<Instant>) -> Result<()> {
        let end = self.check(request, deadline)?;
        let result = self.write(request, end);
        self.finish(result)
    }
    pub(super) fn exchange(
        &mut self,
        request: &[u8],
        maximum_response: usize,
        deadline: Option<Instant>,
    ) -> Result<Vec<u8>> {
        let end = self.check(request, deadline)?;
        if maximum_response == 0 || maximum_response > 1024 * 1024 {
            return Err(ProtocolError::Invalid("invalid response bound".into()));
        }
        let packet = self.io.packet_size();
        if packet == 0 || packet > 65536 {
            return Err(ProtocolError::Invalid("invalid USB IN packet size".into()));
        }
        let length = maximum_response.div_ceil(packet) * packet;
        let result = (|| {
            self.write(request, end)?;
            let response = self.io.read(length, self.remaining(end)?)?;
            self.remaining(end)?;
            if response.is_empty() {
                return Err(ProtocolError::Transport(
                    "empty USB response; device may have disconnected".into(),
                ));
            }
            if response.len() > maximum_response {
                return Err(ProtocolError::Invalid("USB response exceeds bound".into()));
            }
            Ok(response)
        })();
        self.finish(result)
    }

    /// One request and one bounded HDLC reply assembled across native reads.
    /// A short IN is a fragment, never a reason to retransmit OUT or reset time.
    pub(super) fn exchange_framed(
        &mut self,
        request: &[u8],
        maximum_response: usize,
        deadline: Option<Instant>,
    ) -> Result<Vec<u8>> {
        let end = self.check(request, deadline)?;
        if maximum_response == 0 || maximum_response > MAX_REPLY_FRAME {
            return Err(ProtocolError::Invalid(
                "invalid framed response bound".into(),
            ));
        }
        let packet = self.io.packet_size();
        if packet == 0 || packet > 65536 {
            return Err(ProtocolError::Invalid("invalid USB IN packet size".into()));
        }
        let result = (|| {
            self.write(request, end)?;
            let mut decoder = ReplyDecoder::default();
            let mut received = 0;
            loop {
                let available = maximum_response - received;
                if available == 0 {
                    return Err(ProtocolError::Invalid(
                        "incomplete framed reply at limit".into(),
                    ));
                }
                // Request one packet, so a complete frame ending on a full USB
                // packet does not need a ZLP to finish an oversized IN request.
                let fragment = self.io.read(packet, self.remaining(end)?)?;
                self.remaining(end)?;
                if fragment.len() > available {
                    return Err(ProtocolError::Invalid("framed reply exceeds bound".into()));
                }
                received += fragment.len();
                if let Some(frame) = decoder.push(&fragment)? {
                    return Ok(frame);
                }
            }
        })();
        self.finish(result)
    }
}

pub(super) struct NativeIo {
    input: nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::In>,
    output: nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::Out>,
}
impl NativeIo {
    pub(super) fn new(
        interface: nusb::Interface,
        input: u8,
        output: u8,
    ) -> std::result::Result<Self, nusb::Error> {
        use nusb::transfer::{Bulk, In, Out};
        Ok(Self {
            input: interface.endpoint::<Bulk, In>(input)?,
            output: interface.endpoint::<Bulk, Out>(output)?,
        })
    }
}
impl Io for NativeIo {
    fn packet_size(&self) -> usize {
        self.input.max_packet_size()
    }
    fn write(&mut self, bytes: &[u8], timeout: Duration) -> Result<usize> {
        self.output
            .submit(nusb::transfer::Buffer::from(bytes.to_vec()));
        let result = self.output.wait_next_complete(timeout).ok_or_else(|| {
            ProtocolError::Transport("USB OUT timed out; delivery is uncertain".into())
        })?;
        result
            .status
            .map_err(|e| ProtocolError::Transport(e.to_string()))?;
        Ok(result.actual_len)
    }
    fn read(&mut self, length: usize, timeout: Duration) -> Result<Vec<u8>> {
        self.input.submit(nusb::transfer::Buffer::new(length));
        let result = self.input.wait_next_complete(timeout).ok_or_else(|| {
            ProtocolError::Transport("USB IN timed out; command outcome is uncertain".into())
        })?;
        result
            .status
            .map_err(|e| ProtocolError::Transport(e.to_string()))?;
        let mut bytes = result.buffer.into_vec();
        if result.actual_len > length || result.actual_len > bytes.len() {
            return Err(ProtocolError::Invalid(
                "inconsistent USB IN completion length".into(),
            ));
        }
        bytes.truncate(result.actual_len);
        Ok(bytes)
    }
    fn cancel(&mut self) {
        self.output.cancel_all();
        self.input.cancel_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Fake {
        now: Instant,
        packet: usize,
        written: Vec<Vec<u8>>,
        reads: Vec<(usize, Duration)>,
        write_timeouts: Vec<Duration>,
        cancellations: usize,
        output: VecDeque<Result<usize>>,
        input: VecDeque<Result<Vec<u8>>>,
        write_elapsed: Duration,
        read_elapsed: Duration,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                now: Instant::now(),
                packet: 64,
                written: vec![],
                reads: vec![],
                write_timeouts: vec![],
                cancellations: 0,
                output: VecDeque::new(),
                input: VecDeque::new(),
                write_elapsed: Duration::ZERO,
                read_elapsed: Duration::ZERO,
            }
        }
    }
    impl Io for Fake {
        fn packet_size(&self) -> usize {
            self.packet
        }
        fn now(&self) -> Instant {
            self.now
        }
        fn write(&mut self, bytes: &[u8], timeout: Duration) -> Result<usize> {
            self.written.push(bytes.to_vec());
            self.write_timeouts.push(timeout);
            self.now += self.write_elapsed;
            self.output.pop_front().expect("unexpected OUT")
        }
        fn read(&mut self, length: usize, timeout: Duration) -> Result<Vec<u8>> {
            self.reads.push((length, timeout));
            self.now += self.read_elapsed;
            self.input.pop_front().expect("unexpected IN")
        }
        fn cancel(&mut self) {
            self.cancellations += 1;
        }
    }
    fn fault() -> ProtocolError {
        ProtocolError::Transport("injected USB failure".into())
    }
    fn assert_retired(session: &mut Session<Fake>) {
        let counts = (session.io.written.len(), session.io.reads.len());
        assert!(session
            .exchange(&[9], 16, None)
            .unwrap_err()
            .to_string()
            .contains("retired"));
        assert!(session
            .send_once(&[9], None)
            .unwrap_err()
            .to_string()
            .contains("retired"));
        assert!(session
            .exchange_framed(&[9], 16, None)
            .unwrap_err()
            .to_string()
            .contains("retired"));
        assert_eq!(counts, (session.io.written.len(), session.io.reads.len()));
        assert_eq!(session.io.cancellations, 1);
    }
    #[test]
    fn successful_exchanges_reuse_session_and_bound_allocations() {
        let mut io = Fake::default();
        io.output.extend([Ok(1), Ok(1), Ok(1)]);
        io.input.extend([Ok(vec![1, 2]), Ok(vec![3])]);
        let mut session = Session::new(io);
        assert_eq!(session.exchange(&[7], 65, None).unwrap(), [1, 2]);
        assert_eq!(session.exchange(&[8], 1, None).unwrap(), [3]);
        session.send_once(&[9], None).unwrap();
        assert_eq!(
            session.io.reads,
            [(128, TRANSACTION_TIMEOUT), (64, TRANSACTION_TIMEOUT)]
        );
        assert_eq!(session.io.written, [vec![7], vec![8], vec![9]]);
        assert_eq!(session.io.cancellations, 0);
    }
    #[test]
    fn partial_and_failed_out_never_send_remainder_or_read_stale_reply() {
        for completion in [Ok(0), Ok(1), Ok(3), Err(fault())] {
            let mut io = Fake::default();
            io.output.push_back(completion);
            io.input.push_back(Ok(vec![0xaa]));
            let mut session = Session::new(io);
            assert!(session.exchange(&[1, 2], 16, None).is_err());
            assert_eq!(session.io.written, [vec![1, 2]]);
            assert!(session.io.reads.is_empty());
            assert_retired(&mut session);
            assert_eq!(session.io.input.len(), 1);
        }
    }
    #[test]
    fn failed_empty_and_oversized_in_retire_session() {
        for response in [Err(fault()), Ok(vec![]), Ok(vec![0; 17])] {
            let mut io = Fake::default();
            io.output.push_back(Ok(1));
            io.input.extend([response, Ok(vec![0xbb])]);
            let mut session = Session::new(io);
            assert!(session.exchange(&[1], 16, None).is_err());
            assert_eq!(session.io.written.len(), 1);
            assert_eq!(session.io.reads.len(), 1);
            assert_retired(&mut session);
            assert_eq!(session.io.input.len(), 1);
        }
    }
    #[test]
    fn out_and_in_share_one_deadline_with_operation_cap() {
        for cap in [2, 5, 20] {
            let mut io = Fake {
                write_elapsed: Duration::from_secs(1),
                ..Fake::default()
            };
            io.output.push_back(Ok(1));
            io.input.push_back(Ok(vec![1]));
            let deadline = io.now + Duration::from_secs(cap);
            let mut session = Session::new(io);
            session.exchange(&[1], 16, Some(deadline)).unwrap();
            assert_eq!(session.io.write_timeouts, [Duration::from_secs(cap.min(5))]);
            assert_eq!(session.io.reads[0].1, Duration::from_secs(cap.min(5) - 1));
        }
    }
    #[test]
    fn deadline_expiry_after_out_or_in_is_terminal() {
        for (write_secs, read_secs, reads) in [(5, 0, 0), (0, 5, 1), (4, 2, 1)] {
            let mut io = Fake {
                write_elapsed: Duration::from_secs(write_secs),
                read_elapsed: Duration::from_secs(read_secs),
                ..Fake::default()
            };
            io.output.push_back(Ok(1));
            io.input.push_back(Ok(vec![1]));
            let mut session = Session::new(io);
            assert!(session.exchange(&[1], 16, None).is_err());
            assert_eq!(session.io.reads.len(), reads);
            assert_retired(&mut session);
        }
    }
    #[test]
    fn local_validation_sends_nothing_and_does_not_retire_session() {
        let mut session = Session::new(Fake::default());
        for request in [vec![], vec![0; 65537]] {
            assert!(session.exchange(&request, 16, None).is_err());
            assert!(session.send_once(&request, None).is_err());
        }
        for bound in [0, 1024 * 1024 + 1] {
            assert!(session.exchange(&[1], bound, None).is_err());
        }
        for packet in [0, 65537] {
            session.io.packet = packet;
            assert!(session.exchange(&[1], 16, None).is_err());
        }
        let expired = session.io.now;
        assert!(session.exchange(&[1], 16, Some(expired)).is_err());
        assert!(session.send_once(&[1], Some(expired)).is_err());
        assert!(session.io.written.is_empty());
        assert!(session.io.reads.is_empty());
        assert_eq!(session.io.cancellations, 0);
        session.io.packet = 64;
        session.io.output.push_back(Ok(1));
        session.send_once(&[1], None).unwrap();
    }
    #[test]
    fn failed_send_only_retires_session_without_waiting_for_reply() {
        for completion in [Ok(0), Err(fault())] {
            let mut io = Fake::default();
            io.output.push_back(completion);
            let mut session = Session::new(io);
            assert!(session.send_once(&[1], None).is_err());
            assert!(session.io.reads.is_empty());
            assert_retired(&mut session);
        }
    }

    #[test]
    fn framed_reply_accepts_every_split_and_bytewise_escapes_and_crc() {
        use wpi_protocol::qualcomm::encode_hdlc;
        for payload in [vec![2], vec![0x18, 1, 0, 0x7e, 0x7d, 4]] {
            let frame = encode_hdlc(&payload).unwrap();
            for split in 1..frame.len() {
                let mut io = Fake::default();
                io.output.push_back(Ok(1));
                io.input
                    .extend([Ok(frame[..split].to_vec()), Ok(frame[split..].to_vec())]);
                let mut session = Session::new(io);
                assert_eq!(
                    session.exchange_framed(&[6], frame.len(), None).unwrap(),
                    frame
                );
                assert_eq!(session.io.written, [vec![6]]);
                assert_eq!(session.io.reads.len(), 2);
            }
            let mut io = Fake::default();
            io.output.push_back(Ok(1));
            io.input.extend(frame.iter().map(|b| Ok(vec![*b])));
            let mut session = Session::new(io);
            assert_eq!(
                session.exchange_framed(&[6], frame.len(), None).unwrap(),
                frame
            );
            assert_eq!(session.io.reads.len(), frame.len());
        }
    }
    #[test]
    fn framed_malformed_trailing_oversized_or_incomplete_reply_retires() {
        let frame = wpi_protocol::qualcomm::encode_hdlc(&[2]).unwrap();
        let mut bad_crc = frame.clone();
        bad_crc[1] ^= 1;
        let mut trailing = frame.clone();
        trailing.extend_from_slice(&frame);
        for (fragments, bound) in [
            (vec![Ok(vec![])], 32),
            (vec![Ok(vec![1])], 32),
            (vec![Ok(bad_crc)], 32),
            (vec![Ok(trailing)], 32),
            (vec![Ok(vec![0x7e, 1, 1, 1])], 4),
            (vec![Ok(frame.clone())], frame.len() - 1),
            (vec![Ok(vec![0x7e]), Err(fault())], 32),
        ] {
            let mut io = Fake::default();
            io.output.push_back(Ok(1));
            let expected_reads = fragments.len();
            io.input.extend(fragments);
            io.input.push_back(Ok(frame.clone()));
            let mut session = Session::new(io);
            assert!(session.exchange_framed(&[6], bound, None).is_err());
            assert_eq!(session.io.written.len(), 1);
            assert_eq!(session.io.reads.len(), expected_reads);
            assert_retired(&mut session);
            assert_eq!(session.io.input.len(), 1);
        }
    }
    #[test]
    fn fragmented_reads_share_deadline_and_never_repeat_out() {
        let frame = wpi_protocol::qualcomm::encode_hdlc(&[2]).unwrap();
        let mut io = Fake {
            write_elapsed: Duration::from_secs(1),
            read_elapsed: Duration::from_secs(1),
            ..Fake::default()
        };
        io.output.push_back(Ok(1));
        io.input.extend(frame.iter().map(|b| Ok(vec![*b])));
        let mut session = Session::new(io);
        assert!(session.exchange_framed(&[6], 32, None).is_err());
        assert_eq!(
            session
                .io
                .reads
                .iter()
                .map(|r| r.1.as_secs())
                .collect::<Vec<_>>(),
            [4, 3, 2, 1]
        );
        assert_eq!(session.io.written, [vec![6]]);
        assert_retired(&mut session);
    }
    #[test]
    fn framed_limits_and_short_out_stop_before_in() {
        let mut session = Session::new(Fake::default());
        for bound in [0, MAX_REPLY_FRAME + 1] {
            assert!(session.exchange_framed(&[6], bound, None).is_err());
        }
        assert!(session.io.written.is_empty());
        session.io.output.push_back(Ok(0));
        assert!(session.exchange_framed(&[6], 32, None).is_err());
        assert!(session.io.reads.is_empty());
        assert_retired(&mut session);
    }
    #[test]
    fn maximum_framed_reply_uses_packet_reads_and_accepts_bytewise_delivery() {
        let frame = (1..=120)
            .find_map(|value| {
                let frame =
                    wpi_protocol::qualcomm::encode_hdlc(&vec![value; MAX_REPLY_FRAME - 4]).unwrap();
                (frame.len() == MAX_REPLY_FRAME).then_some(frame)
            })
            .unwrap();
        for fragment_length in [1, 64] {
            let mut io = Fake::default();
            io.output.push_back(Ok(1));
            io.input
                .extend(frame.chunks(fragment_length).map(|c| Ok(c.to_vec())));
            let mut session = Session::new(io);
            assert_eq!(
                session
                    .exchange_framed(&[6], MAX_REPLY_FRAME, None)
                    .unwrap(),
                frame
            );
            assert_eq!(session.io.reads.len(), MAX_REPLY_FRAME / fragment_length);
            assert!(session.io.reads.iter().all(|(length, _)| *length == 64));
            assert_eq!(session.io.written.len(), 1);
            assert!(session.io.input.is_empty());
        }
    }
}
