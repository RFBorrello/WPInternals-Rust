# Native USB transaction lifetime

The native `UsbMessages` adapter now shares one private transaction policy with
fault-injection tests. Each exchange submits exactly one OUT and one IN transfer.
An incomplete OUT never causes a remainder write. Send-only mode commands submit
only OUT; this change adds no commands or operation permissions.

Request and response bounds, IN packet size and an already expired operation
deadline are checked before OUT. Local argument rejection sends nothing and leaves
the session usable. A transaction has one five-second budget shared by OUT and
IN, capped by the caller's earlier operation deadline. Previously OUT and IN could
each wait up to five seconds. Returned completions are checked against the same
deadline; the IN wait does not restart the budget after OUT.

Once a transaction starts, any transfer error, short OUT, deadline expiry, empty
IN or oversized IN permanently retires the session. Both endpoints are cancelled.
All subsequent exchange and send-only calls fail before submitting anything,
including when cancellation completions remain queued. There is no queue drain,
automatic reopening, remainder retry or request replay. Callers must inspect device
state before deciding whether a new session is appropriate. Retirement is local
to the handle; it does not itself prevent a caller from explicitly reopening.

The endpoint adapter checks completion status before using bytes, validates the
reported length against the allocation and buffer, and returns only the completed
IN bytes. USB success is not protocol validation or proof of device acceptance;
existing codecs and operation admission checks still apply.

## Validation and remaining work

Seven deterministic tests inject incomplete and failed OUT, failed/empty/oversized
IN, stale queued replies, expiration after OUT or IN, operation deadlines and
invalid local arguments. A fake clock proves that the remaining IN budget shrinks
after OUT without sleeping. Successful multiple exchanges and send-only behavior
are also covered. These tests exercise the transaction policy through injected I/O,
not physical driver cancellation or disconnects.

A read-only native Windows ARM64 identification run using the updated CLI passed
on the connected RM-875 in Normal mode. The sanitized
[hardware record](../tests/hardware/lumia-1020-rm875-usb-session-probe.json) records
the executable hash and scope. It establishes successful information reads only;
no mode changes, fault injection on hardware, programmer upload or writes occurred.

This remains a single-message Normal/Flash adapter. Native fragmented HDLC replies,
serial communication beyond discovery, emergency/programmer arrival handling and
fresh admission for an unlock session still need implementation and validation.
The joined unlock API continues to accept only concrete replay transports. No
unlock, data-preservation or recovery capability is enabled by this change.
