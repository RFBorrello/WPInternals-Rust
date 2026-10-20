# Hardware evidence

The first successful read-only session is recorded in
`lumia-1020-rm875-windows-arm64-normal-info.json`: native normal-mode identification
of a Lumia 1020 RM-875 on Windows ARM64. It records parsed responses and driver
details, with personal identifiers omitted.

`lumia-1020-rm875-browser-normal-info.json` records the user's successful browser
identification of the same model, variant, firmware and USB identity. Its evidence
is the reported UI output, not an independently captured protocol transcript.
The exact browser name/version were not reported; host context is identified
separately from directly reported fields.

These identification sessions do not promote the model or its writing workflows to
verified support. The application retains experimental status while repeatability
and raw protocol fixtures are collected. Do not infer broader support from a model
profile, a successful CI build, or this read-only result.

`lumia-1020-rm875-public-id-mode-test-completed.json` records one complete approved
Normal/Flash/Normal cycle on native Windows ARM64, with all public-ID and final
serial/firmware checks passing. It includes command-relative USB timing, readiness
counts and a compact sanitized journal. Both mode commands completed once; no
firmware or partition writes occurred. This establishes one experiment's result
on the exact recorded combination, not repeatability or production write support.

See `docs/hardware-validation.md` for the first read-only sessions and evidence
requirements. Personal phone identifiers must be redacted before publication.

`lumia-1020-rm875-prepared-cycle.json` records one artifact-bound read-only cycle
using source commit `729f6ab` and the exact CLI digest. The pinned source/package/
loader/layout context, fresh root/security/capacity checks and identity on return
passed; two mode commands took 57,503 ms, excluding local preparation. No entry,
programmer, GPT query or storage write was sent. It does not validate unlock or
preservation. The separately labelled conservative entry-impact model is a local
calculation, not hardware evidence or observed damage.

`lumia-1020-rm875-native-unlock-preflight-path-failure.json` records the first
approved native unlock invocation stopping before emergency entry because a
WinUSB interface path could not be found. Its seven-record journal contains no
storage-changing intent. A subsequent read-only probe confirmed the original
Normal model/product/firmware. This failed invocation does not establish an
unlock, data preservation, the exact driver timing cause, or hardware validation
of the later interface-readiness fix.

`lumia-1020-rm875-native-preflight-only.json` records one explicitly approved
corrected cycle using the shared native unlock preflight and its separate
preflight-only entry point. Both GPT reads matched the saved installed layout,
the original Normal identity returned and exactly two mode commands were sent.
The returning Normal arrival handle was retained for guarded identity queries.
An earlier preflight had stopped on the remaining Normal path-readiness gap;
both outcomes and exact executable/journal digests are recorded. This validates
that single preflight, not emergency entry, unlocking or data preservation.

`lumia-1020-rm875-entry-emergency-unconfigured.json` records a separately approved
live invocation reaching entry and stopping before any RAM programmer. The header,
zero payload and reboot were acknowledged/submitted; stored bytes were not read
back. Windows PnP subsequently showed one unconfigured whole-device 9008 with
matching hub/port/location, while nusb discovery did not list it. The driver
checkpoint was not reached. Storage may have changed, the phone was reported
black-screened, and no recovery or unlock success is established.

`lumia-1020-rm875-winusb-dload.json` records the subsequent manual in-box WinUSB
binding and successful read-only DLOAD alive/root handshake on native Windows
ARM64. The exact saved instance and physical port matched, the driver was healthy,
and two queries returned valid protocol responses. Root availability is not a
reference-root comparison or authenticated model identity. No loader upload,
recovery write or unlock followed from this probe.
