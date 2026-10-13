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

See `docs/hardware-validation.md` for the first read-only sessions and evidence
requirements. Personal phone identifiers must be redacted before publication.
