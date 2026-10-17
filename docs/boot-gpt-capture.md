# Capturing the live primary GPT during return boot

This CLI-only experiment extends the RM-875 / 3051.50009.1451.1003 / native
Windows ARM64 preflight cycle. It is initially covered by synthetic/replay tests;
physical validation is recorded separately. It does not unlock or flash a phone.

```text
wpi boot-gpt-test stock.ffu SELECTED_ID new-primary-gpt.bin
wpi boot-gpt-test stock.ffu SELECTED_ID new-primary-gpt.bin --execute --confirm RM875-BOOT-GPT-READ-ROUNDTRIP --report new-local-journal.jsonl
```

Preview performs only Normal information/public-ID reads and checks that a new
local destination can be created. Execution requires a distinct reviewed cycle.
It enters Flash once, verifies the fresh Normal/Flash public ID and physical
port, compares RRKH/SS, and records the current Flash eMMC capacity. It then
sends the usual identity-revalidated NOKR once to return to Normal.

The existing return observer can see a transient BootManager interface. The
new reader accepts only the previously observed BootMgr 1.16 / protocol 1.1 /
transfer size 2,363,392 / no platform ID profile on the same physical port.
It sends NOKV, NOKT, NOKT, NOKV on one new handle, under an eight-second deadline.
It never requests a BootManager public ID, holds its reboot timer with NOKD,
switches contexts with NOKXCBB, or sends a further reboot to catch a missed
window. Missing the window or encountering a different profile fails the
capture; the two mode commands are never automatically repeated.

The returned 34 primary sectors include MBR, primary GPT header and 128 entries
of 128 bytes. Both reads must agree byte-for-byte. Header/table CRCs, entry
geometry, identities, overlaps and bounds are validated against this cycle's
fresh Flash capacity; the backup header location and reserved table space must
fit that capacity. BootManager information must remain unchanged across reads.
The SHA-256 digest is compared with the stock FFU primary digest, but a difference
is preserved and reported rather than replaced with source FFU coordinates.

Only 17,408 bytes are retained. They remain in memory until the observer verifies
the original returning Normal serial, model, firmware and public ID on the same
port. The primary GPT is then published atomically to a **new** file, with a
re-read digest check and no overwrite. A timeout, changed identity, failed
preflight/GPT read, cancellation or journal failure before publication produces
no primary file. A failure after atomic publication can leave the verified file;
inspect it rather than rerunning or overwriting it. Crashes before publication
lose the in-memory candidate.

BootManager has no verified public-ID query in this workflow. Correlation uses
the physical port plus the Normal/Flash/returning-Normal identities; it is not
cryptographically authenticated device identity. Public journal reports contain
hashes/counts/capacity, not GPT GUIDs, raw sectors or public-ID values. The local
binary contains installed disk identifiers and must remain private.

This preserves only the **live primary GPT**. It does not capture the backup GPT,
installed boot partitions or a full-device backup, authenticate OEM firmware,
validate downgrade/donor/loader acceptance, or enable recovery/unlock writes.
Normal boot may outpace USB discovery; waiting for its verified interface does
not mean the phone is still visibly booting. A failed USB check may require a
manual restart after inspecting phone state.
