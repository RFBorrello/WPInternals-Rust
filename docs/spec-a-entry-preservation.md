# Spec A entry preservation: conservative bound and reference-code interpretation

**Update:** [Exact reference FlashApp analysis](spec-a-entry-code.md) now shows
that binary skipping end-relative payload locations and separately clearing only
the last 33 GPT sectors on header import. The installed binary remains unverified.
The bound below is retained for unknown implementations; it is not the inferred
footprint for that exact reference binary. Native reports now show both models.

The boot-component programmer plan excludes MainOS, Data and EFIESP, but that
does not establish preservation through the **earlier emergency entry**. The
entry profile's first zero payload has both begin-relative and end-relative
128 KiB mappings. `EntryPlan` verifies that profile before a prepared session can
be constructed. The pinned upstream
[FFU parser](https://github.com/ReneLergner/WPinternals/blob/d8fd0aa516b16dc094df0422a3adc525af005c29/Models/FFU.cs)
labels access method 2 as relative to the end and ignores it for source extraction.
That extraction behavior is not evidence of how the phone applies the payload.

## Conservative model, not observed damage

The new `spec_a_entry_impact::assess` models complete first/last chunks against
the saved installed partition ranges in the same opaque prepared bundle. It
requires a bounded capacity aligned to the known 128 KiB chunk size. Unknown
geometry fails rather than producing a clear assessment. It exports names,
ranges and intersections, never disk GUIDs, serials or partition contents.

For the saved RM-875 layout, the modeled final chunk intersects **223 sectors
(114,176 bytes)** of the Data partition, in addition to the disk's trailing
metadata. An independent Python calculation on the saved GPT agrees with the
[local model record](../tests/fixtures/rm875-entry-impact-model.json).
This is an exposure under a conservative whole-chunk interpretation. It does
**not** establish that this FlashApp would write all those sectors, that the
sectors contain allocated files, or that any data has been damaged.

No entry header or payload has been sent to the test phone. The subsequent
[prepared hardware cycle](../tests/hardware/lumia-1020-rm875-prepared-cycle.json)
was read-only apart from two mode commands and returned successfully to Normal.
It did not test this write interpretation.

The saved primary GPT and stock reference ZIP cannot reconstruct original user
bytes from that end range. No capture of those installed bytes is available.
The new impact report therefore leaves physical write interpretation, affected
byte capture, preservation and write capability false. It accompanies native
Normal session reports and future prepared-cycle journal headers. It cannot
authorize execution or be imported to clear a gate.

## Work needed before physical entry

The [experimental native controller](spec-a-native-controller.md) is now
implemented; the installed FlashApp binary, entry interpretation and data
preservation still require physical evidence. Its preview states those limits
and does not turn the reference interpretation into installed-binary proof.

Determine the actual device-side end-mapping behavior or establish a mode-entry
route that avoids the zero payload. Then bind any required installed-range
captures to the selected device and define restoration after partial entry.
This can involve targeted affected-range backups; a universal requirement for a
complete raw device backup is not implied. The separate native emergency writer,
mass-storage continuation and full recovery validation are also unfinished.

Pinned `SwitchModeViewModel` contains the non-payload `NOKXCBE` emergency command,
but describes the route as available on newer Lumias. It is a research candidate,
not verified support for the RM-875. It has not been sent in this milestone and
must not become an automatic fallback or an assumed recovery mechanism.

Tests cover the 223-sector boundary intersection, a shorter Data partition that
does not intersect, reserved ranges, invalid bounds, capacity overflow and
unknown alignment. The calculation models potential exposure; resolving its
physical meaning on the installed firmware is still required before a
data-preserving unlock can be claimed. A new offline GPT recovery capsule and
bounded native targeted-capture path are described in the linked analysis; no
installed snapshot or successful physical recovery has been recorded.
