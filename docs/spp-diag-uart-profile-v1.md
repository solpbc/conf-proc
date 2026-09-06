# SPP diagnostic UART profile, version 1

`SPPUART/1` is the sole diagnostic UART transport profile. It wraps, but does
not replace, the canonical binary `SPPDBN1` success stream and `SPPFLR1`
failure terminal. This document is authoritative for its wire grammar and
state rules.

## Record grammar

Each record is one printable-ASCII, LF-terminated line, in precisely this
order (with no optional fields or whitespace):

```text
SPPUART/1|k=<S|I|F>|c=<64 lowercase hex>|r=<64 lowercase hex>|n=<canonical decimal>|l=<canonical decimal>|h=<64 lowercase hex>|b=<canonical Base64>\n
```

`c` is the 32-byte challenge and `r` the 32-byte run identity. `n` starts at
zero and is strictly consecutive. Decimal is ASCII `0` or a nonzero digit
followed by digits, with no leading zero. `h` is the lowercase SHA-256 hex
digest of the decoded `b`; `b` is RFC 4648 standard Base64 with required
padding and no alternate spelling. Every record authenticates both identities,
its sequence, its decoded length, and its payload.

`S` holds 1 through 65,536 bytes of the unmodified `SPPDBN1` stream. `I` has
length one, payload `00`, and Base64 `AA==`. `F` has length 112 and its decoded
payload is an unmodified `SPPFLR1` terminal. The largest `S` line has 65,536
decoded bytes and 87,384 Base64 bytes. Its non-payload overhead is exactly 232
bytes, below the 256-byte assignment bound.

The host accepts at most a 32 MiB supplied raw blob, a 1 MiB preamble, 258
frames, 22,500,000 wire bytes, and `16 MiB + 1 + 112` decoded bytes. It checks
all counts, field lengths, identities, sequence, kind, and Base64 length before
allocating, decoding, or appending a payload. The `SPPDBN1` capacity remains
16 MiB. The 258-frame cap is total outer records, not an `S`-record cap: a
valid small-chunk stream may use 258 `S` records, or 257 `S` records followed
by `I`. The 256 full-64-KiB `S` chunks plus `I` and `F` are only the
maximum-payload accounting case; their 22,430,310 wire bytes take about 1,947
seconds at 115200 8N1, within the 2,400-second absolute export deadline.

## Writer and poweroff state

One `FramedUartWriter` is retained by the controller from identity acquisition
through collection, export, and fail-stop. It retains the encoded pending
record and offset. Any attempted `S`, `I`, or `F` write, deadline, or drain
failure poisons it, including a failure before its first byte. A positive short
write advances the retained offset; `EAGAIN` and `EINTR` retry under the same
deadline. Once poisoned, no later outer record can be appended.

The writer advances sequence only after the whole LF line has been passed to
the serial driver, and it must drain before another record. Success uses one
absolute 2,400-second write-and-drain deadline; it is never restarted. Primary
poweroff is attempted only after all `S` lines are written, the writer is empty,
and the UART queue is drained. If that poweroff returns or errors, the
controller sends and drains exactly one framed `I` under one absolute second.
Only after a complete `I` may fail-stop append a framed `F` under five seconds,
then try poweroff again. A pre-export failure sends standalone `F` at sequence
zero. A failed or partial `S`, or a failed/partial `I`, sends no later `I` or
`F`; fail-stop still attempts poweroff.

## Off-box observation

`conf_proc_spp_diag_uart_observation.py` accepts one finite supplied blob; it
does not read devices and has no capture, mapper, Azure, or acquisition types.
Arbitrary preamble precedes the first `SPPUART/1|k=` marker. From that marker
records are contiguous and there is no resynchronization. Only a contiguous
run of raw `00` bytes *after* a final semantically complete outer result is
terminal storage fill. It is not an outer invalidator: the `I` record has a
normal wire extent and one-byte decoded content/hash; raw fill has a separate
snapshot-relative padding extent/hash. A partial line followed by zero fill is
incomplete, never padding.

The immutable observation retains the profile identifier/version and the
expected challenge/run identity used for validation. Every public
`SnapshotExtent.offset` is an index in the supplied raw snapshot. A record's
snapshot-relative wire extent maps to its decoded logical content by decoded
length and SHA-256; decoded content deliberately has no public offset. The
aggregate decoded content describes the concatenated authenticated outer
payloads, while `snapshot` is only the concatenated `S` payloads.

The immutable statuses are `complete_result`, `standalone_failure`,
`invalidated_result` (with optional late `F`), `invalid`, and `incomplete`.
Success with only terminal zero fill is `complete_result`. NUL within or
between records, malformed or nonzero suffixes, a second result, `F` after
success without `I`, or a later candidate marker are non-success and are never
resynchronized. The observation records raw, preamble, wire, per-record wire,
decoded-content, and padding lengths and SHA-256 values. It invokes
`parse_export_stream` and `parse_failure_terminal` with explicit expected
identities; both outer and inner identity mismatches are invalid. An observation
is not a `CapturedDiagnostic` and cannot be passed to the mapper.

Only the guest codec/writer and its reasons are in the staged runtime/AppArmor
closure. The host observation decoder is intentionally never staged.
