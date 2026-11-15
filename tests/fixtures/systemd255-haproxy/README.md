# systemd 255 HAProxy offline evidence (PARTIAL audit)

No actual full VPS source/probe snapshot pair was attached or found.
`reported-source.partial.show3lines` preserves the ONLY actual user-reported
values: WatchdogUSec=infinity, empty WatchdogTimestamp, and
WatchdogTimestampMonotonic=0. It is NOT a full snapshot; the actual VPS probe
WatchdogUSec is UNKNOWN. These lines cannot prove a missing-property versus
value-mismatch cause, establish an actual mismatch, or validate the full profile.

`synthetic-pair.json` is SYNTHETIC, sanitized overlays on the in-memory bases
`source_properties(old=True)` and `Offline.probe(c, plan)` in
`tests/diagnose_haproxy_test.py`. The fragment comes from the actual renderer
with the historical three-capability profile, not from a host. Every base field,
overlay field, path, command structure, PID, timestamp and omission in that pair
is SYNTHETIC, even when a watchdog value matches the partial report. Fixed
nonce/path placeholders are public fixture constants, not host identifiers.
The probe base uses the real factory with mocked reservations/files only.

The pair models disabled source infinity versus disabled probe 0, unavailable
optional File metadata, and omitted unused empty Base/Ex hooks. It represents
only the supplied renderer-profile keys, NOT a complete systemctl --all dump
or actual-host compatibility. Inventory tests require exactly the union of
supplied keys and no invented fields. The manifest separates that synthetic
coverage from the partial actual report. Fixture files are read at discovery,
before host guards; tests use copies and mocks afterwards. No probe was run.
