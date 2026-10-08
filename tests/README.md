# Verdict and source contracts

These tests describe required behavior at the scanner and provider boundaries.
They use synthetic responses, temporary storage, and mocked HTTP/DNS. They do not
contact Telegram, internal services, or live threat feeds.

## Outcome semantics

| Outcome | Meaning | Required behavior |
|---|---|---|
| HIT | A successful source check confirms a matching threat | Preserve the evidence and a maximum risk score of 10, regardless of trust signals |
| CLEAN | A successful, valid, current source check found no match | Describe that source result; do not imply that all possible threats were ruled out |
| UNKNOWN | The check was not performed or its data is missing/stale | Show the limitation; do not grant trust or report a successful negative result |
| ERROR | The provider failed, returned invalid data, or could not complete | Preserve the failure reason and other successful source results; do not turn it into CLEAN |

The existing `ThreatVerdict` uses `checked` and `found`. An unavailable check has
`checked=False`; a confirmed hit has `checked=True, found=True`. Transport failures
must remain distinguishable through source status/reason even when represented as
an unavailable verdict. A partial check must preserve any confirmed hit and disclose
its missing sources.

Confirmed threats and weighted heuristics are different. A HIGH heuristic flag alone
does not imply a confirmed hit. Legitimate trust signals can affect heuristic scoring,
but cannot cancel confirmed threat evidence. Missing data cannot create CLEAN_IP,
residential classification, an absent leak, or a zero balance.

## Boundary guarantees

- Geolocation, AbuseIPDB, Tor, and OTX results are independent. Failure of one source
  cannot discard successful evidence from another source.
- Downloaded feed data must pass schema validation before it replaces a good memory
  or disk snapshot. Failure preserves the previous snapshot and its original timestamp.
- A stale snapshot remains stale after a failed refresh, including after a restart.
- User URLs and each redirect must be checked before contacting the endpoint. Private,
  loopback, link-local, and mixed public/private DNS targets cannot reach HTTP transport.
- A reachable public URL remains supported. Refusing unsafe URLs must not disable all
  URL scans.

## Known failures

Known violations use targeted `pytest.mark.xfail(strict=True, raises=AssertionError)`
markers with defect IDs. Tests assert the required behavior, never the current bug.
Unexpected setup/transport errors fail normally. An unexpected pass fails the suite,
so its marker must be removed once the corresponding behavior is implemented.

Use `--runxfail` with the relevant contract files to expose these assertions as failures
while implementing the corresponding fix. A normal run containing xfailed cases does
not mean that the underlying defects have been resolved.
