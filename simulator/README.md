# Central-server simulator

`server.py` is an offline, in-memory implementation of the device-facing `pm-protocol/1.0.0` contract. It supports one-time enrollment, HMAC-authenticated heartbeats, idempotent reading/event batches, effective configuration, configuration reports, signed firmware-manifest polling and authenticated binary downloads, time hints, nonce replay rejection, and contiguous sequence acknowledgements. It is deliberately not a fleet dashboard or production server.

The simulator never accepts an enrollment token as a command-line value and
never prints or persists it. Load a 32–256 character test token from an
environment variable populated by your shell or secret manager:

```powershell
$env:PM_SIMULATOR_ENROLLMENT_TOKEN = Read-Host "One-time test token" -MaskInput
try {
    python -m simulator.server --port 8088
} finally {
    Remove-Item Env:PM_SIMULATOR_ENROLLMENT_TOKEN
}
```

Alternatively, put the token in a restricted file outside this repository and
pass only its path:

```sh
python -m simulator.server --port 8088 --enrollment-token-file path/to/token.txt
```

The in-memory token expires after 900 seconds by default. Override that
test-only lifetime with `--enrollment-token-ttl-seconds`; a successful claim
still consumes it immediately.

Firmware refuses unvalidated production HTTPS. To exercise a device, create a
local test CA and leaf certificate outside this repository, supply `--cert` and
`--key`, and provision the test CA into a simulated-meter build:

```sh
python -m simulator.server --port 8443 --cert path/to/server.crt --key path/to/server.key --enrollment-token-file path/to/token.txt
```

The simulator holds credentials and readings only in memory. Never reuse its
token, CA, or keys in production, and never place the token file inside the
repository. Its request log contains method/path/status only; request bodies
and authentication headers are not logged. Scenario descriptions under
`scenarios/` drive host integration tests and the deterministic
`SimulatedMeter`; no mains hardware is used.

## Deterministic fault injection

Host tests can enqueue one-shot RFC 9457 failures without an external service,
database, delay, or live network dependency:

```python
from simulator.server import HEARTBEAT_ENDPOINT, ServerState

state = ServerState(enrollment_token=token)
state.queue_fault(
    HEARTBEAT_ENDPOINT,
    503,
    "service_unavailable",
    "Deterministic integration-test outage.",
    retry_after_seconds=5,
)
```

Faults are consumed in FIFO order after request authentication. The integration
suite covers enrollment `400`/`403`/`409`/`422`, expired and used tokens,
heartbeat `401`/`403`/`409`/`429`/`503`, nonce replay, successful
enrollment/heartbeat/backfill, and HTTP `200` reading responses containing
record-level rejections.

On Windows, `tools/fetch_server_ca.ps1` can export the certificate chain presented by an HTTPS server and print its leaf SHA-256 fingerprint. A TLS server commonly omits its root CA, so the tool produces `ca-candidate.pem` only when a CA certificate is actually presented. Always compare the reported fingerprint through an independent trusted channel before provisioning it; downloading trust material from an unauthenticated connection is not secure bootstrapping.
