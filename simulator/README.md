# Central-server simulator

`server.py` is an offline, in-memory implementation of the device-facing `pm-protocol/1.0.0` contract. It supports one-time enrollment, HMAC-authenticated heartbeats, idempotent reading/event batches, effective configuration, configuration reports, firmware-manifest polling, time hints, nonce replay rejection, and contiguous sequence acknowledgements. It is deliberately not a fleet dashboard or production server.

Run on loopback:

```sh
python simulator/server.py --port 8088
```

Firmware refuses unvalidated production HTTPS. To exercise a device, create a local test CA and leaf certificate outside this repository, supply `--cert` and `--key`, and provision the test CA into a simulated-meter build:

```sh
python simulator/server.py --port 8443 --cert path/to/server.crt --key path/to/server.key
```

The simulator prints a fresh single-use token and holds all credentials/readings only in memory. Never reuse its token, CA, or keys in production. Scenario descriptions under `scenarios/` drive host integration tests and the deterministic `SimulatedMeter`; no mains hardware is used.

On Windows, `tools/fetch_server_ca.ps1` can export the certificate chain presented by an HTTPS server and print its leaf SHA-256 fingerprint. A TLS server commonly omits its root CA, so the tool produces `ca-candidate.pem` only when a CA certificate is actually presented. Always compare the reported fingerprint through an independent trusted channel before provisioning it; downloading trust material from an unauthenticated connection is not secure bootstrapping.
