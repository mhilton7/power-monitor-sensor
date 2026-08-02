# Local WebUI

The embedded local interface has three views: Status, Setup, and Diagnostics.
It calls only the sensor's local API and never exposes device credentials,
HMAC keys, enrollment material, the CA private key, or central-server device
URLs to browser storage.

## Status polling

Status opens with one immediate `GET /api/v1/ui/status`. While the document is
visible, it polls every 10 seconds with at most one active request. The client
aborts a stale request before replacement, pauses completely while hidden,
and refreshes once when visibility returns. Manual Refresh coalesces with an
active poll. Session renewal pauses polling and is single-flight; one safe GET
may be retried after a successful renewal.

A 35-minute continuously visible session therefore targets no more than 211
requests including the initial request. The 341-request historical pattern is
retained as a worst-case native regression, not as the normal policy.

`503 local_resource_deferred` is a bounded local-capacity response. The client
honors a bounded `Retry-After` instead of creating a retry storm. Setup,
Diagnostics, events, metrics bundles, and microSD history are never loaded by
the Status timer. Setup loads only when opened. Diagnostics and downloads are
explicit, heavy operations and can be deferred to protect TLS.

## Allocation-stable response

The Status handler captures compact lock-bounded snapshots, releases source
locks, serializes with `BoundedJsonWriter`, and leases one of two 2,048-byte
fixed response slots. The response object owns a move-only lease and its coded
cleanup paths release that lease on completion, cancellation, or error. Native
lease tests and mock-browser cancellation tests cover those ownership paths;
this software-only run did not observe a physical AsyncTCP disconnect. Pool
exhaustion returns a static typed 503.
The handler does not construct a dynamic ArduinoJson document, copy the full
runtime configuration, serialize full storage health, scan history, or contact
the central server.

## Server freshness

The browser renders server connection state from the last accepted heartbeat,
not from Wi-Fi association alone:

| State | Interpretation |
|---|---|
| `never_connected` | No successful authenticated heartbeat has occurred |
| `live` | The last success is within the expected heartbeat interval |
| `delayed` | A heartbeat is late but has not crossed the configured stale/offline boundary |
| `stale` | A prior success exists but is beyond freshness policy |
| `offline` | No fresh server-received heartbeat supports an Online claim |
| `unauthenticated` | The server is reachable but current authentication failed |

The UI never labels Delayed, Stale, Offline, or Unauthenticated as “Server
connected.” A 356-second-old heartbeat is stale/offline, never connected.
Wi-Fi offline and never-connected are separate states.

The Status response supplies the last-success timestamp/age, current server
time, expected heartbeat interval, and freshness threshold. The browser may
recalculate the displayed age once per second from the response baseline and
browser monotonic elapsed time. It does not make a one-second network request,
and each new Status response resets the baseline.

The central dashboard remains authoritative for fleet Online state because it
uses server-received heartbeat time. Local freshness cannot fabricate a
central heartbeat.

## Software-only verification

Vitest/JSDOM covers polling, visibility, renewal, retry, manual refresh, and
all freshness boundaries. Pinned browser tests use a mock sensor API to cover
Chromium, Firefox, and WebKit without connected hardware. Those results are
browser/software evidence, not a physical Wi-Fi or ESP32 soak. Physical
confirmation against the exact release image remains pending after deployment.
