# Managed engine integration protocol (v1)

Built engines follow the default branch HEAD of lovitus/flyssh and lovitus/gust (+ gust-x). Build manifests record full commit IDs. An explicit telemetry overlay is applied to those sources, with contextual checks that fail the build on incompatible source drift. Original engine command/config semantics remain authoritative.

When OVPN_SOCKS_TELEMETRY_TOKEN is nonempty (random 32 hex digits supplied by the parent), engines emit one JSON object per stdout line, prefixed with `OVPN_ENGINE_<token> `. No prefix/token is enabled during normal standalone invocation. Snapshots occur every 2 seconds and at lifecycle changes, with bounded listener cardinality (maximum 256). Engine logs are separate and must not contain credentials in snapshots. Parent retains bounded memory only. No metrics files.

OVPN_SOCKS_INSPECT=1 additionally requests configuration-only parsing: consume the same CLI/native config inputs, resolve listener declarations, emit one type=inspect record, and exit. Must not dial, bind, create authentication files, start servers or run user commands. Invalid or unsupported managed modes return nonzero with an actionable error. This mode is a capability of the instrumented build. Inspection must reject inputs the runtime would reject, to the extent possible without network or authentication.

Envelope:

```json
{"version":1,"type":"snapshot","engine":"flyssh","state":"connected","timestamp_ms":0,"listeners":[{"id":"local-0","network":"tcp","address":"127.0.0.1:8080","actual_address":"127.0.0.1:8080","scope":"local","kind":"tcp","state":"listening","error":"","upload_bytes":0,"download_bytes":0,"active_connections":0,"total_connections":0,"failed_connections":0,"metrics_available":true}],"upload_bytes":0,"download_bytes":0,"active_connections":0,"total_connections":0,"failed_connections":0,"metrics_available":true}
```

- type: inspect, snapshot, or error. inspect includes declared listeners with state=configured; no runtime claims. Errors carry only `error_code` from invalid_arguments/invalid_config/unsupported_mode/config_not_found/too_many_listeners, and optional numeric `error_line`; parent maps these to fixed diagnostics without leaking raw config text.
- Optional `counter_scope` / `connection_scope` strings describe native accounting boundaries. In particular gust listener ingress counters can include protocol handshake overhead; native request gauges are not universally UDP association counts. UI must not equate them with OpenVPN SOCKS payload accounting.
- engine: flyssh or gust. state: starting, connecting, connected (SSH chain established), running (process only), ready (gust serving), degraded, failed, stopped. Parent independently tracks process exit/restart and freshness.
- listener id is stable within one configuration (native service name or deterministic index), never an address containing credentials.
- network tcp/udp/unix/other, address declared bind address, actual_address from successful native bind; scope local/remote. Remote SSH -R is explicitly remote, never advertised as local.
- kind protocol/handler name; state configured/starting/listening/failed/closed/unknown. "listening" requires evidence from native listener lifecycle. UDP is serving if socket bind succeeded; UDP association counters are not TCP connections.
- counters describe engine-observed application bytes, not host interface traffic. Counters are monotonic within one child process; parent accounts restarts. active_connections is current flows/associations; total_connections cumulative accepted flows; failed_connections native connection/dial failure count where available. Counters not instrumented MUST set metrics_available=false, not present invented zero statistics as measured values.
- config references, CLI, passwords, keys, auth tokens, remote destination URLs and payloads must never be included in telemetry.
- max JSON record 256 KiB; no unbounded user/client/target labels. Per-listener metrics only (<=256); aggregate totals may include engine work beyond listeners and must have documented scope.

The parent uses exec argv, never a command shell. Managed configs remain encrypted at rest in profiles. Native config materialization uses private temporary files only while needed by the child, and cleanup must handle start failure, stop, restart, and app shutdown. No override of user API/metrics endpoints is required for this channel.
