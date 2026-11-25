# Managed native engines

Public API:

```go
type Options struct {
    ID, Name, Engine, Arguments, ConfigText, ConfigFormat, WorkingDirectory string
    AutoReconnect bool
}
func Inspect(context.Context, Options) (InspectResult, error)
func Start(context.Context, Options) (*Session, error)
func (*Session) Snapshot() vpn.Snapshot
func (*Session) Summary() vpn.Snapshot
func (*Session) Metrics() vpn.MetricsSnapshot
func (*Session) EngineStatus() EngineStatus
func (*Session) Stop()
```

`InspectResult.Listeners` and `EngineStatus.Listeners` contain `[]Listener`.
`EngineStatus` holds Engine, State, ProcessRunning, Fresh, LastTelemetryMS,
MetricsAvailable, TotalConnections, FailedConnections, Restarts, CounterScope and
ConnectionScope. Listener retains the protocol fields, including both scope
strings. All returned slices belong to the caller.

Only the administrator-controlled binary directory is used. An optional executable
prefix in Arguments is stripped when its basename matches the selected engine;
it never overrides the trusted binary path. Arguments are parsed by engineargs,
with no shell. Inline configuration has a private per-child directory (0700 Unix;
protected user/System-only inheritable DACL on Windows). Each restart removes the
old directory and materializes a new one; stopping waits for child termination and
cleanup. Config format selects .ssh, .yaml or .json extension. Relative references
inside native config follow the engine's native rules; WorkingDirectory can set
an absolute current directory.

Windows starts suspended, assigns a kill-on-close Job Object, then resumes with
NtResumeProcess. Failure to establish containment fails closed. Unix uses a process
group. A deliberately daemonizing Unix child that creates a new session can escape
the group; the instrumented supported engines must not daemonize. This package is
not an OS sandbox. Inspect's no-network/no-bind guarantee depends on the trusted
instrumented engine honoring the protocol; inspection is killed after 15 seconds.

Only token-prefixed protocol records are consumed. Native stdout and stderr are
never retained. Records are limited to 256 KiB and 256 listeners; malformed or
oversize lines are drained and discarded without blocking future records. Error
codes map to fixed Chinese diagnostics with a bounded optional line number; native
error messages are never displayed. Listener error strings become a fixed generic
message. Scope descriptions are capped at 512 bytes each and must be static,
credential-free descriptions from the trusted overlay.

Freshness expires after eight seconds without accepted telemetry. Producer clocks
older than eight seconds or more than thirty seconds ahead are rejected. A live
process alone does not produce a connected state. Ready/connected maps to the
common connected state; native state remains available in EngineStatus. Stale
listeners lose listening claims and metrics availability. Snapshot and Summary
provide only the first local listener in the legacy Listen field; EngineStatus is
the authoritative complete listener list, including remote forwards.

Aggregate and per-listener monotonic counters accumulate across children within a
session. Listener IDs must remain stable; the offset map is limited to 256 IDs.
Counters represent only the last observed telemetry before exit, so unsampled final
traffic can be lost. ActiveConnections is current-child state and is zero when
stale or stopped. Native total/failed connection counts are exposed in EngineStatus,
not mislabeled as SOCKS request counters in vpn.MetricsSummary. CounterScope and
ConnectionScope describe native measurement boundaries; MetricsAvailable is the
authority for whether zero is a measured value. Metrics are memory-only, sampled
at two seconds with at most 450 points and fifteen-minute retention. Stale or
unavailable telemetry produces gaps, never fabricated zero samples. Logs retain
at most 100 fixed lifecycle messages or sanitized diagnostics.

Reconnect attempts use 1..60-second exponential backoff with up to 25% jitter,
reset after a child survives sixty seconds. Attempts includes the initial spawn;
Retries, Restarts and ReconnectCount count subsequent spawn attempts (including
failed OS starts). Reconnect.Reconnects counts retried children that report
ready/connected at least once, not freshness recoveries. Aggregate byte rates use
session cumulative totals, so child counter reset cannot underflow a rate.
Stop is idempotent, cancels backoff immediately and waits for cleanup.

Tests copy the running Go test executable into a temporary trusted engine directory
and actually launch it through the production supervisor. Tests cover inspection,
malformed/oversize stdout recovery, sanitized diagnostics, descendant termination,
freshness expiry, restart counter continuity, cancellation, ambiguous config,
per-restart config replacement/removal and bounded history. This validates the
supervisor independently of SSH/network availability; actual upstream overlay
compatibility must additionally be checked by the engine build/integration tasks.
