# Local patches

Upstream: https://github.com/SagerNet/sing-openvpn

Base commit: `d1e498f993a04d705024b41f9477a8d8936e7cc3`.

## Dynamic authentication credentials

`ClientAuthenticationOptions.Credentials` accepts:

```go
func(ctx context.Context) (username, password string, err error)
```

This application combines passwords with time-based one-time codes. Upstream
stages ordinary credentials once and reuses them across full reconnects and TLS
renegotiation, which would send an expired or already-used code. The callback is
therefore invoked in `sessionCredentials`, immediately before constructing each
TLS key-method authentication payload. Both the initial exchange and soft-reset
renegotiation pass their session context and propagate acquisition errors before
writing credentials to TLS. The supervisor skips early ordinary credential
staging when this callback is configured.

Credential priority remains:

1. A valid active server auth-token when that exchange permits it.
2. An interactive staged SCRV1/CRV1 challenge answer.
3. Fresh callback credentials, if configured.
4. The original upstream staged credentials otherwise.

The original auth-token rejection handler still clears a rejected token, so the
next token-free exchange calls the callback again rather than using an old OTP.
Static challenge acquisition and already staged interactive answers retain their
upstream behavior. No callback means the original staged credential behavior.
Static-key clients reject the callback, consistently with ordinary credentials.

Callbacks are serialized per Client using a separate mutex, without holding the
internal authentication state mutex while application code runs. They must honor
context cancellation and must not recursively request credentials from the same
Client. Cancellation is checked before and after invoking application code.
Callback errors are wrapped with `%w` and return empty wire credentials; neither
partially returned values nor cached passwords are used as fallback. Only the
callback's latest username is staged for auth-tokens without auth-token-user;
the generated password is not cached in the staged credential record.

`auth_credentials_test.go` uses fictional values and checks fresh acquisition and
call counts across initial/reconnect/renegotiation-style exchanges, token and
interactive-answer priority, upstream token rejection and fallback, error
propagation through the initial key-method caller, cancellation, serialized
concurrent calls, and unchanged behavior without a callback. These unit tests
exercise authentication selection; they do not substitute for interoperability
testing against a real OpenVPN server.

## Optional reconnect suppression

`ClientOptions.DisableReconnect` defaults to false, preserving upstream retries.
The application sets it when a profile disables automatic reconnect. A failed
initial dial/handshake or an established session ending with an error then
records that error as terminal and stops before authentication challenge retry,
remote/address advancement, or reconnect backoff. `WaitReady` and packet readers
can observe the terminal error. Explicit suspend/resume retains its upstream
behavior; a nil session termination already stops upstream.

`client_reconnect_test.go` runs the real supervisor and static-key client session
with an injected failing dialer or in-memory `net.Pipe` transport. It verifies one
initial attempt on failure, no redial after an established session is closed, and
automatic retry with the default false value. The static-key fixture allows this
lifecycle test to run without certificates or a remote VPN server; callback
selection itself is covered separately by the authentication tests.

## Reconnect stability and observability

The supervisor retains its 1–60 second exponential base, but resets it only after
an established session lasts at least 60 seconds. Actual delays use ±20% jitter,
capped at 60 seconds locally. Server TEMP backoff is applied afterwards as a lower
bound and does not inflate the local exponential base. Context cancellation,
terminal authentication classification and manual reconnect suppression remain.

`Client.ReconnectStatus()` returns a synchronized value snapshot with attempts,
retries, successful reconnects, consecutive failures and the scheduled next
attempt. LastError contains only a fixed category, never authentication content.
`client_supervisor_test.go` exercises consecutive short sessions over net.Pipe,
stability thresholds, jitter bounds, server backoff and cancellation. Exact timing
and network-detection limits are documented in `RECONNECT_BEHAVIOR.zh-CN.md`.
