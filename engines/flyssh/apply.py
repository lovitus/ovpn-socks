#!/usr/bin/env python3
"""Apply the optional ovpn-socks telemetry overlay to a separate FlySSH checkout.
Every replacement is asserted before ANY source file is written. Never patches
an upstream remote. Refuses partially patched or incompatible source trees.
"""
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
here = pathlib.Path(__file__).resolve().parent
files = {}
def patch(name, old, new, count=1):
    text = files.get(name)
    if text is None:
        text = (root / name).read_text(encoding='utf-8')
    found = text.count(old)
    if found != count:
        raise SystemExit(f'FlySSH overlay context drift: {name}: expected {count} matches, got {found}: {old[:100]!r}')
    files[name] = text.replace(old, new)

patch('main.go', '"github.com/flyssh/flyssh/pkg/gateway"', '"github.com/flyssh/flyssh/pkg/gateway"\n "github.com/flyssh/flyssh/pkg/managed"')
patch('main.go', '\tscrubArgs()\n', '''	if handled, err := managed.Configure(opts); err != nil {
        managed.ReportError(err)
        fmt.Fprintf(os.Stderr, "flyssh managed: %v\\n", err)
        os.Exit(255)
    } else if handled { return }
	scrubArgs()
''')
patch('main.go', '\topts, err := cli.ParseArgs(rawArgs)\n\tif err != nil {', '\topts, err := cli.ParseArgs(rawArgs)\n\tif err != nil {\n        managed.Diagnostic("invalid_arguments")')
patch('main.go', '\t\tcycleStarted := time.Now()', '\t\tmanaged.State("connecting")\n\t\tcycleStarted := time.Now()')
patch('main.go', '\t\tif sessionErr == nil {', '\t\tmanaged.State("connecting")\n\t\tif sessionErr == nil {')
patch('main.go', '\tdefer closeClients(allClients)\n\tif connected != nil {', '\tdefer closeClients(allClients)\n\tmanaged.State("connected")\n\tif connected != nil {')
for list_name,short,kind,method in [('LocalForwards','lf','local','StartLocalForwardWithPolicy'),('RemoteForwards','rf','remote','StartRemoteForwardWithPolicy'),('DynamicForwards','dp','dynamic','StartDynamicForwardWithPolicy')]:
    patch('main.go',f'for _, {short} := range opts.{list_name} {{',f'for index, {short} := range opts.{list_name} {{\n        observerID := fmt.Sprintf("{kind}-%d", index)')
    patch('main.go',f'forwarding.{method}(finalClient, forward.Spec, opts.Verbose, forwarding.RelayPolicy(forward.RelayPolicy))',f'forwarding.{method}(finalClient, forward.Spec, opts.Verbose, forwarding.RelayPolicy(forward.RelayPolicy), observerID)')

p='pkg/forwarding/forwarding.go'
patch(p,'"golang.org/x/crypto/ssh"','"golang.org/x/crypto/ssh"\n "github.com/flyssh/flyssh/pkg/managed"')
for method in ['StartLocalForwardWithPolicy','StartRemoteForwardWithPolicy','StartDynamicForwardWithPolicy']:
    old=f'func {method}(client *ssh.Client, spec string, verbose bool, policy RelayPolicy) error {{'
    new=f'''func {method}(client *ssh.Client, spec string, verbose bool, policy RelayPolicy, observerIDs ...string) (retErr error) {{
    observerID := managed.ID(observerIDs)
    observerEpoch := managed.Start(observerID)
    defer func() {{ managed.End(observerID, observerEpoch, retErr) }}()
'''
    patch(p,old,new)
patch(p,'\tdefer listener.Close()\n\n\t// Close listener when SSH connection dies','\tdefer listener.Close()\n    managed.Bound(observerID, observerEpoch, listener.Addr().String())\n\n\t// Close listener when SSH connection dies',2)
patch(p,'\t\ttraceID := newTraceID("L")','\t\tdoneObserver := managed.Accept(observerID)\n\t\ttraceID := newTraceID("L")')
patch(p,'\t\tgo func(traceID string) {\n\t\t\tdefer conn.Close()','\t\tgo func(traceID string) {\n            defer doneObserver()\n\t\t\tdefer conn.Close()',2)
patch(p,'\t\t\t\tif now-prev > int64(2*time.Second)', '\t\t\t\tmanaged.Fail(observerID)\n\t\t\t\tif now-prev > int64(2*time.Second)')
patch(p,'biCopy(conn, remote)','biCopy(conn, remote, observerID)',2)
# Remote listeners share one serving loop; native mux ACK already supplies actual bound address.
patch(p,'bindAddr, localAddr, verbose)','bindAddr, localAddr, verbose, observerID, observerEpoch)',4)
patch(p,'func serveRemoteForwardListener(listener net.Listener, label, bindAddr, localAddr string, verbose bool) error {','func serveRemoteForwardListener(listener net.Listener, label, bindAddr, localAddr string, verbose bool, observerID string, observerEpoch uint64) error {\n    managed.Bound(observerID, observerEpoch, listener.Addr().String())')
patch(p,'\t\ttraceID := newTraceID("R")','\t\tdoneObserver := managed.Accept(observerID)\n\t\ttraceID := newTraceID("R")')
patch(p,'log.Printf("[%s] remote forward dial local %s failed: %v", traceID, localAddr, err)','managed.Fail(observerID)\n                log.Printf("[%s] remote forward dial local %s failed: %v", traceID, localAddr, err)')
# For remote forwarding, upload means local destination -> remote accepted client.
patch(p,'biCopy(conn, local)','biCopy(local, conn, observerID)')
patch(p,'\t\tgo handleSocks5Client(client, conn, verbose, traceID, policy)','\t\tdoneObserver := managed.Accept(observerID)\n        go func() { defer doneObserver(); handleSocks5Client(client, conn, verbose, traceID, policy, observerID) }()')
patch(p,'func handleSocks5Client(client *ssh.Client, conn net.Conn, verbose bool, traceID string, policy RelayPolicy) {','func handleSocks5Client(client *ssh.Client, conn net.Conn, verbose bool, traceID string, policy RelayPolicy, observerID string) {')
patch(p,'\t\t// Only CONNECT supported','\t\tmanaged.Fail(observerID)\n\t\t// Only CONNECT supported')
patch(p,'log.Printf("[%s] dynamic forward connect to %s failed: %v", traceID, targetAddr, err)','managed.Fail(observerID)\n        log.Printf("[%s] dynamic forward connect to %s failed: %v", traceID, targetAddr, err)')
patch(p,'func biCopy(a, b io.ReadWriteCloser) {','func biCopy(a, b io.ReadWriteCloser, observerIDs ...string) {\n    observerID := managed.ID(observerIDs)')
patch(p,'io.Copy(b, a)','io.Copy(managed.Writer(b, observerID, true), a)')
patch(p,'io.Copy(a, b)','io.Copy(managed.Writer(a, observerID, false), b)')
# SSH channel / idleConn wrappers expose CloseWrite, but upstream's concrete TCP
# assertion misses them and leaves finished managed flows alive indefinitely.
patch(p,'if tc, ok := b.(*net.TCPConn); ok {','if tc, ok := b.(interface{ CloseWrite() error }); ok {')
patch(p,'if tc, ok := a.(*net.TCPConn); ok {','if tc, ok := a.(interface{ CloseWrite() error }); ok {')
# No payload metric claim for SSH gateway: only bind lifecycle is instrumented.
p='pkg/gateway/gateway.go'
patch(p,'"golang.org/x/crypto/ssh"','"golang.org/x/crypto/ssh"\n "github.com/flyssh/flyssh/pkg/managed"')
patch(p,'func ServeWithReady(finalClient *ssh.Client, spec string, verbose bool, ready func(ReadyInfo) error) error {','func ServeWithReady(finalClient *ssh.Client, spec string, verbose bool, ready func(ReadyInfo) error) (retErr error) {\n    epoch := managed.Start("gateway-0")\n    defer func() { managed.End("gateway-0", epoch, retErr) }()')
patch(p,'\tif verbose {\n\t\tlog.Printf("[gateway] Listening','\tmanaged.Bound("gateway-0", epoch, ln.Addr().String())\n\tif verbose {\n\t\tlog.Printf("[gateway] Listening')

managed = root/'pkg/managed/managed.go'
test_file = root/'managed_observation_test.go'
if managed.exists() or test_file.exists():
    raise SystemExit('FlySSH overlay already exists; use a fresh source checkout')
for name,text in files.items():
    (root/name).write_text(text,encoding='utf-8',newline='\n')
managed.parent.mkdir(parents=True,exist_ok=True)
managed.write_text((here/'managed.go').read_text(encoding='utf-8'),encoding='utf-8',newline='\n')
test_file.write_text((here/'managed_observation_test.go').read_text(encoding='utf-8'),encoding='utf-8',newline='\n')
print(f'Applied optional ovpn-socks telemetry overlay to {root}')
