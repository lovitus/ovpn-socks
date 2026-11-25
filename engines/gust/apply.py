#!/usr/bin/env python3
"""Apply reviewed managed telemetry additions to fresh gust/gust-x checkouts.

Only new integration code and minimal checked anchors are distributed here.
No upstream dependency source is vendored. Drift fails before any writes.
"""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent

def apply(gust, x):
    writes = {}
    def patch(root, rel, old, new, count=1):
        p = root / rel
        text = writes.get(p, p.read_text(encoding="utf-8"))
        if text.count(old) != count:
            raise RuntimeError(f"source drift/already applied: {rel}: expected {count} anchor(s)")
        writes[p] = text.replace(old, new)
    def new(root, rel, text):
        p = root / rel
        if p.exists():
            raise RuntimeError(f"overlay target already exists: {rel}; use a fresh source checkout")
        writes[p] = text
    patch(gust,"cmd/gost/main.go","func main() {\n\thandleWorkers()","func main() {\n\tmanagedBeforeFlags()\n\thandleWorkers()")
    patch(gust,"cmd/gost/main.go","\tflag.Parse()","\tmanagedParseFlags()")
    patch(gust,"cmd/gost/main.go","\tparseFlags()\n","\tparseFlags()\n\tmanagedAfterFlags()\n")
    patch(gust,"cmd/gost/main.go","\t\tlogger.Default().Fatal(err)","\t\tmanagedRuntimeError()\n\t\tlogger.Default().Fatal(err)")
    patch(gust,"cmd/gost/program.go","func (p *program) Stop() error {","func (p *program) Stop() error {\n\tdefer managedStopped()")
    patch(x,"metrics/metrics.go","func GetCounter(","func nativeGetCounter(")
    patch(x,"metrics/metrics.go","func GetGauge(","func nativeGetGauge(")
    patch(x,"metrics/wrapper/listener.go","!xmetrics.IsEnabled()","(!xmetrics.IsEnabled() && !xmetrics.ManagedEnabled())")
    patch(x,"config/loader/loader.go","\tcandidate := config.Clone(cfg)\n","\tcandidate := config.Clone(cfg)\n\tif err := managedPrepare(candidate); err != nil { return nil, err }\n")
    patch(x,"metrics/wrapper/conn.go","type packetConn struct {\n","type packetConn struct {\n\tmanagedUpstream bool\n")
    # Restrict replacement to the two packet methods; don't alter TCP direction.
    p=x/"metrics/wrapper/conn.go"
    text=writes[p]
    begin=text.index("func (c *packetConn) ReadFrom(")
    end=text.index("func (c *packetConn) Context(")
    region=text[begin:end]
    if region.count("xmetrics.GetCounter(")!=2: raise RuntimeError("packet metrics source drift")
    writes[p]=text[:begin]+region.replace("xmetrics.GetCounter(","xmetrics.ManagedPacketCounter(c.managedUpstream,")+text[end:]
    patch(x,"handler/socks/v5/udp.go","metrics.WrapPacketConn(ro.Service, pc)","metrics.WrapManagedUpstreamPacketConn(ro.Service, pc)")
    new(x,"metrics/wrapper/ovpn_managed.go",'''// Added by ovpn-socks. Native metrics retain their original direction.
package wrapper
import "net"
func WrapManagedUpstreamPacketConn(service string, pc net.PacketConn) net.PacketConn {
 if pc == nil { return nil }
 p := WrapPacketConn(service,pc).(*packetConn)
 p.managedUpstream = true
 return p
}
''')
    new(x,"service/ovpn_managed.go",'''// Added by ovpn-socks. Bound-state evidence for lazy remote listeners.
package service
import "net"
func (s *defaultService) ManagedBoundAddr() net.Addr {
 if p,ok:=s.listener.(interface{ ManagedBoundAddr() net.Addr }); ok { return p.ManagedBoundAddr() }
 return nil
}
''')
    for kind in ("rtcp","rudp","runix"):
        new(x,f"listener/{kind}/ovpn_managed.go",f'''// Added by ovpn-socks. Declaration is not proof of a remote bind.
package {kind}
import "net"
func (l *{kind}Listener) ManagedBoundAddr() net.Addr {{
 if ln:=l.getListener(); ln!=nil {{ return ln.Addr() }}
 return nil
}}
''')
    for root,target,source in (
        (gust,"cmd/gost/ovpn_managed.go","managed_main.go.in"),
        (x,"metrics/ovpn_managed.go","managed_metrics.go.in"),
        (x,"metrics/ovpn_managed_test.go","managed_metrics_test.go.in"),
        (x,"config/loader/ovpn_managed.go","managed_validate.go.in"),
    ):
        new(root,target,(HERE/source).read_text(encoding="utf-8"))
    for p,text in writes.items():
        with p.open("w",encoding="utf-8",newline="\n") as f:
            f.write(text)
    print(f"Applied bounded gust telemetry overlay to {len(writes)} files")

if __name__ == "__main__":
    if len(sys.argv)!=3: raise SystemExit("usage: apply.py GUST_DIR GUST_X_DIR")
    try: apply(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
    except (RuntimeError,OSError,ValueError) as exc: raise SystemExit(str(exc))
