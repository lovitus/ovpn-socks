#!/usr/bin/env python3
"""Black-box tests for the instrumented binary, using loopback fixtures only."""
import base64
import http.client
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time

TOKEN = "0123456789abcdef0123456789abcdef"
PREFIX = "OVPN_ENGINE_" + TOKEN + " "
BIN = str(Path(sys.argv[1]).resolve())
ENV = dict(os.environ, OVPN_SOCKS_TELEMETRY_TOKEN=TOKEN)


def inspect(args, code=None):
    p = subprocess.run([BIN] + args, env=dict(ENV, OVPN_SOCKS_INSPECT="1"),
                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=20, text=True)
    records = [json.loads(x[len(PREFIX):]) for x in p.stdout.splitlines() if x.startswith(PREFIX)]
    assert len(records) == 1, (p.returncode, p.stdout, p.stderr)
    r = records[0]
    if code:
        assert p.returncode != 0 and r["type"] == "error" and r["error_code"] == code, r
    else:
        assert p.returncode == 0 and r["type"] == "inspect", r
        assert all(s["state"] == "configured" and not s["metrics_available"] for s in r["listeners"])
    return r


def fixture(network):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if network == "tcp" else socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    if network == "tcp": s.listen()
    def serve():
        while True:
            try:
                if network == "udp":
                    data, addr = s.recvfrom(65535); s.sendto(data, addr)
                else:
                    c, _ = s.accept()
                    def echo(c):
                        with c:
                            while True:
                                data = c.recv(65535)
                                if not data: return
                                c.sendall(data)
                    threading.Thread(target=echo, args=(c,), daemon=True).start()
            except OSError: return
    threading.Thread(target=serve, daemon=True).start()
    return s


def exact_read(s, count):
    data = b""
    while len(data) < count:
        b = s.recv(count-len(data))
        if not b: raise AssertionError("unexpected EOF")
        data += b
    return data


with tempfile.TemporaryDirectory(prefix="gust-managed-test-") as td:
    td = Path(td)
    cfg = td / "native.json"
    cfg.write_text(json.dumps({"services": [{"name": "file-service", "addr": "127.0.0.1:0",
        "listener": {"type": "tcp"}, "handler": {"type": "http"}}]}))
    yaml = td / "native.yml"
    yaml.write_text("services:\n- name: yaml-service\n  addr: '127.0.0.1:0'\n  listener:\n    type: udp\n  handler:\n    type: udp\n")
    r = inspect(["-C", str(cfg), "-C", str(yaml), "-L", "socks5://alice:secret@127.0.0.1:0?udp=true"])
    assert len(r["listeners"]) == 3
    assert [x["network"] for x in r["listeners"]] == ["tcp", "udp", "tcp"]
    assert "alice" not in json.dumps(r) and "secret" not in json.dumps(r)
    assert str(cfg) not in json.dumps(r)
    inspect(["-C", "http://127.0.0.1:1/must-not-contact"], "unsupported_mode")
    inspect(["-C", "-"], "unsupported_mode")
    inspect(["-watchdog", "-L", ":1"], "unsupported_mode")
    inspect(["-L", ":1", "--", "-L", ":2"], "unsupported_mode")
    inspect(["-L", "stdio://"], "unsupported_mode")
    inspect(["-bad-native-flag"], "invalid_arguments")
    inspect(["-C", str(td / "missing.json")], "config_not_found")
    inspect(["-C", '{"services":[{"name":"x","addr":":1","handler":{"type":"does-not-exist"}}]}'], "invalid_config")
    inspect(sum((["-L", "tcp://127.0.0.1:0"] for _ in range(257)), []), "too_many_listeners")
    # Occupied ports prove inspection did not construct a listener. Native hooks
    # and auth file references are deliberately not initialized.
    occupied = fixture("tcp")
    marker = td / "must-not-exist"
    side_effect_cfg = {"services": [{"name": "inspection", "addr": "127.0.0.1:" + str(occupied.getsockname()[1]),
        "handler": {"type": "http", "auth": {"file": str(marker)}},
        "metadata": {"preUp": "echo SHOULD_NOT_RUN"}}]}
    inspect(["-C", json.dumps(side_effect_cfg)])
    assert not marker.exists()
    occupied.close()

    tcp_echo, udp_echo = fixture("tcp"), fixture("udp")
    args = ["-L", "tcp://127.0.0.1:0/127.0.0.1:%d" % tcp_echo.getsockname()[1],
            "-L", "udp://127.0.0.1:0/127.0.0.1:%d?keepalive=true&ttl=2s" % udp_echo.getsockname()[1],
            "-L", "socks5://127.0.0.1:0?udp=true"]
    p = subprocess.Popen([BIN]+args, env=ENV, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    records = queue.Queue()
    def collect():
        for line in p.stdout:
            if line.startswith(PREFIX): records.put(json.loads(line[len(PREFIX):]))
    threading.Thread(target=collect, daemon=True).start()
    def wait_for(predicate, timeout=15):
        deadline = time.monotonic()+timeout
        last = None
        while time.monotonic() < deadline:
            try: last = records.get(timeout=max(.01, deadline-time.monotonic()))
            except queue.Empty: break
            if predicate(last): return last
        raise AssertionError(("snapshot timeout", last, p.poll()))
    try:
        ready = wait_for(lambda r: r.get("state") == "ready")
        listeners = ready["listeners"]
        assert len(listeners) == 3 and all(x["metrics_available"] for x in listeners), ready
        ports = [int(x["actual_address"].rsplit(":", 1)[1]) for x in listeners]
        assert all(ports)
        with socket.create_connection(("127.0.0.1", ports[0]), timeout=5) as c:
            c.sendall(b"tcp-123456789"); assert exact_read(c, 13) == b"tcp-123456789"
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.settimeout(5)
        udp.sendto(b"udp-1234567", ("127.0.0.1", ports[1]))
        assert udp.recvfrom(100)[0] == b"udp-1234567"
        # SOCKS5 UDP direction is asymmetric to detect reversed private counters.
        control = socket.create_connection(("127.0.0.1", ports[2]), timeout=5)
        control.sendall(b"\x05\x01\x00"); assert exact_read(control, 2) == b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = exact_read(control, 4); assert reply[:2] == b"\x05\x00"
        if reply[3] == 1: relay_host = socket.inet_ntop(socket.AF_INET, exact_read(control, 4))
        elif reply[3] == 4: relay_host = socket.inet_ntop(socket.AF_INET6, exact_read(control, 16))
        else: raise AssertionError(reply)
        relay_port = int.from_bytes(exact_read(control, 2), "big")
        if relay_host in ("0.0.0.0", "::"): relay_host = "127.0.0.1"
        packet = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + udp_echo.getsockname()[1].to_bytes(2, "big") + b"socks-udp-payload"
        udp.sendto(packet, (relay_host, relay_port)); assert udp.recvfrom(100)[0].endswith(b"socks-udp-payload")
        measured = wait_for(lambda r: r.get("upload_bytes", 0) >= 40 and r.get("download_bytes", 0) >= 40)
        assert measured["listeners"][0]["upload_bytes"] == 13, measured
        assert measured["listeners"][0]["download_bytes"] == 13, measured
        assert measured["listeners"][1]["upload_bytes"] == 11, measured
        assert measured["listeners"][1]["download_bytes"] == 11, measured
        assert measured["listeners"][2]["upload_bytes"] >= 16, measured
        control.close(); udp.close()
        settled = wait_for(lambda r: r.get("active_connections") == 0, timeout=12)
        assert settled["upload_bytes"] >= measured["upload_bytes"]
        assert settled["total_connections"] >= 3
    finally:
        p.terminate()
        try: p.wait(timeout=10)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
        tcp_echo.close(); udp_echo.close()
    # User API and Prometheus settings stay active at their configured paths,
    # with their original authentication. Reload keeps private cumulative bytes.
    def free_port():
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0)); return s.getsockname()[1]
    api_port, metrics_port = free_port(), free_port()
    tcp_echo = fixture("tcp")
    cfg_data = {"services": [{"name": "native-preserved", "addr": "127.0.0.1:0",
        "listener": {"type": "tcp"}, "handler": {"type": "tcp"},
        "forwarder": {"nodes": [{"name": "echo", "addr": "127.0.0.1:%d" % tcp_echo.getsockname()[1]}]},
        "metadata": {"enableStats": True, "observer.resetTraffic": True}}],
        "api": {"addr": "127.0.0.1:%d" % api_port, "pathPrefix": "/private-native", "auth": {"username": "u", "password": "p"}},
        "metrics": {"addr": "127.0.0.1:%d" % metrics_port, "path": "/custom-metrics", "auth": {"username": "u", "password": "p"}}}
    cfg.write_text(json.dumps(cfg_data))
    p = subprocess.Popen([BIN, "-C", str(cfg), "-R", "1s"], env=ENV, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    records = queue.Queue()
    threading.Thread(target=collect, daemon=True).start()
    def request(port, path, auth=False):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Authorization": "Basic " + base64.b64encode(b"u:p").decode()} if auth else {}
        c.request("GET", path, headers=headers); response = c.getresponse()
        body = response.read(); status = response.status; c.close(); return status, body
    try:
        ready = wait_for(lambda r: r.get("state") == "ready")
        port = int(ready["listeners"][0]["actual_address"].rsplit(":", 1)[1])
        with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
            c.sendall(b"independent-counts"); assert exact_read(c, 18) == b"independent-counts"
        counted = wait_for(lambda r: r.get("upload_bytes", 0) >= 18)
        assert request(api_port, "/private-native/config")[0] == 401
        assert request(api_port, "/private-native/config", True)[0] == 200
        assert request(metrics_port, "/custom-metrics")[0] == 401
        status, body = request(metrics_port, "/custom-metrics", True)
        assert status == 200 and b"gost_service_transfer_input_bytes_total" in body, (status, body[:1000])
        # The native timer reloads the same service every second. Values do not
        # reset even as old listeners are replaced with new ephemeral sockets.
        later = wait_for(lambda r: r.get("timestamp_ms", 0) >= counted["timestamp_ms"] + 2200, timeout=8)
        assert later["upload_bytes"] >= counted["upload_bytes"]
        assert later["download_bytes"] >= counted["download_bytes"]
    finally:
        p.terminate()
        try: p.wait(timeout=10)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
        tcp_echo.close()
print("PASS: native multi-L/multi-C JSON/YAML, safe diagnostics, no-bind inspection, exact TCP/UDP/SOCKS5 traffic, native API/metrics preservation and cumulative reload")
