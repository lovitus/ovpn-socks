#!/usr/bin/env python3
"""Offline subprocess contract tests: python test_inspect.py PATH_TO_BINARY."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
token = '0123456789abcdef0123456789abcdef'
prefix = 'OVPN_ENGINE_' + token + ' '
env = dict(os.environ, OVPN_SOCKS_TELEMETRY_TOKEN=token, OVPN_SOCKS_INSPECT='1')

def inspect(args, error=None, cwd=None):
    p = subprocess.run([binary] + args, env=env, cwd=cwd, capture_output=True, text=True, encoding='utf-8', timeout=5)
    rows = [json.loads(line[len(prefix):]) for line in p.stdout.splitlines() if line.startswith(prefix)]
    assert len(rows) == 1, (args, p.returncode, p.stdout, p.stderr)
    row = rows[0]
    if error:
        assert p.returncode != 0 and row['type'] == 'error' and row['error_code'] == error, row
        assert 'message' not in row and 'error' not in row
    else:
        assert p.returncode == 0 and row['type'] == 'inspect', (row, p.stderr)
        assert all(l['state'] == 'configured' and not l.get('actual_address') for l in row['listeners'])
    return row

# A bound occupied TCP port must not prevent offline inspection or be rebound.
with socket.socket() as occupied:
    occupied.bind(('127.0.0.1', 0))
    port = occupied.getsockname()[1]
    row = inspect(['-N', '-L', f'127.0.0.1:{port}:target.invalid:80', '-L', '8081:target.invalid:81', '-D', ':1080', '-R', '9000:target.invalid:90', 'host.invalid'])
    assert [l['id'] for l in row['listeners']] == ['local-0','local-1','remote-0','dynamic-0']
    assert row['listeners'][2]['scope'] == 'remote'
    assert row['listeners'][3]['address'] == ':1080'
row = inspect(['-N', '-ltcp://:8080/target:80,:8081/:81', '-dynamicproxy://:1081', 'host.invalid'])
assert [l['address'] for l in row['listeners']] == ['127.0.0.1:8080','127.0.0.1:8081','127.0.0.1:1081']
row = inspect(['--ssh-gateway', 'gateway-user:secret-value@127.0.0.1:0', 'host.invalid'])
assert 'secret-value' not in json.dumps(row) and 'gateway-user' not in json.dumps(row)
assert row['listeners'][0]['metrics_available'] is False
inspect(['-N','-L','tcp://:8080/target:80','host.invalid'], 'invalid_arguments')
inspect(['-N','-L','udp://:8080/target:80','host.invalid'], 'invalid_arguments')
inspect(['-N','-L','[::1]:8080:target:80','host.invalid'], 'invalid_arguments')
inspect(['-N','-D','65536','host.invalid'], 'invalid_arguments')
inspect(['-D','1080','host.invalid'], 'unsupported_mode')
inspect(['-N','-f','-D','1080','host.invalid'], 'unsupported_mode')
inspect(['--check-config','host.invalid'], 'invalid_arguments')
inspect(['-N','-D','1080','-F','does-not-exist','host.invalid'], 'config_not_found')
inspect(['-N'] + ['-D','0'] * 257 + ['host.invalid'], 'too_many_listeners')
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    (root/'ssh.conf').write_text('Host alias\n HostName host.invalid\n Port 22\n IdentityFile relative-key\n UserKnownHostsFile relative-known-hosts\n', encoding='utf-8')
    inspect(['-N','-D','1080','-F','ssh.conf','alias'], cwd=tmp)
    assert sorted(p.name for p in root.iterdir()) == ['ssh.conf'], 'inspection created authentication files'
    (root/'ssh.conf').write_text('Host alias\n Port 65536\n',encoding='utf-8')
    inspect(['-N','-D','1080','-F','ssh.conf','alias'], 'invalid_config', cwd=tmp)
# Managed runtime must disable native reconnect so parent policy is authoritative.
with socket.socket() as blocked, tempfile.TemporaryDirectory() as tmp:
    blocked.bind(('127.0.0.1',0))  # reserved but not listening: immediate refusal
    runtime_env=dict(env)
    runtime_env.pop('OVPN_SOCKS_INSPECT')
    p=subprocess.run([binary,'-N','-D','0','--reconnect-delay','1','-o','ConnectTimeout=1','-o','UserKnownHostsFile='+tmp+'/known_hosts','-p',str(blocked.getsockname()[1]),'u@127.0.0.1'],env=runtime_env,capture_output=True,text=True,encoding='utf-8',timeout=5)
    assert p.returncode!=0,'refused SSH connection unexpectedly succeeded'
    assert 'Reconnect in' not in p.stderr,'native reconnect was not disabled'
print('PASS: offline native inspection, safe error codes, redaction, native bindings, resource bounds, no authentication-file side effects and supervisor-owned reconnect')
