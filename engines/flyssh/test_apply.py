#!/usr/bin/env python3
"""Verify clean-source overlay application and atomic preflight failure paths."""
import hashlib
import pathlib
import subprocess
import sys
import tempfile

source = pathlib.Path(sys.argv[1]).resolve()
here = pathlib.Path(__file__).resolve().parent
names = ['main.go', 'pkg/forwarding/forwarding.go', 'pkg/gateway/gateway.go']
original = {n: subprocess.check_output(['git','-C',str(source),'show','HEAD:'+n]) for n in names}

def materialize(root):
    for n, data in original.items():
        target=root/n
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)

def hashes(root):
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}

def apply(root):
    return subprocess.run([sys.executable,str(here/'apply.py'),str(root)],capture_output=True,text=True)

with tempfile.TemporaryDirectory() as d:
    root=pathlib.Path(d)
    materialize(root)
    p=apply(root)
    assert p.returncode==0,(p.stdout,p.stderr)
    assert (root/'pkg/managed/managed.go').exists()
    assert (root/'managed_observation_test.go').exists()
    before=hashes(root)
    p=apply(root)
    assert p.returncode!=0 and hashes(root)==before,'reapplication mutated files'
with tempfile.TemporaryDirectory() as d:
    root=pathlib.Path(d)
    materialize(root)
    p=root/'pkg/gateway/gateway.go'
    p.write_text(p.read_text().replace('func ServeWithReady(', 'func RenamedServeWithReady('))
    before=hashes(root)
    result=apply(root)
    assert result.returncode!=0 and 'context drift' in result.stderr and hashes(root)==before,'context drift was not atomic'
print('PASS: fresh HEAD apply, repeated-apply rejection and preflight context-drift rejection without partial writes')
