#!/usr/bin/env python3
"""Build managed engines from explicitly checked out upstream HEADs.

Source checkout/authentication is performed by CI (or the developer), never by
an installed server. The manifest records exact source and overlay revisions.
No upstream source is included in release archives.
"""
import argparse
import hashlib
import gzip
import tempfile
import shutil
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(args, cwd=None, env=None):
    subprocess.run([str(x) for x in args], cwd=cwd, env=env, check=True)


def capture(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def overlay_hash():
    digest = hashlib.sha256()
    for path in sorted((ROOT / 'engines').rglob('*')):
        if path.is_file() and path.suffix in ('.py', '.go', '.md', '.in', '.mod', '.sum'):
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--os', choices=['linux', 'windows', 'darwin'])
    parser.add_argument('--arch', choices=['amd64', 'arm64'])
    args = parser.parse_args()
    sources, out = args.sources.resolve(), args.out.resolve()
    manifest_path = sources / 'managed-manifest.json'
    if args.prepare:
        manifest = {'protocol': 1, 'instrumented': True, 'overlay_sha256': overlay_hash(), 'sources': {}}
        for name in ('flyssh', 'gust', 'gust-x'):
            source = sources / name
            if capture(['git', 'status', '--porcelain'], source):
                raise SystemExit(f'{name}: source must be a clean checkout before applying the overlay')
            sha = capture(['git', 'rev-parse', 'HEAD'], source)
            manifest['sources'][name] = {'repository': f'lovitus/{name}', 'commit': sha}
        run([sys.executable, ROOT / 'engines/flyssh/apply.py', sources / 'flyssh'])
        run([sys.executable, ROOT / 'engines/gust/apply.py', sources / 'gust', sources / 'gust-x'])
        relay_dir = sources / 'flyssh/pkg/forwarding/relaybin'
        relay_dir.mkdir(parents=True, exist_ok=True)
        # Match the upstream release's seven embedded SSH fallback relays.
        for target_os, target_arch in [('linux', 'amd64'), ('linux', 'arm64'), ('linux', '386'), ('linux', 'arm'), ('darwin', 'amd64'), ('darwin', 'arm64'), ('freebsd', 'amd64')]:
            env = dict(os.environ, CGO_ENABLED='0', GOOS=target_os, GOARCH=target_arch)
            if target_arch == 'arm':
                env['GOARM'] = '6'
            with tempfile.TemporaryDirectory(prefix='ovpn-relay-') as tmp:
                binary = Path(tmp) / 'relay'
                run([args.go, 'build', '-trimpath', '-ldflags', '-s -w', '-o', binary, './cmd/relay'], cwd=sources / 'flyssh', env=env)
                (relay_dir / f'relay-{target_os}-{target_arch}.gz').write_bytes(gzip.compress(binary.read_bytes(), compresslevel=9, mtime=0))
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        if not args.os:
            return
    if not args.os or not args.arch:
        parser.error('--os and --arch are required when building')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest['overlay_sha256'] != overlay_hash():
        raise SystemExit('Overlay changed since preparation; prepare fresh source checkouts')
    for name, source in manifest['sources'].items():
        if capture(['git', 'rev-parse', 'HEAD'], sources / name) != source['commit']:
            raise SystemExit(f'{name}: HEAD changed since preparation; prepare fresh source checkouts')
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CGO_ENABLED='0', GOOS=args.os, GOARCH=args.arch)
    suffix = '.exe' if args.os == 'windows' else ''
    for name, package in [('flyssh', '.'), ('gust', './cmd/gost')]:
        run([args.go, 'build', '-trimpath', '-ldflags', '-s -w', '-o', out / (name + suffix), package], cwd=sources / name, env=env)
    for name in ('flyssh', 'gust', 'gust-x'):
        shutil.copyfile(sources / name / 'LICENSE', out / (name + '-LICENSE.txt'))
    manifest['target'] = args.os + '/' + args.arch
    for name in ('flyssh', 'gust'):
        manifest.setdefault('binaries', {})[name] = {'file': name + suffix, 'sha256': hashlib.sha256((out / (name + suffix)).read_bytes()).hexdigest()}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
