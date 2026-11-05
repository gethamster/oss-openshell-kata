#!/usr/bin/env python3
"""Package retained Kata executables without invoking a compiler."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tarfile
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def package(target, platform, output):
    if platform not in {'darwin-arm64', 'linux-amd64', 'linux-arm64'}:
        raise ValueError('Unsupported native platform')
    metadata = tomllib.loads(Path('Cargo.toml').read_text())['package']
    names = [metadata['name'], *sorted(path.stem for path in Path('src/bin').glob('*.rs'))]
    binaries = [target / name for name in names]
    if any(not path.is_file() or path.is_symlink() for path in binaries):
        raise ValueError('All retained Kata executables are required')
    output.mkdir(parents=True, exist_ok=True)
    archive = output / ('openshell-kata-' + platform + '.tar.gz')
    with archive.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w') as bundle:
        for name, source, mode in [(('bin/' + path.name), path, 0o755) for path in binaries] + [('LICENSE', Path('LICENSE'), 0o644)]:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = source.stat().st_size, mode, 0
            with source.open('rb') as content:
                bundle.addfile(info, content)
    checksum = hashlib.sha256()
    with archive.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            checksum.update(block)
    digest = checksum.hexdigest()
    (output / (archive.name + '.sha256')).write_text(digest + '  ' + archive.name + '\n')
    (output / 'component.json').write_text(json.dumps({'schema_version': 1, 'component': 'openshell-kata', 'version': metadata['version'], 'platform': platform, 'archive': archive.name, 'sha256': digest, 'bytes': archive.stat().st_size}, sort_keys=True) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--platform', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    package(args.target_dir, args.platform, args.output)
