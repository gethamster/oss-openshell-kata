#!/usr/bin/env python3
"""Install and verify a dedicated Linux Kata node with retained block storage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys

KATA_SHA256 = "1463a2b86845f4d3d8e87f2f764ec59856fc0fee3520967a79ade32762be2e97"
KATA_BYTES = 1021129805
CONFIG = Path("/etc/openshell-kata/node.json")
BIN = Path("/opt/openshell-kata")
RUNTIME_CONFIG = Path("/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml")
POOL_NAME = "openshell-kata-pool"
SHIM = Path("/usr/local/bin/containerd-shim-kata-v2")
CONTAINERD_CONFIG = Path("/etc/containerd/config.toml")
CGROUP_CONTROLLERS = Path("/sys/fs/cgroup/cgroup.controllers")
METADATA_BYTES = 1024**3
# Operator-selected node capacity: retained guests admitted at once, stopped included.
MAX_SANDBOXES_LIMIT = 64


def profile(name):
    """Return fixed CPU, memory MiB, disk MiB and total thin-pool bytes."""
    if name == "local":
        return 1, 2048, 2048, 12 * 1024**3
    if name == "foundry-build":
        return 32, 131072, 262144, 1280 * 1024**3
    raise ValueError("unknown operator resource profile")


def capacity(value):
    """Validate the operator node capacity in retained guests."""
    if type(value) is not int or not 1 <= value <= MAX_SANDBOXES_LIMIT:
        raise ValueError(f"max_sandboxes must be an integer between 1 and {MAX_SANDBOXES_LIMIT}")
    return value


def run(*args, timeout=120):
    result = subprocess.run(args, check=True, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if len(result.stdout) > 1024**2 or len(result.stderr) > 1024**2:
        raise ValueError("node command exceeded output limit")
    return result.stdout.decode().strip()


def write(path, value, mode=0o600):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("unsafe node configuration destination")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    with temporary.open("x") as stream:
        stream.write(value)
        os.fchmod(stream.fileno(), mode)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024**2), b''):
            digest.update(chunk)
    return digest.hexdigest()


def check_backing_file(path, size):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size != size or info.st_uid != os.geteuid():
        raise ValueError("persistent backing file identity or capacity differs")
    if info.st_mode & 0o077:
        raise ValueError("persistent backing file must be private")


def runtime_configuration(original, selected):
    cpu, memory, _, _ = profile(selected)
    replacements = {"default_vcpus": str(cpu), "default_maxvcpus": str(cpu),
                    "default_memory": str(memory), "default_maxmemory": str(memory),
                    "shared_fs": '"none"',
                    # Slow guest boots must not exhaust the agent retry count
                    # before the lifecycle's independently bounded boot ends.
                    "reconnect_timeout_ms": "10000"}
    for key, value in replacements.items():
        original, count = re.subn(r"(?m)^" + key + r"\s*=.*$", key + " = " + value, original)
        if count != 1:
            raise ValueError("official runtime configuration key missing or ambiguous: " + key)
    for key in ("overhead_vcpus", "overhead_memory"):
        original = re.sub(r"(?m)^" + key + r"\s*=.*$", key + " = 0", original)
    return original


def validate_pool_table(table, size, metadata_device, data_device):
    expected = ['0', str(size // 512), 'thin-pool', metadata_device, data_device,
                '128', '32768', '1', 'error_if_no_space']
    if table.split() != expected:
        raise ValueError("thin pool identity, capacity, zeroing or exhaustion behavior differs")


def loop_device(path, create):
    entries = run("losetup", "--associated", str(path), "--output", "NAME", "--noheadings").splitlines()
    if len(entries) > 1:
        raise ValueError("backing file has ambiguous loop device ownership")
    if entries:
        return entries[0].strip()
    if not create:
        raise ValueError("persistent backing file has no reconstructed loop device")
    return run("losetup", "--find", "--show", "--nooverlap", str(path))


def backing_identities(pool):
    filesystem = run('findmnt', '-no', 'UUID', '--target', str(pool))
    if not re.fullmatch(r'[0-9a-fA-F-]{32,36}', filesystem):
        raise ValueError("retained pool requires a filesystem UUID")
    return {name: {'filesystem_uuid': filesystem, 'inode': (pool / name).lstat().st_ino}
            for name in ('data', 'metadata')}


def reconstruct(config, create=True):
    pool = Path(config["pool"]["path"])
    if not pool.is_absolute() or pool.resolve() != pool or pool.is_symlink():
        raise ValueError("pool must be an absolute canonical directory")
    _, _, _, size = profile(config["resource_profile"])
    if config["pool"]["bytes"] != size:
        raise ValueError("pool size differs from selected profile")
    check_backing_file(pool / 'data', size)
    check_backing_file(pool / 'metadata', METADATA_BYTES)
    if config.get('backing_files') != backing_identities(pool):
        raise ValueError('persistent backing file identity changed')
    if create:
        run("modprobe", "dm_thin_pool")
    data = loop_device(pool / 'data', create)
    metadata = loop_device(pool / 'metadata', create)
    data_id = run("lsblk", "-dn", "-o", "MAJ:MIN", data)
    metadata_id = run("lsblk", "-dn", "-o", "MAJ:MIN", metadata)
    try:
        table = run("dmsetup", "table", POOL_NAME)
    except subprocess.CalledProcessError:
        if not create:
            raise
        # No skip_block_zeroing: a new guest must never see recycled guest blocks.
        run("dmsetup", "create", POOL_NAME, "--table",
            f"0 {size // 512} thin-pool {metadata} {data} 128 32768 1 error_if_no_space")
        table = run("dmsetup", "table", POOL_NAME)
    validate_pool_table(table, size, metadata_id, data_id)
    if int(run("blockdev", "--getsize64", "/dev/mapper/" + POOL_NAME)) != size:
        raise ValueError("thin pool observed capacity differs")


def ssh_configuration(user):
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise ValueError("invalid operator account")
    client = f'''Host openshell-kata-linux
  HostName 127.0.0.1
  Port 22220
  User {user}
  IdentityFile /etc/openshell-kata/node-client
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking yes
  UserKnownHostsFile /etc/openshell-kata/node-known-hosts
  GlobalKnownHostsFile /dev/null
  UpdateHostKeys no
  ForwardAgent no
  ConnectTimeout 5
'''
    server = f'''Port 22220
ListenAddress 127.0.0.1
HostKey /etc/openshell-kata/node-host
PidFile /run/openshell-kata-node-sshd.pid
AuthorizedKeysFile /etc/openshell-kata/node-authorized
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
AllowUsers {user}
AllowAgentForwarding no
AllowTcpForwarding local
GatewayPorts no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
UsePAM yes
StrictModes yes
LogLevel VERBOSE
'''
    return client, server


def prepare_ssh(user):
    account = pwd.getpwnam(user)
    for name in ('node-client', 'node-host'):
        path = CONFIG.parent / name
        if not path.exists():
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path))
        if path.is_symlink() or not path.is_file():
            raise ValueError("unsafe node SSH key")
        path.chmod(0o600)
    os.chown(CONFIG.parent / 'node-client', account.pw_uid, account.pw_gid)
    public = (CONFIG.parent / 'node-client.pub').read_text().strip()
    write(CONFIG.parent / 'node-authorized', 'restrict,port-forwarding,command="/usr/bin/false" ' + public + '\n', 0o644)
    host = (CONFIG.parent / 'node-host.pub').read_text().split()
    write(CONFIG.parent / 'node-known-hosts', '[127.0.0.1]:22220 ' + ' '.join(host[:2]) + '\n', 0o644)
    client, server = ssh_configuration(user)
    write(CONFIG.parent / 'node-ssh.config', client, 0o644)
    write(CONFIG.parent / 'node-sshd.config', server)
    run("sshd", "-t", "-f", str(CONFIG.parent / 'node-sshd.config'))
    write('/etc/systemd/system/openshell-kata-node-ssh.service', '''[Unit]
Description=Pinned localhost transport for the native Kata operator
After=network.target
[Service]
Type=simple
ExecStart=/usr/sbin/sshd -D -e -f /etc/openshell-kata/node-sshd.config
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
''', 0o644)


def verify(config):
    if config['version'] != 1 or config['architecture'] != 'x86_64' or config['transport'] != 'linux-local' or config['archive_sha256'] != KATA_SHA256:
        raise ValueError("unexpected node configuration identity")
    cpu, memory, disk, _ = profile(config['resource_profile'])
    if config['resources'] != {'vcpus': cpu, 'memory_mib': memory, 'disk_mib': disk}:
        raise ValueError("node resource configuration differs")
    capacity(config.get('max_sandboxes'))
    reconstruct(config, create=False)
    if not Path('/dev/kvm').is_char_device() or not CGROUP_CONTROLLERS.is_file():
        raise ValueError("KVM and cgroups v2 are required")
    current = RUNTIME_CONFIG.read_text()
    if runtime_configuration(current, config['resource_profile']) != current:
        raise ValueError("installed Kata resource limits differ")
    expected_binaries = config.get('binaries_sha256', {})
    if set(expected_binaries) != {'openshell-kata', 'kata-runtime', 'kata-network', 'kata-workspace', 'kata-operator'}:
        raise ValueError("installed native binary identity set differs")
    for binary, digest in expected_binaries.items():
        path = BIN / binary
        if path.is_symlink() or not path.is_file() or file_digest(path) != digest:
            raise ValueError("installed native binary digest differs")
    run('nft', 'list', 'tables')
    plugins = run('ctr', 'plugins', 'ls')
    if not any('devmapper' in line and line.split()[-1] == 'ok' for line in plugins.splitlines()):
        raise ValueError("devmapper snapshotter is not healthy")
    run('systemctl', 'is-active', '--quiet', 'openshell-kata-pool.service', 'openshell-kata-node-ssh.service', 'containerd.service')
    run('sshd', '-t', '-f', str(CONFIG.parent / 'node-sshd.config'))
    return dict(config, node_verified=True)


def install(args):
    cpu, memory, disk, size = profile(args.resource_profile)
    capacity(args.max_sandboxes)
    if CONTAINERD_CONFIG.exists() and not CONTAINERD_CONFIG.read_text().startswith('# Managed dedicated OpenShell Kata node\n'):
        raise ValueError('refusing to replace an unrelated containerd configuration')
    archive = args.archive.resolve(strict=True)
    if archive.stat().st_size != KATA_BYTES:
        raise ValueError("official Kata archive length differs")
    if file_digest(archive) != KATA_SHA256:
        raise ValueError("official Kata archive digest differs")
    pool = args.pool_dir
    if not pool.is_absolute() or pool.is_symlink() or pool.parent.resolve() != pool.parent:
        raise ValueError("pool path must have canonical existing parent")
    config = {'version': 1, 'transport': 'linux-local', 'architecture': 'x86_64',
              'kata_version': '4.3.1', 'archive_sha256': KATA_SHA256,
              'resource_profile': args.resource_profile, 'operator': args.operator,
              'max_sandboxes': args.max_sandboxes,
              'resources': {'vcpus': cpu, 'memory_mib': memory, 'disk_mib': disk},
              'pool': {'path': str(pool), 'bytes': size, 'zeroing': True}}
    workspace = args.binary_dir / 'kata-workspace'
    with workspace.open('rb') as stream:
        header = stream.read(20)
    if header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00' or 'INTERP' in run('readelf', '-l', str(workspace)):
        raise ValueError("kata-workspace must be a static x86_64 Linux ELF")
    for binary in ('openshell-kata', 'kata-runtime', 'kata-network', 'kata-workspace', 'kata-operator'):
        path = args.binary_dir / binary
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("native binary missing: " + binary)
    config['binaries_sha256'] = {binary: file_digest(args.binary_dir / binary) for binary in ('openshell-kata', 'kata-runtime', 'kata-network', 'kata-workspace', 'kata-operator')}
    if CONFIG.exists():
        retained = json.loads(CONFIG.read_text())
        mutable = ('backing_files', 'max_sandboxes')
        identity = {key: value for key, value in retained.items() if key not in mutable}
        if identity != {key: value for key, value in config.items() if key not in mutable}:
            raise ValueError("existing node identity differs; migration requires explicit quiescence")
        # Capacity is operator policy, not node identity: record a changed value in place.
        # A running node must not have its mapped executables or runtime replaced.
        if retained.get('max_sandboxes') != args.max_sandboxes:
            retained = dict(retained, max_sandboxes=args.max_sandboxes)
            write(CONFIG, json.dumps(retained, sort_keys=True) + '\n')
        return verify(retained)
    if pool.exists() and any(pool.iterdir()):
        raise ValueError("refusing to initialize unowned persistent pool state")
    pool.mkdir(mode=0o700, exist_ok=True)
    for name, length in (('data', size), ('metadata', METADATA_BYTES)):
        path = pool / name
        if not path.exists() and not path.is_symlink():
            # Preallocation reserves the full bounded capacity on the retained SSD.
            with path.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
            run('fallocate', '-l', str(length), str(path))
        check_backing_file(path, length)
    config['backing_files'] = backing_identities(pool)
    run('tar', '--zstd', '-xf', str(archive), '-C', '/', timeout=300)
    write(RUNTIME_CONFIG, runtime_configuration(RUNTIME_CONFIG.read_text(), args.resource_profile), 0o644)
    link = RUNTIME_CONFIG.with_name('configuration.toml')
    if link.exists() and not link.is_symlink():
        raise ValueError("runtime configuration selector is not a symlink")
    link.unlink(missing_ok=True)
    link.symlink_to(RUNTIME_CONFIG.name)
    BIN.mkdir(parents=True, exist_ok=True)
    for binary in ('openshell-kata', 'kata-runtime', 'kata-network', 'kata-workspace', 'kata-operator'):
        shutil.copyfile(args.binary_dir / binary, BIN / binary)
        (BIN / binary).chmod(0o755)
    shutil.copyfile(Path(__file__), BIN / 'linux_node.py')
    shim = SHIM
    if shim.exists() and not shim.is_symlink():
        raise ValueError("Kata shim selector is not a symlink")
    shim.unlink(missing_ok=True)
    shim.symlink_to('/opt/kata/runtime-rs/bin/containerd-shim-kata-v2')
    for module in ('vhost_vsock', 'vhost_net'):
        run('modprobe', module)
    write('/etc/modules-load.d/openshell-kata.conf', 'dm_thin_pool\nvhost_vsock\nvhost_net\n', 0o644)
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    write(CONFIG, json.dumps(config, sort_keys=True) + '\n')
    reconstruct(config)
    write('/etc/systemd/system/openshell-kata-pool.service', '''[Unit]
Description=Reconstruct retained bounded Kata thin pool
After=local-fs.target
Before=containerd.service
RequiresMountsFor=''' + str(pool) + '''
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/openshell-kata/linux_node.py --reconstruct
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''', 0o644)
    root_config = CONTAINERD_CONFIG
    marker = '# Managed dedicated OpenShell Kata node\n'
    if root_config.exists() and not root_config.read_text().startswith(marker):
        raise ValueError("refusing to replace an unrelated containerd configuration")
    write(root_config, marker + f'''version = 2
root = {json.dumps(str(pool / 'containerd'))}
state = "/run/containerd"
[plugins."io.containerd.snapshotter.v1.devmapper"]
  root_path = {json.dumps(str(pool / 'snapshots'))}
  pool_name = "openshell-kata-pool"
  base_image_size = "{disk}MB"
  async_remove = false
[[plugins."io.containerd.transfer.v1.local".unpack_config]]
  platform = "linux/amd64"
  snapshotter = "overlayfs"
[[plugins."io.containerd.transfer.v1.local".unpack_config]]
  platform = "linux/amd64"
  snapshotter = "devmapper"
''', 0o644)
    write('/etc/systemd/system/containerd.service.d/openshell-kata.conf', '[Unit]\nRequires=openshell-kata-pool.service\nAfter=openshell-kata-pool.service\n', 0o644)
    prepare_ssh(args.operator)
    write('/etc/sudoers.d/openshell-kata-operator', args.operator + ' ALL=(root) NOPASSWD: /usr/bin/timeout\n', 0o440)
    run('visudo', '-cf', '/etc/sudoers.d/openshell-kata-operator')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'openshell-kata-pool.service', 'openshell-kata-node-ssh.service')
    run('systemctl', 'restart', 'containerd.service')
    return verify(config)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--verify', action='store_true')
    mode.add_argument('--reconstruct', action='store_true')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--binary-dir', type=Path)
    parser.add_argument('--pool-dir', type=Path)
    parser.add_argument('--resource-profile', choices=('local', 'foundry-build'), default='local')
    parser.add_argument('--operator', default='foundry')
    parser.add_argument('--max-sandboxes', type=int,
                        help=f'retained guests the node admits at once (1..{MAX_SANDBOXES_LIMIT})')
    args = parser.parse_args()
    if not args.verify and not args.reconstruct and not all((args.archive, args.binary_dir, args.pool_dir, args.max_sandboxes)):
        parser.error('installation requires --archive, --binary-dir, --pool-dir and --max-sandboxes')
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() != 0:
        raise ValueError('native setup requires root on a dedicated x86_64 Linux node')
    for command in ('containerd', 'ctr', 'nerdctl', 'nft', 'ip', 'sshd', 'ssh-keygen', 'losetup', 'lsblk', 'findmnt', 'blockdev', 'dmsetup', 'fallocate', 'modprobe', 'tar', 'zstd', 'readelf', 'visudo', 'systemctl'):
        if shutil.which(command) is None:
            raise ValueError('required upstream command missing: ' + command)
    if not Path('/dev/kvm').is_char_device():
        raise ValueError('nested KVM is required')
    if args.reconstruct:
        reconstruct(json.loads(CONFIG.read_text()))
        return
    evidence = verify(json.loads(CONFIG.read_text())) if args.verify else install(args)
    print(json.dumps(evidence, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Command output can contain host paths; never print arbitrary subprocess output.
        print('native Kata setup failed: ' + str(error).splitlines()[0], file=sys.stderr)
        sys.exit(1)
