"""Native node setup boundary tests; no host privileges or network operations."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("linux_node", Path(__file__).with_name("linux_node.py"))
node = importlib.util.module_from_spec(spec)


class NativeNodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec.loader.exec_module(node)

    def test_profile_controls_disk_cpu_memory_and_rejects_unknown(self):
        self.assertEqual(node.profile("local"), (1, 2048, 2048, 12 * 1024**3))
        self.assertEqual(node.profile("foundry-build"), (32, 131072, 262144, 1280 * 1024**3))
        with self.assertRaises(ValueError):
            node.profile("caller-unlimited")

    def test_capacity_is_bounded_integer(self):
        for accepted in (1, 48, 64):
            self.assertEqual(node.capacity(accepted), accepted)
        for rejected in (None, 0, 65, -1, True, 4.0, '48'):
            with self.assertRaises(ValueError):
                node.capacity(rejected)

    def test_runtime_config_disables_shared_files_and_bounds_hardware(self):
        original = '[hypervisor.dragonball]\ndefault_vcpus = 1\ndefault_maxvcpus = 1\ndefault_memory = 2048\ndefault_maxmemory = 2048\nshared_fs = "virtio-fs"\nblock_device_driver = "virtio-blk-pci"\nblock_device_cache_direct = false\n[agent.kata]\ndial_timeout_ms = 10\nreconnect_timeout_ms = 3000\n'
        result = node.runtime_configuration(original, "foundry-build")
        self.assertIn('default_maxvcpus = 32', result)
        self.assertIn('default_memory = 131072', result)
        self.assertIn('shared_fs = "none"', result)
        self.assertIn('block_device_cache_direct = true', result)
        self.assertIn('reconnect_timeout_ms = 10000', result)
        self.assertIn('dial_timeout_ms = 10', result)
        self.assertEqual(node.runtime_configuration(result, "foundry-build"), result)
        # Native x86 Dragonball uses PCI; ARM's mmio workaround must not leak.
        self.assertIn('block_device_driver = "virtio-blk-pci"', result)
        with self.assertRaises(ValueError):
            node.runtime_configuration(original.replace('shared_fs = "virtio-fs"\n', ''), "local")
        for invalid in (original.replace('reconnect_timeout_ms = 3000\n', ''),
                        original + 'reconnect_timeout_ms = 3000\n'):
            with self.assertRaisesRegex(ValueError, 'reconnect_timeout_ms'):
                node.runtime_configuration(invalid, "local")

    def test_pool_verification_binds_devices_and_rejects_recycled_block_exposure(self):
        table = '0 2684354560 thin-pool 7:1 7:0 128 32768 1 error_if_no_space'
        node.validate_pool_table(table, 1280 * 1024**3, '7:1', '7:0')
        for unsafe in [table.replace('error_if_no_space', 'skip_block_zeroing'), table.replace('7:0', '7:9'), table.replace('2684354560', '1'), table + ' skip_block_zeroing']:
            with self.assertRaises(ValueError):
                node.validate_pool_table(unsafe, 1280 * 1024**3, '7:1', '7:0')

    def test_persistent_file_is_never_truncated_or_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'data'
            path.write_bytes(b'existing')
            with self.assertRaises(ValueError):
                node.check_backing_file(path, 1024)
            self.assertEqual(path.read_bytes(), b'existing')
            link = Path(temporary) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                node.check_backing_file(link, 8)

    def test_node_ssh_configuration_pins_localhost_and_disables_user_configuration(self):
        client, server = node.ssh_configuration('foundry')
        for required in ['HostName 127.0.0.1', 'Port 22220', 'StrictHostKeyChecking yes', 'IdentitiesOnly yes', 'ForwardAgent no', 'GlobalKnownHostsFile /dev/null']:
            self.assertIn(required, client)
        for required in ['ListenAddress 127.0.0.1', 'PasswordAuthentication no', 'AllowUsers foundry', 'AllowAgentForwarding no', 'GatewayPorts no']:
            self.assertIn(required, server)
        with self.assertRaises(ValueError):
            node.ssh_configuration('foundry\nPermitRootLogin yes')


class NativeSetupIntegrationTests(unittest.TestCase):
    """Execute install/reboot/verify against a filesystem and command fixture."""

    def test_install_reconstruct_and_repeat_preserve_backing_data(self):
        from contextlib import ExitStack
        from types import SimpleNamespace
        from unittest.mock import patch
        import hashlib
        import json
        import os
        import subprocess

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary).resolve()
            config = root / 'etc/node.json'
            runtime = root / 'opt/kata/configuration-dragonball.toml'
            binaries = root / 'input'
            binaries.mkdir()
            elf = b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\x00' + b'fixture'
            for name in ('openshell-kata', 'kata-runtime', 'kata-network', 'kata-workspace', 'kata-operator'):
                (binaries / name).write_bytes(elf)
                (binaries / name).chmod(0o755)
            archive = root / 'kata.tar.zst'
            archive.write_bytes(b'pinned-archive')
            cgroup = root / 'controllers'
            cgroup.write_text('cpu memory')
            installed = root / 'installed'
            shim = root / 'shim'
            original_profile = node.profile
            stack.enter_context(patch.object(node, 'profile', lambda value: (*original_profile(value)[:3], 4096)))
            for name, value in {'CONFIG': config, 'BIN': installed, 'RUNTIME_CONFIG': runtime,
                                'SHIM': shim, 'CONTAINERD_CONFIG': root / 'containerd.toml',
                                'CGROUP_CONTROLLERS': cgroup, 'METADATA_BYTES': 1024,
                                'KATA_BYTES': archive.stat().st_size,
                                'KATA_SHA256': hashlib.sha256(archive.read_bytes()).hexdigest()}.items():
                stack.enter_context(patch.object(node, name, value))
            stack.enter_context(patch.object(Path, 'is_char_device', return_value=True))
            stack.enter_context(patch.object(node.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())))
            real_write = node.write

            def fixture_write(path, value, mode=0o600):
                path = Path(path)
                if not path.is_relative_to(root):
                    path = root / path.relative_to('/')
                real_write(path, value, mode)

            stack.enter_context(patch.object(node, 'write', fixture_write))
            commands = []
            loop_devices = {}
            direct = set()
            pool = {'active': False}

            def command(*args, **kwargs):
                commands.append(args)
                if args[0] == 'readelf':
                    return 'LOAD'
                if args[0] == 'fallocate':
                    with open(args[-1], 'r+b') as stream:
                        stream.truncate(int(args[2]))
                if args[0] == 'tar':
                    runtime.parent.mkdir(parents=True, exist_ok=True)
                    runtime.write_text('default_vcpus = 1\ndefault_maxvcpus = 1\ndefault_memory = 2048\ndefault_maxmemory = 2048\nshared_fs = "virtio-fs"\nblock_device_driver = "virtio-blk-pci"\nblock_device_cache_direct = false\n[agent.kata]\ndial_timeout_ms = 10\nreconnect_timeout_ms = 3000\n')
                if args[0] == 'losetup':
                    if '--list' in args:
                        return '1' if args[-1] in direct else '0'
                    if args[1] == '--direct-io=on':
                        direct.add(args[-1])
                        return ''
                    path = args[-1] if '--find' in args else args[2]
                    if '--find' in args:
                        self.assertIn('--direct-io=on', args)
                        loop_devices[path] = '/dev/loop' + str(len(loop_devices))
                        direct.add(loop_devices[path])
                    return loop_devices.get(path, '')
                if args[0] == 'findmnt':
                    return 'a499b11b-6ff5-4393-96cd-499f3ea0fa1a'
                if args[0] == 'lsblk':
                    return '7:' + args[-1][-1]
                if args[:2] == ('dmsetup', 'table'):
                    if not pool['active']:
                        raise subprocess.CalledProcessError(1, args)
                    return '0 8 thin-pool 7:1 7:0 128 32768 1 error_if_no_space'
                if args[:2] == ('dmsetup', 'create'):
                    pool['active'] = True
                if args[0] == 'blockdev':
                    return '4096'
                if args[0] == 'ssh-keygen':
                    Path(args[-1]).write_bytes(b'privatefixture')
                    Path(args[-1] + '.pub').write_text('ssh-ed25519 PUBLICFIXTURE fixture\n')
                if args[:3] == ('ctr', 'plugins', 'ls'):
                    return 'io.containerd.snapshotter.v1 devmapper linux/amd64 ok'
                return ''

            stack.enter_context(patch.object(node, 'run', command))
            args = SimpleNamespace(archive=archive, binary_dir=binaries, pool_dir=root / 'pool', resource_profile='foundry-build', operator='foundry', max_sandboxes=4)
            args.pool_dir.mkdir()
            orphan = args.pool_dir / 'metadata'
            orphan.write_bytes(b'RETAINED-UNKNOWN-STATE')
            with self.assertRaisesRegex(ValueError, 'unowned persistent'):
                node.install(args)
            self.assertEqual(orphan.read_bytes(), b'RETAINED-UNKNOWN-STATE')
            self.assertFalse((args.pool_dir / 'data').exists(), 'partial state must not gain a zero backing file')
            orphan.unlink()
            evidence = node.install(args)
            self.assertTrue(evidence['node_verified'])
            self.assertEqual(evidence['max_sandboxes'], 4)
            # An existing node adopts a new capacity in place without reinstalling.
            args.max_sandboxes = 48
            raised = node.install(args)
            self.assertEqual(raised['max_sandboxes'], 48)
            self.assertEqual(json.loads(config.read_text())['max_sandboxes'], 48)
            for invalid in (0, 65):
                args.max_sandboxes = invalid
                with self.assertRaisesRegex(ValueError, 'max_sandboxes'):
                    node.install(args)
            args.max_sandboxes = 48
            # A node configuration written before capacity was explicit must be upgraded.
            legacy = {key: value for key, value in raised.items() if key not in ('max_sandboxes', 'node_verified')}
            with self.assertRaisesRegex(ValueError, 'max_sandboxes'):
                node.verify(legacy)
            self.assertTrue(node.verify(dict(legacy, max_sandboxes=48))['node_verified'])
            evidence = raised
            data = args.pool_dir / 'data'
            with data.open('r+b') as stream:
                stream.write(b'RETAINED')
            node.install(args)
            self.assertEqual(data.read_bytes()[:8], b'RETAINED')
            # Simulate reboot: loop/dm mappings vanish while the SSD files remain.
            loop_devices.clear()
            pool['active'] = False
            node.reconstruct(evidence)
            node.verify(evidence)
            self.assertEqual(data.read_bytes()[:8], b'RETAINED')
            # A retained buffered loop device adopts direct I/O in place.
            direct.clear()
            node.verify(evidence)
            self.assertEqual(direct, set(loop_devices.values()))
            self.assertEqual(sum(call[0] == 'fallocate' for call in commands), 2)
            self.assertEqual(sum(call[0] == 'tar' for call in commands), 1, 'repeat setup must not replace running runtime files')
            lost = data.with_name('data.recovery-evidence')
            data.rename(lost)
            with self.assertRaises(OSError):
                node.install(args)
            self.assertFalse(data.exists(), 'lost backing file must never be silently recreated')
            self.assertEqual(lost.read_bytes()[:8], b'RETAINED')
            self.assertEqual(sum(call[0] == 'fallocate' for call in commands), 2)
            with data.open('xb') as stream:
                stream.truncate(4096)
                os.fchmod(stream.fileno(), 0o600)
            loop_devices.clear()
            pool['active'] = False
            with self.assertRaisesRegex(ValueError, 'backing file identity'):
                node.reconstruct(evidence)
            data.unlink()
            lost.rename(data)
            self.assertIn('base_image_size = "262144MB"', node.CONTAINERD_CONFIG.read_text())
            boot = root / 'etc/systemd/system/openshell-kata-pool.service'
            self.assertIn('Before=containerd.service', boot.read_text())
            self.assertIn('RequiresMountsFor=' + str(args.pool_dir), boot.read_text())

    def test_unrelated_containerd_configuration_is_rejected_before_allocation(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary) / 'config.toml'
            existing.write_text('version = 2\n# unrelated')
            with patch.object(node, 'CONTAINERD_CONFIG', existing), patch.object(node, 'run') as command:
                with self.assertRaisesRegex(ValueError, 'unrelated'):
                    node.install(SimpleNamespace(resource_profile='foundry-build', max_sandboxes=48))
                command.assert_not_called()
            self.assertEqual(existing.read_text(), 'version = 2\n# unrelated')


class NativeSetupCliTests(unittest.TestCase):
    def test_verification_cli_requires_real_linux_root_and_commands(self):
        from contextlib import ExitStack, redirect_stdout
        from unittest.mock import patch
        import io
        import json
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            config = Path(temporary) / 'node.json'
            config.write_text('{"version":1,"resource_profile":"foundry-build"}')
            stack.enter_context(patch.object(node, 'CONFIG', config))
            stack.enter_context(patch.object(node.sys, 'argv', ['linux_node.py', '--verify']))
            stack.enter_context(patch.object(node.platform, 'system', return_value='Linux'))
            stack.enter_context(patch.object(node.platform, 'machine', return_value='x86_64'))
            root = stack.enter_context(patch.object(node.os, 'geteuid', return_value=0))
            commands = stack.enter_context(patch.object(node.shutil, 'which', return_value='/usr/bin/tool'))
            kvm = stack.enter_context(patch.object(Path, 'is_char_device', return_value=True))
            verifier = stack.enter_context(patch.object(node, 'verify', return_value={'node_verified': True}))
            output = io.StringIO()
            with redirect_stdout(output):
                node.main()
            self.assertEqual(json.loads(output.getvalue()), {'node_verified': True})
            verifier.assert_called_once_with({'version': 1, 'resource_profile': 'foundry-build'})
            root.return_value = 1000
            with self.assertRaisesRegex(ValueError, 'requires root'):
                node.main()
            root.return_value = 0
            commands.return_value = None
            with self.assertRaisesRegex(ValueError, 'upstream command missing'):
                node.main()
            commands.return_value = '/usr/bin/tool'
            kvm.return_value = False
            with self.assertRaisesRegex(ValueError, 'nested KVM'):
                node.main()

    def test_reconstruction_cli_does_not_start_any_guest(self):
        from contextlib import ExitStack
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            config = Path(temporary) / 'node.json'
            config.write_text('{"resource_profile":"foundry-build"}')
            stack.enter_context(patch.object(node, 'CONFIG', config))
            stack.enter_context(patch.object(node.sys, 'argv', ['linux_node.py', '--reconstruct']))
            stack.enter_context(patch.object(node.platform, 'system', return_value='Linux'))
            stack.enter_context(patch.object(node.platform, 'machine', return_value='x86_64'))
            stack.enter_context(patch.object(node.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(node.shutil, 'which', return_value='/usr/bin/tool'))
            stack.enter_context(patch.object(Path, 'is_char_device', return_value=True))
            reconstruct = stack.enter_context(patch.object(node, 'reconstruct'))
            install = stack.enter_context(patch.object(node, 'install'))
            node.main()
            reconstruct.assert_called_once_with({'resource_profile': 'foundry-build'})
            install.assert_not_called()


if __name__ == '__main__':
    unittest.main()
