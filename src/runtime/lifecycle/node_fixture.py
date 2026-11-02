#!/usr/bin/env python3
"""Isolated subprocess fixture: host paths are never executed or written."""
import json
from pathlib import Path
import sys

path = Path(__file__).with_suffix('.json')
state = json.loads(path.read_text())
args = sys.argv[1:]
state.setdefault('calls', []).append(args)
output = ''
status = 0
if args == ['cat', '/proc/sys/kernel/random/boot_id']:
    output = state['boot']
elif args[:3] == ['ctr', 'containers', 'info']:
    output = json.dumps(state['native'])
elif args[:3] == ['ctr', 'tasks', 'list']:
    output = 'TASK PID STATUS\n' + ('one 123 RUNNING' if state.get('running') else '')
elif args[:2] == ['test', '-e']:
    status = 0 if (state.get('namespace') if args[2].startswith('/run/netns') else state.get('link')) else 1
elif args[:3] == ['ip', 'netns', 'add']:
    state['namespace'] = True
elif args[:3] == ['ip', 'link', 'add']:
    state['link'] = True
elif args[:3] == ['stat', '-Lc', '%i']:
    output = '12345'
elif args[:2] == ['install', '-D']:
    state.setdefault('transfers', {})[args[-1]] = json.loads(Path(args[-2]).read_text())
elif args[:3] == ['ip', '-j', 'link']:
    output = json.dumps([{'ifindex': 321, 'address': '02:01:02:03:04:05'}])
elif args[:3] == ['ip', '-j', '-n']:
    output = json.dumps([{'address': '02:01:02:03:04:06'}])
elif args[0].endswith('/kata-network') and args[1] == 'install':
    state['installed_spec'] = state['transfers'][args[-1]]
    output = '{"proof":"new-boot-fixture"}'
elif args[:3] == ['ip', 'link', 'set']:
    state['last_link_action'] = args[-1]
else:
    allowed = [['ip', 'link', 'set'], ['ip', 'address', 'add'], ['ip', '-n']]
    if not any(args[:len(prefix)] == prefix for prefix in allowed):
        raise RuntimeError('Unexpected fixture command: ' + str(args))
path.write_text(json.dumps(state))
print(output)
sys.exit(status)
