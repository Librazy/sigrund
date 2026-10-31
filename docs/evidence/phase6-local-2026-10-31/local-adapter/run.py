#!/usr/bin/python3
"""Local-only Phase 6 environment adapter; root approval required."""
import json
import os
from pathlib import Path
import re
import sys
import uuid
REPO = Path('/var/home/librazy/Git/github/Librazy/sigrund')
BINARY = REPO / 'target/debug'
BASE = Path('/tmp/sigrund-phase6-local-1f66ebd')
CHECKS = Path('/tmp/sigrund-phase6-local-checks-1f66ebd/checks.json')
def service():
    import ctypes
    import errno
    lib = ctypes.CDLL(None, use_errno=True)
    if lib.unshare(0x00020000) != 0 or lib.mount(None, b"/", None, 0x4000 | 0x40000, None) != 0:
        raise OSError(ctypes.get_errno(), 'private mount namespace')
    hostroot = BASE / 'hostroot'
    hostroot.mkdir(exist_ok=True)
    if lib.mount(b'/run/host', os.fsencode(hostroot), None, 0x1000 | 0x4000, None) != 0:
        raise OSError(ctypes.get_errno(), 'retain host paths in private namespace')
    if not (hostroot / 'sys/fs/cgroup/cgroup.controllers').is_file():
        raise RuntimeError('retained host mount tree lacks cgroup v2')
    for _ in range(8):
        if lib.umount2(b'/sys/fs/cgroup', 2) != 0:
            if ctypes.get_errno() == errno.EINVAL:
                break
            raise OSError(ctypes.get_errno(), 'detach container cgroup overmount')
    else:
        raise RuntimeError('too many stacked cgroup mounts')
    if lib.mount(os.fsencode(hostroot / 'sys/fs/cgroup'), b'/sys/fs/cgroup', None, 0x1000, None) != 0:
        raise OSError(ctypes.get_errno(), 'coherent delegated cgroup view')
    # Only this test service sees host /run. Host-managed RuntimeDirectory and
    # notify endpoints must be the same directories seen by the test daemons.
    if lib.mount(os.fsencode(hostroot / 'run'), b'/run', None, 0x1000, None) != 0:
        raise OSError(ctypes.get_errno(), 'private host runtime-directory view')
    member = Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]
    group = Path('/sys/fs/cgroup' + member)
    if not re.fullmatch(r'sigrund-mvp-gate-[0-9a-f]{32}\.service', group.name):
        raise RuntimeError('unexpected service cgroup: ' + str(group))
    if (group / 'cgroup.procs').read_text().split() != [str(os.getpid())]:
        raise RuntimeError('service must contain only this acceptance runner')
    config = {'anchor': os.getpid(), 'supervisor': group.name, 'hostroot': str(hostroot)}
    (BASE / 'adapter.json').write_text(json.dumps(config))
    os.environ['PATH'] = str(BASE / 'tools') + ':/usr/sbin:/usr/bin:/sbin:/bin'
    # Bounded transport preflight before repeating the acceptance suite.
    import subprocess
    import tempfile
    namespace = ['/usr/bin/nsenter', '--mount=/proc/' + str(os.getpid()) + '/ns/mnt',
                 '--root=/proc/' + str(os.getpid()) + '/root', '--']
    results = []
    for mode in ('pipes', 'files'):
        probe = 'sigrund-mvp-probe-' + uuid.uuid4().hex
        command = ['/usr/bin/nsenter', '--mount=/proc/1/ns/mnt', '--root=/proc/1/root', '--',
                   '/usr/bin/systemd-run', '--unit=' + probe, '--wait', '--pipe', '--collect',
                   '--property=RuntimeMaxSec=10s', '--property=TimeoutStopSec=3s',
                   '--property=KillMode=control-group', '--property=BindsTo=' + group.name,
                   '--property=After=' + group.name, *namespace, '/usr/bin/true']
        try:
            if mode == 'pipes':
                result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
            else:
                with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=15)
                    out.seek(0); err.seek(0)
                    result.stdout, result.stderr = out.read(), err.read()
            observation = {'mode': mode, 'code': result.returncode,
                           'stdout': result.stdout.decode(errors='replace'),
                           'stderr': result.stderr.decode(errors='replace')}
            results.append(observation)
            print(json.dumps({'event': 'SYSTEMD_PIPE_PREFLIGHT', **observation}), flush=True)
        finally:
            subprocess.run(['/usr/bin/systemctl', 'stop', probe], capture_output=True,
                           env=dict(os.environ, SYSTEMD_IGNORE_CHROOT='1', SYSTEMD_OFFLINE='0'))
    (BASE / 'transport-preflight.json').write_text(json.dumps(results, indent=2) + '\n')
    if results[-1]['code']:
        raise RuntimeError('file-backed foreground transport also failed; no acceptance retry')
    # The repository's real inside entry point owns controller setup and all
    # acceptance gates. The adapter supplies environment, not test replacements.
    os.execv('/usr/bin/python3', ['/usr/bin/python3', str(REPO / 'scripts/verify-mvp.py'),
        '--inside', '--binaries', str(BINARY), '--checks', str(CHECKS),
        '--requester', 'librazy', '--artifacts', str(BASE / 'acceptance-5')])

def main():
    if os.geteuid() != 0:
        raise SystemExit('root required')
    if sys.argv[1:] == ['--service']:
        service()
        return
    (BASE / 'acceptance-5').mkdir(exist_ok=False)
    unit = 'sigrund-mvp-gate-' + uuid.uuid4().hex + '.service'
    # Gio connects to the already-verified host system bus directly; local
    # systemd-run cannot operate when the container lacks /run/systemd/system.
    from gi.repository import Gio, GLib
    import time
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    destination = 'org.freedesktop.systemd1'
    manager = '/org/freedesktop/systemd1'
    interface = 'org.freedesktop.systemd1.Manager'
    def call(path, iface, method, args):
        return bus.call_sync(destination, path, iface, method, args, None,
                             Gio.DBusCallFlags.NONE, 10000, None).unpack()
    def variant(kind, value):
        return GLib.Variant(kind, value)
    output = Path(__file__).parent / (unit + '.log')
    output.touch(mode=0o600)
    output_fd = os.open(output, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
    fd_list = Gio.UnixFDList.new()
    output_index = fd_list.append(output_fd)
    os.close(output_fd)
    command = ['/usr/bin/nsenter', '--mount=/proc/'+str(os.getpid())+'/ns/mnt',
               '--root=/proc/'+str(os.getpid())+'/root',
               '--','/usr/bin/python3',str(Path(__file__).resolve()),'--service']
    properties = [
        ('Description', variant('s', 'sigrund Phase 6 local Distrobox acceptance')),
        ('Type', variant('s', 'exec')),
        ('Delegate', variant('b', True)),
        ('KillMode', variant('s', 'control-group')),
        ('SendSIGKILL', variant('b', True)),
        ('RuntimeMaxUSec', variant('t', 600000000)),
        ('TimeoutStopUSec', variant('t', 15000000)),
        ('RemainAfterExit', variant('b', True)),
        ('StandardOutputFileDescriptor', variant('h', output_index)),
        ('StandardErrorFileDescriptor', variant('h', output_index)),
        ('ExecStart', variant('a(sasb)', [(command[0], command, False)])),
    ]
    print(json.dumps({'event':'PRIVILEGED_GATE_LAUNCH','unit':unit,'command':command}),flush=True)
    bus.call_with_unix_fd_list_sync(destination, manager, interface, 'StartTransientUnit',
         variant('(ssa(sv)a(sa(sv)))', (unit, 'fail', properties, [])), None,
         Gio.DBusCallFlags.NONE, 10000, fd_list, None)
    path = call(manager, interface, 'GetUnit', variant('(s)', (unit,)))[0]
    offset = 0
    code = 1
    try:
        deadline = time.monotonic() + 630
        while True:
            contents = output.read_text()
            print(contents[offset:], end='', flush=True)
            offset = len(contents)
            state = call(path, 'org.freedesktop.DBus.Properties', 'GetAll',
                         variant('(s)', ('org.freedesktop.systemd1.Unit',)))[0]
            details = call(path, 'org.freedesktop.DBus.Properties', 'GetAll',
                           variant('(s)', ('org.freedesktop.systemd1.Service',)))[0]
            if state['SubState'] in ('exited', 'failed', 'dead'):
                print(json.dumps({'event':'PRIVILEGED_GATE_RESULT', 'state':state['SubState'],
                      'result':details['Result'], 'code':details['ExecMainCode'],
                      'status':details['ExecMainStatus']}), flush=True)
                code = 0 if details['Result']=='success' and details['ExecMainStatus']==0 else 1
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('system service gate did not finish')
            time.sleep(0.1)
    finally:
        call(manager, interface, 'StopUnit', variant('(ss)', (unit, 'replace')))
        deadline = time.monotonic()+20
        while time.monotonic()<deadline:
            try:
                state = call(path, 'org.freedesktop.DBus.Properties', 'GetAll',
                             variant('(s)', ('org.freedesktop.systemd1.Unit',)))[0]
                if state['ActiveState'] in ('inactive', 'failed'):
                    break
            except GLib.Error:
                break
            time.sleep(0.1)
        contents = output.read_text()
        print(contents[offset:], end='', flush=True)
        try:
            call(manager, interface, 'ResetFailedUnit', variant('(s)', (unit,)))
        except GLib.Error:
            pass
    # Read-only verification after --wait: the unit must have no surviving tasks.
    group = Path('/run/host/sys/fs/cgroup/system.slice')/unit
    if group.exists():
        events = (group/'cgroup.events').read_text()
        print(json.dumps({'event':'PRIVILEGED_GATE_CLEANUP','events':events}),flush=True)
        if 'populated 1' in events:
            raise RuntimeError('service retained tasks after completion')
    else:
        print(json.dumps({'event':'PRIVILEGED_GATE_CLEANUP','removed':True}),flush=True)
    remaining = group.exists()
    supervisor = {'unit': unit, 'result_code': code, 'cgroup_removed': not remaining,
                  'local_adapter': str(BASE / 'adapter.json'), 'log': str(output)}
    (BASE / 'acceptance-5/supervisor.json').write_text(json.dumps(supervisor, indent=2) + '\n')
    if remaining:
        raise RuntimeError('supervisor cgroup was not removed')
    raise SystemExit(code)

if __name__ == '__main__':
    main()
