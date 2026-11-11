"""Shared lifetime guards for disposable namespace integration services."""
import subprocess
import sys
import time
from pathlib import Path


def stop_service(unit, stop_timeout=30):
    outcome = {'stop_timed_out': False, 'forced_kill': False}
    if unit:
        try:
            subprocess.run(['systemctl', 'stop', unit], check=True, capture_output=True, timeout=stop_timeout)
        except (subprocess.SubprocessError, OSError) as error:
            outcome['stop_timed_out'] = isinstance(error, subprocess.TimeoutExpired)
            outcome['forced_kill'] = True
            print(f'{unit}: stop failed ({error}); killing all service processes', file=sys.stderr)
            try:
                subprocess.run(['systemctl', 'kill', '--kill-whom=all', '--signal=SIGKILL', unit],
                               check=True, capture_output=True, timeout=10)
            except (subprocess.SubprocessError, OSError) as kill_error:
                # A collected/already empty unit can make kill fail. Verify the
                # actual state below instead of letting this bypass recovery.
                print(f'{unit}: kill failed ({kill_error}); checking service state', file=sys.stderr)
        deadline = time.monotonic() + 30
        while True:
            status = subprocess.run(['systemctl', 'show', unit, '--property=LoadState',
                                     '--property=ActiveState', '--property=ControlGroup'],
                                    capture_output=True, text=True, timeout=10)
            properties = dict(line.split('=', 1) for line in status.stdout.splitlines() if '=' in line)
            if status.returncode and properties.get('LoadState') != 'not-found':
                raise RuntimeError(f'cannot verify {unit} stopped; cleanup cannot be confirmed')
            group = properties.get('ControlGroup')
            empty = group == ''
            if group:
                if not group.startswith('/') or group == '/' or '..' in Path(group).parts:
                    raise RuntimeError('unsafe service cgroup path; cleanup cannot be confirmed')
                try:
                    events = (Path('/sys/fs/cgroup') / group[1:] / 'cgroup.events').read_text()
                    empty = 'populated 0' in events.splitlines()
                except FileNotFoundError:
                    empty = True
            if properties.get('ActiveState') in {'inactive', 'failed'} and empty:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f'{unit} still active or populated; cleanup cannot be confirmed')
            time.sleep(0.05)
    return outcome
