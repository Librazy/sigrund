"""Check executable trust fixture bounds using real native ELF programs."""
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import tempfile
import threading
import tomllib
from types import SimpleNamespace
import unittest


REPO = Path(__file__).resolve().parents[2]
TRUST = runpy.run_path(str(REPO / 'scripts/verify-trust.py'))


class TrustFixtureTests(unittest.TestCase):
    def test_approval_retries_pre_request_eof_during_broker_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = SimpleNamespace(approval=Path(directory) / 'approval.sock',
                                      diagnostics=Path(directory) / 'diagnostics')
            fixture.diagnostics.write_text('')
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(fixture.approval)); listener.listen(2); listener.settimeout(2)
                errors = []
                def serve():
                    try:
                        first, _ = listener.accept(); first.close()
                        with listener.accept()[0] as admitted:
                            admitted.settimeout(2)
                            fixture.diagnostics.write_text('{"broker":true}\n')
                            self.assertEqual(admitted.recv(1), b'', 'readiness must send no bytes')
                    except BaseException as error:
                        errors.append(error)
                server = threading.Thread(target=serve); server.start()
                try:
                    connection = TRUST['connect_approval'](fixture, timeout=1)
                    connection.close()
                finally:
                    server.join(3)
                self.assertFalse(server.is_alive())
                self.assertEqual(errors, [])

    def test_approval_admission_timeout_closes_its_unadmitted_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = SimpleNamespace(approval=Path(directory) / 'approval.sock',
                                      diagnostics=Path(directory) / 'diagnostics')
            fixture.diagnostics.write_text('')
            closed = threading.Event()
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(fixture.approval)); listener.listen(1); listener.settimeout(2)
                def serve():
                    with listener.accept()[0] as connection:
                        connection.settimeout(2)
                        if connection.recv(1) == b'': closed.set()
                server = threading.Thread(target=serve); server.start()
                try:
                    with self.assertRaisesRegex(AssertionError, 'broker registered'):
                        TRUST['connect_approval'](fixture, timeout=0.05)
                finally:
                    server.join(3)
                self.assertFalse(server.is_alive())
                self.assertTrue(closed.is_set())

    def test_lease_cleanup_waits_for_delayed_owner_disposal(self):
        with tempfile.TemporaryDirectory(dir='/dev/shm') as directory:
            path = Path(directory) / 'executable'
            path.write_bytes(b'fixture')
            # The owner releases its lease after receiving a break notification,
            # as a delayed request-disposal worker would do after rejection.
            owner = subprocess.Popen([sys.executable, '-c', '''
import fcntl
import os
import signal
import sys
import time

source = open(sys.argv[1], 'rb')
def dispose(signum, frame):
    time.sleep(0.1)
    source.close()
    raise SystemExit(0)
signal.signal(signal.SIGIO, dispose)
fcntl.fcntl(source, fcntl.F_SETOWN, os.getpid())
fcntl.fcntl(source, fcntl.F_SETLEASE, fcntl.F_RDLCK)
print('ready', flush=True)
signal.pause()
''', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(owner.stdout.readline(), 'ready\n')
                with self.assertRaises(BlockingIOError):
                    os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                TRUST['wait_for_lease_cleanup'](path)
                _, stderr = owner.communicate(timeout=5)
                self.assertEqual(owner.returncode, 0, stderr)
            finally:
                if owner.poll() is None:
                    owner.kill()
                owner.communicate(timeout=5)

    def test_lease_cleanup_propagates_unrelated_open_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                TRUST['wait_for_lease_cleanup'](Path(directory) / 'missing')

    def test_native_programs_straddle_snapshot_bound_and_remain_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            commands = base / 'commands'
            commands.mkdir()
            fixture = SimpleNamespace(base=base, commands=commands)
            config = base / 'config'
            config.write_text((REPO / 'config/sigrund.toml.example').read_text())
            TRUST['configure'](fixture)
            limits = tomllib.loads(config.read_text())
            snapshot_max = limits['max_executable_bytes']
            small = TRUST['program'](fixture, 'small', size=None)
            direct = TRUST['program'](fixture, 'direct', size=snapshot_max + 1)
            metadata = TRUST['program'](fixture, 'metadata')
            self.assertLessEqual(small.stat().st_size, snapshot_max)
            self.assertEqual(direct.stat().st_size, snapshot_max + 1)
            self.assertLess(direct.stat().st_size, limits['max_direct_digest_bytes'])
            self.assertGreater(metadata.stat().st_size, 67_108_864)
            self.assertEqual(limits['direct_digest_timeout_ms'], 5000)
            for program in (small, direct, metadata):
                with self.subTest(program=program.name):
                    result = subprocess.run([str(program)], capture_output=True, check=True, timeout=5)
                    self.assertEqual(result.stdout, f'{os.geteuid()}\n'.encode())
                    self.assertFalse(result.stderr)


if __name__ == '__main__':
    unittest.main()
