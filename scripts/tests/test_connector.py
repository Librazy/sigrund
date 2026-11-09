"""Unix backlog retries must sleep, expire, and terminate with their parent."""
import os
from pathlib import Path
import resource
import select
import signal
import socket
import subprocess
import tempfile
import time
import unittest


class ConnectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='sigrund-connector-')
        cls.binary = Path(cls.directory.name) / 'retry'
        source = Path(__file__).resolve().parents[2] / 'crates/sigrund/tests/fixtures/namespace/connector-retry.c'
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(cls.binary)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.path = str(Path(self.directory.name) / 'socket')
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(self.path)
        self.listener.listen(0)
        self.filler = socket.socket(socket.AF_UNIX)
        self.filler.connect(self.path)

    def tearDown(self):
        self.filler.close()
        self.listener.close()
        os.unlink(self.path)

    def test_full_backlog_waits_and_expires_without_spinning(self):
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.monotonic()
        result = subprocess.run([str(self.binary), 'deadline', self.path], timeout=2)
        elapsed = time.monotonic() - started
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu = after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime
        self.assertEqual(result.returncode, 127)
        self.assertGreaterEqual(elapsed, 0.29)
        self.assertLess(cpu, 0.1)

    def test_blocked_connector_dies_if_the_CLI_is_killed(self):
        parent = subprocess.Popen([str(self.binary), 'parent-death', self.path], stdout=subprocess.PIPE)
        pidfd = None
        try:
            self.assertTrue(select.select([parent.stdout], [], [], 2)[0])
            pid = int(parent.stdout.readline())
            pidfd = os.pidfd_open(pid)
            self.assertFalse(select.select([pidfd], [], [], 0.15)[0])
            parent.kill()
            parent.wait(timeout=2)
            self.assertTrue(select.select([pidfd], [], [], 2)[0], 'connector outlived killed CLI')
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.wait(timeout=2)
            parent.stdout.close()
            if pidfd is not None:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.close(pidfd)
