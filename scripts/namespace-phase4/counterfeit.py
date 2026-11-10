#!/usr/bin/env python3
"""Run as a rootless requester: counterfeit listeners must receive no bytes/FDs."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def rejected(listener, command, *, finite=False, anchor=False):
    child = subprocess.Popen(command, stdin=subprocess.PIPE if finite else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if finite:
            child.stdin.write(b'must not escape')
            child.stdin.close()
            child.stdin = None
        listener.settimeout(5)
        peer, _ = listener.accept()
        with peer:
            peer.settimeout(5)
            data, rights, flags, _ = peer.recvmsg(4096, socket.CMSG_SPACE(256))
            assert data == b'' and not rights and not flags, (data, rights, flags)
        stdout, stderr = child.communicate(timeout=5)
        assert child.returncode != 0 and not stdout
        if not anchor:
            assert b'authenticate host daemon' in stderr, stderr
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    path = root / 'fake.sock'
    context = socket.socket(socket.AF_UNIX)
    context.bind(str(path) + '.context')
    context.listen()
    execution = socket.socket(socket.AF_UNIX)
    execution.bind(str(path))
    execution.listen()
    rejected(context, ['/usr/bin/sigrun', '--socket', str(path), '--target', 'registered:container-b',
                       '--account', 'phase4_service', '--security-profile', 'namespace-selinux-v1',
                       '--stdin', 'sha256', '--', '/usr/bin/true'], finite=True)
    execution.setblocking(False)
    try:
        execution.accept()
        raise AssertionError('authentication failure fell back to execution')
    except BlockingIOError:
        pass
    warrant = root / 'signed.json'
    warrant.write_text(json.dumps(json.loads(Path(sys.argv[1]).read_text())['dsse_envelope'], sort_keys=True, separators=(',', ':')))
    execution.setblocking(True)
    rejected(execution, ['/usr/bin/sigrun', '--socket', str(path), '--warrant', str(warrant)])
    anchor = socket.socket(socket.AF_UNIX)
    anchor.bind(str(root / 'fake.anchor'))
    anchor.listen()
    rejected(anchor, ['/usr/bin/sigrund-anchor', '--socket', str(root / 'fake.anchor')], anchor=True)
    context.close()
    execution.close()
    anchor.close()
print(json.dumps({'counterfeit_context': 'no-data-or-rights', 'counterfeit_execution': 'no-data-or-rights',
                  'counterfeit_anchor': 'no-handshake-or-rights', 'fallback': False}))
