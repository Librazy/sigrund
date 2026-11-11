#!/usr/bin/env python3
"""Send an exclusion fixture through the installed public protocol as a user."""
import array
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

body = Path(sys.argv[1]).read_bytes()
peer = socket.socket(socket.AF_UNIX)
peer.settimeout(10)
peer.connect('/run/sigrund/client.sock')
outputs = [os.memfd_create('excluded-output', os.MFD_CLOEXEC) for _ in range(2)]
try:
    started = time.monotonic()
    peer.sendmsg([b'\x01' + struct.pack('>I', len(body)) + body],
                 [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', outputs))])

    def exact(count):
        result = bytearray()
        while len(result) < count:
            chunk = peer.recv(count - len(result))
            assert chunk, 'unexpected EOF'
            result.extend(chunk)
        return bytes(result)

    header = exact(5)
    assert header[0] == 2
    length = struct.unpack('>I', header[1:])[0]
    assert 0 < length <= 512
    decision = json.loads(exact(length))
    elapsed = time.monotonic() - started
    assert decision['status'] == 'TIMEOUT' and 4.7 <= elapsed <= 8, (decision, elapsed)
    assert all(os.fstat(fd).st_size == 0 for fd in outputs)
    print(json.dumps({'decision': decision, 'elapsed': elapsed, 'output_bytes': 0}))
finally:
    peer.close()
    for fd in outputs:
        os.close(fd)
