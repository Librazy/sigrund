#!/usr/bin/env python3
"""Root-only manager fault injector for the installed qualification lab.

Forwards the actual Podman API. The private mode file injects stale/malformed
metadata or event-stream loss; this is never a production resolver service.
"""
import argparse
import ctypes
import http.client
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import time


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and args.directory.is_absolute()
    args.directory.mkdir(mode=0o700)
    mode = args.directory / 'mode'
    mode.write_text('pass')
    mode.chmod(0o600)
    endpoint = args.directory / 'podman.sock'
    # Test socket uses the same manager socket object type permitted by the
    # optional producer policy; reserved authentication labels are untouched.
    library = ctypes.CDLL('libselinux.so.1', use_errno=True)
    assert library.setsockcreatecon(b'system_u:system_r:container_runtime_t:s0') == 0

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            request = bytearray()
            self.request.settimeout(2)
            try:
                while not request.endswith(b'\r\n\r\n'):
                    packet = self.request.recv(1)
                    if not packet:
                        return
                    request.extend(packet)
                    assert len(request) <= 16_384
                target = request.split(b' ', 2)[1]
                backend = socket.socket(socket.AF_UNIX)
                backend.settimeout(2)
                try:
                    backend.connect('/run/podman/podman.sock')
                    backend.sendall(request)
                    if b'/events?' in target:
                        backend.settimeout(.1)
                        while True:
                            current = mode.read_text().strip()
                            if current == 'event-gap':
                                return
                            if current == 'malformed-event':
                                self.request.sendall(b'zz\r\n')
                                return
                            try:
                                packet = backend.recv(16_384)
                            except socket.timeout:
                                continue
                            if not packet:
                                return
                            self.request.sendall(packet)
                    else:
                        response = http.client.HTTPResponse(backend)
                        response.begin()
                        data = response.read(1_048_577)
                        assert len(data) <= 1_048_576
                        current = mode.read_text().strip()
                        if current == 'stall':
                            time.sleep(4)
                            return
                        value = json.loads(data)
                        if current == 'wrong-pid':
                            value['State']['Pid'] = 1
                        elif current == 'wrong-id':
                            value['Id'] = 'f' * 64
                        elif current == 'wrong-name':
                            value['Name'] = 'other-container'
                        elif current == 'wrong-namespace':
                            value['Namespace'] = 'other-tenant'
                        elif current == 'configuration':
                            value['Config']['Labels'] = {'claimed_host_uid': '0', 'owner': 'dishonest'}
                        elif current == 'missing-state':
                            value.pop('State', None)
                        data = json.dumps(value, separators=(',', ':')).encode()
                        if current == 'duplicate-json':
                            data = b'{"Id":"fake",' + data[1:]
                        version = b'6.0.0' if current == 'wrong-version' else response.getheader('Libpod-Api-Version', '').encode()
                        header = b'HTTP/1.1 200 OK\r\nLibpod-Api-Version: ' + version + b'\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(data)).encode() + b'\r\nConnection: close\r\n\r\n'
                        self.request.sendall(header + data)
                finally:
                    backend.close()
            except (OSError, AssertionError, ValueError):
                return

    with Server(str(endpoint), Handler) as server:
        assert library.setsockcreatecon(None) == 0
        endpoint.chmod(0o660)
        subprocess.run(['chcon', 'system_u:object_r:container_var_run_t:s0', str(args.directory), str(endpoint)], check=True)
        server.serve_forever(poll_interval=.1)


if __name__ == '__main__':
    main()
