#!/usr/bin/env python3
"""Verify independent ASCII/JCS v3 host vectors with Python and OpenSSH."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

FIXTURES = Path(__file__).resolve().parents[1] / 'crates/sigrund-core/tests/fixtures/v3-host'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def main():
    hashes = json.loads((FIXTURES / 'sha256.json').read_bytes())
    for name, expected in hashes.items():
        raw = (FIXTURES / (name + '.json')).read_bytes()
        assert canonical(json.loads(raw)) == raw, name
        assert hashlib.sha256(raw).hexdigest() == expected, name
    bundle = json.loads((FIXTURES / 'bundle.json').read_bytes())
    warrant = json.loads((FIXTURES / 'warrant.json').read_bytes())
    assert bundle['target_binding']['context_sha256'] == hashes['acquisition']
    assert bundle['profile_sha256'] == hashes['constraints']
    assert warrant['intent_sha256'] == hashes['intent']
    assert warrant['target_binding'] == bundle['target_binding']
    assert warrant['security_constraints']['profile_sha256'] == hashes['constraints']
    assert canonical({key: warrant[key] for key in ('target_binding', 'security_constraints')}) == (FIXTURES / 'execution-binding.json').read_bytes()
    payload = (FIXTURES / 'warrant.json').read_bytes()
    payload_type = b'application/vnd.sigrun.warrant.v3+json'
    pae = b'DSSEv1 ' + str(len(payload_type)).encode() + b' ' + payload_type + b' ' + str(len(payload)).encode() + b' ' + payload
    assert pae == (FIXTURES / 'warrant.pae').read_bytes()
    with tempfile.TemporaryDirectory() as directory:
        allowed = Path(directory) / 'allowed'
        allowed.write_text('host-vector ' + (FIXTURES / 'signer.pub').read_text())
        command = ['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'host-vector',
                   '-s', str(FIXTURES / 'warrant.sshsig'), '-n', 'sigrun.warrant.v3']
        subprocess.run(command, input=pae, check=True, capture_output=True)
        assert subprocess.run(command, input=pae + b' ', capture_output=True).returncode != 0
        command[-1] = 'sigrun.warrant.v2'
        assert subprocess.run(command, input=pae, capture_output=True).returncode != 0
    print('Independent v3 host canonical/hash/SSHSIG vectors passed')


if __name__ == '__main__':
    main()
