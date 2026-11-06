#!/usr/bin/env python3
"""Independent ASCII-only canonicalization/hash oracle for Phase 0 fixtures.

These records contain only ASCII keys/strings and exact JSON integers, so sorted
Python JSON has the same bytes as JCS. General Unicode JCS remains core-tested.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

FIXTURES = Path(__file__).resolve().parents[2] / 'crates/sigrund-phase0/tests/fixtures'


def main():
    hashes = json.loads((FIXTURES / 'sha256.json').read_bytes())
    for name, expected in hashes.items():
        raw = (FIXTURES / (name + '.json')).read_bytes()
        value = json.loads(raw)
        canonical = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        assert raw == canonical, name
        assert hashlib.sha256(canonical).hexdigest() == expected, name
    bundle = json.loads((FIXTURES / 'bundle.json').read_bytes())
    assert bundle['target_binding']['context_sha256'] == hashes['acquisition']
    assert bundle['profile_sha256'] == hashes['constraints']
    warrant = json.loads((FIXTURES / 'warrant.json').read_bytes())
    assert warrant['target_binding'] == bundle['target_binding']
    assert warrant['security_constraints']['profile_sha256'] == hashes['constraints']
    binding = {key: warrant[key] for key in ['target_binding', 'security_constraints']}
    assert binding == json.loads((FIXTURES / 'execution-binding.json').read_bytes())
    original_intent = json.dumps(warrant['intent'], sort_keys=True, separators=(',', ':')).encode()
    assert warrant['intent_sha256'] == hashlib.sha256(original_intent).hexdigest()
    payload = (FIXTURES / 'warrant.json').read_bytes()
    payload_type = b'application/vnd.sigrun.warrant.v3+json'
    pae = b'DSSEv1 ' + str(len(payload_type)).encode() + b' ' + payload_type + b' ' + str(len(payload)).encode() + b' ' + payload
    assert pae == (FIXTURES / 'warrant.pae').read_bytes()
    with tempfile.TemporaryDirectory() as directory:
        allowed = Path(directory) / 'allowed'
        allowed.write_text('phase0 ' + (FIXTURES / 'signer.pub').read_text())
        command = ['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'phase0',
                   '-s', str(FIXTURES / 'warrant.sshsig'), '-n', 'sigrun.warrant.v3']
        subprocess.run(command, input=pae, check=True, capture_output=True)
        altered = subprocess.run(command, input=pae + b' ', capture_output=True)
        assert altered.returncode != 0
    print('Phase 0 independent canonical/hash vectors passed')


if __name__ == '__main__':
    main()
