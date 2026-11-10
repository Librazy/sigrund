#!/usr/bin/env python3
"""Check installed consumption/audit bindings with the checked collector binary."""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, default=Path('/var/lib/sigrund-v3'))
    parser.add_argument('--audit-log', type=Path, default=Path('/var/log/sigrund-v3/audit.jsonl'))
    parser.add_argument('--collector', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('host root required')
    args.artifacts.mkdir(mode=0o700)
    records = [json.loads(line) for line in args.audit_log.read_text().splitlines()]
    commits = {row['exec_id']: row for row in records if row['event_type'] == 'AUTH_COMMIT'}
    with closing(sqlite3.connect('file:' + str(args.state_dir / 'state.sqlite') + '?mode=ro', uri=True)) as connection:
        stored = connection.execute('SELECT exec_id,execution_binding_sha256,payload_sha256,intent_sha256 FROM consumed_grants').fetchall()
    assert stored and len(commits) == len(stored), (len(commits), len(stored))
    cases = []
    for execution, binding, payload, intent in stored:
        commit = commits[execution]
        expected = hashlib.sha256(canonical({key: commit[key] for key in ('target_binding', 'security_constraints')})).digest()
        assert type(binding) is bytes and len(binding) == 32 and binding == expected
        assert binding.hex() == commit['execution_binding_sha256']
        assert type(payload) is bytes and len(payload) == 32 and payload.hex() == commit['payload_sha256']
        assert type(intent) is bytes and len(intent) == 32 and intent.hex() == commit['intent_sha256']
        fields = ('execution_binding_sha256', 'request_origin', 'intent_sha256', 'approval_exec_id',
                  'exec_id', 'grant_id', 'host_id', 'not_after', 'not_before', 'payload_sha256', 'policy_mode', 'signer_id')
        target = {key: commit[key] for key in fields}
        target['auth_commit_seq'] = commit['seq']
        batch = {'first_seq': commit['seq'], 'last_seq': commit['seq'], 'host_id': commit['host_id'],
                 'records_jcs': [canonical(commit).decode()], 'target_auth': target}
        path = args.artifacts / (execution + '.json')
        path.write_bytes(canonical(batch))
        subprocess.run([str(args.collector), '--validate-batch', str(path)], check=True, capture_output=True)
        batch['target_auth']['execution_binding_sha256'] = 'f' * 64
        mismatch = args.artifacts / (execution + '-mismatch.json')
        mismatch.write_bytes(canonical(batch))
        assert subprocess.run([str(args.collector), '--validate-batch', str(mismatch)], capture_output=True).returncode == 65
        cases.append({'exec_id': execution, 'binding': expected.hex(), 'target_kind': commit['target_binding']['kind'],
                      'database_raw_bytes': 32, 'audit_equality': True, 'collector_valid': True, 'collector_mismatch_rejected': True})
    result = {'passed': True, 'cases': cases,
              'collector_sha256': hashlib.sha256(args.collector.read_bytes()).hexdigest()}
    (args.artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('validated consumption/audit/collector equality for ' + str(len(cases)) + ' executions')


if __name__ == '__main__':
    main()
