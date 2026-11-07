#!/usr/bin/python3
"""End-to-end acceptance entry point for a disposable, real systemd Linux host.

Build and run ordinary regressions as the unprivileged workspace user first.
This root entry point launches a fresh delegated service with an overall time
limit and whole-service cleanup, then repeats the platform/runtime/fault gates
and additional operator-facing scenarios. No local elevation is performed.
"""
import argparse
import array
import base64
import copy
from contextlib import closing
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import pty
import runpy
import select
import signal
import shutil
import socket
import sqlite3
import subprocess
import sys
import termios
import time
import traceback
import uuid

REPO = Path(__file__).resolve().parent.parent
SHARED = runpy.run_path(str(Path(__file__).with_name('verify-runtime.py')))
FAILURES = runpy.run_path(str(Path(__file__).with_name('verify-execution.py')))
Fixture, wait_for, receive = SHARED['Fixture'], SHARED['wait_for'], SHARED['receive']
canonical, unprivileged = SHARED['canonical'], SHARED['unprivileged']
Evidence = FAILURES['Evidence']

ready, authorized, exited, exit_fields = (SHARED[k] for k in ('ready','authorized','exited','exit_fields'))


def run(command, *, log=None, **kwargs):
    result = subprocess.run([str(a) for a in command], check=True, **kwargs)
    if log is not None:
        log.write_text(json.dumps({'command': [str(a) for a in command], 'exit': result.returncode}) + '\n')
    return result


def cli(fixture, warrant, *, input_bytes=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    status = fixture.base / ('status-' + uuid.uuid4().hex)
    output = open(status, 'w+b')
    command = [str(fixture.client_binary), '--socket', str(fixture.client), '--warrant', str(warrant),
               '--status-fd', str(output.fileno())]
    child = subprocess.Popen(command, preexec_fn=unprivileged, pass_fds=(output.fileno(),),
                             stdin=subprocess.PIPE, stdout=stdout, stderr=stderr)
    return child, output, status


def finish(client, output, input_bytes=None):
    try:
        out, err = client.communicate(input_bytes, timeout=10)
        output.seek(0)
        events = [json.loads(line) for line in output]
        return client.returncode, out, err, events
    finally:
        if client.poll() is None:
            client.kill()
            client.communicate(timeout=5)
        output.close()


def cancel_blocked_output(client, output, status_path, jobs_empty, *, timeout=6):
    """Observe cancellation through status/cgroups before reading either pipe."""
    def pipe_full():
        pending = array.array('i', [0])
        fcntl.ioctl(client.stdout.fileno(), termios.FIONREAD, pending)
        return pending[0] == fcntl.fcntl(client.stdout.fileno(), fcntl.F_GETPIPE_SZ)

    def events():
        # The status writer may be between writes; only inspect complete lines.
        return [json.loads(line) for line in status_path.read_bytes().split(b'\n')[:-1]]

    wait_for(pipe_full, 'full output pipe without reads', timeout=timeout)
    wait_for(lambda: any('exec_outcome' in e for e in events()),
             'blocked output client readiness', timeout=timeout)
    assert client.poll() is None and not jobs_empty(), 'workload completed before cancellation'
    client.send_signal(signal.SIGINT)
    wait_for(lambda: any('signal' in e for e in events()),
             'child signal outcome while output remains blocked', timeout=timeout)
    assert exit_fields(events()[-1]) == {'exit_code': None, 'signal': signal.SIGINT}, events()
    wait_for(jobs_empty, 'blocked-output cancellation cleanup without reads', timeout=timeout)
    assert pipe_full(), 'output was drained before cancellation was verified'
    # The client legitimately waits for its relays to drain after child exit.
    code, _, _, result = finish(client, output)
    assert code == 128 + signal.SIGINT and exit_fields(result[-1]) == {'exit_code': None, 'signal': signal.SIGINT}, (code, result)
    return {'signal': signal.SIGINT, 'exit_code': code, 'cleanup_before_drain': True}


def deny(f, warrant, status, input_bytes=None):
    client, output, _ = cli(f, warrant)
    code, out, err, events = finish(client, output, input_bytes)
    assert code == 255 and out == b'' and len(events) == 1 and events[0]['status'] == 'TIMEOUT', (code, out, err, events)
    return events[0]


def count(f):
    with closing(sqlite3.connect(f.state / 'state.sqlite')) as db:
        return db.execute('select count(*) from consumed_grants').fetchone()[0]


def independently_verify_audit(f):
    """Python HMAC/SHA-256 implementation, independent of the Rust writer."""
    state = json.loads((f.state/'audit_ratchet.state').read_bytes())
    key = bytes.fromhex(state['initial_key_hex'])
    old_domain_key = key
    previous = '0' * 64
    host_id = None
    count = 0
    def jcs(record):
        # Audit field names are fixed ASCII; UTF-8 string values and bounded
        # integers use this exact JCS subset without floating-point conversion.
        return json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    for count,raw in enumerate(f.log.read_bytes().splitlines(),start=1):
        record = json.loads(raw)
        assert jcs(record) == raw
        assert record['schema_version'] == 3 and record['seq'] == count-1
        assert record['prev_record_sha256'] == previous
        host_id = host_id or record['host_id']
        assert record['host_id'] == host_id
        digest = record.pop('entry_hmac')
        assert hmac.compare_digest(hmac.new(key,jcs(record),hashlib.sha256).hexdigest(),digest)
        previous = hashlib.sha256(raw).hexdigest()
        key = hashlib.sha256(key+b'sigrun-ratchet-v3').digest()
        old_domain_key = hashlib.sha256(old_domain_key+b'sigrun-ratchet-v2').digest()
    assert count > 0 and state['schema_version'] == 3 and state['seq'] == count
    assert state['key_hex'] == key.hex() and state['last_record_sha256'] == previous
    assert state['key_hex'] != old_domain_key.hex()
    return {'records':count,'last_record_sha256':previous,'domain':'sigrun-ratchet-v3',
            'retained_seed_verification':True,'external_rollback_protection':False}


def package_workflow(parent, binaries, evidence):
    """Export a client-full CSR and preserve its bytes through offline signing."""
    f = Fixture(parent, binaries)
    try:
        f.launch()
        csr = f.export(f.commands / 'id', ('-u',))
        original = csr.read_bytes()
        pae = f.base / 'request.pae'
        ctl = binaries / 'sigrundctl'
        run([ctl, 'csr-pae', '--csr', csr, '--pae', pae])
        assert count(f) == 0
        signed = run(['ssh-keygen', '-Y', 'sign', '-n', 'sigrun.warrant.v3', '-O', 'hashalg=sha512',
                      '-f', f.key, pae], capture_output=True)
        envelope = f.base / 'packaged.json'
        run([ctl, 'pack-warrant', '--csr', csr, '--signature', str(pae) + '.sig', '--signer-id', SHARED['SIGNER'],
             '--output', envelope])
        envelope.chmod(0o644)
        assert base64.b64decode(json.loads(envelope.read_bytes())['payload']) == original
        client, output, status_path = cli(f, envelope)
        code, out, err, events = finish(client, output)
        assert code == 0 and out == b'0\n' and err == SHARED['CLIENT_PROGRESS'], (code, out, err, events)
        assert exit_fields(events[-1]) == {'exit_code': 0, 'signal': None}
        assert count(f) == 1
        # Independently reconstruct both digests from the preserved canonical
        # CSR, then exercise the actual collector validator against AUTH_COMMIT.
        value = json.loads(original)
        binding_digest = hashlib.sha256(canonical({k: value[k] for k in ('target_binding', 'security_constraints')})).digest()
        payload_digest = hashlib.sha256(original).hexdigest()
        with closing(sqlite3.connect(f.state / 'state.sqlite')) as db:
            stored = db.execute('select execution_binding_sha256,payload_sha256 from consumed_grants where grant_id=?', (value['grant_id'],)).fetchone()
        assert type(stored[0]) is bytes and len(stored[0]) == 32 and stored[0] == binding_digest, stored
        assert stored[1] == bytes.fromhex(payload_digest), stored
        commit = next(r for r in f.records() if r.get('event_type') == 'AUTH_COMMIT')
        assert commit['execution_binding_sha256'] == binding_digest.hex() and commit['payload_sha256'] == payload_digest, commit
        fields = ('execution_binding_sha256', 'request_origin', 'intent_sha256', 'approval_exec_id',
                  'exec_id', 'grant_id', 'host_id', 'not_after', 'not_before', 'payload_sha256', 'policy_mode', 'signer_id')
        target = {k: commit[k] for k in fields}
        target['auth_commit_seq'] = commit['seq']
        batch = {'first_seq':commit['seq'], 'last_seq':commit['seq'], 'host_id':commit['host_id'],
                 'records_jcs':[canonical(commit).decode()], 'target_auth':target}
        batch_path = f.base / 'collector-batch.json'
        batch_path.write_bytes(canonical(batch))
        run([binaries / 'sigrund-collector', '--validate-batch', batch_path], capture_output=True)
        for label, edit in (
            ('digest', lambda b: b['target_auth'].update(execution_binding_sha256='f' * 64)),
            ('uppercase', lambda b: b['target_auth'].update(execution_binding_sha256=binding_digest.hex().upper())),
            ('old-schema', lambda b: b.update(records_jcs=[canonical({**commit, 'schema_version':2}).decode()])),
            ('future-schema', lambda b: b.update(records_jcs=[canonical({**commit, 'schema_version':4}).decode()])),
        ):
            rejected = copy.deepcopy(batch)
            edit(rejected)
            path = f.base / ('collector-reject-' + label + '.json')
            path.write_bytes(canonical(rejected))
            result = subprocess.run([str(binaries / 'sigrund-collector'), '--validate-batch', str(path)], capture_output=True)
            assert result.returncode == 65, (label, result)
        evidence.passed('execution-binding-digest-equality', database_bytes=32, execution_binding_sha256=binding_digest.hex(),
                        payload_sha256=payload_digest, collector_schema_only=True, mismatches_rejected=4)
        deny(f, envelope, 'REPLAY_DETECTED')
        directory = evidence.root / 'offline-workflow'
        directory.mkdir(exist_ok=True)
        for source in (csr, pae, Path(str(pae) + '.sig'), envelope, status_path):
            (directory / source.name).write_bytes(source.read_bytes())
        evidence.passed('offline-workflow', csr_sha256=hashlib.sha256(original).hexdigest(), output='0\n', replay='REPLAY_DETECTED')
        f.stop()
        evidence.passed('independent-v3-audit-ratchet', **independently_verify_audit(f))
    finally:
        evidence.capture(f, 'offline-workflow')
        f.cleanup()


def binding_and_replay(parent, binaries, evidence):
    f = Fixture(parent, binaries)
    try:
        f.launch()
        warrant, envelope = f.signed(f.commands / 'true')
        changed = copy.deepcopy(envelope)
        value = json.loads(base64.b64decode(changed['payload']))
        value['command']['argv'].append('changed-after-signing')
        value['intent']['command']['argv'].append('changed-after-signing')
        value['intent_sha256'] = hashlib.sha256(canonical(value['intent'])).hexdigest()
        changed['payload'] = base64.b64encode(canonical(value)).decode()
        altered = f.base / 'altered.json'
        altered.write_bytes(canonical(changed))
        altered.chmod(0o644)
        # A changed CSR with the original signature cannot authorize.
        denied = deny(f, altered, 'POLICY_VIOLATION')
        assert count(f) == 0 and f.empty()
        wrong_uid, _ = f.signed(f.commands / 'true', uid=0)
        deny(f, wrong_uid, 'POLICY_VIOLATION')
        content = b'\x00binary\xff\n' * 64
        hashed, _ = f.signed(f.commands / 'cat', input_bytes=content)
        deny(f, hashed, 'STDIN_HASH_MISMATCH', b'different')
        assert count(f) == 0
        # Same exact signed bytes and peer UID/GID; one child and one commit.
        clients = [cli(f, warrant) for _ in range(2)]
        results = [finish(c, out) for c, out, _ in clients]
        assert sorted(r[0] for r in results) == [0, 255], results
        assert sorted(r[3][0]['status'] for r in results) == ['APPROVED', 'TIMEOUT'], results
        assert count(f) == 1
        commits = [r for r in f.records() if r.get('event_type') == 'AUTH_COMMIT']
        assert len(commits) == 1
        wait_for(f.empty, 'concurrent replay job cleanup')
        f.stop()
        f.launch()
        deny(f, warrant, 'REPLAY_DETECTED')
        assert count(f) == 1
        f.stop()
        evidence.passed('binding-and-concurrent-replay', mutation=denied['status'], commits=1, replay_after_restart=True,
                        stdin_mismatch='STDIN_HASH_MISMATCH', wrong_uid='POLICY_VIOLATION')
    finally:
        evidence.capture(f, 'binding-and-concurrent-replay')
        f.cleanup()


def host_binding_invariants(parent, binaries, evidence):
    """A valid signer cannot substitute a live host generation or profile."""
    f = Fixture(parent, binaries)
    try:
        f.launch()
        warrant, envelope = f.signed(f.commands / 'true', uid=0)
        original = json.loads(base64.b64decode(envelope['payload']))
        edits = (
            ('epoch', lambda w: w['target_binding'].update(daemon_epoch=SHARED['uuid7']())),
            ('instance', lambda w: w['target_binding'].update(instance_id=SHARED['uuid7']())),
            ('acquisition', lambda w: w['target_binding'].update(context_sha256='1' * 64)),
            ('profile', lambda w: w['security_constraints'].update(profile_sha256='1' * 64)),
            ('authority', lambda w: w.update(host_id='sigrun-host:sha256:' + '1' * 64)),
            ('credentials', lambda w: (w['intent']['account'].update(uid=55), w['execution_context'].update(target_uid=55))),
            ('origin', lambda w: w.update(request_origin='daemon_expanded_thin', approval_exec_id=SHARED['uuid7']())),
            ('model', lambda w: w['command'].update(executable_trust={'model':'digest_direct', 'sha256':hashlib.sha256((f.commands / 'true').read_bytes()).hexdigest()})),
        )
        outcomes = []
        for name, edit in edits:
            value = copy.deepcopy(original)
            edit(value)
            value['intent_sha256'] = hashlib.sha256(canonical(value['intent'])).hexdigest()
            _, signed = f.sign_payload(canonical(value))
            start = time.monotonic()
            stream = FAILURES['connect_envelope'](f, signed)
            decision = receive(stream, 2)
            elapsed = time.monotonic() - start
            assert set(decision) == {'exec_id', 'status'} and decision['status'] == 'TIMEOUT', decision
            assert 2.3 <= elapsed < 4.0, (name, elapsed)
            assert stream.recv(1) == b''
            stream.close()
            assert count(f) == 0 and f.empty()
            outcomes.append({'substitution':name, 'public_status':decision['status'], 'elapsed_secs':elapsed})
        # An unused, still-unexpired warrant and deliberately distributed full
        # bundle both become stale after a restart of the same host authority.
        bundle = f.export_binding()
        old_epoch = f.binding()['target_binding']['daemon_epoch']
        f.stop()
        f.launch()
        assert f.binding()['target_binding']['daemon_epoch'] != old_epoch
        stream = FAILURES['connect_envelope'](f, envelope)
        assert receive(stream, 2)['status'] == 'TIMEOUT'
        assert stream.recv(1) == b''
        stream.close()
        command = [str(f.client_binary), '--socket', str(f.client), '--target', 'host',
                   '--security-profile', f.profile_id('digest_memfd'), '--target-uid','33','--target-gid','33',
                   '--binding-bundle',str(bundle)]
        result = subprocess.run(command + ['--full-only','--',str(f.commands/'true')], preexec_fn=unprivileged,
                                input=b'', capture_output=True, timeout=6)
        assert result.returncode == 255 and b'TIMEOUT' in result.stderr and not result.stdout, result
        # Epoch freshness is deliberately not public context. Local export may
        # preserve a stale trusted bundle; redemption must reject those exact
        # bytes instead of silently replacing the binding with the current one.
        directory = f.base/'stale-exports'
        directory.mkdir()
        os.chown(directory,65534,65534)
        exported = directory/'stale.csr'
        result = subprocess.run(command + ['--export-csr',str(exported),'--',str(f.commands/'true')],
                                preexec_fn=unprivileged, input=b'', capture_output=True, timeout=6)
        assert result.returncode == 0 and not result.stdout and not result.stderr, result
        stale = json.loads(exported.read_bytes())
        assert stale['target_binding']['daemon_epoch'] == old_epoch
        signed, _ = f.sign_payload(exported.read_bytes())
        deny(f,signed,'STALE_TARGET')
        assert count(f) == 0 and f.empty()
        f.stop()
        evidence.passed('live-host-binding-substitutions', substitutions=outcomes, stale_warrant_rejected=True,
                        stale_bundle_full_only_rejected=True, stale_export_preserved_and_redemption_rejected=True, no_consumption=True)
    finally:
        evidence.capture(f, 'live-host-binding-substitutions')
        f.cleanup()


def host_resource_ownership(parent, binaries, evidence):
    """Keep host charges while a real source close/helper handoff is blocked."""
    import struct
    for resource in ('targets', 'reviews', 'target_fds', 'helpers'):
        f = Fixture(parent, binaries)
        entered_r, entered_w = os.pipe()
        release_r, release_w = os.pipe()
        streams = []
        try:
            limits = {'targets':4, 'target_fds':128, 'helpers':2, 'reviews':2}
            limits[resource] = {'target_fds':80}.get(resource, 1)
            config = f.base / 'config'
            config.write_text(config.read_text() + '\n[host_limits.global]\ntargets=64\ntarget_fds=2048\nhelpers=16\nreviews=16\n[host_limits.per_uid]\n' +
                              '\n'.join(k+'='+str(v) for k,v in limits.items()) + '\n')
            interposer = f.base / 'host-ownership.so'
            run(['cc','-shared','-fPIC','-Wall','-Werror','-o',interposer,
                 REPO/'crates/sigrund/tests/fixtures/transport/metadata.c'])
            source = (f.commands/'true').stat()
            full = resource in ('helpers','target_fds')
            environment = dict(os.environ, LD_PRELOAD=str(interposer), SIGRUND_GATE_INODE=str(source.st_ino),
                               SIGRUND_GATE_DEVICE=str(source.st_dev), SIGRUND_GATE_ENTERED_FD=str(entered_w),
                               SIGRUND_GATE_RELEASE_FD=str(release_r))
            if not full:
                environment['SIGRUND_GATE_CLOSE'] = '1'
            f.launch(environment, (entered_w, release_r))
            csr = json.loads(f.export(f.commands/'true', target=33).read_bytes())
            csr['requester_uid'] = 0
            csr['requester_gid'] = 0
            hello = {'version':'3.0','mode':'full_csr' if full else 'thin_csr','tty_mode':'stdio','caller_env':{}}
            hello['csr_payload' if full else 'intent'] = canonical(csr).decode() if full else csr['intent']
            def submit():
                stream = socket.socket(socket.AF_UNIX)
                stream.settimeout(6)
                stream.connect(str(f.client))
                data = SHARED['frame'](1, hello)
                with open('/dev/null','r+b') as null:
                    stream.sendmsg([data[:1]], [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[null.fileno(),null.fileno()]))])
                stream.sendall(data[1:])
                streams.append(stream)
                return stream
            first = submit()
            assert select.select([entered_r], [], [], 4)[0], (resource, f.diagnostics.read_text(), f.records())
            assert len(os.read(entered_r, struct.calcsize('Q'))) == 8
            assert receive(first,2)['status'] == 'TIMEOUT'
            assert first.recv(1) == b''
            # The deadline/disconnect has retired the public request, but its
            # worker still owns a target/review, and full access also its helper.
            second = submit()
            second_decision = receive(second,2)
            assert second_decision['status'] == 'TIMEOUT'
            assert second.recv(1) == b''
            wait_for(lambda: any(r.get('exec_id') == second_decision['exec_id'] and r.get('reason_code') == 'RESOURCE_EXHAUSTED'
                                 and r.get('reason','').startswith('host ') for r in f.records()), 'private host quota classification')
            assert not select.select([entered_r],[],[],0.05)[0], 'quota refunded before actual close/reap: '+resource
            assert count(f) == 0 and f.empty()
            first_token = next(json.loads(line)['worker_task'] for line in f.diagnostics.read_text().splitlines()
                               if json.loads(line).get('event') == 'SOCKET_ADMITTED' and not json.loads(line).get('broker'))
            os.write(release_w,b'x')
            # Wait for actual disposal before verifying capacity is usable again.
            wait_for(lambda: any(json.loads(line).get('event') == 'FD_VALIDATION_COMPLETE' and json.loads(line).get('worker_task') == first_token
                                 for line in f.diagnostics.read_text().splitlines()),
                     'retained source disposal')
            third = submit()
            assert select.select([entered_r],[],[],4)[0], 'quota not released after actual disposal: '+resource
            assert len(os.read(entered_r,8)) == 8
            os.write(release_w,b'x' * 16)
            assert receive(third,2)['status'] == 'TIMEOUT'
            assert third.recv(1) == b''
            f.stop()
            evidence.passed('host-owned-'+resource, blocked_through_timeout=True, no_early_refund=True,
                            reacquired_after_disposal=True, consumed=0)
        finally:
            for stream in streams:
                stream.close()
            # EOF releases an interposed syscall even on a failed assertion.
            os.close(release_w)
            evidence.capture(f, 'host-owned-'+resource)
            f.cleanup()
            for fd in (entered_r,entered_w,release_r):
                os.close(fd)


def public_context_capacity_is_independent(parent, binaries, evidence):
    f = Fixture(parent,binaries)
    held = []
    def connect(uid):
        left,right = socket.socketpair()
        code = ("import os,socket,array,sys; relay=socket.socket(fileno=int(sys.argv[1])); "
                "uid=int(sys.argv[3]); os.setgroups([]); os.setgid(uid); os.setuid(uid); "
                "peer=socket.socket(socket.AF_UNIX); peer.connect(sys.argv[2]); "
                "relay.sendmsg([b'x'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[peer.fileno()]))])")
        child = subprocess.Popen([sys.executable,'-c',code,str(right.fileno()),str(f.client)+'.context',str(uid)],pass_fds=(right.fileno(),))
        right.close()
        try:
            _,controls,flags,_ = left.recvmsg(1,socket.CMSG_SPACE(4))
            assert child.wait(timeout=5)==0 and flags==0 and len(controls)==1
            descriptors=array.array('i'); descriptors.frombytes(controls[0][2])
            assert len(descriptors)==1
            peer=socket.socket(fileno=descriptors[0]); peer.settimeout(1)
            return peer
        finally:
            left.close()
    try:
        config=f.base/'config'
        config.write_text(config.read_text().replace('request_admissions_global = 256','request_admissions_global = 1')
                          .replace('request_admissions_per_uid = 256','request_admissions_per_uid = 1'))
        f.launch()
        held.extend(connect(0) for _ in range(2))
        excess=connect(0)
        assert excess.recv(1)==b''
        excess.close()
        for uid in (33,65534,65533):
            held.extend(connect(uid) for _ in range(2))
        excess=connect(65532)
        assert excess.recv(1)==b''
        excess.close()
        # Both context workers and all eight context slots are occupied. The
        # single execution-rate allowance must still authorize a real child.
        stream=f.socket(f.commands/'true')
        assert ready(stream)['status']=='APPROVED'
        assert exited(stream)=={'exit_code':0,'signal':None}
        stream.close()
        assert count(f)==1
        for peer in held: peer.close()
        held.clear()
        f.stop()
        evidence.passed('public-context-capacity-independent',per_uid_context_slots=2,global_context_slots=8,
                        execution_admission_allowance=1,context_exhaustion_did_not_charge_execution=True,real_child_exit=0)
    finally:
        for peer in held: peer.close()
        evidence.capture(f,'public-context-capacity-independent')
        f.cleanup()


def thin_input_before_private_lookup(parent, binaries, evidence):
    native = runpy.run_path(str(REPO/'scripts/verify-v3.py'))
    f = Fixture(parent,binaries)
    observations = []
    try:
        f.launch()
        _,envelope = f.signed(f.commands/'true')
        base = json.loads(base64.b64decode(envelope['payload']))['intent']
        for name in ('root','missing-'+uuid.uuid4().hex):
            intent = copy.deepcopy(base)
            intent['account'] = {'kind':'name','name':name}
            intent['command']['stdin_policy'] = 'sha256'
            peer = native['requester_socket'](f)
            source = f.base/('input-'+uuid.uuid4().hex)
            content = b'finite-private-lookup-input' * 512
            source.write_bytes(content)
            output = os.memfd_create('phase1-private-lookup-output',os.MFD_CLOEXEC)
            try:
                with source.open('rb') as input_file, open('/dev/null','r+b') as null:
                    message = SHARED['frame'](1,{'version':'3.0','mode':'thin_csr','tty_mode':'stdio','caller_env':{},'intent':intent})
                    started = time.monotonic()
                    peer.sendmsg([message],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[input_file.fileno(),output,null.fileno()]))])
                    wait_for(lambda: os.lseek(input_file.fileno(),0,os.SEEK_CUR)==len(content),'finite input capture before private lookup',timeout=2)
                    decision = receive(peer,2)
                    assert set(decision)=={'exec_id','status'} and decision['status']=='TIMEOUT'
                    assert peer.recv(1)==b'' and os.fstat(output).st_size==0
                    elapsed = time.monotonic()-started
                    assert 2.3 <= elapsed < 4.0, elapsed
                    observations.append({'account_exists':name=='root','stdin_consumed':len(content),'status':decision['status'],'elapsed_secs':elapsed})
            finally:
                peer.close()
                os.close(output)
        assert count(f)==0 and f.empty()
        f.stop()
        evidence.passed('thin-input-before-private-account-lookup',cases=observations,no_workload_output=True,no_consumption=True)
    finally:
        evidence.capture(f,'thin-input-before-private-account-lookup')
        f.cleanup()


def host_account_profile_changes(parent, binaries, evidence):
    # Only this child mount namespace sees replacement host account files.
    directory = evidence.root / 'host-account-profile'
    code = "import runpy,sys; from pathlib import Path; a=runpy.run_path(sys.argv[1]); a['_host_account_profile_child'](*map(Path,sys.argv[2:]))"
    command = ['unshare','--mount','--propagation','private',sys.executable,'-c',code,
               str(Path(__file__).resolve()),str(parent),str(binaries),str(directory)]
    run(command)
    result = json.loads((directory/'manifest.json').read_bytes())
    assert result['result'] == 'passed'
    evidence.passed('host-account-profile-after-preparation', command=command, child_manifest=str(directory/'manifest.json'),
                    original_name_preserved=True, resolved_credentials_preserved=True, immutable_profile_preserved=True)


def _host_account_profile_child(parent, binaries, artifacts):
    native = runpy.run_path(str(REPO/'scripts/verify-v3.py'))
    e = Evidence(artifacts)
    f = Fixture(parent,binaries,authorization_timeout_ms=8000)
    peer = approver = None
    descriptors = []
    try:
        passwd = f.base/'passwd'
        groups = f.base/'group'
        name = 'sigrund-phase1-target'
        original_passwd = Path('/etc/passwd').read_text()
        original_groups = Path('/etc/group').read_text()
        passwd.write_text(original_passwd + name+':x:33:33::/:/bin/false\n')
        groups.write_text(original_groups + 'sigrund-phase1-group:x:104:'+name+'\n')
        passwd.chmod(0o644)
        groups.chmod(0o644)
        for source,target in ((passwd,'/etc/passwd'),(groups,'/etc/group')):
            run(['mount','--bind',source,target])
        probe=f.commands/'account-probe'
        run(['cc','-O2','-Wall','-Werror',REPO/'crates/sigrund/tests/fixtures/execution/account.c','-o',probe])
        f.launch()
        _,envelope=f.signed(probe,uid=0)
        value=json.loads(base64.b64decode(envelope['payload']))
        intent=value['intent']
        intent['account']={'kind':'name','name':name}
        approver=native['broker'](f)
        peer=socket.socket(socket.AF_UNIX)
        peer.settimeout(10)
        peer.connect(str(f.client))
        output=os.memfd_create('phase1-account-observed',os.MFD_CLOEXEC)
        descriptors.append(output)
        body=SHARED['frame'](1,{'version':'3.0','mode':'thin_csr','tty_mode':'stdio','caller_env':{},'intent':intent})
        with open('/dev/null','r+b') as null:
            peer.sendmsg([body],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[output,null.fileno()]))])
        request=native['review'](approver)
        assert set(request)=={'exec_id','signer_id','csr_payload','remaining_ms'}, request
        prepared=json.loads(request['csr_payload'])
        assert prepared['intent']['account']=={'kind':'name','name':name}
        assert prepared['execution_context']['target_uid']==33 and prepared['execution_context']['target_gid']==33
        assert prepared['execution_context']['supplementary_gids']==[104]
        original_profile=prepared['security_constraints']['profile_sha256']
        # Change both the account and same-named profile after preparation. No
        # reload is implemented; the approved captured generation must prevail.
        passwd.write_text(original_passwd + name+':x:0:0::/:/bin/false\n')
        groups.write_text(original_groups)
        config=f.base/'config'
        config.write_text(config.read_text().replace('memory_max = 268435456','memory_max = 134217728'))
        _,signed=f.sign_payload(request['csr_payload'].encode())
        response=canonical({'exec_id':request['exec_id'],'status':'approved','dsse_envelope':signed})
        approver.sendall(len(response).to_bytes(4,'big')+response)
        decision=ready(peer)
        live_job=next((f.group/'jobs').glob('job-*'))
        assert (live_job/'memory.max').read_text().strip()=='268435456'
        assert exited(peer)=={'exit_code':0,'signal':None}
        observed=json.loads(os.pread(output,4096,0))
        assert observed=={'uid':[33,33,33],'gid':[33,33,33],'groups':[104]}, observed
        commit=next(r for r in f.records() if r.get('event_type')=='AUTH_COMMIT')
        assert commit['security_constraints']['profile_sha256']==original_profile
        peer.close(); peer=None
        approver.close(); approver=None
        wait_for(f.empty,'named-account job cleanup')
        f.stop()
        e.passed('observed-host-account-profile',observed=observed,memory_max=268435456,profile_sha256=original_profile)
        e.manifest['result']='passed'
    finally:
        if peer: peer.close()
        if approver: approver.close()
        for fd in descriptors: os.close(fd)
        e.capture(f,'host-account-profile')
        f.cleanup()
        e.save()


def output_and_limits(parent, binaries, evidence):
    f = Fixture(parent, binaries)
    gate = None
    try:
        probe = f.commands / 'mvp-probe'
        run(['cc', '-O2', '-Wall', '-Werror', REPO / 'crates/sigrund/tests/fixtures/execution/probe.c', '-o', probe])
        gate = SHARED['Gate'](f, 'cleanup-before')
        warrant, _ = f.signed(probe, ('output',))
        client, output, _ = cli(f, warrant)
        code, out, err, events = finish(client, output)
        expected = bytes(range(256)) * (2097152 // 256)
        assert code == 23 and out == expected and err == SHARED['CLIENT_PROGRESS'] + expected, (code, len(out), len(err), events)
        assert exit_fields(events[-1]) == {'exit_code': 23, 'signal': None}
        # A genuinely blocked local sink must not prevent a signal cancellation.
        blocked, _ = f.signed(probe, ('blocked-output',))
        client, output, status_path = cli(f, blocked)
        try:
            cancellation = cancel_blocked_output(client, output, status_path, f.empty)
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)
            if not output.closed:
                output.close()
            for stream in (client.stdin, client.stdout, client.stderr):
                if stream:
                    stream.close()
        # Memory and pids are actually enforced, beyond control read-back.
        memory, _ = f.signed(probe, ('memory',))
        gate.arm()
        client, output, _ = cli(f, memory)
        gate.arrive()
        memory_events = dict(line.split() for line in next((f.group / 'jobs').glob('job-*/memory.events')).read_text().splitlines())
        assert int(memory_events['oom_kill']) >= 1, memory_events
        gate.unblock()
        code, out, err, events = finish(client, output)
        assert code == 137 and exit_fields(events[-1]) == {'exit_code': None, 'signal': 9}, (code, out, err, events)
        wait_for(f.empty, 'OOM job cleanup')
        pids, _ = f.signed(probe, ('pids',))
        gate.arm()
        client, output, _ = cli(f, pids)
        gate.arrive()
        pids_events = dict(line.split() for line in next((f.group / 'jobs').glob('job-*/pids.events')).read_text().splitlines())
        assert int(pids_events['max']) >= 1, pids_events
        gate.unblock()
        code, out, err, events = finish(client, output)
        assert code == 0 and out.startswith(b'pids-denied:'), (code, out, err, events)
        denied_at = int(out.strip().split(b':')[1])
        assert 0 < denied_at < 128
        wait_for(f.empty, 'background descendants cleaned with job')
        f.stop()
        evidence.passed('output-and-enforced-limits', stdout_bytes=len(expected), stderr_bytes=len(expected),
                        blocked_output_cancellation=cancellation,
                        oom_signal=9, fork_denied_after=denied_at, descendants_cleaned=True, memory_events=memory_events, pids_events=pids_events)
    finally:
        evidence.capture(f, 'output-and-enforced-limits')
        if gate:
            gate.close()
        f.cleanup()


def failed_job_limit(parent, binaries, evidence):
    f = Fixture(parent, binaries)
    gate = None
    try:
        gate = SHARED['Gate'](f, 'limit-fail')
        gate.arm()
        warrant, _ = f.signed(f.commands / 'true')
        child, output, _ = cli(f, warrant)
        code, out, err, events = finish(child, output)
        assert code == 254 and not out and events[0]['status'] == 'APPROVED' and events[-1]['status'] == 'SETUP_FAILED', (code,out,err,events)
        assert count(f) == 1
        wait_for(f.empty, 'failed cgroup setup cleanup')
        assert not any(r.get('event_type') == 'EXEC_READY_TO_EXEC' for r in f.records())
        deny(f, warrant, 'REPLAY_DETECTED')
        f.stop()
        evidence.passed('failed-job-limit', no_readiness=True, consumed=True, replay='REPLAY_DETECTED')
    finally:
        evidence.capture(f, 'failed-job-limit')
        if gate:
            gate.close()
        f.cleanup()


def local_recovery(parent, binaries, evidence):
    f = Fixture(parent, binaries)
    try:
        f.launch()
        warrant, _ = f.signed(f.commands / 'true')
        client, output, _ = cli(f, warrant)
        assert finish(client, output)[0] == 0
        f.stop()
        identity = (f.state / 'host_identity.key').read_bytes()
        with open(f.log, 'ab') as log:
            log.write(b'{"partial":')
            log.flush()
            os.fsync(log.fileno())
        f.launch()
        deny(f, warrant, 'REPLAY_DETECTED')
        f.stop()
        assert any(r.get('event_type') == 'RATCHET_PARTIAL_WRITE_TRUNCATED' for r in f.records()), f.records()
        assert (f.state / 'host_identity.key').read_bytes() == identity and count(f) == 1
        verification = independently_verify_audit(f)
        # Forward recovery and poison/restart are exercised by the runtime service
        # state-fail gate; this case covers a synchronized partial tail.
        evidence.passed('synchronized-partial-tail-recovery', identity_preserved=True, consumption_preserved=True, independent_audit=verification)
    finally:
        evidence.capture(f, 'synchronized-partial-tail-recovery')
        f.cleanup()


def coherent_rollback_limitation(parent, binaries, evidence):
    """Qualify the stated local-audit limit on this disposable fixture only."""
    f = Fixture(parent,binaries)
    try:
        paths = (f.state/'state.sqlite',f.state/'state.sqlite-wal',f.state/'state.sqlite-shm',
                 f.state/'audit_ratchet.state',f.log)
        baseline = {path:path.read_bytes() for path in paths if path.exists()}
        f.launch()
        warrant,_ = f.signed(f.commands/'true')
        client,output,_ = cli(f,warrant)
        assert finish(client,output)[0] == 0
        assert count(f) == 1
        old_epoch = f.binding()['target_binding']['daemon_epoch']
        f.stop()
        # Deliberately restore a complete old, internally authentic set. This
        # is outside crash recovery and cannot be detected without an external
        # checkpoint; no production state or other fixture is modified.
        # WAL/SHM are part of this deliberate rollback too. Leaving a newer
        # WAL would replay the committed row over the restored main database.
        for path in paths:
            if path in baseline:
                path.write_bytes(baseline[path])
            else:
                path.unlink(missing_ok=True)
        f.launch()
        assert f.binding()['target_binding']['daemon_epoch'] != old_epoch
        assert count(f) == 0
        deny(f,warrant,'STALE_TARGET')
        assert count(f) == 0 and f.empty()
        f.stop()
        evidence.passed('coherent-rollback-local-audit-limit', coherent_rollback_detected=False,
                        external_checkpoint_required=True, old_epoch_redemption_rejected=True,
                        independent_audit=independently_verify_audit(f))
    finally:
        evidence.capture(f,'coherent-rollback-local-audit-limit')
        f.cleanup()


def operator_workflow(binaries, requester, evidence, supervisor_unit):
    """Exercise both shipped service recipes with a real requester terminal."""
    import fcntl
    import pwd
    import shutil
    account = pwd.getpwnam(requester)
    base = Path('/var/lib') / ('sigrund-mvp-fixture-' + uuid.uuid4().hex[:12])
    lab = REPO / 'scripts/operator-lab.py'
    approver = None
    child = None
    foreground = None
    masters = []
    try:
        run([sys.executable, lab, 'prepare', '--directory', base, '--binaries', binaries, '--requester', requester,
             '--supervisor-unit', supervisor_unit],
            capture_output=True)
        # This case deliberately tests retained snapshot bytes after mutation.
        config_path = base / 'config.toml'
        config_path.write_text(config_path.read_text().replace('authorization_timeout_ms = 120000', 'authorization_timeout_ms = 5000').replace(
            'executable_trust_models = ["fs_verity", "ctime", "digest_direct", "digest_memfd"]',
            'executable_trust_models = ["digest_memfd"]'))
        manifest = json.loads((base / 'lab.json').read_text())
        tools = base / 'bin'
        runtime = Path(manifest['runtime'])
        run([sys.executable, lab, 'start', '--directory', base], capture_output=True)
        run([sys.executable, lab, 'status', '--directory', base], capture_output=True)
        master, slave = pty.openpty()
        masters.extend([master, slave])
        def operator_tty():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        approver = subprocess.Popen([str(tools / 'sigrund-approve'), '--socket', str(runtime / 'approve.sock'),
                                     '--signers', str(base / 'signers.toml'), '--identity', str(base / 'signer'),
                                     '--epoch-file', str(base / 'state/host-epoch.json')],
                                    stdin=slave, stdout=slave, stderr=subprocess.PIPE, preexec_fn=operator_tty)
        def requester_ids():
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
        # Give the broker event a chance to run before submitting; readiness of
        # the process alone is not an approval-attachment barrier.
        group = subprocess.check_output(['systemctl', 'show', '--property=ControlGroup', '--value', manifest['unit']], text=True).strip()
        main_pid = int(subprocess.check_output(['systemctl', 'show', '--property=MainPID', '--value', manifest['unit']], text=True))
        def broker_attached():
            records = subprocess.check_output(['journalctl', '-u', manifest['unit'], '--no-pager', '-o', 'cat'], text=True)
            return any('SOCKET_ADMITTED' in line and '"broker":true' in line for line in records.splitlines())
        wait_for(broker_attached, 'approver broker registration')
        # The acceptance script owns only these new terminals and disposable key.
        for index, (answer, target, stdin_bytes) in enumerate(((b'no\n', 0, None), (b'yes\n', 0, None),
                                                            (b'yes\n', 33, b'\x00reviewed\xff\n'))):
            rm, rs = pty.openpty()
            masters.extend([rm, rs])
            attrs = termios.tcgetattr(rs)
            attrs[1] &= ~termios.OPOST
            termios.tcsetattr(rs, termios.TCSANOW, attrs)
            command = base / 'commands' / ('id' if stdin_bytes is None else 'cat')
            status_path = base / ('terminal-' + str(index) + '.status')
            with open(status_path, 'w+b') as status:
                args = [str(tools / 'sigrun'), '--socket', str(runtime / 'client.sock'), '--target', 'host', '--security-profile', 'host-baseline',
                        '--target-uid', str(target),
                        '--target-gid', str(target), '--cwd', '/', '--status-fd', str(status.fileno())]
                if stdin_bytes is not None:
                    args.extend(['--stdin', 'sha256'])
                args.extend(['--', str(command)] + (['-u'] if stdin_bytes is None else []))
                child = subprocess.Popen(args, preexec_fn=requester_ids, pass_fds=(status.fileno(),),
                                         stdin=subprocess.PIPE, stdout=rs, stderr=rs)
                if stdin_bytes is not None:
                    child.stdin.write(stdin_bytes)
                child.stdin.close()
                prompt = b''
                deadline = time.monotonic() + 8
                while b'Approve and sign? [y/yes/n/no] ' not in prompt:
                    assert time.monotonic() < deadline and child.poll() is None, prompt
                    if select.select([master], [], [], 0.1)[0]:
                        prompt += os.read(master, 8192)
                    assert len(prompt) < 1048576
                assert str(account.pw_uid).encode() in prompt
                if stdin_bytes is not None:
                    assert hashlib.sha256(stdin_bytes).hexdigest().encode() in prompt
                # The approved executable must come from the retained snapshot
                # even if its pathname changes while root reviews the request.
                if index == 1:
                    command.write_bytes((base / 'commands/false').read_bytes())
                os.write(master, answer)
                child.wait(timeout=8)
                terminal = b''
                while select.select([rm], [], [], 0.05)[0]:
                    terminal += os.read(rm, 65536)
                status.seek(0)
                events = [json.loads(line) for line in status]
            directory = evidence.root / 'operator-workflow'
            directory.mkdir(exist_ok=True)
            (directory / (str(index) + '.prompt')).write_bytes(prompt)
            (directory / (str(index) + '.terminal')).write_bytes(terminal)
            (directory / (str(index) + '.status.jsonl')).write_bytes(status_path.read_bytes())
            if answer == b'no\n':
                assert child.returncode == 255 and events[0]['status'] == 'TIMEOUT', (terminal, events)
            else:
                assert child.returncode == 0 and exit_fields(events[-1]) == {'exit_code': 0, 'signal': None}, (terminal, events)
                fallback = b'sigrun: local full preparation unavailable; submitting thin intent\n'
                assert terminal == fallback + SHARED['CLIENT_PROGRESS'] + (b'0\n' if stdin_bytes is None else stdin_bytes), terminal
        approver.terminate()
        approver.wait(timeout=5)
        approver = None
        run([sys.executable, lab, 'stop', '--directory', base], capture_output=True)
        assert not runtime.exists()
        # Start the exact foreground recipe against the retained state. It is
        # bound to the same acceptance supervisor and must remove its sockets.
        foreground = subprocess.Popen([sys.executable, str(lab), 'foreground', '--directory', str(base)],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        wait_for(lambda: (runtime / 'client.sock').exists(), 'foreground recipe startup')
        run([sys.executable, lab, 'status', '--directory', base], capture_output=True)
        run(['systemctl', 'stop', manifest['unit']])
        foreground.communicate(timeout=8)
        assert foreground.returncode == 0 and not runtime.exists()
        directory = evidence.root / 'operator-workflow'
        (directory / 'audit.jsonl').write_bytes((base / 'log/audit.jsonl').read_bytes())
        (directory / 'daemon.service').write_bytes((base / 'daemon.service').read_bytes())
        evidence.passed('operator-workflow', requester_uid=account.pw_uid, root_uid=0, service_uid=33,
                        requester_tty=True, root_tty=True, explicit_refusal='TIMEOUT',
                        hashed_stdin=True, packaged_and_foreground=True, group=group, daemon_pid=main_pid)
    finally:
        if child and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        if approver and approver.poll() is None:
            approver.kill()
            approver.wait(timeout=5)
        if approver and approver.stderr:
            (evidence.root / 'operator-approver.stderr').write_bytes(approver.stderr.read())
        if (base / 'log/audit.jsonl').exists():
            (evidence.root / 'operator-final-audit.jsonl').write_bytes((base / 'log/audit.jsonl').read_bytes())
        if (base / 'lab.json').exists():
            manifest = json.loads((base / 'lab.json').read_text())
            subprocess.run(['systemctl', 'stop', manifest['unit']], capture_output=True)
            target = Path('/run/systemd/system') / manifest['unit']
            target.unlink(missing_ok=True)
            subprocess.run(['systemctl', 'reset-failed', manifest['unit']], capture_output=True)
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
        if foreground and foreground.poll() is None:
            foreground.kill()
            foreground.communicate(timeout=5)
        for fd in masters:
            os.close(fd)
        if base.exists():
            shutil.rmtree(base)


def prerequisites(binaries, platform_binary):
    problems = []
    if os.geteuid() != 0:
        problems.append('run this entry point as root in the disposable VM')
    for command in ('systemd-run', 'systemctl', 'cc', 'ssh-keygen', 'strace'):
        import shutil
        if shutil.which(command) is None:
            problems.append('missing command: ' + command)
    if not Path('/run/systemd/system').is_dir() or not Path('/sys/fs/cgroup/cgroup.controllers').is_file():
        problems.append('requires booted systemd and unified cgroup v2')
    for name in ('sigrund', 'sigrun', 'sigrundctl', 'sigrund-approve', 'sigrund-collector'):
        if not os.access(binaries / name, os.X_OK):
            problems.append('build executable: ' + str(binaries / name))
    if not os.access(platform_binary, os.X_OK):
        problems.append('supply the built cgroup test executable')
    try:
        from gi.repository import Gio  # noqa: F401
    except ImportError:
        problems.append('install python3-gi for the existing real-service gate')
    if problems:
        raise RuntimeError('\n'.join(problems))


def inside(args):
    membership = Path('/proc/self/cgroup').read_text().strip()
    if not membership.startswith('0::/') or 'sigrund-mvp-gate-' not in membership:
        raise RuntimeError('inside entry point requires its dedicated delegated service')
    parent = Path('/sys/fs/cgroup' + membership.split('::', 1)[1])
    # Move only this harness into a leaf before enabling domain controllers.
    runner = parent / 'runner'
    runner.mkdir()
    (runner / 'cgroup.procs').write_text(str(os.getpid()))
    (parent / 'cgroup.subtree_control').write_text('+memory +pids')
    evidence = Evidence(args.artifacts)
    evidence.manifest['suite'] = 'acceptance'
    evidence.manifest['ordinary_checks'] = json.loads(args.checks.read_bytes())
    evidence.manifest['delegated_parent'] = str(parent)
    evidence.manifest['binaries'] = {name: hashlib.sha256((args.binaries / name).read_bytes()).hexdigest()
                                     for name in ('sigrund', 'sigrun', 'sigrundctl', 'sigrund-approve', 'sigrund-collector')}
    evidence.save()
    try:
        strace = shutil.which('strace')
        if strace is None:
            raise RuntimeError('strace disappeared after prerequisite validation')
        for label, command in (
            ('platform', [sys.executable, REPO / 'scripts/verify-platform.py', args.platform_binary, '--cgroup-parent', parent]),
            ('runtime', [sys.executable, REPO / 'scripts/verify-runtime.py', '--cgroup-parent', parent,
                         '--binaries', args.binaries, '--systemd']),
            ('v3', [sys.executable, REPO / 'scripts/verify-v3.py', '--cgroup-parent', parent, '--binaries', args.binaries]),
            ('trust', [sys.executable, REPO / 'scripts/verify-trust.py', '--cgroup-parent', parent,
                       '--binaries', args.binaries, '--artifacts', args.artifacts / 'trust']),
            ('failures', [sys.executable, REPO / 'scripts/verify-execution.py', '--cgroup-parent', parent,
                          '--binaries', args.binaries, '--artifacts', args.artifacts / 'execution',
                          '--strace', strace]),
        ):
            with open(args.artifacts / (label + '.log'), 'wb') as log:
                run(command, stdout=log, stderr=subprocess.STDOUT)
            evidence.passed(label, log=label + '.log', command=[str(a) for a in command])
        package_workflow(parent, args.binaries, evidence)
        binding_and_replay(parent, args.binaries, evidence)
        host_binding_invariants(parent, args.binaries, evidence)
        host_resource_ownership(parent, args.binaries, evidence)
        public_context_capacity_is_independent(parent, args.binaries, evidence)
        thin_input_before_private_lookup(parent, args.binaries, evidence)
        host_account_profile_changes(parent, args.binaries, evidence)
        output_and_limits(parent, args.binaries, evidence)
        failed_job_limit(parent, args.binaries, evidence)
        local_recovery(parent, args.binaries, evidence)
        coherent_rollback_limitation(parent, args.binaries, evidence)
        operator_workflow(args.binaries, args.requester, evidence, parent.name)
        evidence.manifest['result'] = 'passed'
    except BaseException:
        evidence.manifest['result'] = 'failed'
        evidence.manifest['error'] = traceback.format_exc()
        raise
    finally:
        evidence.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries', type=Path, default=REPO / 'target/debug')
    parser.add_argument('--checks', type=Path, required=True, help='checks.json from check.py for this source/build')
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--requester', default='mvp-requester', help='existing unprivileged login, distinct from UID 0/33/65534')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.binaries = args.binaries.resolve(strict=True)
    args.checks = args.checks.resolve(strict=True)
    checks = json.loads(args.checks.read_bytes())
    digest = runpy.run_path(str(Path(__file__).with_name('check.py')))['source_digest']()
    if checks.get('result') != 'passed' or checks.get('source_sha256') != digest:
        parser.error('ordinary checks must pass against the current source snapshot')
    args.platform_binary = Path(checks['platform_binary']).resolve(strict=True)
    for name, expected in checks['binaries'].items():
        if hashlib.sha256((args.binaries / name).read_bytes()).hexdigest() != expected:
            parser.error('binary changed after ordinary checks: ' + name)
    args.artifacts = args.artifacts.absolute()
    prerequisites(args.binaries, args.platform_binary)
    if args.inside:
        inside(args)
        return
    args.artifacts.mkdir(parents=True, exist_ok=False)
    unit = 'sigrund-mvp-gate-' + uuid.uuid4().hex
    command = ['systemd-run', '--unit=' + unit, '--wait', '--collect', '--service-type=exec',
               '--property=Delegate=yes', '--property=KillMode=control-group', '--property=SendSIGKILL=yes',
               '--property=RuntimeMaxSec=1200s', '--property=TimeoutStopSec=15s',
               sys.executable, str(Path(__file__).resolve()), '--inside', '--binaries', str(args.binaries),
               '--checks', str(args.checks), '--artifacts', str(args.artifacts), '--requester', args.requester]
    if Path('/sys/fs/selinux/enforce').exists():
        context = Path('/proc/self/attr/current').read_text().strip('\0\n')
        command.insert(2, '--property=SELinuxContext=' + context)
    try:
        run(command)
    finally:
        subprocess.run(['systemctl', 'stop', unit], capture_output=True)
        observation = subprocess.run(['systemctl', 'show', '--property=ControlGroup', '--value', unit],
                                     capture_output=True, text=True)
        group = Path('/sys/fs/cgroup/system.slice') / (unit + '.service')
        cleaned = not group.exists()
        (args.artifacts / 'supervisor.json').write_text(json.dumps({'unit': unit, 'command': command,
                'cgroup_removed': cleaned, 'unit_query': observation.stdout.strip()}, indent=2) + '\n')
        if not cleaned:
            raise RuntimeError('supervisor cgroup retained: ' + str(group))


if __name__ == '__main__':
    main()
