#!/usr/bin/python3
"""Native v2 confidentiality, requester access and provenance acceptance gates."""
import argparse
import array
import base64
import copy
import json
import os
from pathlib import Path
import runpy
import select
import socket
import struct
import subprocess
import sys
import time

SHARED = runpy.run_path(str(Path(__file__).with_name('verify-runtime.py')))
Fixture, canonical, frame, receive, wait_for = (SHARED[k] for k in ('Fixture', 'canonical', 'frame', 'receive', 'wait_for'))


def requester_socket(f, groups=()):
    """Connect with kernel-authenticated credentials, then hand the FD to the driver."""
    parent, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        try:
            parent.close()
            os.setgroups(groups)
            os.setgid(65534)
            os.setuid(65534)
            peer = socket.socket(socket.AF_UNIX)
            peer.connect(str(f.client))
            child.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [peer.fileno()]))])
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    _, controls, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
    _, status = os.waitpid(pid, 0)
    assert status == 0 and len(controls) == 1
    rights = array.array('i'); rights.frombytes(controls[0][2])
    peer = socket.socket(fileno=rights[0]); peer.settimeout(6)
    parent.close()
    return peer


def payload(f, executable=None):
    _, envelope = f.signed(executable or f.commands / 'true', target_uid=33, supplementary_gids=())
    return json.loads(base64.b64decode(envelope['payload']))


def hello(w, mode='thin_csr'):
    common = {'version':'2.0', 'mode':mode, 'tty_mode':'stdio', 'caller_env':{}}
    if mode == 'full_csr':
        return {**common, 'csr_payload':canonical(w).decode()}
    intent = {'command':{k:v for k,v in w['command'].items() if k not in ('executable_trust','stdin_sha256')},
              'execution_context':{k:v for k,v in w['execution_context'].items() if k != 'post_exec_capabilities'},
              'policy':{'mode':w['policy']['mode'],'ttl_secs':w['policy']['not_after']-w['policy']['not_before']}, 'caller_env':{}}
    return {**common,'intent':intent}


def submit(peer, body):
    read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    regular = os.memfd_create('v2-output-observation', os.MFD_CLOEXEC)
    peer.sendmsg([frame(1,body)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[write,regular]))])
    os.close(write)
    return read, regular


def broker(f):
    peer = None
    before = f.diagnostics.read_text().count('"broker":true')
    def admitted():
        nonlocal peer
        if peer is None:
            peer = socket.socket(socket.AF_UNIX); peer.settimeout(6)
            peer.connect(str(f.approval))
        if f.diagnostics.read_text().count('"broker":true') > before: return True
        if select.select([peer],[],[],0)[0] and peer.recv(1,socket.MSG_PEEK) == b'':
            peer.close(); peer = None
        return False
    wait_for(admitted, 'broker admission')
    return peer


def review(peer):
    def exact(n):
        value = b''
        while len(value) < n:
            chunk = peer.recv(n-len(value)); assert chunk
            value += chunk
        return value
    size = struct.unpack('>I',exact(4))[0]; assert size <= 524288
    return json.loads(exact(size))


def refuse(peer, request):
    response = canonical({'exec_id':request['exec_id'],'status':'rejected','reason':'private test refusal'})
    peer.sendall(struct.pack('>I',len(response))+response)


def timeout(peer, endpoints, started):
    assert not select.select([peer, endpoints[0]],[],[],0.1)[0], 'early control bytes or output EOF'
    assert os.fstat(endpoints[1]).st_size == 0
    result = receive(peer,2)
    assert set(result) == {'exec_id','status'} and result['status'] == 'TIMEOUT', result
    assert time.monotonic()-started >= 2.3, 'target-dependent early timeout'
    assert peer.recv(1) == b''
    peer.close()
    for fd in endpoints: os.close(fd)
    return result


def gate(parent, binaries):
    f = Fixture(parent,binaries)
    cases = []
    try:
        f.launch()
        w = payload(f)
        # Readable bytes and a valid full document still need current access proof.
        for case in ('missing','non_elf','schema','forged_evidence','unreadable','ancestor','acl','thin_refusal'):
            original = f.commands/'true'
            program = f.commands/('case-'+case)
            program.write_bytes(original.read_bytes()); program.chmod(0o755)
            doc = payload(f,program)
            body = hello(doc, 'full_csr' if case in ('forged_evidence','unreadable','ancestor','acl') else 'thin_csr')
            if case == 'missing': program.unlink()
            elif case == 'non_elf': program.write_text('not ELF\n')
            elif case == 'schema': body['extra'] = True
            elif case == 'forged_evidence':
                doc['command']['executable_trust']['sha256'] = '0'*64
                body = hello(doc,'full_csr')
            elif case == 'unreadable': program.chmod(0o000)
            elif case == 'ancestor':
                # The root itself is pinned and readable. Traversal above it is denied.
                f.base.chmod(0o700)
            elif case == 'acl': subprocess.run(['setfacl','-m','u:65534:---',str(program)],check=True)
            approver = broker(f)
            peer = requester_socket(f) if case != 'ancestor' else None
            if case == 'ancestor':
                f.base.chmod(0o755); peer = requester_socket(f); f.base.chmod(0o700)
            started = time.monotonic()
            endpoints = submit(peer,body)
            if case == 'thin_refusal':
                request = review(approver)
                expanded = json.loads(request['csr_payload'])
                assert expanded['request_origin'] == 'daemon_expanded_thin'
                assert expanded['approval_exec_id'] == request['exec_id']
                assert expanded['intent_sha256'] == __import__('hashlib').sha256(canonical(body['intent'])).hexdigest()
                refuse(approver,request)
            result = timeout(peer,endpoints,started)
            f.base.chmod(0o755)
            if case != 'thin_refusal':
                assert not select.select([approver],[],[],0)[0], 'invalid request reached mandator'
            approver.close()
            cases.append(result['exec_id'])
            # No silent failure may consume a grant or execute a child.
            assert not any(r.get('event_type') == 'AUTH_COMMIT' for r in f.records())
        # Read permission without execute permission is enough for full-CSR eligibility.
        program = f.commands/'true'; program.chmod(0o444)
        approver = broker(f); peer = requester_socket(f)
        endpoints = submit(peer,hello(payload(f,program),'full_csr'))
        request = review(approver)
        assert json.loads(request['csr_payload'])['request_origin'] == 'client_full'
        started = time.monotonic(); refuse(approver,request)
        decision = receive(peer,2)
        assert decision['status'] == 'REJECTED' and time.monotonic()-started < 1
        assert set(decision) == {'exec_id','status'}
        peer.close(); approver.close()
        for fd in endpoints: os.close(fd)
        # Kernel-authenticated supplementary groups, rather than the requested target groups.
        program.chmod(0o640); os.chown(program,0,500)
        approver = broker(f); peer = requester_socket(f,(500,))
        endpoints = submit(peer,hello(payload(f,program),'full_csr'))
        request = review(approver); refuse(approver,request)
        assert receive(peer,2)['status'] == 'REJECTED'
        peer.close(); approver.close()
        for fd in endpoints: os.close(fd)
        # Local preparation failures cannot turn full-only/export into a
        # privileged expansion request, even when a mandator is connected.
        approver = broker(f)
        before = f.diagnostics.read_text().count('"event":"SOCKET_ADMITTED"')
        export_dir = f.base / 'v2-exports'; export_dir.mkdir(); os.chown(export_dir,65534,65534)
        for option in (['--full-only'], ['--export-csr',str(export_dir/'missing.csr')]):
            result = subprocess.run([str(f.client_binary),'--socket',str(f.client),*option,
                                     '--',str(f.commands/'missing')],preexec_fn=SHARED['unprivileged'],
                                    input=b'',capture_output=True,timeout=6)
            assert result.returncode == 64 and not result.stdout, result
        assert not (export_dir/'missing.csr').exists()
        assert f.diagnostics.read_text().count('"event":"SOCKET_ADMITTED"') == before
        assert not select.select([approver],[],[],0)[0]
        approver.close()
        # A real client preserves its intent on fallback and sees no refusal.
        program.chmod(0o000)
        approver = broker(f)
        with open(f.base/'fallback.status','w+b') as status:
            started = time.monotonic()
            client = subprocess.Popen([str(f.client_binary),'--socket',str(f.client),'--cwd','/',
                                       '--target-uid','33','--target-gid','33','--status-fd',str(status.fileno()),
                                       '--stdin','sha256',
                                       '--',str(program)],preexec_fn=SHARED['unprivileged'],
                                      pass_fds=(status.fileno(),),stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                content = bytes(range(256)) * 16
                client.stdin.write(content); client.stdin.close(); client.stdin = None
                request = review(approver)
                expanded = json.loads(request['csr_payload'])
                assert expanded['request_origin'] == 'daemon_expanded_thin'
                assert expanded['command']['argv'] == [str(program)]
                assert expanded['command']['stdin_policy'] == 'sha256'
                assert expanded['command']['stdin_sha256'] == __import__('hashlib').sha256(content).hexdigest()
                refuse(approver,request)
                out,err = client.communicate(timeout=6)
                status.seek(0); events = [json.loads(line) for line in status]
                assert client.returncode == 255 and not out and b'local full preparation unavailable' in err
                assert len(events)==1 and set(events[0])=={'exec_id','status'} and events[0]['status']=='TIMEOUT'
                assert time.monotonic()-started >= 2.3
            finally:
                if client.poll() is None:
                    client.kill(); client.communicate(timeout=6)
        approver.close()
        wait_for(lambda: all(any(r.get('exec_id')==i and r.get('event_type')=='PRIVATE_OUTCOME' for r in f.records()) for i in cases), 'private outcome audit')
        for record in f.records():
            if record.get('exec_id') in cases and record['event_type'] == 'PRIVATE_OUTCOME':
                assert record['public_outcome']=='TIMEOUT' and record['delivery_status']=='sent', record
        # A thin approval executes through its active request, but the exact
        # signed artifact cannot authorize a standalone redemption.
        approver = broker(f); peer = requester_socket(f)
        endpoints = submit(peer,hello(payload(f,program)))
        request = review(approver)
        expanded = json.loads(request['csr_payload'])
        assert expanded['request_origin'] == 'daemon_expanded_thin'
        assert expanded['approval_exec_id'] == request['exec_id']
        _, envelope = f.sign_payload(request['csr_payload'].encode())
        response = canonical({'exec_id':request['exec_id'],'status':'approved','dsse_envelope':envelope})
        approver.sendall(struct.pack('>I',len(response))+response)
        decision = receive(peer,2)
        assert set(decision)=={'exec_id','status'} and decision['status']=='APPROVED', decision
        assert receive(peer,8)=={'exec_id':decision['exec_id'],'exec_outcome':'unknown'}
        assert receive(peer,5)=={'exec_id':decision['exec_id'],'status':'EXITED','exit_code':0,'signal':None}
        peer.close(); approver.close()
        for fd in endpoints: os.close(fd)
        commits = [r for r in f.records() if r.get('event_type')=='AUTH_COMMIT']
        assert len(commits)==1 and commits[0]['approval_exec_id']==request['exec_id']
        peer = requester_socket(f)
        started = time.monotonic()
        endpoints = submit(peer,{'version':'2.0','mode':'signed','tty_mode':'stdio','caller_env':{},'dsse_envelope':envelope})
        timeout(peer,endpoints,started)
        assert len([r for r in f.records() if r.get('event_type')=='AUTH_COMMIT'])==1
        f.stop()
        print(json.dumps({'gate':'v2-native-access-and-confidentiality','result':'passed','silent_cases':len(cases),'full_rejection':True,'supplementary_groups':True,'thin_execution':True,'thin_redemption_denied':True}),flush=True)
    finally:
        if sys.exc_info()[0] is not None:
            print(f.diagnostics.read_text(), file=sys.stderr)
            print(json.dumps(f.records()), file=sys.stderr)
        f.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cgroup-parent',type=Path,required=True)
    parser.add_argument('--binaries',type=Path,default=Path(__file__).resolve().parents[1]/'target/debug')
    args = parser.parse_args()
    assert os.geteuid()==0
    gate(args.cgroup_parent,args.binaries)


if __name__ == '__main__': main()
