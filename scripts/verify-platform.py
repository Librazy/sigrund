#!/usr/bin/python3
"""Run the privileged kernel and child-setup fixture in a fresh, supervised cgroup.

The supplied parent must already delegate memory and pids to children. Only
this script's newly created cgroup is changed or killed. Run under an external
supervisor with whole-service cleanup and a final time limit on a test host.
"""
import argparse
import ctypes
import os
import pathlib
import signal
import time
import traceback
import uuid


def isolate(group_fd):
    # Descriptor-relative migration also works if the visible mount changes.
    procs = os.open("cgroup.procs", os.O_WRONLY | os.O_CLOEXEC, dir_fd=group_fd)
    try:
        os.write(procs, str(os.getpid()).encode())
    finally:
        os.close(procs)
    lib = ctypes.CDLL(None, use_errno=True)
    if lib.unshare(0x00020000) != 0:  # NEWNS
        raise OSError(ctypes.get_errno(), "mount namespace")
    if lib.mount(None, b"/", None, 0x4000 | 0x40000, None) != 0:  # REC | PRIVATE
        raise OSError(ctypes.get_errno(), "private mount propagation")
    # Preserve the existing cgroup2 view and actual service membership for
    # CgroupLayout::discover(). The production clone3 child creates its own
    # mount/cgroup namespaces and locks the inherited mount with mount_setattr.
    # Remounting cgroup2 here adds unrelated superblock-option constraints.


def wait_child(pid, deadline):
    while True:
        found, status = os.waitpid(pid, os.WNOHANG)
        if found:
            return os.waitstatus_to_exitcode(status)
        if time.monotonic() >= deadline:
            raise TimeoutError("platform gate exceeded its deadline")
        time.sleep(0.01)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--cgroup-parent", type=pathlib.Path, default=pathlib.Path("/sys/fs/cgroup"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root required")
    if not args.binary.is_absolute() or not args.cgroup_parent.is_absolute():
        parser.error("binary and cgroup parent must be absolute paths")
    if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        parser.error("build the cgroup test binary before running this gate")
    controls = (args.cgroup_parent / "cgroup.subtree_control").read_text().split()
    if not {"memory", "pids"}.issubset(controls):
        parser.error("parent must already delegate memory and pids; supply a prepared --cgroup-parent")
    group = args.cgroup_parent / ("sigrund-platform-test-" + str(uuid.uuid4()))
    group.mkdir(mode=0o755)
    pid = None
    try:
        group_fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            for control, flags in (("cgroup.procs", os.O_WRONLY),
                                   ("cgroup.kill", os.O_WRONLY),
                                   ("cgroup.events", os.O_RDONLY)):
                fd = os.open(control, flags | os.O_CLOEXEC, dir_fd=group_fd)
                os.close(fd)
            pid = os.fork()
            if pid == 0:
                try:
                    isolate(group_fd)
                    os.close(group_fd)
                    env = dict(os.environ, SIGRUND_CGROUP_DELEGATED_TEST="1")
                    os.execve(args.binary, [str(args.binary), "--exact", "delegated_platform_gate",
                                           "--ignored", "--nocapture", "--test-threads=1"], env)
                except BaseException:
                    traceback.print_exc()
                    os._exit(1)
        finally:
            os.close(group_fd)
        # The deadline includes namespace/mount setup, unlike Popen preexec_fn.
        code = wait_child(pid, time.monotonic() + 60)
        pid = None
        if code:
            raise SystemExit(code if code > 0 else 128 - code)
    finally:
        try:
            (group / "cgroup.kill").write_text("1\n")
        finally:
            if pid is not None:
                # The child may have stalled before entering the new group.
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                wait_child(pid, time.monotonic() + 10)
        deadline = time.monotonic() + 10
        while "populated 1" in (group / "cgroup.events").read_text():
            if time.monotonic() >= deadline:
                raise RuntimeError("fixture cleanup stalled; retained " + str(group))
            time.sleep(0.01)
        for path in sorted(group.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if path.is_dir():
                path.rmdir()
        group.rmdir()


if __name__ == "__main__":
    main()
