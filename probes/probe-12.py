"""Issue 12 probe: process spawn / wait / sched / credential divergences.

Each line: GT <name> <result>. Run on Linux with GT_HOST=1 for reference values,
and inside Ginux (python:3.13-alpine domain). Every test runs in a forked child
with a watchdog so a hang only affects that row.
"""
import ctypes, errno, os, select, signal, struct, subprocess, sys, time

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
HOST = os.environ.get("GT_HOST") == "1"
NR = dict(wait4=61, waitid=247, setuid=105, setgid=106, setfsuid=122, setfsgid=123,
          sched_setscheduler=144, sched_getscheduler=145, sched_setattr=314, sched_getattr=315,
          sched_setparam=142)


def sc(name, *args):
    a = [ctypes.c_long(x) if isinstance(x, int) else x for x in args]
    r = libc.syscall(ctypes.c_long(NR[name]), *a)
    if r == -1:
        e = ctypes.get_errno()
        return "-" + errno.errorcode.get(e, str(e))
    return r


def out(name, value):
    print("GT", name, value, flush=True)


def run_isolated(name, fn, limit=10.0):
    """Run fn in a forked child so a hang or crash only affects this test."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            res = str(fn())
        except Exception as exc:
            res = "EXC:" + type(exc).__name__ + ":" + str(exc)[:60]
        os.write(w, res.encode())
        os._exit(0)
    os.close(w)
    ready, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 300).decode() if ready else "HANG(>%ss)" % limit
    if not ready:
        os.kill(pid, signal.SIGKILL)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    os.close(r)
    out(name, res or "EMPTY")


run = run_isolated

# ---------------- A: spawn ----------------
def posix_spawn_true():
    pid = os.posix_spawn("/bin/true", ["true"], {})
    _, st = os.waitpid(pid, 0)
    return "status=%d" % st


def posix_spawn_exit7():
    pid = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 7"], {})
    _, st = os.waitpid(pid, 0)
    return "exitcode=%s" % os.waitstatus_to_exitcode(st)


def posix_spawn_enoent():
    try:
        os.posix_spawn("/nonexistent/bin", ["x"], {})
        return "spawned"
    except OSError as exc:
        return "-" + errno.errorcode[exc.errno]


def posix_spawn_parent_memory():
    # vfork semantics: the parent must still run normally afterwards and
    # its stack/heap must be intact.
    marker = [1, 2, 3]
    pids = [os.posix_spawn("/bin/true", ["true"], {}) for _ in range(3)]
    sts = [os.waitpid(p, 0)[1] for p in pids]
    return "statuses=%s marker=%s" % (sts, marker)


def posix_spawn_many_unwaited():
    # Ginux has 7 process storage slots per domain; exhaustion must be EAGAIN.
    pids, err = [], None
    try:
        for _ in range(8):
            pids.append(os.posix_spawn("/bin/true", ["true"], {}))
    except OSError as exc:
        err = "-" + errno.errorcode[exc.errno]
    sts = [os.waitpid(p, 0)[1] for p in pids]
    return "spawned=%d err=%s all_zero=%s" % (len(pids), err, all(s == 0 for s in sts))


def posix_spawn_file_actions():
    r, w = os.pipe()
    pid = os.posix_spawn("/bin/echo", ["echo", "spawned-out"], {},
                         file_actions=[(os.POSIX_SPAWN_DUP2, w, 1), (os.POSIX_SPAWN_CLOSE, r)])
    os.close(w)
    data = os.read(r, 100)
    os.close(r)
    os.waitpid(pid, 0)
    return data.decode().strip()


run("posix_spawn_true", posix_spawn_true)
run("posix_spawn_exit7", posix_spawn_exit7)
run("posix_spawn_enoent", posix_spawn_enoent)
run("posix_spawn_parent_intact", posix_spawn_parent_memory)
run("posix_spawn_8_unwaited", posix_spawn_many_unwaited)
run("os_system_true", lambda: os.system("/bin/true"))
run("os_system_exit3", lambda: os.waitstatus_to_exitcode(os.system("exit 3")))
run("os_popen_echo", lambda: os.popen("echo popen-ok").read().strip())


def fork_execv_true():
    pid = os.fork()
    if pid == 0:
        try:
            os.execv("/bin/true", ["true"])
        finally:
            os._exit(99)
    _, st = os.waitpid(pid, 0)
    return "status=%d" % st


run("fork_execv_true", fork_execv_true)
run("subprocess_run_plain", lambda: subprocess.run(["/bin/true"]).returncode)

def fork_dup2_exec_capture():
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.dup2(w, 1)
        os.close(r)
        os.close(w)
        os.execv("/bin/echo", ["echo", "manual"])
    os.close(w)
    data = b""
    while True:
        chunk = os.read(r, 100)
        if not chunk:
            break
        data += chunk
    os.close(r)
    os.waitpid(pid, 0)
    return repr(data)


run("fork_dup2_exec_read_eof", fork_dup2_exec_capture)


def argv0_preserved():
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.dup2(w, 1)
        os.close(r)
        os.close(w)
        os.execv("/bin/sh", ["-sh", "-c", "echo $0"])
    os.close(w)
    data = b""
    while True:
        chunk = os.read(r, 100)
        if not chunk:
            break
        data += chunk
    os.close(r)
    os.waitpid(pid, 0)
    return repr(data.strip())


run("execv_argv0_preserved", argv0_preserved)

# ---------------- B: wait status ----------------
def killed_child_status(sig):
    def inner():
        pid = os.fork()
        if pid == 0:
            os.kill(os.getpid(), sig)
            time.sleep(5)
            os._exit(1)
        _, st = os.waitpid(pid, 0)
        return "WIFSIGNALED=%s sig=%s raw=%d" % (os.WIFSIGNALED(st), os.WTERMSIG(st) if os.WIFSIGNALED(st) else "-", st)
    return inner


run("wait_killed_sigterm", killed_child_status(signal.SIGTERM))
run("wait_killed_sigkill", killed_child_status(signal.SIGKILL))


def parent_kills_child():
    pid = os.fork()
    if pid == 0:
        time.sleep(5)
        os._exit(1)
    time.sleep(0.2)
    os.kill(pid, signal.SIGKILL)
    _, st = os.waitpid(pid, 0)
    return "WIFSIGNALED=%s sig=%s raw=%d" % (os.WIFSIGNALED(st), os.WTERMSIG(st) if os.WIFSIGNALED(st) else "-", st)


run("wait_parent_sigkill", parent_kills_child)


def exit_200_status():
    pid = os.fork()
    if pid == 0:
        os._exit(200)
    _, st = os.waitpid(pid, 0)
    return "WIFEXITED=%s code=%s raw=%d" % (os.WIFEXITED(st), os.WEXITSTATUS(st), st)


run("wait_exit_200", exit_200_status)


def waitid_killed():
    pid = os.fork()
    if pid == 0:
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(5)
        os._exit(1)
    r = os.waitid(os.P_PID, pid, os.WEXITED)
    return "code=%s status=%s" % (r.si_code, r.si_status)


def waitid_exited():
    pid = os.fork()
    if pid == 0:
        os._exit(9)
    r = os.waitid(os.P_PID, pid, os.WEXITED)
    return "code=%s status=%s" % (r.si_code, r.si_status)


run("waitid_killed_sigterm", waitid_killed)
run("waitid_exited_9", waitid_exited)


def sigchld_info_killed():
    got = []
    signal.signal(signal.SIGCHLD, lambda *a: None)
    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGCHLD])
    pid = os.fork()
    if pid == 0:
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(5)
        os._exit(1)
    info = signal.sigtimedwait([signal.SIGCHLD], 5)
    os.waitpid(pid, 0)
    if info is None:
        return "timeout"
    return "code=%s status=%s" % (info.si_code, info.si_status)


run("sigchld_siginfo_killed", sigchld_info_killed)


def waitid_wstopped_does_not_reap():
    pid = os.fork()
    if pid == 0:
        os._exit(3)
    time.sleep(0.3)
    info = ctypes.create_string_buffer(128)
    r = sc("waitid", 0, 0, ctypes.addressof(info), 2 | 1)  # P_ALL, WSTOPPED|WNOHANG
    si_pid = struct.unpack_from("i", info, 16)[0]
    try:
        rpid, st = os.waitpid(pid, 0)
        later = "reaped_later=%s" % (rpid == pid)
    except ChildProcessError:
        later = "ECHILD_later"
    return "ret=%s si_pid_set=%s %s" % (r, si_pid != 0, later)


run("waitid_wstopped_only", waitid_wstopped_does_not_reap)


def wait_flag(flag):
    def inner():
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        time.sleep(0.2)
        st = ctypes.c_int(0)
        r = sc("wait4", pid, ctypes.addressof(st), flag, 0)
        if r != pid:
            os.waitpid(pid, 0)
        return "reaped" if r == pid else r
    return inner


def waitid_flag(flag):
    def inner():
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        time.sleep(0.2)
        info = ctypes.create_string_buffer(128)
        r = sc("waitid", 1, pid, ctypes.addressof(info), 4 | flag)
        if r != 0:
            os.waitpid(pid, 0)
        return "reaped" if r == 0 else r
    return inner


# include/uapi/linux/wait.h: __WNOTHREAD 0x20000000, __WALL 0x40000000, __WCLONE 0x80000000
run("wait4___WALL", wait_flag(0x40000000))
run("wait4___WCLONE", wait_flag(0x80000000))
run("wait4___WCLONE___WALL", wait_flag(0xC0000000))
run("wait4___WNOTHREAD", wait_flag(0x20000000))
run("waitid___WALL", waitid_flag(0x40000000))
run("waitid___WCLONE", waitid_flag(0x80000000))

# ---------------- C: sched / credentials ----------------
param = ctypes.c_int(0)
P = ctypes.addressof(param)


def sched_seq(policy):
    def inner():
        r = sc("sched_setscheduler", 0, policy, P)
        g = sc("sched_getscheduler", 0)
        return "set=%s get=%s" % (r, g)
    return inner


run("sched_setscheduler_batch", sched_seq(3))
run("sched_setscheduler_idle", sched_seq(5))
run("sched_setscheduler_normal", sched_seq(0))
run("sched_setscheduler_reset_on_fork_batch", sched_seq(3 | 0x40000000))
run("sched_setscheduler_fifo_prio0", sched_seq(1))
param1 = ctypes.c_int(1)
run("sched_setscheduler_fifo_prio1", lambda: sc("sched_setscheduler", 0, 1, ctypes.addressof(param1)))
run("sched_setscheduler_batch_prio1", lambda: sc("sched_setscheduler", 0, 3, ctypes.addressof(param1)))
param100 = ctypes.c_int(100)
run("sched_setscheduler_fifo_prio100", lambda: sc("sched_setscheduler", 0, 1, ctypes.addressof(param100)))
run("sched_setscheduler_bad_policy", lambda: sc("sched_setscheduler", 0, 4, P))


def idle_then_normal():
    a = sc("sched_setscheduler", 0, 5, P)
    b = sc("sched_setscheduler", 0, 0, P)
    return "idle=%s normal=%s get=%s" % (a, b, sc("sched_getscheduler", 0))


run("sched_idle_then_normal", idle_then_normal)


def batch_inherited():
    sc("sched_setscheduler", 0, 3, P)
    pid = os.fork()
    if pid == 0:
        os._exit(sc("sched_getscheduler", 0) & 0xff)
    _, st = os.waitpid(pid, 0)
    return "child_policy=%s" % os.WEXITSTATUS(st)


def reset_on_fork_child():
    sc("sched_setscheduler", 0, 3 | 0x40000000, P)
    pid = os.fork()
    if pid == 0:
        g = sc("sched_getscheduler", 0)
        os._exit(1 if g == 3 else 2 if g == (3 | 0x40000000) else 3)
    _, st = os.waitpid(pid, 0)
    return "child_code=%s" % os.WEXITSTATUS(st)


def clear_reset_on_fork():
    a = sc("sched_setscheduler", 0, 0 | 0x40000000, P)
    b = sc("sched_setscheduler", 0, 0, P)
    return "set_rof=%s clear=%s get=%s" % (a, b, sc("sched_getscheduler", 0))


run("sched_batch_inherited_by_fork", batch_inherited)
run("sched_reset_on_fork_child", reset_on_fork_child)
run("sched_clear_reset_on_fork", clear_reset_on_fork)


def setattr_policy(policy, flags=0, prio=0):
    def inner():
        attr = ctypes.create_string_buffer(struct.pack("IIQiIQQQ", 48, policy, flags, 0, prio, 0, 0, 0), 56)
        r = sc("sched_setattr", 0, ctypes.addressof(attr), 0)
        return "set=%s get=%s" % (r, sc("sched_getscheduler", 0))
    return inner


run("sched_setattr_batch", setattr_policy(3))
run("sched_setattr_idle", setattr_policy(5))
run("sched_setattr_batch_reset_on_fork", setattr_policy(3, 1))
run("sched_setattr_fifo_prio0", setattr_policy(1))
run("sched_setattr_batch_prio1", setattr_policy(3, 0, 1))
run("sched_setattr_deadline_zero", setattr_policy(6))


def sched_getattr_policy():
    sc("sched_setscheduler", 0, 3, P)
    attr = ctypes.create_string_buffer(56)
    r = sc("sched_getattr", 0, ctypes.addressof(attr), 56, 0)
    return "ret=%s policy=%s" % (r, struct.unpack_from("I", attr, 4)[0])


run("sched_getattr_after_batch", sched_getattr_policy)

run("setuid_minus1", lambda: sc("setuid", 0xFFFFFFFF))
run("setgid_minus1", lambda: sc("setgid", 0xFFFFFFFF))
run("setuid_self", lambda: sc("setuid", os.getuid()))
run("setfsuid_query", lambda: "ret=%s uid=%s" % (sc("setfsuid", 0xFFFFFFFF), os.getuid()))
run("setfsuid_other", lambda: "ret=%s uid=%s" % (sc("setfsuid", 12345), os.getuid()))
run("setfsgid_other", lambda: "ret=%s gid=%s" % (sc("setfsgid", 12345), os.getgid()))
run("setfsuid_twice", lambda: "first=%s second=%s" % (sc("setfsuid", 12345), sc("setfsuid", 0xFFFFFFFF)))

# ---------------- A2: subprocess capture (last: a hang here stalls the run) ----------------
def popen_blocking_read():
    p = subprocess.Popen(["/bin/echo", "rd"], stdout=subprocess.PIPE)
    data = p.stdout.read()
    p.wait()
    return repr(data)


run("posix_spawn_dup2_pipe", posix_spawn_file_actions)
run("subprocess_capture_fork_mode", lambda: repr(subprocess.run(["/bin/echo", "hi"], capture_output=True, preexec_fn=lambda: None).stdout))
run("subprocess_popen_blocking_read", popen_blocking_read)
run("subprocess_capture_echo", lambda: repr(subprocess.run(["/bin/echo", "hi"], capture_output=True).stdout))
run("subprocess_capture_stdout_only", lambda: repr(subprocess.run(["/bin/echo", "hi"], stdout=subprocess.PIPE).stdout))
run("subprocess_check_output", lambda: repr(subprocess.check_output(["/bin/echo", "co"])))


print("GT_DONE", flush=True)
