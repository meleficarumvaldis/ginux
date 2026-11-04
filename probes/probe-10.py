"""Probe for issue 10 (signal semantics). Run on Linux (GT_HOST=1) and inside Ginux; diff.

Each line: GT <name> <result>. Every test runs in a forked child (run_isolated) so a
signal that kills the process only affects that test. kill(-1, SIGWINCH) is guarded by
`not HOST`; kill(-1, 0) and kill(-1, 999) only perform permission/validity checks.
"""
import ctypes, errno, os, select, signal, struct, sys, time

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
HOST = os.environ.get("GT_HOST") == "1"
NR = dict(rt_sigaction=13, rt_sigprocmask=14, kill=62, rt_sigpending=127, rt_sigqueueinfo=129,
          sigaltstack=131, tkill=200, tgkill=234, rt_tgsigqueueinfo=297, getpid=39, gettid=186)
SIGUSR1, SIGCHLD, SIGWINCH = 10, 17, 28


def sc(name, *args):
    a = [ctypes.c_long(x) for x in args]
    r = libc.syscall(ctypes.c_long(NR[name]), *a)
    if r == -1:
        e = ctypes.get_errno()
        return "-" + errno.errorcode.get(e, str(e))
    return r


def out(name, value):
    print("GT", name, value, flush=True)


def run(name, fn, limit=8.0):
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
    res = os.read(r, 200).decode() if ready else "HANG(>%ss)" % limit
    if not ready:
        os.kill(pid, signal.SIGKILL)
    _, st = os.waitpid(pid, 0)
    if not res and os.WIFSIGNALED(st):
        res = "child_killed_sig%d" % os.WTERMSIG(st)
    out(name, res or "EMPTY")


def get_action(sig):
    act = ctypes.create_string_buffer(32)
    sc("rt_sigaction", sig, 0, ctypes.addressof(act), 8)
    return struct.unpack("QQQQ", act.raw)


def set_action(sig, handler, flags, restorer, mask):
    new = ctypes.create_string_buffer(struct.pack("QQQQ", handler, flags, restorer, mask), 32)
    return sc("rt_sigaction", sig, ctypes.addressof(new), 0, 8)


def siginfo(sig, code):
    info = ctypes.create_string_buffer(128)
    struct.pack_into("iii", info, 0, sig, 0, code)
    KEEP.append(info)  # callers pass only its address
    return info


KEEP = []
hits = {"n": 0}


def count(*_):
    hits["n"] += 1


# 1. kill(-1)
if not HOST:
    def kill_minus_one():
        signal.signal(signal.SIGWINCH, count)
        r = sc("kill", -1, SIGWINCH)
        time.sleep(0.05)
        return "ret=%s caller_signaled=%s" % (r, hits["n"] != 0)
    run("kill_minus1_excludes_caller", kill_minus_one)
run("kill_minus1_sig0", lambda: sc("kill", -1, 0))
run("kill_minus1_badsig", lambda: sc("kill", -1, 999))


# 2. SA_NOCLDSTOP / unknown sa_flags
def sa_nocldstop(raise_fn):
    def body():
        signal.signal(signal.SIGCHLD, count)
        h, f, r, m = get_action(SIGCHLD)
        set_action(SIGCHLD, h, f | 1, r, m)
        ret = raise_fn()
        sc("getpid")
        return "ret=%s handler=%d" % (ret, hits["n"])
    return body


run("sa_nocldstop_kill", sa_nocldstop(lambda: sc("kill", os.getpid(), SIGCHLD)))
run("sa_nocldstop_tgkill", sa_nocldstop(lambda: sc("tgkill", os.getpid(), sc("gettid"), SIGCHLD)))


def sa_nocldwait_usr1():
    signal.signal(signal.SIGUSR1, count)
    h, f, r, m = get_action(SIGUSR1)
    set_action(SIGUSR1, h, f | 2, r, m)
    ret = sc("kill", os.getpid(), SIGUSR1)
    return "ret=%s handler=%d" % (ret, hits["n"])


run("sa_nocldwait_usr1_delivery", sa_nocldwait_usr1)


def sa_unsupported_readback():
    signal.signal(signal.SIGUSR1, count)
    h, f, r, m = get_action(SIGUSR1)
    set_action(SIGUSR1, h, f | 0x400 | 0x800 | 0x00800000, r, m)
    _, f2, _, _ = get_action(SIGUSR1)
    return "unsupported=%d tagbits=%d internal=%d" % (bool(f2 & 0x400), bool(f2 & 0x800), bool(f2 & 0x00800000))


run("sa_unsupported_readback", sa_unsupported_readback)


# 3. blocked signals are never ignored at generation
def blocked_queued(sig, disposition, raise_fn):
    def body():
        signal.signal(sig, disposition)
        signal.pthread_sigmask(signal.SIG_BLOCK, [sig])
        raise_fn(sig)
        pending = sig in signal.sigpending()
        got = signal.sigtimedwait([sig], 0)
        return "pending=%s wait=%s" % (pending, got.si_signo if got else "NONE")
    return body


kill_self = lambda s: sc("kill", os.getpid(), s)
tgkill_self = lambda s: sc("tgkill", os.getpid(), sc("gettid"), s)
queue_self = lambda s: sc("rt_sigqueueinfo", os.getpid(), s, ctypes.addressof(siginfo(s, -1)))
run("blocked_dfl_sigchld_kill", blocked_queued(signal.SIGCHLD, signal.SIG_DFL, kill_self))
run("blocked_dfl_sigchld_tgkill", blocked_queued(signal.SIGCHLD, signal.SIG_DFL, tgkill_self))
run("blocked_dfl_sigchld_sigqueue", blocked_queued(signal.SIGCHLD, signal.SIG_DFL, queue_self))
run("blocked_ign_usr1_kill", blocked_queued(signal.SIGUSR1, signal.SIG_IGN, kill_self))
run("blocked_ign_usr1_tgkill", blocked_queued(signal.SIGUSR1, signal.SIG_IGN, tgkill_self))


def blocked_ign_unblock():
    signal.signal(signal.SIGUSR1, signal.SIG_IGN)
    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1])
    sc("kill", os.getpid(), SIGUSR1)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGUSR1])
    sc("getpid")
    return "alive pending=%s" % (signal.SIGUSR1 in signal.sigpending())


run("blocked_ign_then_unblock", blocked_ign_unblock)


# 4. ignored disposition flushes pending
def ign_flushes(sig, new_disposition, raise_fn=kill_self):
    def body():
        signal.signal(sig, count)
        signal.pthread_sigmask(signal.SIG_BLOCK, [sig])
        raise_fn(sig)
        before = sig in signal.sigpending()
        signal.signal(sig, new_disposition)
        after = sig in signal.sigpending()
        signal.signal(sig, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, [sig])
        sc("getpid")
        return "before=%s after=%s alive" % (before, after)
    return body


run("sig_ign_flushes_pending", ign_flushes(signal.SIGUSR1, signal.SIG_IGN))
run("sig_ign_flushes_thread_pending", ign_flushes(signal.SIGUSR1, signal.SIG_IGN, tgkill_self))
run("sig_dfl_sigchld_flushes_pending", ign_flushes(signal.SIGCHLD, signal.SIG_DFL))
run("sig_ign_flushes_rt_queue", ign_flushes(40, signal.SIG_IGN, queue_self))


# 5. rt_sigqueueinfo rules
def sigqueue_self(code):
    def body():
        signal.signal(signal.SIGUSR1, count)
        r = sc("rt_sigqueueinfo", os.getpid(), SIGUSR1, ctypes.addressof(siginfo(SIGUSR1, code)))
        sc("getpid")
        return "ret=%s handler=%d" % (r, hits["n"])
    return body


run("rt_sigqueueinfo_self_si_user", sigqueue_self(0))
run("rt_sigqueueinfo_self_si_kernel", sigqueue_self(0x80))
run("rt_sigqueueinfo_self_si_tkill", sigqueue_self(-6))
run("rt_sigqueueinfo_sig0_null", lambda: sc("rt_sigqueueinfo", os.getpid(), 0, 0))
run("rt_sigqueueinfo_sig0_info", lambda: sc("rt_sigqueueinfo", os.getpid(), 0, ctypes.addressof(siginfo(0, -1))))
run("rt_sigqueueinfo_badsig_null", lambda: sc("rt_sigqueueinfo", os.getpid(), 65, 0))
run("rt_sigqueueinfo_badsig_info", lambda: sc("rt_sigqueueinfo", os.getpid(), 65, ctypes.addressof(siginfo(65, -1))))
run("rt_sigqueueinfo_nopid_badsig", lambda: sc("rt_sigqueueinfo", 999999, 65, ctypes.addressof(siginfo(65, -1))))
run("rt_sigqueueinfo_other_si_user", lambda: sc("rt_sigqueueinfo", os.getppid(), 0, ctypes.addressof(siginfo(0, 0))))
run("rt_tgsigqueueinfo_self_si_tkill", lambda: sc("rt_tgsigqueueinfo", os.getpid(), sc("gettid"), 0, ctypes.addressof(siginfo(0, -6))))
run("rt_tgsigqueueinfo_sig0_null", lambda: sc("rt_tgsigqueueinfo", os.getpid(), sc("gettid"), 0, 0))


# 6. SA_RESETHAND
def resethand_readback():
    signal.signal(signal.SIGUSR1, count)
    h, f, r, m = get_action(SIGUSR1)
    set_action(SIGUSR1, h, f | 0x80000000 | 4, r, m | (1 << 11))
    sc("kill", os.getpid(), SIGUSR1)
    h2, f2, r2, m2 = get_action(SIGUSR1)
    return "ran=%d handler_dfl=%s flags_kept=%s restorer_kept=%s mask_kept=%s" % (
        hits["n"], h2 == 0, f2 == (f | 0x80000004), r2 == r, bool(m2 & (1 << 11)))


run("sa_resethand_readback", resethand_readback)


# 7. sigaltstack
STACK = ctypes.create_string_buffer(65536)


def altstack(sp, flags, size):
    def body():
        ss = ctypes.create_string_buffer(struct.pack("QIiQ", sp, flags, 0, size), 24)
        r = sc("sigaltstack", ctypes.addressof(ss), 0)
        old = ctypes.create_string_buffer(24)
        sc("sigaltstack", 0, ctypes.addressof(old))
        osp, oflags, _, osize = struct.unpack("QIiQ", old.raw)
        return "ret=%s flags=%#x sp_set=%s" % (r, oflags, osp == sp)
    return body


run("sigaltstack_ss_onstack_flag", altstack(ctypes.addressof(STACK), 1, 65536))
run("sigaltstack_onstack_autodisarm", altstack(ctypes.addressof(STACK), 1 | (1 << 31), 65536))
run("sigaltstack_autodisarm", altstack(ctypes.addressof(STACK), 1 << 31, 65536))
run("sigaltstack_bad_mode", altstack(ctypes.addressof(STACK), 4, 65536))
run("sigaltstack_small", altstack(ctypes.addressof(STACK), 0, 1024))
run("sigaltstack_unmapped_sp", altstack(0x1000, 0, 65536))
run("sigaltstack_bad_uss", lambda: sc("sigaltstack", 8, 0))
run("sigaltstack_bad_uoss", lambda: sc("sigaltstack", 0, 8))


# 8. error precedence
PEND = ctypes.create_string_buffer(8)
run("rt_sigpending_size4", lambda: sc("rt_sigpending", ctypes.addressof(PEND), 4))
run("rt_sigpending_size0", lambda: sc("rt_sigpending", ctypes.addressof(PEND), 0))
run("rt_sigpending_size9", lambda: sc("rt_sigpending", ctypes.addressof(PEND), 9))
run("kill_nonexistent_badsig", lambda: sc("kill", 999999, 999))
run("kill_self_badsig", lambda: sc("kill", os.getpid(), 999))
run("kill_nopgrp_badsig", lambda: sc("kill", -999999, 999))
run("tkill_nonexistent_badsig", lambda: sc("tkill", 999999, 999))
run("tgkill_nonexistent_badsig", lambda: sc("tgkill", 999999, 999999, 999))
run("tgkill_self_badsig", lambda: sc("tgkill", os.getpid(), sc("gettid"), 999))

print("GT_DONE", flush=True)
