"""Probe for patch 22: threads after fork, FUTEX_WAKE counts, sleeping threads.

Each test runs in a forked child with a watchdog. GT <name> <result>.
Linux reference: GT_HOST=1 python3 probe-22.py
"""
import ctypes, os, select, signal, threading, time

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
FUTEX = 202
WAIT_PRIV, WAKE_PRIV, CMP_REQUEUE_PRIV = 128, 129, 132


def futex(addr, op, val, a4=0, a5=0, a6=0):
    r = libc.syscall(ctypes.c_long(FUTEX), ctypes.c_long(addr), ctypes.c_long(op),
                     ctypes.c_long(val), ctypes.c_long(a4), ctypes.c_long(a5), ctypes.c_long(a6))
    return r if r >= 0 else -ctypes.get_errno()


def iso(name, fn, limit=15):
    r, w = os.pipe(); pid = os.fork()
    if pid == 0:
        os.close(r)
        try: res = str(fn())
        except Exception as e: res = "EXC:%s:%s" % (type(e).__name__, str(e)[:60])
        os.write(w, res.encode()); os._exit(0)
    os.close(w)
    ok, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 300).decode() if ok else "HANG"
    if not ok: os.kill(pid, signal.SIGKILL)
    _, st = os.waitpid(pid, 0)
    print("GT", name, res, "status=%d" % st, flush=True)


def fork_once():
    p = os.fork()
    if p == 0: os._exit(0)
    os.waitpid(p, 0)


def busy(seconds):
    e = time.monotonic() + seconds
    while time.monotonic() < e: pass


# 1+2: n threads FUTEX_WAIT on a word; the main thread wakes them all.
def wake_all(nthreads, main_sleep, forked):
    def test():
        if forked: fork_once()
        word = (ctypes.c_int * 2)(0, 0); addr = ctypes.addressof(word)
        res = []
        ts = [threading.Thread(target=lambda: res.append(futex(addr, WAIT_PRIV, 0))) for _ in range(nthreads)]
        [t.start() for t in ts]
        time.sleep(0.5) if main_sleep else busy(0.5)
        blocked = sum(t.is_alive() for t in ts)
        w = futex(addr, WAKE_PRIV, nthreads)
        [t.join(2) for t in ts]
        return "blocked=%d wake=%s res=%s alive=%s" % (blocked, w, sorted(res), sum(t.is_alive() for t in ts))
    return test


# 2: a lone FUTEX_WAIT must stay blocked until woken.
def wait_blocks():
    word = (ctypes.c_int * 1)(0); addr = ctypes.addressof(word)
    res = []
    t = threading.Thread(target=lambda: res.append(futex(addr, WAIT_PRIV, 0))); t.start()
    time.sleep(0.3); early = list(res)
    w = futex(addr, WAKE_PRIV, 1); t.join(2)
    return "early=%s wake=%s res=%s" % (early, w, res)


# 2: CMP_REQUEUE with two waiters (from probe-07).
def requeue_with_waiters(wake, requeue, val3=0):
    def test():
        word = (ctypes.c_int * 2)(0, 0); addr = ctypes.addressof(word)
        res = []
        ts = [threading.Thread(target=lambda: res.append(futex(addr, WAIT_PRIV, 0))) for _ in range(2)]
        [t.start() for t in ts]
        time.sleep(0.5)
        r = futex(addr, CMP_REQUEUE_PRIV, wake, requeue, addr + 4, val3)
        time.sleep(0.2)
        tw = futex(addr + 4, WAKE_PRIV, 2)
        sw = futex(addr, WAKE_PRIV, 2)
        [t.join(2) for t in ts]
        return "ret=%s target_wake=%s source_wake=%s rets=%s alive=%s" % (
            r, tw, sw, sorted(res), sum(t.is_alive() for t in ts))
    return test


# 3: time.sleep in a secondary thread (Python 3.13 -> clock_nanosleep).
def thread_sleep(forked):
    def test():
        if forked: fork_once()
        t0 = time.monotonic()
        t = threading.Thread(target=lambda: time.sleep(0.05)); t.start(); t.join(5)
        return "done=%s ms_ok=%s" % (not t.is_alive(), time.monotonic() - t0 >= 0.05)
    return test


def thread_sleep_two():
    t0 = time.monotonic()
    ts = [threading.Thread(target=lambda: time.sleep(0.1)) for _ in range(2)]
    [t.start() for t in ts]
    time.sleep(0.05)
    [t.join(5) for t in ts]
    return "done=%s ms_ok=%s" % (not any(t.is_alive() for t in ts), time.monotonic() - t0 >= 0.1)


for forked in (False, True):
    for n in (1, 2):
        for sl in (False, True):
            iso("wake_f%d_n%d_sleep%d" % (forked, n, sl), wake_all(n, sl, forked))
iso("wait_blocks", wait_blocks)
iso("cmp_requeue_2w_requeue2", requeue_with_waiters(0, 2))
iso("cmp_requeue_2w_wake1_requeue1", requeue_with_waiters(1, 1))
iso("cmp_requeue_2w_mismatch", requeue_with_waiters(0, 2, 5))
iso("thread_sleep_50ms", thread_sleep(False), 20)
iso("thread_sleep_50ms_after_fork", thread_sleep(True), 20)
iso("two_threads_sleep_main_sleeps", thread_sleep_two, 20)
print("GT_DONE", flush=True)
