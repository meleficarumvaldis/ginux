"""Probe for patch 18: musl pthread_create (raw clone ABI) in Ginux.

Each test runs in a forked child with a watchdog. GT <name> <result>.
Linux reference: GT_HOST=1 python3 probe-18.py
"""
import threading, os, select, signal, time
def iso(name, fn, limit=15):
    r, w = os.pipe(); pid = os.fork()
    if pid == 0:
        os.close(r)
        try: res = str(fn())
        except Exception as e: res = "EXC:%s:%s" % (type(e).__name__, str(e)[:60])
        os.write(w, res.encode()); os._exit(0)
    os.close(w)
    ok, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 200).decode() if ok else "HANG"
    if not ok: os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("GT", name, res, flush=True)
def one_thread():
    out = []
    t = threading.Thread(target=lambda: out.append(threading.get_native_id() != os.getpid())); t.start(); t.join()
    return out
def four_threads_counter():
    n = [0]; lock = threading.Lock()
    def work():
        for _ in range(1000):
            with lock: n[0] += 1
    ts = [threading.Thread(target=work) for _ in range(4)]
    [t.start() for t in ts]; [t.join() for t in ts]
    return n[0]
def condvar_broadcast():
    c = threading.Condition(); ready = [0]; go = [False]
    def waiter():
        with c:
            ready[0] += 1; c.notify_all()
            while not go[0]: c.wait()
    ts = [threading.Thread(target=waiter) for _ in range(3)]
    [t.start() for t in ts]
    with c:
        while ready[0] < 3: c.wait()
        go[0] = True; c.notify_all()
    [t.join(5) for t in ts]
    return all(not t.is_alive() for t in ts)
iso("thread_start", one_thread)
iso("threads_lock_counter", four_threads_counter, 30)
iso("condvar_broadcast_3_waiters", condvar_broadcast, 30)
def thread_local_and_tid():
    # Each thread gets its own TLS (fs_base = clone tls argument) and TID
    # (CLONE_PARENT_SETTID / CLONE_CHILD_CLEARTID, joined via futex).
    loc = threading.local(); loc.v = "main"; res = []
    def work(i):
        loc.v = i; res.append((loc.v == i, threading.get_native_id()))
    ts = [threading.Thread(target=work, args=(i,)) for i in range(3)]
    [t.start() for t in ts]; [t.join() for t in ts]
    tids = {r[1] for r in res}
    return all(r[0] for r in res) and len(tids) == 3 and os.getpid() not in tids and loc.v == "main"
def thread_sleep():
    # Separate finding (not fixed by patch 18): on cpu=1 a sleeping secondary
    # thread hung the whole domain. Run last; it cannot hide other rows.
    t = threading.Thread(target=lambda: time.sleep(0.05)); t.start(); t.join(5)
    return not t.is_alive()
iso("thread_local_tls_and_tid", thread_local_and_tid, 30)
iso("thread_sleep_50ms", thread_sleep, 20)
print("GT_DONE", flush=True)
