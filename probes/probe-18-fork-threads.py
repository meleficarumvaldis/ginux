import threading, os, select, signal, ctypes, time
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
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
    _, st = os.waitpid(pid, 0)
    print("GT", name, res, "status=%d" % st, flush=True)
def fork_once():
    p = os.fork()
    if p == 0: os._exit(0)
    os.waitpid(p, 0)
def scen(nthreads, main_sleep, forked):
    def test():
        if forked: fork_once()
        word = (ctypes.c_int * 2)(0, 0); addr = ctypes.addressof(word)
        def fw(): return libc.syscall(ctypes.c_long(202), ctypes.c_long(addr), ctypes.c_long(128), ctypes.c_long(0), ctypes.c_long(0), ctypes.c_long(0), ctypes.c_long(0))
        res = []
        ts = [threading.Thread(target=lambda: res.append(fw())) for _ in range(nthreads)]
        [t.start() for t in ts]
        if main_sleep: time.sleep(0.5)
        else:
            e = time.monotonic() + 0.5
            while time.monotonic() < e: pass
        w = libc.syscall(ctypes.c_long(202), ctypes.c_long(addr), ctypes.c_long(129), ctypes.c_long(nthreads), 0, 0, 0)
        [t.join(2) for t in ts]
        return "wake=%s res=%s alive=%s" % (w, res, sum(t.is_alive() for t in ts))
    return test
for forked in (False, True):
    for n in (1, 2):
        for sl in (False, True):
            iso("f%d_n%d_sleep%d" % (forked, n, sl), scen(n, sl, forked))
print("GT_DONE", flush=True)
