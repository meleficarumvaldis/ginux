"""Probe 17: a synchronous CPU fault in a non-init process kills only that process.

Each test forks a child that faults; the parent reports the wait status.
Run on Linux for reference (GT_HOST=1 python3 probe-17.py) and inside Ginux.
Optional argv[1] selects one test by name; default runs all.
"""
import ctypes, errno, mmap, os, signal, sys

libc = ctypes.CDLL(None, use_errno=True)
HOST = os.environ.get("GT_HOST") == "1"
ONLY = sys.argv[1] if len(sys.argv) > 1 else None
BASE = os.environ.get("GT_BASE", "/tmp/gt17" if HOST else "/root/gt17")
os.makedirs(BASE, exist_ok=True)


def status(st):
    if os.WIFSIGNALED(st):
        return "signaled sig=%d core=%d" % (os.WTERMSIG(st), int(os.WCOREDUMP(st)))
    if os.WIFEXITED(st):
        return "exit=%d" % os.WEXITSTATUS(st)
    return "raw=%#x" % st


def child(fn):
    pid = os.fork()
    if pid == 0:
        try:
            fn()
        except BaseException as exc:
            print("GT child_exception", type(exc).__name__, str(exc)[:60], flush=True)
            os._exit(98)
        os._exit(0)
    _, st = os.waitpid(pid, 0)
    return status(st)


def run(name, fn):
    if ONLY and ONLY != name:
        return
    try:
        print("GT", name, fn(), flush=True)
    except Exception as exc:
        print("GT", name, "EXC:" + type(exc).__name__ + ":" + str(exc)[:60], flush=True)


def segv():
    ctypes.memset(16, 0, 1)


def code(raw):
    # Executable anonymous page holding `raw` followed by ret.
    # Write the page, then flip it to read+exec (Ginux refuses W+X mappings).
    page = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    page.write(raw + b"\xc3")
    address = ctypes.addressof(ctypes.c_char.from_buffer(page))
    if libc.mprotect(ctypes.c_void_p(address), 4096, mmap.PROT_READ | mmap.PROT_EXEC) != 0:
        raise OSError(ctypes.get_errno(), "mprotect")
    return ctypes.CFUNCTYPE(None)(address), page


def execute(raw):
    fn, _page = code(raw)
    fn()


class SigAction(ctypes.Structure):
    _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_ulong * 16),
                ("flags", ctypes.c_int), ("restorer", ctypes.c_void_p)]


# Raw handler (no libffi closure): exit_group(40 + signo).
HANDLER_CODE = b"\x83\xc7\x28\xb8\xe7\x00\x00\x00\x0f\x05"


def with_handler(sig, fault):
    def body():
        handler, page = code(HANDLER_CODE)
        action = SigAction()
        action.handler = ctypes.cast(handler, ctypes.c_void_p).value
        if libc.sigaction(sig, ctypes.byref(action), None) != 0:
            os._exit(99)
        fault()
    return body


def blocked(sig, fault):
    def body():
        signal.pthread_sigmask(signal.SIG_BLOCK, {sig})
        fault()
    return body


def ignored(sig, fault):
    def body():
        signal.signal(sig, signal.SIG_IGN)
        fault()
    return body


def grandchild():
    print("GT grandchild_segv_inner", child(segv), flush=True)


def exec_fault():
    os.execv(sys.executable, [sys.executable, "-c", "import ctypes; ctypes.memset(16, 0, 1)"])


def faulthandler_child():
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.dup2(w, 2)
        import faulthandler
        faulthandler.enable()
        segv()
        os._exit(0)
    os.close(w)
    text = b""
    while True:
        chunk = os.read(r, 4096)
        if not chunk:
            break
        text += chunk
    _, st = os.waitpid(pid, 0)
    return "%s handler_ran=%s" % (status(st), b"Segmentation fault" in text)


def big_pwrite():
    fd = os.open(BASE + "/lo", os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.pwrite(fd, b"Z", (1 << 32) + 5)
        result = "size=%d" % os.fstat(fd).st_size
    except OSError as exc:
        result = "-" + errno.errorcode[exc.errno]
    os.close(fd)
    os.unlink(BASE + "/lo")
    print("GT pwrite_4g_child_result", result, flush=True)


UD2 = b"\x0f\x0b"
DIV0 = b"\x31\xc9\xf7\xf1"  # xor ecx, ecx; div ecx
GP = b"\x48\xb8" + (1 << 63).to_bytes(8, "little") + b"\x8b\x00"  # non-canonical load
INT3 = b"\xcc"

run("child_segv", lambda: child(segv))
run("grandchild_segv", lambda: child(grandchild))
run("child_exec_segv", lambda: child(exec_fault))
run("child_ud_sigill", lambda: child(lambda: execute(UD2)))
run("child_de_sigfpe", lambda: child(lambda: execute(DIV0)))
run("child_gp_sigsegv", lambda: child(lambda: execute(GP)))
run("child_int3_sigtrap", lambda: child(lambda: execute(INT3)))
run("child_segv_handler", lambda: child(with_handler(signal.SIGSEGV, segv)))
run("child_ill_handler", lambda: child(with_handler(signal.SIGILL, lambda: execute(UD2))))
run("child_fpe_handler", lambda: child(with_handler(signal.SIGFPE, lambda: execute(DIV0))))
run("child_gp_handler", lambda: child(with_handler(signal.SIGSEGV, lambda: execute(GP))))
run("child_segv_blocked", lambda: child(blocked(signal.SIGSEGV, segv)))
run("child_segv_ignored", lambda: child(ignored(signal.SIGSEGV, segv)))
run("child_faulthandler", faulthandler_child)
run("pwrite_4g_child", lambda: child(big_pwrite))
print("GT parent_alive", os.getpid() > 0, flush=True)
print("GT_DONE", flush=True)
