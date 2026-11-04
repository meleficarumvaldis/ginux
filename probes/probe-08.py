"""Probe for issue 08: MAP_SHARED + PROT_WRITE on a descriptor not opened for writing.

Run on Linux (GT_HOST=1 python3 probe-08.py) and inside Ginux; compare the GT lines.
Each test runs in a forked child so a fault cannot abort the run.
"""
import ctypes, errno, os, select, signal

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
HOST = os.environ.get("GT_HOST") == "1"
NR = dict(mmap=9, mprotect=10, munmap=11, msync=26, memfd_create=319)
PROT_R, PROT_W = 1, 2
MAP_SHARED, MAP_PRIVATE = 1, 2
MS_SYNC = 4
PAGE = 4096


def sc(name, *args):
    a = [ctypes.c_long(x) if isinstance(x, int) else x for x in args]
    r = libc.syscall(ctypes.c_long(NR[name]), *a)
    if r == -1:
        e = ctypes.get_errno()
        return "-" + errno.errorcode.get(e, str(e))
    return r


def addr_or(r):
    return "addr" if isinstance(r, int) and r > 0 else r


def out(name, value):
    print("GT", name, value, flush=True)


def run_isolated(name, fn, limit=8.0):
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
    data = b""
    ready, _, _ = select.select([r], [], [], limit)
    if ready:
        while True:
            chunk = os.read(r, 4096)
            if not chunk:
                break
            data += chunk
    os.close(r)
    if not ready:
        os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    if not ready:
        out(name, "TIMEOUT")
    elif os.WIFSIGNALED(status) and not data:
        out(name, "SIG%d" % os.WTERMSIG(status))
    else:
        out(name, data.decode())


os.makedirs("/tmp/gt", exist_ok=True)
VICTIM = "/tmp/gt/victim08"


def reset_victim():
    if os.path.exists(VICTIM):
        os.chmod(VICTIM, 0o644)
    with open(VICTIM, "wb") as f:
        f.write(b"ORIG" + b"." * (PAGE - 4))
    os.chmod(VICTIM, 0o444)


def head():
    with open(VICTIM, "rb") as f:
        return f.read(4)


def shared_rw_rdonly():
    reset_victim()
    fd = os.open(VICTIM, os.O_RDONLY)
    r = sc("mmap", 0, PAGE, PROT_R | PROT_W, MAP_SHARED, fd, 0)
    if isinstance(r, int) and r > 0:
        ctypes.memmove(r, b"PWN!", 4)
        sc("msync", r, PAGE, MS_SYNC)
        sc("munmap", r, PAGE)
    return "%s file=%s" % (addr_or(r), head())


def shared_r_then_mprotect_rw():
    reset_victim()
    fd = os.open(VICTIM, os.O_RDONLY)
    r = sc("mmap", 0, PAGE, PROT_R, MAP_SHARED, fd, 0)
    if not (isinstance(r, int) and r > 0):
        return "mmap=%s" % r
    m = sc("mprotect", r, PAGE, PROT_R | PROT_W)
    if m == 0:
        ctypes.memmove(r, b"PWN!", 4)
        sc("msync", r, PAGE, MS_SYNC)
    sc("munmap", r, PAGE)
    return "mprotect=%s file=%s" % (m, head())


def shared_r_fork_child_mprotect_rw():
    reset_victim()
    fd = os.open(VICTIM, os.O_RDONLY)
    r = sc("mmap", 0, PAGE, PROT_R, MAP_SHARED, fd, 0)
    if not (isinstance(r, int) and r > 0):
        return "mmap=%s" % r
    rp, wp = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.write(wp, str(sc("mprotect", r, PAGE, PROT_R | PROT_W)).encode())
        os._exit(0)
    os.close(wp)
    res = os.read(rp, 64).decode()
    os.waitpid(pid, 0)
    return "child_mprotect=%s" % res


def private_rw_rdonly():
    reset_victim()
    fd = os.open(VICTIM, os.O_RDONLY)
    r = sc("mmap", 0, PAGE, PROT_R | PROT_W, MAP_PRIVATE, fd, 0)
    if not (isinstance(r, int) and r > 0):
        return "mmap=%s" % r
    ctypes.memmove(r, b"PWN!", 4)
    seen = ctypes.string_at(r, 4)
    sc("msync", r, PAGE, MS_SYNC)
    sc("munmap", r, PAGE)
    return "addr seen=%s file=%s" % (seen, head())


def shared_rw_rdwr():
    reset_victim()
    os.chmod(VICTIM, 0o644)
    fd = os.open(VICTIM, os.O_RDWR)
    r = sc("mmap", 0, PAGE, PROT_R | PROT_W, MAP_SHARED, fd, 0)
    if not (isinstance(r, int) and r > 0):
        return "mmap=%s" % r
    ctypes.memmove(r, b"NEW!", 4)
    s = sc("msync", r, PAGE, MS_SYNC)
    sc("munmap", r, PAGE)
    return "addr msync=%s file=%s" % (s, head())


def shared_r_rdwr_mprotect_rw():
    reset_victim()
    os.chmod(VICTIM, 0o644)
    fd = os.open(VICTIM, os.O_RDWR)
    r = sc("mmap", 0, PAGE, PROT_R, MAP_SHARED, fd, 0)
    if not (isinstance(r, int) and r > 0):
        return "mmap=%s" % r
    m = sc("mprotect", r, PAGE, PROT_R | PROT_W)
    if m == 0:
        ctypes.memmove(r, b"UPG!", 4)
    sc("munmap", r, PAGE)
    return "mprotect=%s file=%s" % (m, head())


def memfd_reopened_rdonly():
    fd = sc("memfd_create", ctypes.c_char_p(b"gt08"), 0)
    if not isinstance(fd, int) or fd < 0:
        return "memfd=%s" % fd
    os.write(fd, b"ORIG" + b"." * (PAGE - 4))
    ro = os.open("/proc/self/fd/%d" % fd, os.O_RDONLY)
    r = sc("mmap", 0, PAGE, PROT_R | PROT_W, MAP_SHARED, ro, 0)
    return "%s" % addr_or(r)


def shm_rdonly():
    path = "/dev/shm/gt08"
    if not os.path.isdir("/dev/shm"):
        return "no-dev-shm"
    with open(path, "wb") as f:
        f.write(b"ORIG" + b"." * (PAGE - 4))
    fd = os.open(path, os.O_RDONLY)
    r = sc("mmap", 0, PAGE, PROT_R | PROT_W, MAP_SHARED, fd, 0)
    os.unlink(path)
    return "%s" % addr_or(r)


def image_file_rdonly():
    # A file from the container image (immutable rootfs layer in Ginux).
    fd = os.open("/etc/os-release", os.O_RDONLY)
    r = sc("mmap", 0, PAGE, PROT_R | PROT_W, MAP_SHARED, fd, 0)
    return "%s" % addr_or(r)


def image_file_shared_r_mprotect_rw():
    fd = os.open("/etc/os-release", os.O_RDONLY)
    r = sc("mmap", 0, PAGE, PROT_R, MAP_SHARED, fd, 0)
    if not (isinstance(r, int) and r > 0):
        return "mmap=%s" % r
    return "mprotect=%s" % sc("mprotect", r, PAGE, PROT_R | PROT_W)


def wronly_shared_rw():
    reset_victim()
    os.chmod(VICTIM, 0o644)
    fd = os.open(VICTIM, os.O_WRONLY)
    return addr_or(sc("mmap", 0, PAGE, PROT_R | PROT_W, MAP_SHARED, fd, 0))


run_isolated("mmap_shared_rw_rdonly_fd", shared_rw_rdonly)
run_isolated("mmap_shared_r_rdonly_then_mprotect_rw", shared_r_then_mprotect_rw)
run_isolated("mmap_shared_r_rdonly_fork_child_mprotect_rw", shared_r_fork_child_mprotect_rw)
run_isolated("mmap_private_rw_rdonly_fd", private_rw_rdonly)
run_isolated("mmap_shared_rw_rdwr_fd", shared_rw_rdwr)
run_isolated("mmap_shared_r_rdwr_then_mprotect_rw", shared_r_rdwr_mprotect_rw)
run_isolated("mmap_shared_rw_memfd_reopened_rdonly", memfd_reopened_rdonly)
run_isolated("mmap_shared_rw_dev_shm_rdonly", shm_rdonly)
run_isolated("mmap_shared_rw_image_file_rdonly", image_file_rdonly)
run_isolated("mmap_shared_r_image_file_then_mprotect_rw", image_file_shared_r_mprotect_rw)
run_isolated("mmap_shared_rw_wronly_fd", wronly_shared_rw)
print("GT_DONE", flush=True)
