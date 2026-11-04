"""Probe 27: small file-I/O ABI divergences - pwrite on O_APPEND, SEEK_DATA /
SEEK_HOLE, fallocate modes, FIFO open without a reader, ftruncate on a
read-only descriptor. Tests from probe-fs3.py plus edge cases, raw syscalls
where libc might hide the kernel answer.

Prints 'GT <name> <result>'. Run on Linux with GT_HOST=1 for reference values.
"""
import ctypes, errno, os, select, shutil, signal, stat, sys

HOST = os.environ.get("GT_HOST") == "1"
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
BASE = "/tmp/gt27"

SYS_LSEEK, SYS_PWRITE64, SYS_FTRUNCATE, SYS_FALLOCATE = 8, 18, 77, 285
SYS_PWRITEV, SYS_PWRITEV2 = 296, 328
RWF_APPEND, RWF_NOAPPEND = 0x10, 0x20


def sc(nr, *args):
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) if isinstance(a, int) else a for a in args])
    return -ctypes.get_errno() if r == -1 else r


def e(v):
    return ("-" + errno.errorcode.get(-v, str(-v))) if isinstance(v, int) and v < 0 else v


def run(name, fn, limit=10.0):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            res = str(fn())
        except OSError as exc:
            res = "-" + errno.errorcode.get(exc.errno, str(exc.errno))
        except Exception as exc:
            res = "EXC:%s:%s" % (type(exc).__name__, str(exc)[:60])
        os.write(w, res.encode()[:600])
        os._exit(0)
    os.close(w)
    ok, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 600).decode() if ok else "HANG"
    if not ok:
        os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("GT", name, res, flush=True)


def p(*n):
    return os.path.join(BASE, *n)


def mk(path, data=b"hello"):
    with open(path, "wb") as f:
        f.write(data)
    return path


def rd(path):
    return open(path, "rb").read()


def iov(data):
    buf = ctypes.create_string_buffer(data, len(data))
    vec = (ctypes.c_void_p * 2)(ctypes.cast(buf, ctypes.c_void_p).value, len(data))
    return buf, vec


# --- pwrite on O_APPEND -------------------------------------------------------

def t_append_pwrite():
    fd = os.open(mk(p("ap"), b"0123"), os.O_WRONLY | os.O_APPEND)
    os.pwrite(fd, b"XY", 0)
    os.close(fd)
    return rd(p("ap")).decode()


def t_append_pwrite64_raw():
    fd = os.open(mk(p("ap64"), b"0123"), os.O_WRONLY | os.O_APPEND)
    r = sc(SYS_PWRITE64, fd, b"XY", 2, 0)
    pos = os.lseek(fd, 0, os.SEEK_CUR)
    os.close(fd)
    return "r=%s data=%s pos=%d" % (e(r), rd(p("ap64")).decode(), pos)


def t_append_pwritev_raw():
    fd = os.open(mk(p("apv"), b"0123"), os.O_WRONLY | os.O_APPEND)
    keep, vec = iov(b"XY")
    r = sc(SYS_PWRITEV, fd, vec, 1, 1, 0)
    os.close(fd)
    return "r=%s data=%s" % (e(r), rd(p("apv")).decode())


def t_pwritev2_flags():
    out = []
    keep, vec = iov(b"XY")
    fd = os.open(mk(p("apn"), b"0123"), os.O_WRONLY | os.O_APPEND)
    r = sc(SYS_PWRITEV2, fd, vec, 1, 1, 0, RWF_NOAPPEND)
    out.append("noappend=%s %s" % (e(r), rd(p("apn")).decode()))
    os.close(fd)
    fd = os.open(mk(p("apa"), b"0123"), os.O_WRONLY)
    r = sc(SYS_PWRITEV2, fd, vec, 1, 0, 0, RWF_APPEND)
    out.append("append=%s %s" % (e(r), rd(p("apa")).decode()))
    r = sc(SYS_PWRITEV2, fd, vec, 1, 0, 0, RWF_APPEND | RWF_NOAPPEND)
    out.append("both=%s" % e(r))
    os.close(fd)
    return " ".join(out)


def t_pwrite_negative():
    fd = os.open(mk(p("pn"), b"0123"), os.O_WRONLY)
    r = sc(SYS_PWRITE64, fd, b"XY", 2, -1)
    os.close(fd)
    return "r=%s" % e(r)


# --- SEEK_DATA / SEEK_HOLE ------------------------------------------------------

def seeks(fd, cases):
    out = []
    for name, off, wh in cases:
        out.append("%s=%s" % (name, e(sc(SYS_LSEEK, fd, off, wh))))
    return " ".join(out)


def t_seek_data_hole():
    fd = os.open(mk(p("sh"), b"x" * 100), os.O_RDWR)
    out = []
    for name, off, wh in [("data0", 0, 3), ("hole0", 0, 4), ("data_eof", 100, 3), ("hole_past", 200, 4)]:
        try:
            out.append("%s=%d" % (name, os.lseek(fd, off, wh)))
        except OSError as x:
            out.append(name + "=" + errno.errorcode[x.errno])
    return " ".join(out)


def t_seek_data_hole_edges():
    fd = os.open(mk(p("sh2"), b"x" * 100), os.O_RDWR)
    s = seeks(fd, [("data50", 50, 3), ("hole50", 50, 4), ("data99", 99, 3), ("hole100", 100, 4),
                   ("data_neg", -1, 3), ("hole_neg", -5, 4), ("bad_whence", 0, 5)])
    os.lseek(fd, 10, os.SEEK_SET)
    sc(SYS_LSEEK, fd, 20, 4)
    pos_after_hole = os.lseek(fd, 0, os.SEEK_CUR)
    os.lseek(fd, 10, os.SEEK_SET)
    sc(SYS_LSEEK, fd, 200, 3)
    pos_after_enxio = os.lseek(fd, 0, os.SEEK_CUR)
    os.close(fd)
    return "%s pos_after_hole=%d pos_after_enxio=%d" % (s, pos_after_hole, pos_after_enxio)


def t_seek_data_empty():
    fd = os.open(mk(p("she"), b""), os.O_RDONLY)
    s = seeks(fd, [("data0", 0, 3), ("hole0", 0, 4)])
    os.close(fd)
    return s


def t_seek_data_lower():
    # An image file (copy-up candidate in Ginux, a copy in /tmp on the host).
    src = "/etc/shells"
    path = src
    if HOST:
        path = p("lower_shells"); shutil.copyfile(src, path)
    size = os.stat(path).st_size
    fd = os.open(path, os.O_RDONLY)
    s = seeks(fd, [("data0", 0, 3), ("hole0", 0, 4), ("data_eof", size, 3)])
    os.close(fd)
    return "%s size_match=%s" % (s, sc(SYS_LSEEK, os.open(path, os.O_RDONLY), 0, 4) == size)


# --- fallocate ------------------------------------------------------------------

def fcall(fd, mode, off, ln):
    return sc(SYS_FALLOCATE, fd, mode, off, ln)


def t_fallocate():
    fd = os.open(mk(p("fa"), b"abcdefgh"), os.O_RDWR)
    def call(mode, off, ln):
        return fcall(fd, mode, off, ln)
    out = ["grow=%s size=%d" % (e(call(0, 0, 32)), os.fstat(fd).st_size)]
    out.append("keep=%s size=%d" % (e(call(1, 0, 64)), os.fstat(fd).st_size))
    out.append("punch=%s data=%r" % (e(call(3, 2, 2)), os.pread(fd, 8, 0)))
    out.append("punch_nokeep=%s" % e(call(2, 0, 1)))
    out.append("bad_len=%s" % e(call(0, 0, 0)))
    out.append("zero_range=%s data=%r" % (e(call(0x10, 0, 1)), os.pread(fd, 2, 0)))
    os.close(fd)
    r = os.open(p("fa"), os.O_RDONLY); fd = r
    out.append("rdonly=%s" % e(call(0, 0, 100)))
    return " ".join(out)


def t_fallocate_keep_then_write():
    fd = os.open(mk(p("fk"), b"abcdefgh"), os.O_RDWR)
    r = fcall(fd, 1, 100, 50)
    size1 = os.fstat(fd).st_size
    os.lseek(fd, 0, os.SEEK_END)
    os.write(fd, b"Z")
    size2 = os.fstat(fd).st_size
    os.close(fd)
    return "keep_past_eof=%s size=%d after_write=%d data=%r" % (e(r), size1, size2, rd(p("fk")))


def t_fallocate_punch_edges():
    fd = os.open(mk(p("fp"), b"abcdefgh"), os.O_RDWR)
    out = []
    out.append("across_eof=%s" % e(fcall(fd, 3, 6, 20)))
    out.append("size=%d data=%r" % (os.fstat(fd).st_size, os.pread(fd, 16, 0)))
    out.append("past_eof=%s size=%d" % (e(fcall(fd, 3, 100, 10)), os.fstat(fd).st_size))
    out.append("big=%s" % e(fcall(fd, 3, 0, 1 << 20)))
    out.append("all_zero=%s size=%d" % (os.pread(fd, 16, 0) == b"\0" * 8, os.fstat(fd).st_size))
    os.close(fd)
    return " ".join(out)


def t_fallocate_precedence():
    fd = os.open(mk(p("fq"), b"abcdefgh"), os.O_RDWR)
    ro = os.open(p("fq"), os.O_RDONLY)
    rp, wp = os.pipe()
    os.makedirs(p("fqd"), exist_ok=True)
    d = os.open(p("fqd"), os.O_RDONLY)
    out = []
    for name, f, m, o, l in [
        ("unknown_bit", fd, 0x100, 0, 1), ("no_hide_stale", fd, 0x4, 0, 1),
        ("collapse", fd, 0x8, 0, 4096), ("insert", fd, 0x20, 0, 4096),
        ("unshare", fd, 0x40, 0, 1), ("keep_zero", fd, 0x11, 0, 1),
        ("collapse_keep", fd, 0x9, 0, 1), ("punch_zero", fd, 0x12, 0, 1),
        ("neg_off", fd, 0, -1, 1), ("neg_len", fd, 0, 0, -1),
        ("overflow", fd, 0, (1 << 63) - 2, 4),
        ("bad_fd", 999, 0, 0, 1), ("bad_fd_bad_len", 999, 0, 0, 0),
        ("ro_bad_len", ro, 0, 0, 0), ("ro_bad_mode", ro, 0x100, 0, 1),
        ("ro_punch_nokeep", ro, 2, 0, 1), ("ro_zero_range", ro, 0x10, 0, 1),
        ("ro_keep", ro, 1, 0, 1), ("ro_punch", ro, 3, 0, 1),
        ("pipe_w", wp, 0, 0, 1), ("pipe_r", rp, 0, 0, 1), ("dir", d, 0, 0, 1)]:
        out.append("%s=%s" % (name, e(fcall(f, m, o, l))))
    out.append("data=%r" % rd(p("fq")))
    return " ".join(out)


def t_fallocate_lower():
    # Image file opened O_RDWR: punch must copy up and zero, size unchanged.
    src = "/etc/issue"
    path = src
    if HOST:
        path = p("lower_issue"); shutil.copyfile(src if os.path.exists(src) else "/etc/shells", path)
    before = rd(path)
    fd = os.open(path, os.O_RDWR)
    keep = fcall(fd, 1, 0, 4096)
    punch = fcall(fd, 3, 0, 2)
    os.close(fd)
    after = rd(path)
    return "keep=%s punch=%s size_same=%s zeroed=%s rest_same=%s" % (
        e(keep), e(punch), len(after) == len(before), after[:2] == b"\0\0", after[2:] == before[2:])


# --- FIFO -----------------------------------------------------------------------

def t_fifo_open():
    os.mkfifo(p("ff"))
    try:
        os.open(p("ff"), os.O_WRONLY | os.O_NONBLOCK); w = "0"
    except OSError as x:
        w = errno.errorcode[x.errno]
    r = os.open(p("ff"), os.O_RDONLY | os.O_NONBLOCK)
    w2 = os.open(p("ff"), os.O_WRONLY | os.O_NONBLOCK)
    os.write(w2, b"hi")
    return "wronly_no_reader=%s read=%s mode_fifo=%s" % (w, os.read(r, 5).decode(), stat.S_ISFIFO(os.stat(p("ff")).st_mode))


def t_fifo_edges():
    os.mkfifo(p("ff2"))
    out = []
    def tryopen(name, flags):
        try:
            fd = os.open(p("ff2"), flags); out.append(name + "=0"); return fd
        except OSError as x:
            out.append(name + "=" + errno.errorcode[x.errno]); return None
    a = tryopen("rdwr_nb", os.O_RDWR | os.O_NONBLOCK)
    if a is not None:
        os.close(a)
    b = tryopen("rdonly_nb_no_writer", os.O_RDONLY | os.O_NONBLOCK)
    c = tryopen("wronly_nb_with_reader", os.O_WRONLY | os.O_NONBLOCK)
    for x in (b, c):
        if x is not None:
            os.close(x)
    tryopen("wronly_nb_after_close", os.O_WRONLY | os.O_NONBLOCK)
    return " ".join(out)


# --- ftruncate / wrong mode -----------------------------------------------------

def t_wrong_mode():
    out = []
    r = os.open(mk(p("wm")), os.O_RDONLY); w = os.open(p("wm"), os.O_WRONLY)
    for name, fn in [("write_rdonly", lambda: os.write(r, b"x")), ("read_wronly", lambda: os.read(w, 1)),
                     ("ftruncate_rdonly", lambda: os.ftruncate(r, 0)), ("pwrite_rdonly", lambda: os.pwrite(r, b"x", 0))]:
        try:
            fn(); out.append(name + "=0")
        except OSError as x:
            out.append(name + "=" + errno.errorcode[x.errno])
    return " ".join(out)


def t_ftruncate_edges():
    r = os.open(mk(p("ft"), b"abcdef"), os.O_RDONLY)
    w = os.open(p("ft"), os.O_WRONLY)
    rp, wp = os.pipe()
    os.makedirs(p("ftd"), exist_ok=True)
    d = os.open(p("ftd"), os.O_RDONLY)
    pa = os.open(p("ft"), getattr(os, "O_PATH", 0o10000000))
    out = []
    for name, fd, ln in [("ro", r, 0), ("ro_neg", r, -1), ("bad_fd", 999, 0), ("bad_fd_neg", 999, -1),
                         ("pipe_w", wp, 0), ("pipe_r", rp, 0), ("dir", d, 0), ("o_path", pa, 0),
                         ("wo_neg", w, -1), ("wo", w, 3)]:
        out.append("%s=%s" % (name, e(sc(SYS_FTRUNCATE, fd, ln))))
    out.append("size=%d" % os.fstat(w).st_size)
    return " ".join(out)


TESTS = [t_append_pwrite, t_append_pwrite64_raw, t_append_pwritev_raw, t_pwritev2_flags,
         t_pwrite_negative, t_seek_data_hole, t_seek_data_hole_edges, t_seek_data_empty,
         t_seek_data_lower, t_fallocate, t_fallocate_keep_then_write, t_fallocate_punch_edges,
         t_fallocate_precedence, t_fallocate_lower, t_fifo_open, t_fifo_edges, t_wrong_mode,
         t_ftruncate_edges]

if __name__ == "__main__":
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE)
    only = sys.argv[1:]
    for t in TESTS:
        name = t.__name__[2:]
        if not only or name in only:
            run(name, t)
    print("GT_DONE", flush=True)
