"""Probe 29: AF_UNIX sockets bound to a filesystem path.

bind() on a pathname must create a socket inode (S_IFSOCK) where the path
leads, EADDRINUSE when anything already exists there, ENOENT for a missing
parent; connect() by path reaches the bound socket; close() keeps the node,
unlink() removes it; abstract names create no file.

Prints 'GT <name> <result>'. Run on Linux with GT_HOST=1 (the image directory
is then a copy in /tmp).
"""
import ctypes, errno, os, select, signal, socket, stat, struct, sys

HOST = os.environ.get("GT_HOST") == "1"
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
BASE = "/tmp/gt29"
SYS_BIND, SYS_GETSOCKNAME, SYS_GETDENTS64 = 49, 51, 217


def sc(nr, *args):
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) if isinstance(a, int) else a for a in args])
    return -ctypes.get_errno() if r == -1 else r


def e(v):
    return ("-" + errno.errorcode.get(-v, str(-v))) if isinstance(v, int) and v < 0 else v


def err(fn):
    try:
        r = fn()
        return "0" if r is None or isinstance(r, int) else str(r)
    except OSError as x:
        return errno.errorcode.get(x.errno, str(x.errno))


def run(name, fn, limit=15.0):
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
        os.write(w, res.encode()[:400])
        os._exit(0)
    os.close(w)
    ok, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 400).decode() if ok else "HANG"
    if not ok:
        os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("GT", name, res, flush=True)


def p(*n):
    return os.path.join(BASE, *n)


def lower_dir():
    if not HOST:
        return "/usr/local/lib/python3.13/email"
    d = "/tmp/gt29_lower/email"
    if not os.path.isdir(d):
        import shutil
        shutil.copytree(os.path.dirname(os.__file__) + "/email", d)
    return d


def us(kind=socket.SOCK_STREAM):
    return socket.socket(socket.AF_UNIX, kind)


def kind(path):
    try:
        m = os.lstat(path).st_mode
    except OSError as x:
        return errno.errorcode.get(x.errno)
    return "sock" if stat.S_ISSOCK(m) else "reg" if stat.S_ISREG(m) else "dir" if stat.S_ISDIR(m) else oct(m)


def dtype(directory, name):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    buf = ctypes.create_string_buffer(8192)
    n = sc(SYS_GETDENTS64, fd, buf, 8192)
    os.close(fd)
    off = 0
    while off < n:
        reclen = struct.unpack_from("H", buf.raw, off + 16)[0]
        t = buf.raw[off + 18]
        nm = buf.raw[off + 19:off + reclen].split(b"\0")[0].decode()
        if nm == name:
            return t
        off += reclen
    return "missing"


def raw_bind(s, path_bytes, addrlen=None):
    sa = struct.pack("H", socket.AF_UNIX) + path_bytes
    sa = sa + b"\0" * (112 - len(sa))
    buf = ctypes.create_string_buffer(sa, len(sa))
    return sc(SYS_BIND, s.fileno(), buf, addrlen if addrlen is not None else 2 + len(path_bytes))


def raw_name(s):
    buf = ctypes.create_string_buffer(112)
    ln = ctypes.c_int(112)
    r = sc(SYS_GETSOCKNAME, s.fileno(), buf, ctypes.byref(ln))
    return r, ln.value, buf.raw[2:ln.value]


def roundtrip(path, connect_path=None):
    srv = us(); srv.bind(path); srv.listen(4)
    cli = us(); cli.connect(connect_path or path); cli.sendall(b"ping")
    conn, _ = srv.accept(); got = conn.recv(16); conn.sendall(b"pong")
    return got.decode() + "/" + cli.recv(16).decode()


# ------------------------------------------------------------------ tests
def t_bind_only():
    s = us()
    return "bind=%s" % err(lambda: s.bind(p("only")))


def t_bind_node():
    s = us(); s.bind(p("node"))
    st = os.lstat(p("node"))
    return "kind=%s perm=%o listed=%s dtype=%s size=%d" % (
        kind(p("node")), st.st_mode & 0o7777, "node" in os.listdir(BASE), dtype(BASE, "node"), st.st_size)


def t_bind_umask():
    old = os.umask(0o027)
    s = us(); s.bind(p("um"))
    os.umask(old)
    return "perm=%o" % (os.lstat(p("um")).st_mode & 0o7777)


def t_bind_existing():
    s = us(); s.bind(p("ex_sock"))
    open(p("ex_reg"), "w").close(); os.mkdir(p("ex_dir")); os.symlink(p("nowhere"), p("ex_dangling"))
    out = []
    for n in ("ex_sock", "ex_reg", "ex_dir", "ex_dangling"):
        out.append("%s=%s" % (n, err(lambda: us().bind(p(n)))))
    out.append("reg_kind=%s" % kind(p("ex_reg")))
    return " ".join(out)


def t_bind_twice():
    s = us(); s.bind(p("tw1"))
    r = err(lambda: s.bind(p("tw2")))
    exist = err(lambda: us().bind(p("tw1")))
    return "second_path=%s created=%s same_path_other_sock=%s" % (r, kind(p("tw2")), exist)


def t_bind_missing_dir():
    return "missing_parent=%s parent_is_file=%s" % (
        err(lambda: us().bind(p("nodir", "s"))),
        err(lambda: (open(p("pf"), "w").close(), us().bind(p("pf", "s")))[1]))


def t_bind_image_dir():
    d = lower_dir(); path = os.path.join(d, "gt29.sock")
    s = us(); r = err(lambda: s.bind(path))
    k = kind(path); listed = "gt29.sock" in os.listdir(d)
    rt = "-"
    if r == "0":
        s.listen(1)
        rt = err(lambda: (lambda c: (c.connect(path), "ok")[1])(us()))
    os.unlink(path) if k == "sock" else None
    return "bind=%s kind=%s listed=%s connect=%s gone=%s" % (r, k, listed, rt, kind(path))


def t_bind_relative():
    os.mkdir(p("rel")); old = os.getcwd(); os.chdir(p("rel"))
    s = us(); s.bind("r.sock"); s.listen(2)
    name = s.getsockname()
    os.chdir(old)
    c = us(); c.connect(p("rel", "r.sock")); c.sendall(b"x")
    conn, _ = s.accept()
    return "kind=%s name=%s abs_connect=%s" % (kind(p("rel", "r.sock")), name, conn.recv(4).decode())


def t_abstract():
    before = sorted(os.listdir(BASE)); cwd_before = sorted(os.listdir("."))
    s = us(); s.bind("\0gt29abstract"); s.listen(2)
    c = us(); c.connect("\0gt29abstract"); c.sendall(b"a")
    conn, _ = s.accept()
    return "recv=%s base_unchanged=%s cwd_unchanged=%s name=%r" % (
        conn.recv(4).decode(), sorted(os.listdir(BASE)) == before,
        sorted(os.listdir(".")) == cwd_before, s.getsockname())


def t_roundtrip():
    return roundtrip(p("rt"))


def t_fork_child_connect():
    srv = us(); srv.bind(p("fk")); srv.listen(2)
    pid = os.fork()
    if pid == 0:
        try:
            c = us(); c.connect(p("fk")); c.sendall(b"child"); c.recv(8)
            os._exit(0)
        except OSError as x:
            os._exit(100 + x.errno % 100)
    conn, _ = srv.accept(); got = conn.recv(16); conn.sendall(b"ok")
    _, status = os.waitpid(pid, 0)
    return "parent_got=%s child_exit=%d" % (got.decode(), os.WEXITSTATUS(status))


def t_close_keeps_node():
    s = us(); s.bind(p("ck")); s.listen(1); s.close()
    return "after_close=%s connect=%s rebind=%s" % (
        kind(p("ck")), err(lambda: us().connect(p("ck"))), err(lambda: us().bind(p("ck"))))


def t_unlink_rebind():
    s = us(); s.bind(p("ul")); s.listen(1)
    os.unlink(p("ul"))
    gone = kind(p("ul")); conn_gone = err(lambda: us().connect(p("ul")))
    s2 = us(); r = err(lambda: s2.bind(p("ul"))); s2.listen(1)
    c = us(); c.connect(p("ul"))
    a, _ = s2.accept()
    # select, not setblocking: Python's setblocking uses ioctl(FIONBIO).
    old_pending = "readable" if select.select([s], [], [], 0)[0] else "empty"
    return "after_unlink=%s connect_gone=%s rebind=%s new_reaches_new=1 old_listener=%s" % (
        gone, conn_gone, r, old_pending)


def t_connect_errors():
    open(p("ce_reg"), "w").close()
    out = ["missing=%s" % err(lambda: us().connect(p("ce_missing")))]
    out.append("regular=%s" % err(lambda: us().connect(p("ce_reg"))))
    out.append("missing_dir=%s" % err(lambda: us().connect(p("ce_nodir", "x"))))
    out.append("abstract_missing=%s" % err(lambda: us().connect("\0gt29nobody")))
    s = us(); s.bind(p("ce_unlistened"))
    out.append("not_listening=%s" % err(lambda: us().connect(p("ce_unlistened"))))
    return " ".join(out)


def t_open_node():
    s = us(); s.bind(p("on"))
    o_path = getattr(os, "O_PATH", 0o10000000)
    rp = err(lambda: os.close(os.open(p("on"), o_path)))
    return "open_rdonly=%s open_path=%s" % (err(lambda: os.open(p("on"), os.O_RDONLY)), rp)


def t_sun_path_len():
    out = []
    name108 = (BASE + "/" + "L" * (108 - len(BASE) - 1)).encode()
    s = us(); r = raw_bind(s, name108, 110)
    out.append("len108_nonul=%s kind=%s" % (e(r) if r else 0, kind(name108.decode())))
    s2 = us(); out.append("addrlen111=%s" % e(raw_bind(s2, name108 + b"X", 111)))
    s3 = us(); out.append("addrlen2_autobind=%s" % e(raw_bind(s3, b"", 2)))
    r, ln, nm = raw_name(s3)
    out.append("autoname_len=%d abstract=%s" % (ln, nm[:1] == b"\0"))
    return " ".join(out)


def t_getsockname_path():
    s = us(); s.bind(p("gn"))
    c = us(); s.listen(1); c.connect(p("gn"))
    a, _ = s.accept()
    return "name=%s peer=%s" % (s.getsockname(), c.getpeername())


def t_dgram_path():
    srv = us(socket.SOCK_DGRAM); srv.bind(p("dg"))
    cli = us(socket.SOCK_DGRAM)
    r1 = err(lambda: cli.connect(p("dg")))
    r2 = err(lambda: cli.send(b"dg1"))
    ready = select.select([srv], [], [], 2)[0]
    got = err(lambda: srv.recv(16).decode()) if ready else "timeout"
    return "kind=%s connect=%s send=%s recv=%s" % (kind(p("dg")), r1, r2, got)


def t_type_mismatch():
    s = us(); s.bind(p("tm")); s.listen(1)
    return "dgram_to_stream=%s" % err(lambda: us(socket.SOCK_DGRAM).connect(p("tm")))


def t_mknod_sock():
    r = err(lambda: os.mknod(p("mk"), stat.S_IFSOCK | 0o600))
    return "mknod=%s kind=%s connect=%s" % (r, kind(p("mk")), err(lambda: us().connect(p("mk"))))


def t_rename_node():
    s = us(); s.bind(p("rn_old")); s.listen(1)
    os.rename(p("rn_old"), p("rn_new"))
    return "old=%s new=%s connect_new=%s connect_old=%s" % (
        kind(p("rn_old")), kind(p("rn_new")), err(lambda: us().connect(p("rn_new"))),
        err(lambda: us().connect(p("rn_old"))))


def t_probe_fs4_unix_socket_file():
    s = us(); s.bind(p("sock"))
    st = os.lstat(p("sock"))
    again = us()
    rebind = err(lambda: again.bind(p("sock")))
    return "is_sock=%s rebind=%s listed=%s" % (stat.S_ISSOCK(st.st_mode), rebind, "sock" in os.listdir(BASE))


def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True); os.makedirs(BASE)
    if HOST:
        shutil.rmtree("/tmp/gt29_lower", ignore_errors=True)
    for n in sorted(k for k in globals() if k.startswith("t_")):
        run(n[2:], globals()[n])
    print("GT_DONE", flush=True)


if __name__ == "__main__":
    main()
