"""Probe 26: renameat2(RENAME_EXCHANGE) (syscall 316, flag 2).

Prints 'GT <name> <result>'. Run it on Linux with GT_HOST=1: "lower" entries
are then copies in /tmp instead of image files, so nothing on the host changes.
"""
import ctypes, errno, os, select, signal, sys

HOST = os.environ.get("GT_HOST") == "1"
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
BASE = "/tmp/gtx26"
NOREPLACE, EXCHANGE, WHITEOUT = 1, 2, 4


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
        os.write(w, res.encode()[:300])
        os._exit(0)
    os.close(w)
    ok, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 300).decode() if ok else "HANG"
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
    with open(path, "rb") as f:
        return f.read().decode(errors="replace")


def x(a, b, flags=EXCHANGE):
    return e(sc(316, -100, a.encode(), -100, b.encode(), flags))


def fresh(name):
    d = p(name)
    os.makedirs(d)
    return d


def lower_file():
    if not HOST:
        return "/etc/os-release"
    dst = "/tmp/gtx26_lower/os-release"
    os.makedirs("/tmp/gtx26_lower", exist_ok=True)
    mk(dst, open("/etc/os-release", "rb").read())
    return dst


def lower_dir():
    if not HOST:
        return "/usr/local/lib/python3.13/json"
    d = "/tmp/gtx26_lower/json"
    if not os.path.isdir(d):
        import shutil
        shutil.copytree(os.path.dirname(os.__file__) + "/json", d)
    return d


def lower_copied_up():
    # An image file that has already been copied up by a write.
    if not HOST:
        return "/etc/shells"
    dst = "/tmp/gtx26_lower/shells"
    os.makedirs("/tmp/gtx26_lower", exist_ok=True)
    mk(dst, open("/etc/shells", "rb").read())
    return dst


def t_flags():
    d = fresh("flags"); mk(os.path.join(d, "a"), b"A"); mk(os.path.join(d, "b"), b"B")
    a, b = os.path.join(d, "a"), os.path.join(d, "b")
    return "noreplace_exchange=%s whiteout_exchange=%s unknown=%s untouched=%s" % (
        x(a, b, NOREPLACE | EXCHANGE), x(a, b, WHITEOUT | EXCHANGE), x(a, b, 8),
        rd(a) + rd(b))


def t_file_file():
    d = fresh("ff"); a = mk(os.path.join(d, "a"), b"one"); b = mk(os.path.join(d, "b"), b"two")
    ia, ib = os.stat(a).st_ino, os.stat(b).st_ino
    r = x(a, b)
    return "ret=%s data=%s/%s inodes_swapped=%s" % (
        r, rd(a), rd(b), (os.stat(a).st_ino, os.stat(b).st_ino) == (ib, ia))


def t_dir_dir():
    d = fresh("dd"); a = os.path.join(d, "a"); b = os.path.join(d, "b")
    os.makedirs(os.path.join(a, "sa")); mk(os.path.join(a, "sa", "f"), b"deep-a")
    os.mkdir(b); mk(os.path.join(b, "fb"), b"b-child")
    r = x(a, b)
    return "ret=%s a=%s b=%s deep=%s" % (
        r, sorted(os.listdir(a)), sorted(os.listdir(b)), rd(os.path.join(b, "sa", "f")))


def t_dir_file():
    d = fresh("df"); a = os.path.join(d, "dir"); os.mkdir(a); mk(os.path.join(a, "x"), b"X")
    f = mk(os.path.join(d, "file"), b"F")
    r = x(a, f)
    return "ret=%s file_is_dir=%s child=%s dir_is_file=%s data=%s" % (
        r, os.path.isdir(f), rd(os.path.join(f, "x")), os.path.isfile(a), rd(a))


def t_missing_source():
    d = fresh("ms"); b = mk(os.path.join(d, "b"), b"B")
    return "ret=%s target_kept=%s" % (x(os.path.join(d, "nope"), b), rd(b))


def t_missing_target():
    d = fresh("mt"); a = mk(os.path.join(d, "a"), b"A")
    r = x(a, os.path.join(d, "nope"))
    return "ret=%s source_kept=%s created=%s" % (r, rd(a), os.path.exists(os.path.join(d, "nope")))


def t_missing_both():
    d = fresh("mb")
    return "ret=%s" % x(os.path.join(d, "n1"), os.path.join(d, "n2"))


def t_missing_parent():
    d = fresh("mp"); a = mk(os.path.join(d, "a"), b"A")
    return "ret=%s" % x(a, os.path.join(d, "nodir", "b"))


def t_self():
    d = fresh("self"); a = mk(os.path.join(d, "a"), b"A")
    os.mkdir(os.path.join(d, "dir"))
    return "file=%s dir=%s data=%s" % (x(a, a), x(os.path.join(d, "dir"), os.path.join(d, "dir")), rd(a))


def t_hardlinks_same_inode():
    d = fresh("hl"); a = mk(os.path.join(d, "a"), b"A"); b = os.path.join(d, "b")
    try:
        os.link(a, b)
    except OSError as exc:
        return "link=-" + errno.errorcode.get(exc.errno, "?")
    return "ret=%s both=%s" % (x(a, b), os.path.exists(a) and os.path.exists(b))


def t_cross_directory():
    d = fresh("cd"); os.makedirs(os.path.join(d, "p1", "q")); os.mkdir(os.path.join(d, "p2"))
    a = mk(os.path.join(d, "p1", "q", "a"), b"from-p1"); b = mk(os.path.join(d, "p2", "b"), b"from-p2")
    r = x(a, b)
    return "ret=%s a=%s b=%s" % (r, rd(a), rd(b))


def t_parent_nlink_dir_file():
    d = fresh("nl"); p1 = os.path.join(d, "p1"); p2 = os.path.join(d, "p2")
    os.mkdir(p1); os.mkdir(p2)
    sub = os.path.join(p1, "sub"); os.mkdir(sub); mk(os.path.join(sub, "c"), b"C")
    f = mk(os.path.join(p2, "f"), b"F")
    before = (os.stat(p1).st_nlink, os.stat(p2).st_nlink)
    r = x(sub, f)
    after = (os.stat(p1).st_nlink, os.stat(p2).st_nlink)
    dotdot = os.stat(os.path.join(f, "..")).st_ino == os.stat(p2).st_ino
    return "ret=%s nlink_before=%d/%d nlink_after=%d/%d dotdot_is_p2=%s child=%s" % (
        r, before[0], before[1], after[0], after[1], dotdot, rd(os.path.join(f, "c")))


def t_into_own_subtree():
    d = fresh("st"); a = os.path.join(d, "a"); os.makedirs(os.path.join(a, "b", "c"))
    return "src_ancestor=%s dst_ancestor=%s still=%s" % (
        x(a, os.path.join(a, "b", "c")), x(os.path.join(a, "b", "c"), a),
        os.path.isdir(os.path.join(a, "b", "c")))


def t_open_fd_follows_inode():
    d = fresh("fd"); a = mk(os.path.join(d, "a"), b"one"); b = mk(os.path.join(d, "b"), b"two")
    fd = os.open(a, os.O_RDONLY)
    r = x(a, b)
    data = os.read(fd, 10).decode(); os.close(fd)
    return "ret=%s fd_reads=%s path_a=%s" % (r, data, rd(a))


def t_cwd_follows_directory():
    d = fresh("cw"); a = os.path.join(d, "a"); b = os.path.join(d, "b"); os.mkdir(a); os.mkdir(b)
    mk(os.path.join(a, "here"), b"H")
    os.chdir(a)
    r = x(a, b)
    return "ret=%s cwd=%s relative=%s" % (r, os.getcwd()[len(d):], rd("here"))


def t_relative_dirfd():
    d = fresh("rel"); mk(os.path.join(d, "a"), b"A"); os.mkdir(os.path.join(d, "s")); mk(os.path.join(d, "s", "b"), b"B")
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    sfd = os.open(os.path.join(d, "s"), os.O_RDONLY | os.O_DIRECTORY)
    r = e(sc(316, fd, b"a", sfd, b"b", EXCHANGE))
    os.close(fd); os.close(sfd)
    return "ret=%s a=%s s/b=%s" % (r, rd(os.path.join(d, "a")), rd(os.path.join(d, "s", "b")))


def t_lower_file():
    lf = lower_file(); before = rd(lf)
    up = mk(p("upper_for_lower"), b"upper")
    r = x(lf, up)
    return "ret=%s lower_now_upper=%s upper_now_lower=%s" % (
        r, rd(lf) == "upper", rd(up) == before)


def t_lower_copied_up_file():
    lf = lower_copied_up()
    with open(lf, "ab") as h:
        h.write(b"#copied\n")
    before = rd(lf)
    up = mk(p("upper_for_copied"), b"upper2")
    r = x(lf, up)
    return "ret=%s lower_now_upper=%s upper_now_copy=%s" % (r, rd(lf) == "upper2", rd(up) == before)


def t_lower_dir():
    ld = lower_dir(); names = sorted(os.listdir(ld))
    ud = p("upper_dir_for_lower"); os.mkdir(ud); mk(os.path.join(ud, "u"), b"U")
    r = x(ld, ud)
    return "ret=%s lower_now_upper=%s upper_now_lower=%s" % (
        r, sorted(os.listdir(ld)) == ["u"], sorted(os.listdir(ud)) == names)


def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True); os.makedirs(BASE)
    if HOST:
        shutil.rmtree("/tmp/gtx26_lower", ignore_errors=True)
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("t_") and callable(f)]
    order = [n for n, _ in tests if not n.startswith("t_lower")] + [n for n, _ in tests if n.startswith("t_lower")]
    for n in order:
        run(n[2:], globals()[n])
    if HOST:
        shutil.rmtree("/tmp/gtx26_lower", ignore_errors=True)
    shutil.rmtree(BASE, ignore_errors=True)
    print("GT_DONE", flush=True)


main()
