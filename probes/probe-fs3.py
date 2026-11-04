"""File-system probe 3: path rules, renameat2, append/seek/holes, fallocate,
metadata, statfs, in-kernel copies, d_type, and the same operations on files
that come from the image (copy-up).

Prints 'GT <name> <result>'. Run it on Linux with GT_HOST=1: "lower" files are
then copies in /tmp instead of image files, so nothing on the host changes.
"""
import ctypes, errno, os, select, signal, stat, struct, sys, time

HOST = os.environ.get("GT_HOST") == "1"
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
BASE = "/tmp/gtfs3"


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


# Lower-layer stand-ins: real image files in Ginux, /tmp copies on the host.
LOWER_SRC = ["/etc/os-release", "/etc/shells", "/etc/profile", "/etc/issue"]


def lower(i):
    src = LOWER_SRC[i]
    if not HOST:
        return src
    dst = "/tmp/gtfs3_lower" + src.replace("/", "_")
    if not os.path.exists(dst):
        os.makedirs("/tmp/gtfs3_lower", exist_ok=True)
        with open(src, "rb") as a, open(dst, "wb") as b:
            b.write(a.read())
        os.utime(dst, (1_000_000, 1_000_000))
    return dst


def lower_dir():
    # A non-empty image directory with a few files.
    if not HOST:
        return "/usr/local/lib/python3.13/json"
    d = "/tmp/gtfs3_lower/json"
    if not os.path.isdir(d):
        import shutil
        shutil.copytree("/usr/lib/python3.13/json" if os.path.isdir("/usr/lib/python3.13/json")
                        else os.path.dirname(os.__file__) + "/json", d)
    return d


# ---------------------------------------------------------------- path rules
def t_name_max():
    ok = os.open(p("a" * 255), os.O_CREAT | os.O_WRONLY, 0o600); os.close(ok)
    try:
        os.open(p("b" * 256), os.O_CREAT | os.O_WRONLY, 0o600)
        return "256=ok"
    except OSError as x:
        return "255=ok 256=-" + errno.errorcode[x.errno]


def t_component_is_file():
    mk(p("f1"))
    out = []
    for fn in (lambda: os.stat(p("f1", "x")), lambda: os.open(p("f1", "x"), os.O_CREAT | os.O_WRONLY, 0o600),
               lambda: os.mkdir(p("f1", "x")), lambda: os.unlink(p("f1", "x"))):
        try:
            fn(); out.append("0")
        except OSError as x:
            out.append(errno.errorcode[x.errno])
    return " ".join(out)


def t_trailing_slash():
    mk(p("f2"))
    out = []
    for fn in (lambda: os.stat(p("f2") + "/"), lambda: os.open(p("f2") + "/", os.O_RDONLY),
               lambda: os.open(p("new2") + "/", os.O_CREAT | os.O_WRONLY, 0o600),
               lambda: os.unlink(p("f2") + "/"), lambda: os.rename(p("f2"), p("f2b") + "/")):
        try:
            r = fn(); out.append("0"); isinstance(r, int) and os.close(r)
        except OSError as x:
            out.append(errno.errorcode[x.errno])
    os.mkdir(p("d2")); os.mkdir(p("d2b") + "/")
    out.append("mkdir_slash=%s" % os.path.isdir(p("d2b")))
    return " ".join(out)


def t_dir_errors():
    os.mkdir(p("d3")); mk(p("d3", "c"))
    out = []
    for name, fn in [("mkdir_exist", lambda: os.mkdir(p("d3"))),
                     ("open_dir_wronly", lambda: os.open(p("d3"), os.O_WRONLY)),
                     ("open_dir_creat", lambda: os.open(p("d3"), os.O_CREAT | os.O_RDONLY, 0o600)),
                     ("unlink_dir", lambda: os.unlink(p("d3"))),
                     ("rmdir_dot", lambda: os.rmdir(p("d3", "."))),
                     ("rmdir_dotdot", lambda: os.rmdir(p("d3", ".."))),
                     ("link_dir", lambda: os.link(p("d3"), p("d3l"))),
                     ("odirectory_file", lambda: os.open(p("d3", "c"), os.O_RDONLY | os.O_DIRECTORY)),
                     ("openat_filefd", lambda: os.open("c", os.O_RDONLY, dir_fd=os.open(p("d3", "c"), os.O_RDONLY)))]:
        try:
            r = fn(); out.append(name + "=0"); isinstance(r, int) and os.close(r)
        except OSError as x:
            out.append(name + "=" + errno.errorcode[x.errno])
    return " ".join(out)


def t_symlink_rules():
    os.symlink(p("nowhere"), p("dangling"))
    os.symlink(p("f4"), p("sl4")); mk(p("f4"))
    out = []
    for name, fn in [("excl_on_dangling", lambda: os.open(p("dangling"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)),
                     ("creat_through_dangling", lambda: os.open(p("dangling"), os.O_CREAT | os.O_WRONLY, 0o600)),
                     ("nofollow", lambda: os.open(p("sl4"), os.O_RDONLY | os.O_NOFOLLOW)),
                     ("symlink_empty", lambda: os.symlink("", p("empty_sl"))),
                     ("symlink_exists", lambda: os.symlink("x", p("sl4")))]:
        try:
            r = fn(); out.append(name + "=0"); isinstance(r, int) and os.close(r)
        except OSError as x:
            out.append(name + "=" + errno.errorcode[x.errno])
    out.append("dangling_target_created=%s" % os.path.exists(p("nowhere")))
    buf = ctypes.create_string_buffer(4)
    n = libc.readlink(p("sl4").encode(), buf, 4)
    out.append("readlink_short=%d:%s" % (n, buf.raw[:max(n, 0)].decode(errors="replace")))
    return " ".join(out)


def renameat2(a, b, flags):
    return sc(316, -100, a.encode(), -100, b.encode(), flags)


def t_renameat2():
    mk(p("r1"), b"one"); mk(p("r2"), b"two")
    noreplace = renameat2(p("r1"), p("r2"), 1)
    exch = renameat2(p("r1"), p("r2"), 2)
    data = open(p("r1"), "rb").read() + b"/" + open(p("r2"), "rb").read()
    exch_missing = renameat2(p("r1"), p("nope"), 2)
    mk(p("r3"))
    noreplace_new = renameat2(p("r3"), p("r4"), 1)
    both = renameat2(p("r4"), p("r1"), 3)
    os.mkdir(p("rd")); mk(p("rd", "x"))
    exch_dir_file = renameat2(p("rd"), p("r1"), 2)
    dir_now = os.path.isdir(p("r1")) and os.path.exists(p("r1", "x"))
    return "noreplace=%s exchange=%s data=%s exch_missing=%s noreplace_new=%s both_flags=%s exch_dir_file=%s dir_swapped=%s" % (
        e(noreplace), e(exch), data.decode(), e(exch_missing), e(noreplace_new), e(both), e(exch_dir_file), dir_now)


# ------------------------------------------------------------- file I/O rules
def t_append_pwrite():
    fd = os.open(mk(p("ap"), b"0123"), os.O_WRONLY | os.O_APPEND)
    os.pwrite(fd, b"XY", 0)
    os.close(fd)
    return open(p("ap"), "rb").read().decode()


def t_two_append_fds():
    mk(p("ap2"), b"")
    a = os.open(p("ap2"), os.O_WRONLY | os.O_APPEND); b = os.open(p("ap2"), os.O_WRONLY | os.O_APPEND)
    for i in range(5):
        os.write(a, b"a" * 3); os.write(b, b"b" * 2)
    os.close(a); os.close(b)
    return open(p("ap2"), "rb").read().decode()


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


def t_lseek():
    fd = os.open(mk(p("ls"), b"abc"), os.O_RDWR)
    out = []
    try:
        os.lseek(fd, -1, os.SEEK_SET); out.append("neg=0")
    except OSError as x:
        out.append("neg=" + errno.errorcode[x.errno])
    try:
        out.append("bad_whence=%d" % os.lseek(fd, 0, 7))
    except OSError as x:
        out.append("bad_whence=" + errno.errorcode[x.errno])
    out.append("end_plus=%d" % os.lseek(fd, 10, os.SEEK_END))
    os.write(fd, b"Z")
    data = os.pread(fd, 20, 0)
    out.append("hole_zeros=%s size=%d" % (data == b"abc" + b"\0" * 10 + b"Z", os.fstat(fd).st_size))
    out.append("read_eof=%d pread_past=%d" % (len(os.read(fd, 5)), len(os.pread(fd, 5, 100))))
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


def t_fallocate():
    fd = os.open(mk(p("fa"), b"abcdefgh"), os.O_RDWR)
    f = libc.fallocate
    f.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
    def call(mode, off, ln):
        r = f(fd, mode, off, ln)
        return 0 if r == 0 else -ctypes.get_errno()
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


def t_otrunc():
    mk(p("ot"), b"abcdef")
    os.utime(p("ot"), (1_000_000, 1_000_000))
    fd = os.open(p("ot"), os.O_WRONLY | os.O_TRUNC); os.close(fd)
    st = os.stat(p("ot"))
    return "size=%d mtime_bumped=%s" % (st.st_size, st.st_mtime > 1_000_000)


def t_big_file():
    chunk = bytes(range(256)) * 4096  # 1 MiB
    with open(p("big"), "wb") as f:
        for _ in range(16):
            f.write(chunk)
    with open(p("big"), "rb") as f:
        ok = all(f.read(len(chunk)) == chunk for _ in range(16))
    return "16MiB_roundtrip=%s size=%d" % (ok, os.stat(p("big")).st_size)


def t_sync_calls():
    fd = os.open(mk(p("sy")), os.O_RDWR)
    out = []
    for name, fn in [("fsync", lambda: os.fsync(fd)), ("fdatasync", lambda: os.fdatasync(fd)),
                     ("sync_file_range", lambda: sc(277, fd, 0, 0, 0)), ("syncfs", lambda: sc(306, fd)),
                     ("fsync_dir", lambda: os.fsync(os.open(BASE, os.O_RDONLY)))]:
        try:
            r = fn(); out.append("%s=%s" % (name, e(r) if isinstance(r, int) else 0))
        except OSError as x:
            out.append(name + "=" + errno.errorcode[x.errno])
    return " ".join(out)


def t_offsets_shared():
    fd = os.open(mk(p("of"), b"abcdef"), os.O_RDONLY)
    d = os.dup(fd); other = os.open(p("of"), os.O_RDONLY)
    os.read(fd, 2)
    return "dup_shares=%s other_independent=%s" % (os.read(d, 1) == b"c", os.read(other, 1) == b"a")


def t_unlinked_open():
    fd = os.open(mk(p("uo"), b"keep"), os.O_RDWR)
    os.unlink(p("uo"))
    os.write(fd, b"MORE")
    data = os.pread(fd, 20, 0)
    mk(p("uo"), b"new")
    return "data=%s fresh=%s" % (data.decode(), open(p("uo"), "rb").read().decode())


def t_copy_calls():
    src = os.open(mk(p("cs"), b"0123456789"), os.O_RDONLY)
    dst = os.open(p("cd"), os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
    n = os.sendfile(dst, src, 2, 4)
    try:
        m = os.copy_file_range(src, dst, 3, 0, 4)
    except OSError as x:
        m = "-" + errno.errorcode[x.errno]
    os.close(dst)
    return "sendfile=%s copy_file_range=%s data=%s src_off=%d" % (
        n, m, open(p("cd"), "rb").read().decode(), os.lseek(src, 0, os.SEEK_CUR))


# --------------------------------------------------------------- metadata
def t_umask():
    old = os.umask(0o027)
    fd = os.open(p("um"), os.O_CREAT | os.O_WRONLY, 0o666); os.close(fd)
    os.mkdir(p("umd"), 0o777)
    os.umask(old)
    return "file=%o dir=%o" % (stat.S_IMODE(os.stat(p("um")).st_mode), stat.S_IMODE(os.stat(p("umd")).st_mode))


def t_chmod():
    mk(p("cm")); os.symlink(p("cm"), p("cml"))
    os.chmod(p("cml"), 0o604)
    out = ["through_symlink=%o" % stat.S_IMODE(os.stat(p("cm")).st_mode)]
    r = sc(452, -100, p("cml").encode(), 0o600, 0x100)  # fchmodat2 AT_SYMLINK_NOFOLLOW
    out.append("fchmodat2_nofollow=%s" % e(r))
    os.chmod(p("cm"), 0o4755)
    out.append("setuid_kept=%o" % stat.S_IMODE(os.stat(p("cm")).st_mode))
    os.chmod(p("cm"), 0o17777)
    out.append("masked=%o" % stat.S_IMODE(os.stat(p("cm")).st_mode))
    return " ".join(out)


def t_ownership():
    mk(p("ow")); st = os.stat(p("ow"))
    os.chown(p("ow"), -1, -1)
    return "uid_is_euid=%s gid_is_egid=%s" % (st.st_uid == os.geteuid(), st.st_gid == os.getegid())


def t_utimensat():
    mk(p("ut"))
    os.utime(p("ut"), ns=(5_000_000_000, 7_000_000_000))
    ts = (ctypes.c_long * 4)(0, (1 << 30) - 2, 0, (1 << 30) - 2)  # UTIME_OMIT, UTIME_OMIT
    r1 = libc.utimensat(-100, p("ut").encode(), ts, 0)
    st = os.stat(p("ut"))
    keep = (st.st_atime_ns, st.st_mtime_ns) == (5_000_000_000, 7_000_000_000)
    ts2 = (ctypes.c_long * 4)(0, (1 << 30) - 1, 0, (1 << 30) - 2)  # atime NOW, mtime OMIT
    before = time.time() - 5
    libc.utimensat(-100, p("ut").encode(), ts2, 0)
    st = os.stat(p("ut"))
    os.symlink(p("ut"), p("utl"))
    os.utime(p("utl"), ns=(3_000_000_000, 3_000_000_000), follow_symlinks=False)
    lst = os.lstat(p("utl")); tst = os.stat(p("ut"))
    bad = (ctypes.c_long * 4)(0, 1_000_000_000, 0, 0)
    r_bad = libc.utimensat(-100, p("ut").encode(), bad, 0)
    r_bad = -ctypes.get_errno() if r_bad else 0
    return "omit_keeps=%s now_atime=%s mtime_kept=%s nofollow_link=%s target_untouched=%s bad_nsec=%s" % (
        keep, st.st_atime >= before, st.st_mtime_ns == 7_000_000_000,
        lst.st_mtime_ns == 3_000_000_000, tst.st_mtime_ns == 7_000_000_000, e(r_bad))


def t_blocks():
    mk(p("bl"), b"x" * 10000)
    st = os.stat(p("bl"))
    return "blocks_ge_20=%s blksize_pos=%s" % (st.st_blocks >= 20, st.st_blksize > 0)


def t_statfs():
    v = os.statvfs(BASE)
    buf = (ctypes.c_long * 15)()
    libc.statfs(BASE.encode(), buf)
    return "bsize_pos=%s namemax=%d blocks_pos=%s frsize_pos=%s" % (
        v.f_bsize > 0, v.f_namemax, v.f_blocks > 0, v.f_frsize > 0)


def t_dtype():
    os.mkdir(p("dt")); mk(p("dt", "f")); os.mkdir(p("dt", "d")); os.symlink("f", p("dt", "l")); os.mkfifo(p("dt", "p"))
    kinds = {}
    for de in os.scandir(p("dt")):
        kinds[de.name] = ("d" if de.is_dir(follow_symlinks=False) else "l" if de.is_symlink() else "f" if de.is_file(follow_symlinks=False) else "o")
    return ",".join("%s:%s" % kv for kv in sorted(kinds.items()))


def t_dir_nlink_after_rmdir():
    os.mkdir(p("nl")); os.mkdir(p("nl", "a")); os.mkdir(p("nl", "b"))
    n1 = os.stat(p("nl")).st_nlink
    os.rmdir(p("nl", "a"))
    n2 = os.stat(p("nl")).st_nlink
    os.rename(p("nl", "b"), p("nl_b_moved"))
    n3 = os.stat(p("nl")).st_nlink
    return "nlink=%d,%d,%d dotdot_moved=%s" % (n1, n2, n3, os.path.samefile(p("nl_b_moved", ".."), BASE))


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


def t_opath():
    fd = os.open(mk(p("op")), os.O_PATH)
    out = ["fstat=%s" % stat.S_ISREG(os.fstat(fd).st_mode)]
    try:
        os.read(fd, 1); out.append("read=0")
    except OSError as x:
        out.append("read=" + errno.errorcode[x.errno])
    return " ".join(out)


def t_rewinddir():
    os.mkdir(p("rw")); mk(p("rw", "a"))
    fd = os.open(p("rw"), os.O_RDONLY)
    first = sorted(os.listdir(fd))
    mk(p("rw", "b"))
    os.lseek(fd, 0, 0)
    second = sorted(os.listdir(fd))
    return "first=%s second=%s" % (",".join(first), ",".join(second))


# -------------------------------------------------- image (lower) files
def t_lower_append():
    f = lower(0); before = open(f, "rb").read()
    with open(f, "ab") as h:
        h.write(b"#appended\n")
    after = open(f, "rb").read()
    return "prefix_kept=%s grew=%d" % (after.startswith(before), len(after) - len(before))


def t_lower_rw_middle():
    f = lower(1); before = open(f, "rb").read()
    fd = os.open(f, os.O_RDWR); os.pwrite(fd, b"ZZ", 3); os.close(fd)
    after = open(f, "rb").read()
    return "same_len=%s patched=%s rest_kept=%s" % (len(after) == len(before), after[3:5] == b"ZZ", after[5:] == before[5:])


def t_lower_chmod_utime():
    f = lower(2)
    os.chmod(f, 0o640); m = stat.S_IMODE(os.stat(f).st_mode)
    os.utime(f, (2_000_000, 2_000_000)); t = os.stat(f).st_mtime
    data_ok = len(open(f, "rb").read()) > 0
    return "mode=%o mtime=%d data_ok=%s" % (m, t, data_ok)


def t_lower_ftruncate_open_rdwr():
    f = lower(3); before = open(f, "rb").read()
    fd = os.open(f, os.O_RDWR); os.ftruncate(fd, 4); os.close(fd)
    after = open(f, "rb").read()
    return "len=%d prefix=%s" % (len(after), after == before[:4])


def t_lower_dir_rename_with_contents():
    d = lower_dir(); names = sorted(os.listdir(d))
    dst = d + "_moved"
    os.rename(d, dst)
    moved = sorted(os.listdir(dst))
    content_ok = all(os.path.getsize(os.path.join(dst, n)) >= 0 for n in moved)
    return "renamed=%s same_entries=%s old_gone=%s content_ok=%s" % (
        os.path.isdir(dst), moved == names, not os.path.exists(d), content_ok)


def t_lower_0_open_then_unlink():
    f = os.path.join(lower_dir(), "decoder.py")
    fd = os.open(f, os.O_RDONLY)
    os.unlink(f)
    data = os.read(fd, 16)
    return "read_after_unlink=%d gone=%s" % (len(data), not os.path.exists(f))


def t_lower_hardlink_write():
    f = lower(0)
    os.link(f, p("lower_link"))
    with open(p("lower_link"), "ab") as h:
        h.write(b"#via-link\n")
    return "seen_via_original=%s nlink=%d" % (open(f, "rb").read().endswith(b"#via-link\n"), os.stat(f).st_nlink)


def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True); os.makedirs(BASE)
    if HOST:
        shutil.rmtree("/tmp/gtfs3_lower", ignore_errors=True)
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("t_") and callable(f)]
    order = [n for n, _ in tests if not n.startswith("t_lower")] + [n for n, _ in tests if n.startswith("t_lower")]
    for n in order:
        run(n[2:], globals()[n])
    print("GT_DONE", flush=True)


if __name__ == "__main__":
    main()
