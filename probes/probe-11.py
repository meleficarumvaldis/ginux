"""Issue 11 probe: overlay/rootfs file-system syscalls. Run on Linux (reference) and inside Ginux.

Each line: GT <name> <result>. Inside Ginux the "lower" paths are real image files
(/etc/hostname, /usr, ...). With GT_HOST=1 the same operations run on an equivalent
tree under /tmp/gt/lw so the Linux reference values come from a real kernel without
touching the host's /etc or /usr.
"""
import ctypes, errno, os, select, signal, stat as st, struct, sys

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
HOST = os.environ.get("GT_HOST") == "1"
NR = dict(dup=32, dup2=33, fcntl=72, openat=257, openat2=437, timerfd_create=283, eventfd2=290,
          epoll_create1=291, preadv=295, preadv2=327, pwritev2=328, newfstatat=262, statx=332,
          faccessat=269, unlinkat=263, renameat2=316, rmdir=84, unlink=87, rename=82)
AT_FDCWD = -100


def sc(name, *args):
    a = [ctypes.c_long(x) if isinstance(x, int) else x for x in args]
    r = libc.syscall(ctypes.c_long(NR[name]), *a)
    if r == -1:
        e = ctypes.get_errno()
        return "-" + errno.errorcode.get(e, str(e))
    return r


def out(name, value):
    print("GT", name, value, flush=True)


def run(name, fn, limit=8.0):
    """Run fn in a forked child so a hang or crash only affects this test."""
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
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    out(name, res or "EMPTY")


def err(fn):
    try:
        r = fn()
        return "0" if r is None else str(r)
    except OSError as exc:
        return "-" + errno.errorcode[exc.errno]


def read(path):
    with open(path, "rb") as f:
        return f.read()


os.makedirs("/tmp/gt", exist_ok=True)
os.chdir("/tmp/gt")

# ---------------- lower (image) layer stand-ins ----------------
if HOST:
    LW = "/tmp/gt/lw"
    for d in ("etc", "usr/share/ca-certificates", "mnt", "opt/small", "srv/lowdir/sub"):
        os.makedirs(LW + "/" + d, exist_ok=True)
    for f, data in (("etc/os-release", b"NAME=x\n"), ("etc/hostname", b"localhost\n"),
                    ("etc/issue", b"Welcome\n"), ("etc/shells", b"/bin/sh\n"), ("etc/passwd", b"root:x:0:0\n"),
                    ("usr/share/ca-certificates/a.crt", b"c"), ("opt/small/one", b"1"),
                    ("opt/small/two", b"2"), ("srv/lowdir/sub/f", b"f")):
        with open(LW + "/" + f, "wb") as fh:
            fh.write(data)
else:
    LW = ""


def L(path):
    return LW + path


def small_lower_dir():
    """A lower directory holding only 1-4 regular files (no subdirectories)."""
    if HOST:
        return L("/opt/small")
    for top in ("/etc", "/usr/share", "/usr/lib", "/lib"):
        for root, dirs, files in os.walk(top):
            if not dirs and 1 <= len(files) <= 4 and all(
                    st.S_ISREG(os.lstat(os.path.join(root, f)).st_mode) for f in files):
                return root
    return None


SMALL = small_lower_dir()
out("small_lower_dir", SMALL)

O_CREAT, O_EXCL, O_NOCTTY, O_TRUNC = os.O_CREAT, os.O_EXCL, os.O_NOCTTY, os.O_TRUNC
O_DIRECTORY = os.O_DIRECTORY

# ---------------- A1: O_CREAT on existing lower entries ----------------


def creat_rdonly_lower_file(path, extra=0):
    before = read(path)
    fd = os.open(path, os.O_RDONLY | O_CREAT | extra, 0o644)
    via_fd = os.read(fd, 4096)
    os.close(fd)
    return "fd_read_ok=%s content_kept=%s" % (via_fd == before, read(path) == before)


run("open_creat_rdonly_lower_file", lambda: creat_rdonly_lower_file(L("/etc/os-release")))
run("flock_open_hostname", lambda: creat_rdonly_lower_file(L("/etc/hostname"), O_NOCTTY))


def creat_wronly_lower_file():
    path = L("/etc/issue")
    before = read(path)
    fd = os.open(path, os.O_WRONLY | O_CREAT, 0o644)
    os.close(fd)
    return "content_kept=%s" % (read(path) == before)


run("open_creat_wronly_lower_file", creat_wronly_lower_file)
run("open_creat_lower_dir", lambda: err(lambda: os.close(os.open(L("/usr"), os.O_RDONLY | O_CREAT))))
run("open_creat_overlay_dir", lambda: err(lambda: os.close(os.open("/tmp/gt", os.O_RDONLY | O_CREAT))))

# ---------------- A4: O_CREAT|O_DIRECTORY, O_DIRECTORY|O_TRUNC ----------------


def open_creat_directory():
    res = err(lambda: os.close(os.open("/tmp/gt/nd", O_CREAT | O_DIRECTORY, 0o600)))
    return "%s exists_after=%s" % (res, os.path.exists("/tmp/gt/nd"))


run("open_creat_directory", open_creat_directory)


def open_trunc_directory(path):
    before = read(path)
    res = err(lambda: os.close(os.open(path, os.O_WRONLY | O_TRUNC | O_DIRECTORY)))
    return "%s content_kept=%s" % (res, read(path) == before)


with open("/tmp/gt/tr", "wb") as f:
    f.write(b"abc")
run("open_trunc_directory_overlay_file", lambda: open_trunc_directory("/tmp/gt/tr"))
run("open_trunc_directory_lower_file", lambda: open_trunc_directory(L("/etc/passwd")))

# ---------------- A2: unlink/rmdir of lower entries ----------------


def removal(fn, path, check=os.path.lexists):
    res = err(lambda: fn(path))
    return "%s exists_after=%s" % (res, check(path))


run("unlink_lower_dir", lambda: removal(os.unlink, L("/etc")))
run("rmdir_lower_file", lambda: removal(os.rmdir, L("/etc/passwd")))
run("rmdir_lower_nonempty", lambda: removal(os.rmdir, L("/usr/share/ca-certificates")))
run("rmdir_lower_usr", lambda: removal(os.rmdir, L("/usr")))


def rmdir_lower_with_overlay_child():
    d = L("/mnt")
    with open(d + "/gtchild", "w") as f:
        f.write("x")
    first = err(lambda: os.rmdir(d))
    os.unlink(d + "/gtchild")
    second = err(lambda: os.rmdir(d))
    return "with_child=%s after_unlink=%s exists_after=%s" % (first, second, os.path.lexists(d))


run("rmdir_lower_with_overlay_child", rmdir_lower_with_overlay_child)


def rmdir_lower_after_children_unlinked():
    if SMALL is None:
        return "no-candidate"
    names = os.listdir(SMALL)
    for name in names:
        os.unlink(os.path.join(SMALL, name))
    res = err(lambda: os.rmdir(SMALL))
    return "%s exists_after=%s" % (res, os.path.lexists(SMALL))


run("rmdir_lower_after_children_unlinked", rmdir_lower_after_children_unlinked)

# ---------------- A3: rename ----------------


def rename_same_file():
    with open("/tmp/gt/same", "w") as f:
        f.write("x")
    res = err(lambda: os.rename("/tmp/gt/same", "/tmp/gt/same"))
    return "%s exists_after=%s" % (res, os.path.exists("/tmp/gt/same"))


run("rename_same_file", rename_same_file)


def rename_same_lower():
    path = L("/etc/hostname")
    before = read(path)
    res = err(lambda: os.rename(path, path))
    return "%s content_kept=%s" % (res, os.path.exists(path) and read(path) == before)


run("rename_same_lower", rename_same_lower)


def rename_file_over_emptydir():
    os.makedirs("/tmp/gt/edir", exist_ok=True)
    with open("/tmp/gt/f1", "w") as f:
        f.write("x")
    res = err(lambda: os.rename("/tmp/gt/f1", "/tmp/gt/edir"))
    return "%s dir_kept=%s" % (res, os.path.isdir("/tmp/gt/edir"))


run("rename_file_over_emptydir", rename_file_over_emptydir)


def rename_dir_over_file():
    os.makedirs("/tmp/gt/d2", exist_ok=True)
    with open("/tmp/gt/f2", "w") as f:
        f.write("x")
    res = err(lambda: os.rename("/tmp/gt/d2", "/tmp/gt/f2"))
    return "%s file_kept=%s" % (res, os.path.isfile("/tmp/gt/f2"))


run("rename_dir_over_file", rename_dir_over_file)


def rename_dir_into_subtree():
    os.makedirs("/tmp/gt/d3/sub", exist_ok=True)
    return err(lambda: os.rename("/tmp/gt/d3", "/tmp/gt/d3/sub/x"))


run("rename_dir_into_own_subtree", rename_dir_into_subtree)


def rename_dir_over_nonempty_dir():
    os.makedirs("/tmp/gt/d4", exist_ok=True)
    os.makedirs("/tmp/gt/d5", exist_ok=True)
    with open("/tmp/gt/d5/x", "w") as f:
        f.write("x")
    res = err(lambda: os.rename("/tmp/gt/d4", "/tmp/gt/d5"))
    return "%s child_kept=%s" % (res, os.path.exists("/tmp/gt/d5/x"))


run("rename_dir_over_nonempty_dir", rename_dir_over_nonempty_dir)


def rename_onto_ancestor():
    os.makedirs("/tmp/gt/d6/child", exist_ok=True)
    return err(lambda: os.rename("/tmp/gt/d6/child", "/tmp/gt/d6"))


run("rename_onto_ancestor", rename_onto_ancestor)


def rename_dir_over_emptydir():
    os.makedirs("/tmp/gt/d7", exist_ok=True)
    os.makedirs("/tmp/gt/d8", exist_ok=True)
    with open("/tmp/gt/d7/x", "w") as f:
        f.write("x")
    res = err(lambda: os.rename("/tmp/gt/d7", "/tmp/gt/d8"))
    return "%s moved=%s" % (res, os.path.exists("/tmp/gt/d8/x") and not os.path.exists("/tmp/gt/d7"))


run("rename_dir_over_emptydir", rename_dir_over_emptydir)


def rename_file_over_lower_dir():
    with open("/tmp/gt/f9", "w") as f:
        f.write("x")
    res = err(lambda: os.rename("/tmp/gt/f9", L("/usr")))
    return "%s dir_kept=%s" % (res, os.path.isdir(L("/usr")))


run("rename_file_over_lower_dir", rename_file_over_lower_dir)


def rename_dir_over_lower_nonempty_dir():
    os.makedirs("/tmp/gt/d10", exist_ok=True)
    target = L("/usr/share/ca-certificates")
    res = err(lambda: os.rename("/tmp/gt/d10", target))
    return "%s children_kept=%s" % (res, len(os.listdir(target)) > 0)


run("rename_dir_over_lower_nonempty_dir", rename_dir_over_lower_nonempty_dir)


def mv_lower_file(src, dst):
    before = read(src)
    res = err(lambda: os.rename(src, dst))
    moved = os.path.exists(dst) and read(dst) == before
    try:
        left = read(src)
        gone = "False(%d bytes, same=%s)" % (len(left), left == before)
    except OSError as exc:
        gone = "True(" + errno.errorcode[exc.errno] + ")"
    return "%s moved=%s source_gone=%s" % (res, moved, gone)


run("mv_lower_file", lambda: mv_lower_file(L("/etc/shells"), "/tmp/gt/shells"))
run("mv_etc_hostname", lambda: mv_lower_file(L("/etc/hostname"), "/tmp/gt/hn"))


def rename_overlay_file_over_lower_file():
    with open("/tmp/gt/f11", "wb") as f:
        f.write(b"new")
    res = err(lambda: os.rename("/tmp/gt/f11", L("/etc/issue")))
    return "%s replaced=%s source_gone=%s" % (
        res, read(L("/etc/issue")) == b"new", not os.path.exists("/tmp/gt/f11"))


run("rename_overlay_file_over_lower_file", rename_overlay_file_over_lower_file)


def rename_lower_dir():
    # Linux overlayfs without redirect_dir: EXDEV (mv falls back to copying).
    # A plain host directory gives 0.
    src = L("/srv") if HOST else "/srv"
    return err(lambda: os.rename(src, "/tmp/gt/srvmoved"))


run("rename_lower_dir", rename_lower_dir)

# ---------------- B: lookup semantics ----------------


def stat_symlink_follow():
    os.makedirs("/tmp/gt/realdir", exist_ok=True)
    if not os.path.lexists("/tmp/gt/ln"):
        os.symlink("/tmp/gt/realdir", "/tmp/gt/ln")
    mode = os.stat("/tmp/gt/ln").st_mode
    lmode = os.lstat("/tmp/gt/ln").st_mode
    return "stat=%s lstat=%s" % ("dir" if st.S_ISDIR(mode) else oct(mode),
                                 "link" if st.S_ISLNK(lmode) else oct(lmode))


run("stat_follows_symlink", stat_symlink_follow)
run("access_symlink_to_dir_x", lambda: err(lambda: None if os.access("/tmp/gt/ln", os.X_OK) else 1))
run("chdir_symlink_to_dir", lambda: err(lambda: os.chdir("/tmp/gt/ln")) + " cwd=" + os.getcwd())
run("stat_empty_path", lambda: err(lambda: os.stat("") and None))
run("statx_empty_path_no_flag", lambda: sc("statx", AT_FDCWD, ctypes.c_char_p(b""), 0, 0xfff,
                                          ctypes.addressof(ctypes.create_string_buffer(256))))

# ---------------- B: open flags ----------------


def open_ok(path, flags, mode=0o600):
    fd = os.open(path, flags, mode)
    os.close(fd)
    return "ok"


run("open_osync", lambda: err(lambda: open_ok("/tmp/gt/sync", os.O_WRONLY | O_CREAT | os.O_SYNC)))
run("open_odsync", lambda: err(lambda: open_ok("/tmp/gt/sync", os.O_WRONLY | os.O_DSYNC)))
run("open_oasync", lambda: err(lambda: open_ok("/tmp/gt/sync", os.O_RDONLY | 0o20000)))
run("open_rdonly_excl_nocreat", lambda: err(lambda: open_ok("/tmp/gt/tr", os.O_RDONLY | O_EXCL)))
run("open_accmode3", lambda: err(lambda: open_ok("/tmp/gt/tr", 3)))


def openat2(flags):
    how = ctypes.create_string_buffer(struct.pack("QQQ", flags, 0, 0), 24)
    r = sc("openat2", AT_FDCWD, ctypes.c_char_p(b"/tmp/gt/tr"), ctypes.addressof(how), 24)
    if isinstance(r, int):
        os.close(r)
        return "ok"
    return r


run("openat2_high_bit", lambda: openat2(1 << 40))
run("openat2_osync", lambda: openat2(os.O_RDONLY | os.O_SYNC))

# ---------------- B: positioned iov ----------------
with open("/tmp/gt/ro", "wb") as f:
    f.write(b"A" * 4096)


def iov1(n=4):
    buf = ctypes.create_string_buffer(n)
    iov = ctypes.create_string_buffer(struct.pack("QQ", ctypes.addressof(buf), n), 16)
    KEEP.append((buf, iov))
    return ctypes.addressof(iov)


KEEP = []


def preadv2_pos(pos_l, pos_h):
    fd = os.open("/tmp/gt/ro", os.O_RDONLY)
    r = sc("preadv2", fd, iov1(), 1, pos_l, pos_h, 0)
    os.close(fd)
    return r


run("preadv2_pos_minus1", lambda: preadv2_pos(-1, -1))
run("preadv2_pos_minus1_advances", lambda: (lambda fd: (sc("preadv2", fd, iov1(), 1, -1, 0, 0),
                                                         os.lseek(fd, 0, os.SEEK_CUR))[1])(os.open("/tmp/gt/ro", os.O_RDONLY)))
run("preadv_4g_offset", lambda: (lambda fd: os.preadv(fd, [bytearray(4)], 1 << 32))(os.open("/tmp/gt/ro", os.O_RDONLY)))
run("preadv_pos_h_ignored", lambda: (lambda fd: sc("preadv", fd, iov1(), 1, 0, 7))(os.open("/tmp/gt/ro", os.O_RDONLY)))
run("preadv_negative", lambda: (lambda fd: sc("preadv", fd, iov1(), 1, -2, 0))(os.open("/tmp/gt/ro", os.O_RDONLY)))
run("preadv2_negative", lambda: preadv2_pos(-2, 0))

# ---------------- B: dup / fcntl ----------------


def dup_kind(fd):
    if not isinstance(fd, int):
        return "create:" + str(fd)
    d = sc("dup", fd)
    d2 = sc("dup2", fd, 77)
    d3 = sc("fcntl", fd, 0, 50)  # F_DUPFD
    d4 = sc("fcntl", fd, 1030, 60)  # F_DUPFD_CLOEXEC
    return "dup=%s dup2=%s f_dupfd=%s f_dupfd_cloexec=%s" % (
        "ok" if isinstance(d, int) and d > fd else d, d2,
        "ok" if isinstance(d3, int) and d3 >= 50 else d3,
        "ok" if isinstance(d4, int) and d4 >= 60 else d4)


run("dup_eventfd", lambda: dup_kind(sc("eventfd2", 0, 0)))
run("dup_timerfd", lambda: dup_kind(sc("timerfd_create", 1, 0)))
run("dup_epoll", lambda: dup_kind(sc("epoll_create1", 0)))
run("fcntl_getpipe_sz", lambda: sc("fcntl", os.pipe()[0], 1032, 0))
run("fcntl_setfl_largefile", lambda: sc("fcntl", os.pipe()[0], 4, os.O_NONBLOCK | 0o100000))
run("fcntl_setfl_unknown_bits", lambda: (lambda p: (sc("fcntl", p, 4, 0o4000 | 0o10000000 | 0o2), sc("fcntl", p, 3, 0) & 0o4000)[0:2])(os.pipe()[0]))

print("GT_DONE", flush=True)
