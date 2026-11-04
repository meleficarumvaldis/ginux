"""File-system probe 4: xattrs, locks, mmap/write coherence, large directories,
inode numbers, deleted cwd, descriptors after rename, /proc/self/fd, statx,
openat2 RESOLVE_* flags, sockets and device nodes in the overlay, and the five
leftovers from probe-fs3 (relative symlink targets, symlinks mid-path, utime on
an image directory, O_APPEND start position, FIFO without reader).

Prints 'GT <name> <result>'. Run on Linux with GT_HOST=1 (image files are then
copies in /tmp).
"""
import ctypes, errno, fcntl, mmap, os, select, signal, socket, stat, struct, sys, time

HOST = os.environ.get("GT_HOST") == "1"
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
BASE = "/tmp/gtfs4"


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


def mk(path, data=b"hello"):
    with open(path, "wb") as f:
        f.write(data)
    return path


def lower_dir():
    if not HOST:
        return "/usr/local/lib/python3.13/email"
    d = "/tmp/gtfs4_lower/email"
    if not os.path.isdir(d):
        import shutil
        shutil.copytree(os.path.dirname(os.__file__) + "/email", d)
    return d


def lower_file():
    if not HOST:
        return "/etc/profile"
    d = "/tmp/gtfs4_lower"
    os.makedirs(d, exist_ok=True)
    f = d + "/profile"
    if not os.path.exists(f):
        mk(f, open("/etc/profile", "rb").read())
    return f


# ----------------------------------------------------------- leftovers from fs3
def t_relative_symlink_target():
    os.mkdir(p("rl")); os.mkdir(p("rl", "sub"))
    os.symlink("target_rel", p("rl", "sub", "link"))
    old = os.getcwd(); os.chdir(BASE)
    fd = os.open(p("rl", "sub", "link"), os.O_CREAT | os.O_WRONLY, 0o600); os.close(fd)
    created_next_to_link = os.path.exists(p("rl", "sub", "target_rel"))
    created_in_cwd = os.path.exists(p("target_rel"))
    mk(p("rl", "sub", "real"), b"R"); os.symlink("real", p("rl", "sub", "l2"))
    data = open(p("rl", "sub", "l2"), "rb").read().decode()
    os.chdir(old)
    return "next_to_link=%s in_cwd=%s read_rel=%s" % (created_next_to_link, created_in_cwd, data)


def t_symlink_mid_path():
    os.mkdir(p("mp")); os.mkdir(p("mp", "dir")); mk(p("mp", "dir", "c"), b"C")
    os.symlink(p("mp", "dir"), p("mp", "dlink"))
    os.symlink("dir", p("mp", "rlink"))
    out = []
    for name, path in [("abs", p("mp", "dlink", "c")), ("rel", p("mp", "rlink", "c"))]:
        out.append("%s_stat=%s" % (name, err(lambda: os.stat(path).st_size)))
        out.append("%s_open=%s" % (name, err(lambda: open(path, "rb").read().decode())))
    out.append("create_via=%s" % err(lambda: os.close(os.open(p("mp", "dlink", "new"), os.O_CREAT | os.O_WRONLY, 0o600))))
    out.append("new_in_dir=%s" % os.path.exists(p("mp", "dir", "new")))
    out.append("listdir_via=%s" % err(lambda: ",".join(sorted(os.listdir(p("mp", "dlink"))))))
    return " ".join(out)


def t_lower_dir_utime_listing():
    d = lower_dir(); before = sorted(os.listdir(d))
    os.utime(d, (3_000_000, 3_000_000))
    after = sorted(os.listdir(d))
    return "entries_kept=%s mtime=%d" % (after == before, os.stat(d).st_mtime)


def t_lower_dir_new_file_listing():
    d = lower_dir(); before = set(os.listdir(d))
    mk(os.path.join(d, "zz_new_file"))
    after = set(os.listdir(d))
    return "old_kept=%s new_listed=%s" % (before <= after, "zz_new_file" in after)


def t_append_start_position():
    fd = os.open(mk(p("ap"), b"0123"), os.O_RDWR | os.O_APPEND)
    pos0 = os.lseek(fd, 0, os.SEEK_CUR)
    first = os.read(fd, 2)
    os.write(fd, b"X")
    pos1 = os.lseek(fd, 0, os.SEEK_CUR)
    return "start=%d read=%s after_write=%d" % (pos0, first.decode(), pos1)


def t_fifo_no_reader():
    os.mkfifo(p("ff"))
    return "wronly_nonblock=%s rdwr_nonblock=%s" % (
        err(lambda: os.open(p("ff"), os.O_WRONLY | os.O_NONBLOCK)),
        err(lambda: os.open(p("ff"), os.O_RDWR | os.O_NONBLOCK)))


# -------------------------------------------------------------------- xattrs
def t_xattr_new_file():
    f = mk(p("xa"))
    out = ["set=%s" % err(lambda: os.setxattr(f, "user.k", b"v1"))]
    out.append("get=%s" % err(lambda: os.getxattr(f, "user.k").decode()))
    out.append("list=%s" % err(lambda: ",".join(sorted(os.listxattr(f)))))
    out.append("create_exists=%s" % err(lambda: os.setxattr(f, "user.k", b"v2", os.XATTR_CREATE)))
    out.append("replace_missing=%s" % err(lambda: os.setxattr(f, "user.none", b"v", os.XATTR_REPLACE)))
    out.append("remove=%s" % err(lambda: os.removexattr(f, "user.k")))
    out.append("get_removed=%s" % err(lambda: os.getxattr(f, "user.k")))
    out.append("bad_ns=%s" % err(lambda: os.setxattr(f, "bogus.k", b"v")))
    return " ".join(out)


def t_xattr_lower_file():
    f = lower_file()
    return "set=%s get=%s data_ok=%s" % (
        err(lambda: os.setxattr(f, "user.k", b"v")),
        err(lambda: os.getxattr(f, "user.k").decode()),
        len(open(f, "rb").read()) > 0)


# --------------------------------------------------------------------- locks
def t_flock_two_processes():
    f = mk(p("lk"))
    a = os.open(f, os.O_RDWR)
    fcntl.flock(a, fcntl.LOCK_EX)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        b = os.open(f, os.O_RDWR)
        try:
            fcntl.flock(b, fcntl.LOCK_EX | fcntl.LOCK_NB); res = b"got"
        except OSError as x:
            res = errno.errorcode[x.errno].encode()
        os.write(w, res); os._exit(0)
    os.waitpid(pid, 0)
    child = os.read(r, 20).decode()
    fcntl.flock(a, fcntl.LOCK_UN)
    return "other_process_nb=%s" % child


def t_posix_lock_two_processes():
    f = mk(p("pl"), b"x" * 100)
    a = os.open(f, os.O_RDWR)
    fcntl.lockf(a, fcntl.LOCK_EX, 10, 0)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        b = os.open(f, os.O_RDWR)
        out = []
        for name, start in [("overlap", 5), ("disjoint", 50)]:
            try:
                fcntl.lockf(b, fcntl.LOCK_EX | fcntl.LOCK_NB, 10, start); out.append(name + "=got")
            except OSError as x:
                out.append(name + "=" + errno.errorcode[x.errno])
        os.write(w, " ".join(out).encode()); os._exit(0)
    os.waitpid(pid, 0)
    return os.read(r, 100).decode()


def t_ofd_lock():
    f = mk(p("ofd"), b"x" * 100)
    a = os.open(f, os.O_RDWR); b = os.open(f, os.O_RDWR)
    F_OFD_SETLK = 37
    lk = struct.pack("hhqqi", fcntl.F_WRLCK, 0, 0, 10, 0)
    ra = err(lambda: fcntl.fcntl(a, F_OFD_SETLK, lk))
    rb = err(lambda: fcntl.fcntl(b, F_OFD_SETLK, lk))
    return "first=%s second_same_process=%s" % (ra if ra == "0" or len(ra) > 6 else ra, rb if len(rb) < 12 else "0")


# ------------------------------------------------------------- mmap coherence
def t_mmap_write_coherence():
    f = mk(p("mm"), b"a" * 4096)
    fd = os.open(f, os.O_RDWR)
    m = mmap.mmap(fd, 4096, mmap.MAP_SHARED)
    os.pwrite(fd, b"W", 10)
    seen_in_map = m[10:11] == b"W"
    m[20:21] = b"M"
    seen_by_read = os.pread(fd, 1, 20) == b"M"
    other = os.open(f, os.O_RDONLY)
    seen_other_fd = os.pread(other, 1, 20) == b"M"
    m.close()
    return "write_seen_in_map=%s map_seen_by_read=%s map_seen_other_fd=%s" % (seen_in_map, seen_by_read, seen_other_fd)


def t_mmap_truncate_sigbus():
    f = mk(p("mt"), b"a" * 8192)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        fd = os.open(f, os.O_RDWR)
        m = mmap.mmap(fd, 8192, mmap.MAP_SHARED)
        os.ftruncate(fd, 100)
        os.write(w, b"before")
        _ = m[5000]
        os.write(w, b" read_ok"); os._exit(0)
    _, status = os.waitpid(pid, 0)
    msg = os.read(r, 50).decode()
    return "%s signal=%s" % (msg, os.WTERMSIG(status) if os.WIFSIGNALED(status) else "none")


# ------------------------------------------------------------ directories/inodes
def t_large_directory():
    d = p("big"); os.mkdir(d)
    for i in range(2000):
        mk(os.path.join(d, "f%04d" % i), b"")
    names = os.listdir(d)
    return "count=%d unique=%d" % (len(names), len(set(names)))


def t_unlink_during_readdir():
    d = p("ud"); os.mkdir(d)
    for i in range(300):
        mk(os.path.join(d, "e%03d" % i), b"")
    seen = []
    with os.scandir(d) as it:
        for i, de in enumerate(it):
            seen.append(de.name)
            if i == 10:
                for j in range(150, 300):
                    os.unlink(os.path.join(d, "e%03d" % j))
    dup = len(seen) - len(set(seen))
    return "duplicates=%d remaining=%d" % (dup, len(os.listdir(d)))


def t_inode_numbers():
    a = mk(p("ia")); b = mk(p("ib"))
    ia, ib = os.stat(a).st_ino, os.stat(b).st_ino
    fd = os.open(a, os.O_RDONLY); held = os.fstat(fd).st_ino
    os.unlink(a)
    c = mk(p("ic"))
    ic = os.stat(c).st_ino
    dev_same = os.stat(b).st_dev == os.stat(BASE).st_dev
    return "distinct=%s reused_while_open=%s fstat_stable=%s dev_same=%s" % (
        ia != ib, ic == held, os.fstat(fd).st_ino == ia, dev_same)


def t_inode_stable_across_copy_up():
    f = lower_file()
    before = os.stat(f).st_ino
    with open(f, "ab") as h:
        h.write(b"\n# x\n")
    return "ino_same=%s" % (os.stat(f).st_ino == before)


def t_deleted_cwd():
    d = p("dc"); os.mkdir(d); old = os.getcwd(); os.chdir(d); os.rmdir(d)
    out = ["getcwd=%s" % err(lambda: os.getcwd())]
    out.append("create_in_deleted=%s" % err(lambda: os.close(os.open("x", os.O_CREAT | os.O_WRONLY, 0o600))))
    out.append("listdir_dot=%s" % err(lambda: len(os.listdir("."))))
    os.chdir(old)
    return " ".join(out)


def t_fd_after_rename():
    os.mkdir(p("fr")); f = mk(p("fr", "a"), b"data")
    fd = os.open(f, os.O_RDWR)
    os.rename(p("fr"), p("fr2"))
    os.write(fd, b"XY")
    link = os.readlink("/proc/self/fd/%d" % fd)
    return "content=%s proc_link=%s" % (open(p("fr2", "a"), "rb").read().decode(), link.replace(BASE, "B"))


def t_proc_fd_deleted():
    fd = os.open(mk(p("pd")), os.O_RDONLY)
    os.unlink(p("pd"))
    return "link=%s" % os.readlink("/proc/self/fd/%d" % fd).replace(BASE, "B")


def t_rename_over_open_file():
    a = mk(p("ro_a"), b"AAA"); b = mk(p("ro_b"), b"BBB")
    fd = os.open(b, os.O_RDONLY)
    os.rename(a, b)
    return "old_fd_reads=%s path_reads=%s" % (os.read(fd, 3).decode(), open(b, "rb").read().decode())


def t_statx():
    f = mk(p("sx"), b"12345")
    buf = ctypes.create_string_buffer(256)
    r = sc(332, -100, f.encode(), 0, 0xfff, buf)  # STATX_ALL | BTIME
    if r < 0:
        return e(r)
    mask = struct.unpack_from("I", buf, 0)[0]
    size = struct.unpack_from("Q", buf, 40)[0]
    return "mask_basic=%s btime=%s size=%d" % (mask & 0x7ff == 0x7ff, bool(mask & 0x800), size)


def t_openat2_resolve():
    os.mkdir(p("o2")); mk(p("o2", "f")); os.symlink("/etc/hostname", p("o2", "abs")); os.symlink("../o2/f", p("o2", "up"))
    dfd = os.open(p("o2"), os.O_RDONLY | os.O_DIRECTORY)
    def oa2(path, resolve):
        how = struct.pack("QQQ", os.O_RDONLY, 0, resolve)
        b = ctypes.create_string_buffer(how)
        r = sc(437, dfd, path.encode(), b, len(how))
        if r >= 0:
            os.close(r); return "0"
        return e(r)[1:]
    return "beneath_dotdot=%s beneath_abs_link=%s no_symlinks=%s no_xdev_ok=%s in_root_abs=%s" % (
        oa2("../o2/f", 0x08), oa2("abs", 0x08), oa2("up", 0x04), oa2("f", 0x01), oa2("abs", 0x10))


def t_unix_socket_file():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(p("sock"))
    st = os.lstat(p("sock"))
    again = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    rebind = err(lambda: again.bind(p("sock")))
    return "is_sock=%s rebind=%s listed=%s" % (stat.S_ISSOCK(st.st_mode), rebind, "sock" in os.listdir(BASE))


def t_mknod_devices():
    out = []
    for name, mode in [("chr", stat.S_IFCHR | 0o600), ("reg", stat.S_IFREG | 0o600), ("fifo", stat.S_IFIFO | 0o600)]:
        out.append("%s=%s" % (name, err(lambda: os.mknod(p("mn_" + name), mode, os.makedev(1, 3)))))
    return " ".join(out)


def t_odirectory_ocreat():
    return "creat_dir_flag=%s" % err(lambda: os.open(p("odc"), os.O_CREAT | os.O_DIRECTORY | os.O_RDWR, 0o600))


def t_two_writers_append():
    f = mk(p("tw"), b"")
    pids = []
    for c in (b"a", b"b"):
        pid = os.fork()
        if pid == 0:
            fd = os.open(f, os.O_WRONLY | os.O_APPEND)
            for _ in range(200):
                os.write(fd, c * 10)
            os._exit(0)
        pids.append(pid)
    for pid in pids:
        os.waitpid(pid, 0)
    data = open(f, "rb").read()
    return "size=%d a=%d b=%d" % (len(data), data.count(b"a"), data.count(b"b"))


def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True); os.makedirs(BASE)
    if HOST:
        shutil.rmtree("/tmp/gtfs4_lower", ignore_errors=True)
    for n in sorted(k for k in globals() if k.startswith("t_")):
        run(n[2:], globals()[n])
    print("GT_DONE", flush=True)


if __name__ == "__main__":
    main()
