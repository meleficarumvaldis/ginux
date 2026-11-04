"""Probe 30: file locks between processes and open file descriptions.

POSIX record locks (F_SETLK/F_SETLKW/F_GETLK), OFD locks (F_OFD_*) and
flock(2): conflicts, ranges (overlap, adjacent, split, merge, unlock of a
middle part), F_GETLK fields, release on close of ANY descriptor of the file,
fork/dup semantics, flock upgrade/downgrade, OFD vs POSIX interaction, access
mode checks and blocking waits.

Prints 'GT <name> <result>'. Run on Linux with GT_HOST=1 (the image file is
then a copy in /tmp).
"""
import ctypes, errno, fcntl, os, select, signal, struct, sys, time

HOST = os.environ.get("GT_HOST") == "1"
BASE = "/tmp/gt30"
F_RDLCK, F_WRLCK, F_UNLCK = 0, 1, 2
F_GETLK, F_SETLK, F_SETLKW = 5, 6, 7
F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW = 36, 37, 38
TYPES = {0: "R", 1: "W", 2: "U"}
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def sc(nr, *args):
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])
    return -ctypes.get_errno() if r == -1 else r


def en(v):
    return "0" if v == 0 else errno.errorcode.get(-v, str(-v)) if isinstance(v, int) and v < 0 else str(v)


def lk(fd, cmd, typ, start=0, length=0, whence=0, pid=0):
    """fcntl lock call; returns (result, (type, whence, start, len, pid))."""
    buf = struct.pack("hhqqi4x", typ, whence, start, length, pid)
    try:
        out = fcntl.fcntl(fd, cmd, buf)
    except OSError as x:
        return errno.errorcode.get(x.errno, str(x.errno)), None
    return "0", struct.unpack("hhqqi4x", out)


def st(fd, cmd, typ, start=0, length=0, whence=0, pid=0):
    return lk(fd, cmd, typ, start, length, whence, pid)[0]


def fl(fd, op):
    try:
        fcntl.flock(fd, op)
        return "0"
    except OSError as x:
        return errno.errorcode.get(x.errno, str(x.errno))


def getlk(fd, typ, start=0, length=0, cmd=F_GETLK, owner=None):
    r, f = lk(fd, cmd, typ, start, length)
    if f is None:
        return r
    t, w, s, l, pid = f
    who = "unlocked" if t == F_UNLCK else ("owner" if pid == owner else "pid=%d" % pid if pid in (0, -1) else "other")
    return "%s/w%d/%d+%d/%s" % (TYPES.get(t, t), w, s, l, who)


def in_child(fn, limit=10.0):
    """Run fn() in a forked child, return its string result."""
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
    data = b""
    while True:
        chunk = os.read(r, 300)
        if not chunk:
            break
        data += chunk
    os.close(r)
    os.waitpid(pid, 0)
    return data.decode()


def run(name, fn, limit=20.0):
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


def mk(name, size=100):
    path = os.path.join(BASE, name)
    with open(path, "wb") as f:
        f.write(b"x" * size)
    return path


def rw(path):
    return os.open(path, os.O_RDWR)


# ------------------------------------------------------------ POSIX locks
def t_posix_overlap_adjacent():
    f = mk("p1"); a = rw(f)
    st(a, F_SETLK, F_WRLCK, 0, 10)
    def child():
        b = rw(f)
        return "overlap=%s adjacent=%s disjoint=%s read_inside=%s" % (
            st(b, F_SETLK, F_WRLCK, 5, 10), st(b, F_SETLK, F_WRLCK, 10, 10),
            st(b, F_SETLK, F_WRLCK, 50, 10), st(b, F_SETLK, F_RDLCK, 9, 1))
    return in_child(child)


def t_posix_read_shared():
    f = mk("p2"); a = rw(f)
    st(a, F_SETLK, F_RDLCK, 0, 10)
    def child():
        b = rw(f)
        return "read=%s write=%s" % (st(b, F_SETLK, F_RDLCK, 0, 10), st(b, F_SETLK, F_WRLCK, 0, 10))
    return in_child(child)


def t_posix_getlk_fields():
    f = mk("p3"); a = rw(f); me = os.getpid()
    st(a, F_SETLK, F_WRLCK, 10, 10)
    st(a, F_SETLK, F_RDLCK, 40, 0)
    def child():
        b = rw(f)
        free = lk(b, F_GETLK, F_WRLCK, 25, 5, whence=0, pid=4242)[1]
        return "conflict=%s eof_lock=%s read_vs_read=%s free_raw=%s self=%s" % (
            getlk(b, F_WRLCK, 0, 100, owner=me), getlk(b, F_WRLCK, 30, 0, owner=me),
            getlk(b, F_RDLCK, 40, 5, owner=me), free, getlk(a, F_WRLCK, 0, 0, owner=me))
    return in_child(child)


def t_posix_split_unlock_middle():
    f = mk("p4"); a = rw(f); me = os.getpid()
    st(a, F_SETLK, F_WRLCK, 0, 100)
    st(a, F_SETLK, F_UNLCK, 40, 20)
    def child():
        b = rw(f)
        return "middle=%s left=%s right=%s first=%s after_middle=%s" % (
            st(b, F_SETLK, F_WRLCK, 40, 20), st(b, F_SETLK, F_WRLCK, 30, 10),
            st(b, F_SETLK, F_WRLCK, 60, 10), getlk(b, F_WRLCK, 0, 0, owner=me),
            getlk(b, F_WRLCK, 45, 0, owner=me))
    return in_child(child)


def t_posix_merge_adjacent():
    f = mk("p5"); a = rw(f); me = os.getpid()
    st(a, F_SETLK, F_WRLCK, 0, 10); st(a, F_SETLK, F_WRLCK, 10, 10)
    st(a, F_SETLK, F_WRLCK, 30, 10); st(a, F_SETLK, F_WRLCK, 25, 10)
    return in_child(lambda: "first=%s second=%s" % (
        getlk(rw(f), F_WRLCK, 0, 0, owner=me), getlk(rw(f), F_WRLCK, 21, 0, owner=me)))


def t_posix_downgrade_part():
    f = mk("p6"); a = rw(f); me = os.getpid()
    st(a, F_SETLK, F_WRLCK, 0, 20); st(a, F_SETLK, F_RDLCK, 5, 5)
    def child():
        b = rw(f)
        return "read_mid=%s read_left=%s getlk_read=%s getlk_write=%s" % (
            st(b, F_SETLK, F_RDLCK, 5, 5), st(b, F_SETLK, F_RDLCK, 0, 1),
            getlk(b, F_RDLCK, 0, 0, owner=me), getlk(b, F_WRLCK, 5, 1, owner=me))
    return in_child(child)


def t_posix_negative_length():
    f = mk("p7"); a = rw(f); me = os.getpid()
    r = st(a, F_SETLK, F_WRLCK, 10, -5)
    return "set=%s seen=%s before_start=%s" % (r, in_child(lambda: getlk(rw(f), F_WRLCK, 0, 0, owner=me)),
                                               st(a, F_SETLK, F_WRLCK, 3, -5))


def t_posix_whence():
    f = mk("p8", 100); a = rw(f); me = os.getpid()
    os.lseek(a, 30, os.SEEK_SET)
    r1 = st(a, F_SETLK, F_WRLCK, 5, 5, whence=1)
    r2 = st(a, F_SETLK, F_WRLCK, -10, 5, whence=2)
    return "cur=%s end=%s seen=%s" % (r1, r2, in_child(lambda: getlk(rw(f), F_WRLCK, 0, 0, owner=me) + "," +
                                                       getlk(rw(f), F_WRLCK, 40, 0, owner=me)))


def t_posix_invalid_args():
    f = mk("p9"); a = rw(f)
    return "type=%s whence=%s negstart=%s neg_before_zero=%s getlk_unlck=%s" % (
        st(a, F_SETLK, 5, 0, 1), st(a, F_SETLK, F_WRLCK, 0, 1, whence=3),
        st(a, F_SETLK, F_WRLCK, -1, 1), st(a, F_SETLK, F_WRLCK, 0, -1),
        st(a, F_GETLK, F_UNLCK, 0, 1))


def t_posix_access_mode():
    f = mk("pa")
    ro = os.open(f, os.O_RDONLY); wo = os.open(f, os.O_WRONLY)
    return "read_on_wronly=%s write_on_rdonly=%s read_on_rdonly=%s write_on_wronly=%s unlock_on_rdonly=%s getlk_w_on_rdonly=%s" % (
        st(wo, F_SETLK, F_RDLCK, 0, 1), st(ro, F_SETLK, F_WRLCK, 0, 1),
        st(ro, F_SETLK, F_RDLCK, 0, 1), st(wo, F_SETLK, F_WRLCK, 10, 1),
        st(ro, F_SETLK, F_UNLCK, 0, 1), st(ro, F_GETLK, F_WRLCK, 0, 1))


def t_posix_same_owner_any_fd():
    f = mk("pb"); a = rw(f); b = rw(f)
    st(a, F_SETLK, F_WRLCK, 0, 10)
    return "relock_other_fd=%s getlk_self=%s" % (st(b, F_SETLK, F_WRLCK, 0, 10), getlk(b, F_WRLCK, 0, 10))


def t_posix_close_any_fd_releases():
    f = mk("pc"); a = rw(f); b = rw(f)
    st(a, F_SETLK, F_WRLCK, 0, 10)
    held = in_child(lambda: st(rw(f), F_SETLK, F_WRLCK, 0, 10))
    os.close(b)
    after = in_child(lambda: st(rw(f), F_SETLK, F_WRLCK, 0, 10))
    return "before_close=%s after_closing_other_fd=%s" % (held, after)


def t_posix_dup_close_releases():
    f = mk("pd"); a = rw(f); b = os.dup(a)
    st(a, F_SETLK, F_WRLCK, 0, 10)
    os.close(b)
    return "after_close_dup=%s" % in_child(lambda: st(rw(f), F_SETLK, F_WRLCK, 0, 10))


def t_posix_fork_not_inherited():
    f = mk("pe"); a = rw(f); me = os.getpid()
    st(a, F_SETLK, F_WRLCK, 0, 10)
    def child():
        r1 = st(a, F_SETLK, F_WRLCK, 0, 10)
        g = getlk(a, F_WRLCK, 0, 10, owner=me)
        u = st(a, F_SETLK, F_UNLCK, 0, 10)
        r2 = st(a, F_SETLK, F_WRLCK, 0, 10)
        os.close(a)
        return "child_inherited_fd=%s getlk=%s child_unlock=%s still=%s" % (r1, g, u, r2)
    c = in_child(child)
    return c + " parent_after=%s" % in_child(lambda: st(rw(f), F_SETLK, F_WRLCK, 0, 10))


def t_posix_released_on_exit():
    f = mk("pf")
    def child():
        st(rw(f), F_SETLK, F_WRLCK, 0, 10)
        return "locked"
    c = in_child(child)
    return "child=%s parent_after_exit=%s" % (c, st(rw(f), F_SETLK, F_WRLCK, 0, 10))


def t_posix_unlock_unlocked():
    f = mk("pg"); a = rw(f)
    return "unlock_free=%s" % st(a, F_SETLK, F_UNLCK, 0, 0)


def t_posix_setlkw_waits_for_parent():
    f = mk("ph"); a = rw(f)
    st(a, F_SETLK, F_WRLCK, 0, 10)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        b = rw(f)
        t0 = time.monotonic()
        res = st(b, F_SETLKW, F_WRLCK, 0, 10)
        os.write(w, ("%s waited=%s" % (res, time.monotonic() - t0 >= 0.4)).encode()); os._exit(0)
    time.sleep(0.6)
    st(a, F_SETLK, F_UNLCK, 0, 10)
    os.waitpid(pid, 0)
    return os.read(r, 100).decode()


def t_posix_setlkw_waits_for_child():
    f = mk("pi")
    r, w = os.pipe(); go_r, go_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        b = rw(f)
        st(b, F_SETLK, F_WRLCK, 0, 10)
        os.write(w, b"L")
        os.read(go_r, 1)
        time.sleep(0.6)
        st(b, F_SETLK, F_UNLCK, 0, 10)
        time.sleep(0.3)
        os._exit(0)
    os.read(r, 1)
    a = rw(f)
    nb = st(a, F_SETLK, F_WRLCK, 0, 10)
    os.write(go_w, b"G")
    t0 = time.monotonic()
    res = st(a, F_SETLKW, F_WRLCK, 0, 10)
    waited = time.monotonic() - t0
    os.waitpid(pid, 0)
    return "nonblocking=%s blocking=%s waited=%s" % (nb, res, waited >= 0.3)


def t_posix_setlkw_eintr():
    f = mk("pj"); a = rw(f)
    st(a, F_SETLK, F_WRLCK, 0, 10)
    def child():
        class Alarm(Exception):
            pass
        def handler(*_):
            raise Alarm()
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, 0.3)
        b = rw(f)
        try:
            return "setlkw=%s" % st(b, F_SETLKW, F_WRLCK, 0, 10)
        except Alarm:
            return "interrupted_by_signal"
    return in_child(child)


def t_posix_image_file():
    path = "/etc/profile" if not HOST else os.path.join(BASE, "profile")
    if HOST:
        with open(path, "wb") as fh:
            fh.write(open("/etc/profile", "rb").read())
    a = os.open(path, os.O_RDONLY); me = os.getpid()
    r = st(a, F_SETLK, F_RDLCK, 0, 0)
    def child():
        b = os.open(path, os.O_RDONLY)
        return "getlk_w=%s read=%s" % (getlk(b, F_WRLCK, 0, 0, owner=me), st(b, F_SETLK, F_RDLCK, 0, 0))
    return "parent_read=%s %s" % (r, in_child(child))


# --------------------------------------------------------------- OFD locks
def t_ofd_two_descriptions():
    f = mk("o1"); a = rw(f); b = rw(f)
    return "first=%s second_overlap=%s second_disjoint=%s getlk=%s" % (
        st(a, F_OFD_SETLK, F_WRLCK, 0, 10), st(b, F_OFD_SETLK, F_WRLCK, 5, 10),
        st(b, F_OFD_SETLK, F_WRLCK, 10, 10), getlk(b, F_WRLCK, 0, 0, cmd=F_OFD_GETLK))


def t_ofd_vs_posix_same_process():
    f = mk("o2"); a = rw(f); b = rw(f)
    st(a, F_OFD_SETLK, F_WRLCK, 0, 10)
    st(b, F_SETLK, F_WRLCK, 20, 10)
    return "posix_vs_ofd=%s ofd_vs_posix=%s posix_getlk=%s" % (
        st(b, F_SETLK, F_WRLCK, 0, 10), st(a, F_OFD_SETLK, F_WRLCK, 20, 10),
        getlk(b, F_WRLCK, 0, 0))


def t_ofd_pid_and_args():
    f = mk("o3"); a = rw(f)
    return "pid_nonzero=%s getlk_pid_nonzero=%s" % (
        st(a, F_OFD_SETLK, F_WRLCK, 0, 1, pid=1), st(a, F_OFD_GETLK, F_WRLCK, 0, 1, pid=1))


def t_ofd_fork_and_dup_shared():
    f = mk("o4"); a = rw(f); d = os.dup(a)
    st(a, F_OFD_SETLK, F_WRLCK, 0, 10)
    dup_res = st(d, F_OFD_SETLK, F_WRLCK, 0, 10)
    def child():
        return "child_inherited=%s child_own_open=%s" % (
            st(a, F_OFD_SETLK, F_WRLCK, 0, 10), st(rw(f), F_OFD_SETLK, F_WRLCK, 0, 10))
    return "dup=%s %s" % (dup_res, in_child(child))


def t_ofd_close_releases():
    f = mk("o5"); a = rw(f); d = os.dup(a); b = rw(f)
    st(a, F_OFD_SETLK, F_WRLCK, 0, 10)
    os.close(a)
    still = st(b, F_OFD_SETLK, F_WRLCK, 0, 10)
    os.close(d)
    return "after_first_close=%s after_last_close=%s" % (still, st(b, F_OFD_SETLK, F_WRLCK, 0, 10))


def t_ofd_survives_posix_close():
    f = mk("o6"); a = rw(f); c = rw(f); b = rw(f)
    st(a, F_OFD_SETLK, F_WRLCK, 0, 10)
    os.close(c)
    return "after_closing_other_fd=%s" % st(b, F_OFD_SETLK, F_WRLCK, 0, 10)


# --------------------------------------------------------------- flock(2)
def t_flock_other_process():
    f = mk("f1"); a = rw(f)
    r0 = fl(a, fcntl.LOCK_EX)
    held = in_child(lambda: "ex=%s sh=%s" % (fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB), fl(rw(f), fcntl.LOCK_SH | fcntl.LOCK_NB)))
    fl(a, fcntl.LOCK_UN)
    return "lock=%s other=%s after_unlock=%s" % (r0, held, in_child(lambda: fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB)))


def t_flock_shared():
    f = mk("f2"); a = rw(f)
    fl(a, fcntl.LOCK_SH)
    return in_child(lambda: "sh=%s ex=%s" % (fl(rw(f), fcntl.LOCK_SH | fcntl.LOCK_NB), fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB)))


def t_flock_same_process_two_opens():
    f = mk("f3"); a = rw(f); b = rw(f)
    fl(a, fcntl.LOCK_EX)
    return "second_open=%s same_fd_again=%s" % (fl(b, fcntl.LOCK_EX | fcntl.LOCK_NB), fl(a, fcntl.LOCK_EX | fcntl.LOCK_NB))


def t_flock_dup_shares():
    f = mk("f4"); a = rw(f); d = os.dup(a)
    fl(a, fcntl.LOCK_EX)
    r = fl(d, fcntl.LOCK_UN)
    return "unlock_via_dup=%s other_after=%s" % (r, in_child(lambda: fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB)))


def t_flock_fork_shares():
    f = mk("f5"); a = rw(f)
    fl(a, fcntl.LOCK_EX)
    c = in_child(lambda: "child_relock=%s child_unlock=%s" % (fl(a, fcntl.LOCK_EX | fcntl.LOCK_NB), fl(a, fcntl.LOCK_UN)))
    return "%s other_after=%s" % (c, fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB))


def t_flock_close_last_reference():
    f = mk("f6"); a = rw(f); d = os.dup(a)
    fl(a, fcntl.LOCK_EX)
    os.close(a)
    still = in_child(lambda: fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB))
    os.close(d)
    return "after_first_close=%s after_last_close=%s" % (still, in_child(lambda: fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB)))


def t_flock_child_close_keeps_lock():
    f = mk("f7"); a = rw(f)
    fl(a, fcntl.LOCK_EX)
    in_child(lambda: os.close(a))
    return "after_child_closed_inherited=%s" % fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB)


def t_flock_upgrade_downgrade():
    f = mk("f8"); a = rw(f)
    fl(a, fcntl.LOCK_EX)
    down = fl(a, fcntl.LOCK_SH)
    other_sh = in_child(lambda: fl(rw(f), fcntl.LOCK_SH | fcntl.LOCK_NB))
    up = fl(a, fcntl.LOCK_EX | fcntl.LOCK_NB)
    other_ex = in_child(lambda: fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB))
    return "downgrade=%s other_sh=%s upgrade=%s other_ex=%s" % (down, other_sh, up, other_ex)


def t_flock_failed_upgrade_drops_lock():
    f = mk("f9"); a = rw(f); b = rw(f)
    fl(a, fcntl.LOCK_SH); fl(b, fcntl.LOCK_SH)
    up = fl(a, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return "a_upgrade=%s b_upgrade_after=%s" % (up, fl(b, fcntl.LOCK_EX | fcntl.LOCK_NB))


def t_flock_vs_posix_independent():
    f = mk("fa"); a = rw(f); me = os.getpid()
    fl(a, fcntl.LOCK_EX)
    st(a, F_SETLK, F_WRLCK, 0, 10)
    return in_child(lambda: "posix_disjoint=%s posix_conflict=%s flock=%s" % (
        st(rw(f), F_SETLK, F_WRLCK, 20, 10), st(rw(f), F_SETLK, F_WRLCK, 0, 10),
        fl(rw(f), fcntl.LOCK_SH | fcntl.LOCK_NB)))


def t_flock_invalid():
    f = mk("fb"); a = rw(f)
    return "zero=%s nb_only=%s sh_ex=%s bad_fd=%s unlock_free=%s rdonly_ex=%s" % (
        en(sc(73, a, 0)), en(sc(73, a, 4)), en(sc(73, a, 3)), en(sc(73, 999, 2)),
        en(sc(73, a, 8)), en(sc(73, os.open(f, os.O_RDONLY), 2 | 4)))


def t_flock_blocking_waits():
    f = mk("fc")
    r, w = os.pipe(); go_r, go_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        b = rw(f)
        fl(b, fcntl.LOCK_EX)
        os.write(w, b"L")
        os.read(go_r, 1)
        time.sleep(0.6)
        fl(b, fcntl.LOCK_UN)
        time.sleep(0.3)
        os._exit(0)
    os.read(r, 1)
    a = rw(f)
    nb = fl(a, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.write(go_w, b"G")
    t0 = time.monotonic()
    res = fl(a, fcntl.LOCK_EX)
    waited = time.monotonic() - t0
    os.waitpid(pid, 0)
    return "nonblocking=%s blocking=%s waited=%s" % (nb, res, waited >= 0.3)


def t_flock_released_on_exit():
    f = mk("fd")
    in_child(lambda: fl(rw(f), fcntl.LOCK_EX))
    return "after_child_exit=%s" % fl(rw(f), fcntl.LOCK_EX | fcntl.LOCK_NB)


def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True); os.makedirs(BASE)
    only = sys.argv[1].split(",") if len(sys.argv) > 1 else None
    for n in sorted(k for k in globals() if k.startswith("t_")):
        if only and n[2:] not in only:
            continue
        run(n[2:], globals()[n])
    print("GT_DONE", flush=True)


if __name__ == "__main__":
    main()
