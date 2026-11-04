"""Linux ABI divergence probe. Run on Linux (reference) and inside Ginux; diff the output.

Each line: GT <name> <result>. Results are raw syscall returns (negative errno names on error).
Set GT_HOST=1 to skip tests that are unsafe on a real host (kill(-1), image-layer mutation).
"""
import ctypes, errno, os, select, signal, struct, subprocess, sys, time

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
HOST = os.environ.get("GT_HOST") == "1"
NR = dict(mmap=9, mprotect=10, munmap=11, brk=12, rt_sigaction=13, rt_sigprocmask=14, mremap=25,
          msync=26, mincore=27, madvise=28, dup=32, nanosleep=35, kill=62, fcntl=72, setuid=105,
          getgroups=115, setgroups=116, rt_sigpending=127, rt_sigqueueinfo=129, sigaltstack=131,
          sched_setscheduler=144, futex=202, clock_nanosleep=230, wait4=61, waitid=247,
          timerfd_create=283, timerfd_settime=286, eventfd2=290, preadv2=327, getpid=39, newfstatat=262)


def sc(name, *args):
    a = [ctypes.c_long(x) if isinstance(x, int) else x for x in args]
    r = libc.syscall(ctypes.c_long(NR[name]), *a)
    if r == -1:
        e = ctypes.get_errno()
        return "-" + errno.errorcode.get(e, str(e))
    return r


def out(name, value):
    print("GT", name, value, flush=True)


def run(name, fn):
    try:
        out(name, fn())
    except Exception as exc:  # report, never abort the run
        out(name, "EXC:" + type(exc).__name__ + ":" + str(exc)[:60])


KEEP = []


def ts(sec, nsec):
    buf = ctypes.create_string_buffer(struct.pack("qq", sec, nsec), 16)
    KEEP.append(buf)  # keep alive: callers pass only its address
    return buf


os.makedirs("/tmp/gt", exist_ok=True)
os.chdir("/tmp/gt")

# ---------------- futex / time ----------------
word = (ctypes.c_int * 2)(0, 0)
addr = ctypes.addressof(word)
run("futex_requeue_private", lambda: sc("futex", addr, 3 | 128, 0, 1, addr + 4, 0))
run("futex_cmp_requeue_private", lambda: sc("futex", addr, 4 | 128, 0, 1, addr + 4, 0))
run("futex_op_fd_unknown", lambda: sc("futex", addr, 2, 0, 0, 0, 0))
run("futex_wake_val0_nowaiters", lambda: sc("futex", addr, 1 | 128, 0, 0, 0, 0))
run("futex_wait_timeout_alone", lambda: sc("futex", addr, 0 | 128, 0, ctypes.addressof(ts(0, 20_000_000)), 0, 0))
word[0] = 1
run("futex_wait_mismatch_bad_ts", lambda: sc("futex", addr, 0 | 128, 0, ctypes.addressof(ts(0, 2_000_000_000)), 0, 0))
word[0] = 0
run("nanosleep_bad_rmtp", lambda: sc("nanosleep", ctypes.addressof(ts(0, 1_000_000)), 8))
run("clock_nanosleep_boottime", lambda: sc("clock_nanosleep", 7, 0, ctypes.addressof(ts(0, 1_000_000)), 0))
run("clock_nanosleep_monotonic_raw", lambda: sc("clock_nanosleep", 4, 0, ctypes.addressof(ts(0, 1_000_000)), 0))
run("clock_nanosleep_flag2", lambda: sc("clock_nanosleep", 1, 2, ctypes.addressof(ts(0, 1_000_000)), 0))


def huge_sleep():
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        res = sc("nanosleep", ctypes.addressof(ts(0x7FFFFFFFFFFFFFFF, 0)), 0)
        os.write(w, str(res).encode())
        os._exit(0)
    os.close(w)
    ready, _, _ = select.select([r], [], [], 1.5)
    result = os.read(r, 64).decode() if ready else "BLOCKED"
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    return result


run("nanosleep_huge", huge_sleep)


def timerfd_read64():
    fd = sc("timerfd_create", 1, 0)
    its = ctypes.create_string_buffer(struct.pack("qqqq", 0, 0, 0, 1_000_000), 32)
    sc("timerfd_settime", fd, 0, ctypes.addressof(its), 0)
    time.sleep(0.02)
    try:
        return len(os.read(fd, 64))
    except OSError as exc:
        return "-" + errno.errorcode[exc.errno]
    finally:
        os.close(fd)


run("timerfd_read_64", timerfd_read64)


def timerfd_cancel_on_set_monotonic():
    fd = sc("timerfd_create", 1, 0)
    its = ctypes.create_string_buffer(struct.pack("qqqq", 0, 0, 999999, 0), 32)
    r = sc("timerfd_settime", fd, 1 | 2, ctypes.addressof(its), 0)
    os.close(fd)
    return r


run("timerfd_cancel_on_set_mono", timerfd_cancel_on_set_monotonic)

# ---------------- memory ----------------
PROT_R, PROT_W, PROT_X = 1, 2, 4
MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANON, MAP_NOREPLACE = 1, 2, 0x10, 0x20, 0x100000
with open("/tmp/gt/ro", "wb") as f:
    f.write(b"A" * 4096)
os.chmod("/tmp/gt/ro", 0o644)


def mmap_shared_rw_on_rdonly():
    fd = os.open("/tmp/gt/ro", os.O_RDONLY)
    r = sc("mmap", 0, 4096, PROT_R | PROT_W, MAP_SHARED, fd, 0)
    os.close(fd)
    return "ADDR" if isinstance(r, int) and r > 0 else r


run("mmap_shared_rw_rdonly_fd", mmap_shared_rw_on_rdonly)


def addr_or(r):
    return "ADDR" if isinstance(r, int) and r > 0 else r


run("mmap_rwx_anon", lambda: addr_or(sc("mmap", 0, 4096, 7, MAP_PRIVATE | MAP_ANON, -1, 0)))
run("mmap_wonly_anon", lambda: addr_or(sc("mmap", 0, 4096, PROT_W, MAP_PRIVATE | MAP_ANON, -1, 0)))
run("mmap_anon_fd0", lambda: addr_or(sc("mmap", 0, 4096, 3, MAP_PRIVATE | MAP_ANON, 0, 0)))
p = sc("mmap", 0, 8192, 3, MAP_PRIVATE | MAP_ANON, -1, 0)
run("mprotect_len0", lambda: sc("mprotect", p, 0, PROT_R))
run("mprotect_rwx", lambda: sc("mprotect", p, 4096, 7))
run("madvise_len0", lambda: sc("madvise", p, 0, 4))
run("msync_len0", lambda: sc("msync", p, 0, 4))
run("msync_unaligned", lambda: sc("msync", p + 1, 4096, 4))
vec = ctypes.create_string_buffer(4)
run("mincore_len0", lambda: sc("mincore", p, 0, ctypes.addressof(vec)))
q = sc("mmap", 0, 4096, 0, MAP_PRIVATE | MAP_ANON, -1, 0)
run("madvise_dontneed_protnone", lambda: sc("madvise", q, 4096, 4))
sc("munmap", q, 4096)
run("mremap_unmapped", lambda: sc("mremap", q, 4096, 8192, 1, 0))
free = sc("mmap", 0, 4096, 3, MAP_PRIVATE | MAP_ANON, -1, 0)
sc("munmap", free, 4096)
run("mmap_fixed_and_noreplace", lambda: addr_or(sc("mmap", free, 4096, 3, MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_NOREPLACE, -1, 0)))


def mremap_fixed_same_size():
    a = sc("mmap", 0, 4096, 3, MAP_PRIVATE | MAP_ANON, -1, 0)
    b = sc("mmap", 0, 4096, 3, MAP_PRIVATE | MAP_ANON, -1, 0)
    ctypes.c_char.from_address(a).value = b"X"
    r = sc("mremap", a, 4096, 4096, 1 | 2, b)
    moved = r == b and ctypes.c_char.from_address(b).value == b"X"
    return "MOVED" if moved else ("SAME" if r == a else r)


run("mremap_fixed_same_size", mremap_fixed_same_size)


def mmap_empty_file():
    fd = os.open("/tmp/gt/empty", os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
    r = sc("mmap", 0, 4096, PROT_R, MAP_PRIVATE, fd, 0)
    os.close(fd)
    return addr_or(r)


run("mmap_empty_file", mmap_empty_file)


def mmap_munmap_cycle():
    for i in range(600):
        r = sc("mmap", 0, 1 << 30, 3, MAP_PRIVATE | MAP_ANON | 0x4000, -1, 0)  # MAP_NORESERVE
        if not (isinstance(r, int) and r > 0):
            return "FAIL_AT_%d_%s" % (i, r)
        sc("munmap", r, 1 << 30)
    return "OK600"



# ---------------- signals ----------------
SIGCHLD, SIGUSR1 = 17, 10
hits = {"chld": 0, "usr1": 0}
signal.signal(signal.SIGCHLD, lambda *a: hits.__setitem__("chld", hits["chld"] + 1))


def sa_nocldstop():
    act = ctypes.create_string_buffer(32)
    sc("rt_sigaction", SIGCHLD, 0, ctypes.addressof(act), 8)
    handler, flags, restorer, mask = struct.unpack("QQQQ", act.raw)
    new = ctypes.create_string_buffer(struct.pack("QQQQ", handler, flags | 1, restorer, mask), 32)
    sc("rt_sigaction", SIGCHLD, ctypes.addressof(new), 0, 8)
    r = sc("kill", os.getpid(), SIGCHLD)
    after = sc("getpid")
    return "kill=%s handler=%d getpid_ok=%s" % (r, hits["chld"], isinstance(after, int) and after > 0)


run("sa_nocldstop_delivery", sa_nocldstop)
signal.signal(signal.SIGCHLD, signal.SIG_DFL)


def blocked_dfl_ignored_pending():
    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGCHLD])
    os.kill(os.getpid(), signal.SIGCHLD)
    got = signal.sigtimedwait([signal.SIGCHLD], 0)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGCHLD])
    return got.si_signo if got else "NONE"


run("blocked_default_ignored_queued", blocked_dfl_ignored_pending)


def ign_flushes_pending():
    signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1])
    os.kill(os.getpid(), signal.SIGUSR1)
    signal.signal(signal.SIGUSR1, signal.SIG_IGN)
    pending = signal.SIGUSR1 in signal.sigpending()
    signal.signal(signal.SIGUSR1, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGUSR1])
    return "pending=%s" % pending


r_ign, w_ign = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r_ign)
    try:
        res = ign_flushes_pending()
    except Exception as exc:
        res = "EXC:" + str(exc)
    os.write(w_ign, (res + " alive").encode())
    os._exit(0)
os.close(w_ign)
_, st = os.waitpid(pid, 0)
out("sig_ign_flushes_pending", (os.read(r_ign, 100).decode() or "child_died_sig%s" % (os.WTERMSIG(st) if os.WIFSIGNALED(st) else os.WEXITSTATUS(st))))


def sigqueueinfo_self_si_user():
    signal.signal(signal.SIGUSR1, lambda *a: hits.__setitem__("usr1", hits["usr1"] + 1))
    info = ctypes.create_string_buffer(128)
    struct.pack_into("iii", info, 0, SIGUSR1, 0, 0)  # si_code = SI_USER (0)
    r = sc("rt_sigqueueinfo", os.getpid(), SIGUSR1, ctypes.addressof(info))
    signal.signal(signal.SIGUSR1, signal.SIG_DFL)
    return r


run("rt_sigqueueinfo_self_si_user", sigqueueinfo_self_si_user)
run("rt_sigqueueinfo_sig0_null", lambda: sc("rt_sigqueueinfo", os.getpid(), 0, 0))


def resethand_readback():
    act = ctypes.create_string_buffer(32)
    sc("rt_sigaction", SIGUSR1, 0, ctypes.addressof(act), 8)
    signal.signal(signal.SIGUSR1, lambda *a: None)
    sc("rt_sigaction", SIGUSR1, 0, ctypes.addressof(act), 8)
    handler, flags, restorer, mask = struct.unpack("QQQQ", act.raw)
    new = ctypes.create_string_buffer(struct.pack("QQQQ", handler, flags | 0x80000000, restorer, mask | (1 << 11)), 32)
    sc("rt_sigaction", SIGUSR1, ctypes.addressof(new), 0, 8)
    os.kill(os.getpid(), SIGUSR1)
    sc("rt_sigaction", SIGUSR1, 0, ctypes.addressof(act), 8)
    h2, f2, r2, m2 = struct.unpack("QQQQ", act.raw)
    signal.signal(signal.SIGUSR1, signal.SIG_DFL)
    return "handler_dfl=%s flags_kept=%s mask_kept=%s" % (h2 == 0, bool(f2 & 0x80000000), bool(m2 & (1 << 11)))


run("sa_resethand_readback", resethand_readback)


def sigaltstack_onstack_flag():
    stack = ctypes.create_string_buffer(65536)
    ss = ctypes.create_string_buffer(struct.pack("QiiQ", ctypes.addressof(stack), 1, 0, 65536), 24)
    r = sc("sigaltstack", ctypes.addressof(ss), 0)
    off = ctypes.create_string_buffer(struct.pack("QiiQ", 0, 2, 0, 0), 24)
    sc("sigaltstack", ctypes.addressof(off), 0)
    return r


run("sigaltstack_ss_onstack_flag", sigaltstack_onstack_flag)
pend = ctypes.create_string_buffer(8)
run("rt_sigpending_size4", lambda: sc("rt_sigpending", ctypes.addressof(pend), 4))
run("kill_nonexistent_badsig", lambda: sc("kill", 999999, 999))

if not HOST:
    def kill_minus_one():
        signal.signal(signal.SIGUSR1, lambda *a: hits.__setitem__("usr1", hits["usr1"] + 100))
        before = hits["usr1"]
        r = sc("kill", -1, SIGUSR1)
        time.sleep(0.05)
        signal.signal(signal.SIGUSR1, signal.SIG_DFL)
        return "ret=%s caller_signaled=%s" % (r, hits["usr1"] != before)
    run("kill_minus1_excludes_caller", kill_minus_one)

# ---------------- process ----------------
def run_isolated(name, fn, limit=8.0):
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


run = run_isolated
if os.environ.get("GT_SKIP_EARLY") == "1":
    pass
def killed_child_status():
    pid = os.fork()
    if pid == 0:
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(5)
        os._exit(1)
    _, st = os.waitpid(pid, 0)
    return "WIFSIGNALED=%s sig=%s raw=%d" % (os.WIFSIGNALED(st), os.WTERMSIG(st) if os.WIFSIGNALED(st) else "-", st)


run("wait_killed_child", killed_child_status)


def waitid_wstopped_does_not_reap():
    pid = os.fork()
    if pid == 0:
        os._exit(3)
    time.sleep(0.3)
    info = ctypes.create_string_buffer(128)
    r = sc("waitid", 0, 0, ctypes.addressof(info), 2 | 1)  # P_ALL, WSTOPPED|WNOHANG
    si_pid = struct.unpack_from("i", info, 16)[0]
    try:
        rpid, st = os.waitpid(pid, 0)
        later = "reaped_later=%s" % (rpid == pid)
    except ChildProcessError:
        later = "ECHILD_later"
    return "ret=%s si_pid_set=%s %s" % (r, si_pid != 0, later)


run("waitid_wstopped_only", waitid_wstopped_does_not_reap)


def wait_wall():
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    time.sleep(0.2)
    st = ctypes.c_int(0)
    r = sc("wait4", pid, ctypes.addressof(st), 0x40000000, 0)
    if r != pid:
        os.waitpid(pid, 0)
    return "ok" if r == pid else r


run("wait4___WALL", wait_wall)
def rdonly_shared_write_reaches_file():
    with open("/tmp/gt/victim", "wb") as f:
        f.write(b"ORIG" + b"." * 4092)
    os.chmod("/tmp/gt/victim", 0o444)
    fd = os.open("/tmp/gt/victim", os.O_RDONLY)
    r = sc("mmap", 0, 4096, 3, 1, fd, 0)
    os.close(fd)
    if not (isinstance(r, int) and r > 0):
        return "mmap=%s" % r
    ctypes.memmove(r, b"PWN!", 4)
    sc("msync", r, 4096, 4)
    sc("munmap", r, 4096)
    return "file_now=%s" % open("/tmp/gt/victim", "rb").read(4)


run("rdonly_fd_shared_write_reaches_file", rdonly_shared_write_reaches_file)
run("argv0_preserved", lambda: subprocess.run(["-sh", "-c", "echo $0"], executable="/bin/sh", capture_output=True, text=True).stdout.strip())
param = ctypes.c_int(0)
run("sched_setscheduler_batch", lambda: sc("sched_setscheduler", 0, 3, ctypes.addressof(param)))
run("setuid_minus1", lambda: sc("setuid", -1 & 0xFFFFFFFF))

# ---------------- files ----------------
def preadv2_minus1():
    fd = os.open("/tmp/gt/ro", os.O_RDONLY)
    buf = ctypes.create_string_buffer(4)
    iov = ctypes.create_string_buffer(struct.pack("QQ", ctypes.addressof(buf), 4), 16)
    r = sc("preadv2", fd, ctypes.addressof(iov), 1, -1, -1, 0)
    os.close(fd)
    return r


run("preadv2_pos_minus1", preadv2_minus1)
run("preadv_4g_offset", lambda: (lambda fd: (os.preadv(fd, [bytearray(4)], 1 << 32), os.close(fd))[0])(os.open("/tmp/gt/ro", os.O_RDONLY)))
run("dup_eventfd", lambda: (lambda e: "ok" if isinstance(sc("dup", e), int) and sc("dup", e) > 0 else sc("dup", e))(sc("eventfd2", 0, 0)))
run("fcntl_getpipe_sz", lambda: sc("fcntl", os.pipe()[0], 1032, 0))
run("fcntl_setfl_largefile", lambda: sc("fcntl", os.pipe()[0], 4, os.O_NONBLOCK | 0o100000))
run("open_osync", lambda: "ok" if os.open("/tmp/gt/sync", os.O_WRONLY | os.O_CREAT | os.O_SYNC, 0o600) > 0 else "?")
run("open_rdonly_excl_nocreat", lambda: "ok" if os.open("/tmp/gt/ro", os.O_RDONLY | os.O_EXCL) > 0 else "?")


def open_creat_directory_side_effect():
    try:
        os.open("/tmp/gt/nd", os.O_CREAT | os.O_DIRECTORY, 0o600)
        res = "opened"
    except OSError as exc:
        res = "-" + errno.errorcode[exc.errno]
    return "%s exists_after=%s" % (res, os.path.exists("/tmp/gt/nd"))


run("open_creat_directory", open_creat_directory_side_effect)


def rename_same():
    with open("/tmp/gt/same", "w") as f:
        f.write("x")
    try:
        os.rename("/tmp/gt/same", "/tmp/gt/same")
        res = "0"
    except OSError as exc:
        res = "-" + errno.errorcode[exc.errno]
    return "%s exists_after=%s" % (res, os.path.exists("/tmp/gt/same"))


run("rename_same_file", rename_same)


def rename_file_over_emptydir():
    os.makedirs("/tmp/gt/edir", exist_ok=True)
    with open("/tmp/gt/f1", "w") as f:
        f.write("x")
    try:
        os.rename("/tmp/gt/f1", "/tmp/gt/edir")
        return "0"
    except OSError as exc:
        return "-" + errno.errorcode[exc.errno]


run("rename_file_over_emptydir", rename_file_over_emptydir)


def rmdir_nonempty():
    os.makedirs("/tmp/gt/ne", exist_ok=True)
    open("/tmp/gt/ne/x", "w").close()
    try:
        os.rmdir("/tmp/gt/ne")
        return "0"
    except OSError as exc:
        return "-" + errno.errorcode[exc.errno]


run("rmdir_nonempty_tmp", rmdir_nonempty)


def stat_symlink_follow():
    os.makedirs("/tmp/gt/realdir", exist_ok=True)
    if not os.path.lexists("/tmp/gt/ln"):
        os.symlink("/tmp/gt/realdir", "/tmp/gt/ln")
    import stat as st
    mode = os.stat("/tmp/gt/ln").st_mode
    return "dir" if st.S_ISDIR(mode) else ("link" if st.S_ISLNK(mode) else oct(mode))


run("stat_follows_symlink", stat_symlink_follow)


def stat_empty_path():
    try:
        os.stat("")
        return "0"
    except OSError as exc:
        return "-" + errno.errorcode[exc.errno]


run("stat_empty_path", stat_empty_path)

if not HOST:
    def creat_on_lower():
        before = open("/etc/os-release").read()
        fd = os.open("/etc/os-release", os.O_RDONLY | os.O_CREAT, 0o644)
        os.close(fd)
        return "content_kept=%s" % (open("/etc/os-release").read() == before)
    run("open_creat_on_lower_file", creat_on_lower)

    def rmdir_lower_nonempty():
        try:
            os.rmdir("/usr/share/ca-certificates")
            res = "0"
        except OSError as exc:
            res = "-" + errno.errorcode[exc.errno]
        return "%s exists_after=%s" % (res, os.path.isdir("/usr/share/ca-certificates"))
    run("rmdir_lower_nonempty", rmdir_lower_nonempty)

if os.environ.get("GT_BIG") == "1":
    run("mmap_munmap_1g_x600", mmap_munmap_cycle)

print("GT_DONE", flush=True)
