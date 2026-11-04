"""Issue 07 probe: futex/time ABI. Run on Linux (GT_HOST=1) and inside Ginux; diff the output.

Each line: GT <name> <result>. Results are raw syscall returns (negative errno names on error).
Every test runs in a forked child with a watchdog, so a hang only affects that test.
"""
import ctypes, errno, os, select, signal, struct, sys, threading, time

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
HOST = os.environ.get("GT_HOST") == "1"
NR = dict(nanosleep=35, getitimer=36, alarm=37, setitimer=38, futex=202, clock_nanosleep=230,
          timerfd_create=283, timerfd_settime=286)

FUTEX_WAIT, FUTEX_WAKE, FUTEX_FD, FUTEX_REQUEUE, FUTEX_CMP_REQUEUE, FUTEX_WAKE_OP = 0, 1, 2, 3, 4, 5
PRIV, CLOCK_RT = 128, 256
LLONG_MAX = 0x7FFFFFFFFFFFFFFF


def sc(name, *args):
    a = [ctypes.c_long(x) if isinstance(x, int) else x for x in args]
    r = libc.syscall(ctypes.c_long(NR[name]), *a)
    if r == -1:
        e = ctypes.get_errno()
        return "-" + errno.errorcode.get(e, str(e))
    return r


def out(name, value):
    print("GT", name, value, flush=True)


KEEP = []


def ts(sec, nsec):
    buf = ctypes.create_string_buffer(struct.pack("qq", sec, nsec), 16)
    KEEP.append(buf)  # keep alive: callers pass only its address
    return ctypes.addressof(buf)


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
    os.waitpid(pid, 0)
    os.close(r)
    out(name, res or "EMPTY")


def blocks(fn, window=1.5):
    """'BLOCKED' if fn() is still running after window seconds, else its result.

    fn runs in a thread and the watchdog is a sleeping sibling thread of the same
    process: Ginux runs a forked child until it blocks, so a watchdog in another
    process would never get the CPU while the child idles.
    """
    def probe():
        result = []
        worker = threading.Thread(target=lambda: result.append(fn()), daemon=True)
        worker.start()
        time.sleep(window)
        return result[0] if result else "BLOCKED"
    return probe


word = (ctypes.c_int * 2)(0, 0)
addr = ctypes.addressof(word)


def futex(op, val=0, timeout=0, uaddr2=0, val3=0, uaddr=None):
    return sc("futex", addr if uaddr is None else uaddr, op, val, timeout, uaddr2, val3)


def with_word(value, fn):
    def wrapped():
        word[0] = value
        return fn()
    return wrapped


# ---------------- futex op dispatch ----------------
run("futex_requeue_private", lambda: futex(FUTEX_REQUEUE | PRIV, 0, 1, addr + 4))
run("futex_cmp_requeue_private", lambda: futex(FUTEX_CMP_REQUEUE | PRIV, 0, 1, addr + 4, 0))
run("futex_cmp_requeue_mismatch", lambda: futex(FUTEX_CMP_REQUEUE | PRIV, 0, 1, addr + 4, 7))
run("futex_cmp_requeue_shared", lambda: futex(FUTEX_CMP_REQUEUE, 0, 1, addr + 4, 0))
run("futex_requeue_negative_nr", lambda: futex(FUTEX_REQUEUE | PRIV, 0, 0xFFFFFFFF, addr + 4))
run("futex_requeue_misaligned_uaddr2", lambda: futex(FUTEX_REQUEUE | PRIV, 0, 1, addr + 2))
run("futex_op_fd_unknown", lambda: futex(FUTEX_FD))
run("futex_op_14_unknown", lambda: futex(14 | PRIV))
run("futex_wake_op", lambda: futex(FUTEX_WAKE_OP | PRIV, 0, 0, addr + 4, 0))
run("futex_wake_clock_realtime", lambda: futex(FUTEX_WAKE | PRIV | CLOCK_RT, 1))

# ---------------- futex wait timeouts ----------------
run("futex_wait_timeout_alone", lambda: futex(FUTEX_WAIT | PRIV, 0, ts(0, 20_000_000)))
run("futex_wait_mismatch_bad_ts", with_word(1, lambda: futex(FUTEX_WAIT | PRIV, 0, ts(0, 2_000_000_000))))
run("futex_wait_mismatch_neg_ts", with_word(1, lambda: futex(FUTEX_WAIT | PRIV, 0, ts(-1, 0))))
run("futex_wait_mismatch_good_ts", with_word(1, lambda: futex(FUTEX_WAIT | PRIV, 0, ts(0, 1000))))
run("futex_wait_zero_ts", lambda: futex(FUTEX_WAIT | PRIV, 0, ts(0, 0)))
run("futex_wait_bitset_past", lambda: futex(9 | PRIV, 0, ts(0, 1), 0, 0xFFFFFFFF))
run("futex_wait_bitset_zero_bad_ts", lambda: futex(9 | PRIV, 0, ts(0, 2_000_000_000), 0, 0))


# ---------------- nanosleep / clock_nanosleep ----------------
run("nanosleep_bad_rmtp", lambda: sc("nanosleep", ts(0, 1_000_000), 8))
run("nanosleep_bad_ts", lambda: sc("nanosleep", ts(0, 1_000_000_000), 0))


def nanosleep_bad_rmtp_interrupted():
    signal.signal(signal.SIGALRM, lambda *a: None)
    signal.setitimer(signal.ITIMER_REAL, 0.1)
    return sc("nanosleep", ts(2, 0), 8)


run("nanosleep_bad_rmtp_interrupted", nanosleep_bad_rmtp_interrupted)
for clock, label in [(7, "boottime"), (11, "tai"), (4, "monotonic_raw"), (5, "realtime_coarse"),
                     (6, "monotonic_coarse"), (3, "thread_cputime"), (12, "invalid12"), (99, "invalid99")]:
    run("clock_nanosleep_" + label, lambda c=clock: sc("clock_nanosleep", c, 0, ts(0, 1_000_000), 0))
run("clock_nanosleep_flag2", lambda: sc("clock_nanosleep", 1, 2, ts(0, 1_000_000), 0))
run("clock_nanosleep_raw_bad_ts", lambda: sc("clock_nanosleep", 4, 0, ts(0, 2_000_000_000), 0))
run("clock_nanosleep_abs_realtime_past", lambda: sc("clock_nanosleep", 0, 1, ts(1, 0), 0))

# ---------------- itimers / alarm ----------------
def setitimer_huge():
    spec = ctypes.create_string_buffer(struct.pack("qqqq", 0, 0, LLONG_MAX, 0), 32)
    r = sc("setitimer", 0, ctypes.addressof(spec), 0)
    off = ctypes.create_string_buffer(32)
    sc("setitimer", 0, ctypes.addressof(off), 0)
    return r


run("setitimer_huge", setitimer_huge)


def alarm_rounding():
    sc("alarm", 2)
    time.sleep(0.7)
    return sc("alarm", 0)  # 1.3 s left: Linux rounds to nearest -> 1


run("alarm_round_nearest", alarm_rounding)


def alarm_subsecond():
    sc("alarm", 1)
    time.sleep(0.8)
    return sc("alarm", 0)  # 0.2 s left: never reported as 0 -> 1


run("alarm_round_subsecond", alarm_subsecond)

# ---------------- timerfd ----------------
def timerfd_read(count):
    def test():
        fd = sc("timerfd_create", 1, 0)
        its = ctypes.create_string_buffer(struct.pack("qqqq", 0, 0, 0, 1_000_000), 32)
        sc("timerfd_settime", fd, 0, ctypes.addressof(its), 0)
        time.sleep(0.02)
        try:
            return len(os.read(fd, count))
        except OSError as exc:
            return "-" + errno.errorcode[exc.errno]
        finally:
            os.close(fd)
    return test


run("timerfd_read_64", timerfd_read(64))
run("timerfd_read_8", timerfd_read(8))
run("timerfd_read_4", timerfd_read(4))


def timerfd_settime_flags(flags, fd_override=None, spec=(0, 0, 999999, 0)):
    def test():
        fd = sc("timerfd_create", 1, 0)
        its = ctypes.create_string_buffer(struct.pack("qqqq", *spec), 32)
        r = sc("timerfd_settime", fd if fd_override is None else fd_override, flags,
               ctypes.addressof(its), 0)
        os.close(fd)
        return r
    return test


run("timerfd_cancel_on_set_mono", timerfd_settime_flags(1 | 2))
run("timerfd_cancel_on_set_relative", timerfd_settime_flags(2))
run("timerfd_unknown_flag", timerfd_settime_flags(4))
run("timerfd_badfd_unknown_flag", timerfd_settime_flags(4, fd_override=999))
run("timerfd_badfd_bad_spec", timerfd_settime_flags(0, fd_override=999, spec=(0, 0, 0, 2_000_000_000)))
run("timerfd_badfd_ok", timerfd_settime_flags(0, fd_override=999))
run("timerfd_huge_relative", timerfd_settime_flags(0, spec=(0, 0, LLONG_MAX, 0)))

# ---------------- tests that need threads ----------------
# Ginux cannot start threads in a forked child, so these run in the main
# process, last. blocks() leaves its worker parked forever; the probe exits
# with os._exit() so that cannot hold it up.
def run_inline(name, fn):
    try:
        out(name, fn())
    except Exception as exc:
        out(name, "EXC:" + type(exc).__name__ + ":" + str(exc)[:60])


def requeue_with_waiters(wake, requeue, expected_val3=0):
    """Two threads wait on word[0]; CMP_REQUEUE moves/wakes them; wake the rest on word[1]."""
    def test():
        word[0] = 0
        word[1] = 0
        results = []

        def waiter():
            results.append(futex(FUTEX_WAIT | PRIV, 0))

        threads = [threading.Thread(target=waiter) for _ in range(2)]
        for t in threads:
            t.start()
        time.sleep(0.5)
        r = futex(FUTEX_CMP_REQUEUE | PRIV, wake, requeue, addr + 4, expected_val3)
        time.sleep(0.2)
        woken_on_target = futex(FUTEX_WAKE | PRIV, 2, uaddr=addr + 4)
        leftover = futex(FUTEX_WAKE | PRIV, 2)
        for t in threads:
            t.join(2)
        alive = sum(t.is_alive() for t in threads)
        return "ret=%s target_wake=%s source_wake=%s waiter_rets=%s alive=%s" % (
            r, woken_on_target, leftover, sorted(map(str, results)), alive)
    return test


run_inline("futex_cmp_requeue_2_waiters_requeue2", requeue_with_waiters(0, 2))
run_inline("futex_cmp_requeue_2_waiters_wake1_requeue1", requeue_with_waiters(1, 1))
run_inline("futex_cmp_requeue_2_waiters_mismatch", requeue_with_waiters(0, 2, 5))

run_inline("futex_wait_huge_ts", blocks(lambda: futex(FUTEX_WAIT | PRIV, 0, ts(LLONG_MAX, 0), uaddr=addr + 4)))
run_inline("nanosleep_huge", blocks(lambda: sc("nanosleep", ts(LLONG_MAX, 0), 0)))
run_inline("clock_nanosleep_huge", blocks(lambda: sc("clock_nanosleep", 1, 0, ts(LLONG_MAX, 0), 0)))

print("GT_DONE", flush=True)

# `probe-07.py forever <nanosleep|clock_nanosleep|futex>`: after GT_DONE, block
# the (only) process forever. Ginux cannot start threads in this image and runs
# a forked child until it blocks, so this is the single-process check: a result
# line appearing right after "begin" means the call returned instead of blocking.
if len(sys.argv) == 3 and sys.argv[1] == "forever":
    kind = sys.argv[2]
    calls = {
        "nanosleep": lambda: sc("nanosleep", ts(LLONG_MAX, 0), 0),
        "clock_nanosleep": lambda: sc("clock_nanosleep", 1, 0, ts(LLONG_MAX, 0), 0),
        "futex": lambda: futex(FUTEX_WAIT | PRIV, 0, ts(LLONG_MAX, 0), uaddr=addr + 4),
    }
    out("forever_%s_begin" % kind, "")
    out("forever_%s_RETURNED" % kind, calls[kind]())
os._exit(0)
