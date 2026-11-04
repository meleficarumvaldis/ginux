"""Probe 21: blocking TCP socket syscalls must block (not EAGAIN after a poll budget).

Each line: GT <name> <result> t=<elapsed seconds, 0.5 s resolution>.
Run on Linux (reference) with GT_HOST=1 and inside Ginux; diff the output.
"""
import errno, os, signal, socket, struct, sys, time

HOST = os.environ.get("GT_HOST") == "1"
DELAY = 3.0
# Ginux has no loopback interface; its TCP loopback is a connect to the
# guest's own address (10.0.2.15 under QEMU user networking).
LOCAL = "127.0.0.1" if HOST else os.environ.get("GT_LOCAL", "10.0.2.15")


def out(name, value):
    print("GT", name, value, flush=True)


def rounded(seconds):
    return "t=%.1f" % (round(seconds * 2) / 2)


def err(exc):
    return "-" + errno.errorcode.get(exc.errno, str(exc.errno)) if isinstance(exc, OSError) and exc.errno else type(exc).__name__


class Hang(Exception):
    pass


def on_alarm(signum, frame):
    raise Hang()


signal.signal(signal.SIGALRM, on_alarm)


def run(name, fn, limit=12):
    """Run fn in this process (Ginux forks of deep Python trees are fragile),
    with an alarm so a hang only costs this test."""
    signal.alarm(limit)
    try:
        res = str(fn())
    except Hang:
        res = "HANG(>%ss)" % limit
    except Exception as exc:
        res = "EXC:" + type(exc).__name__ + ":" + str(exc)[:60]
    finally:
        signal.alarm(0)
    out(name, res or "EMPTY")


def listener(flags=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM | flags)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LOCAL, 0))
    s.listen(4)
    return s


def timed(fn, start=None):
    start = time.monotonic() if start is None else start
    try:
        res = fn()
    except OSError as exc:
        res = err(exc)
    return "%s %s" % (res, rounded(time.monotonic() - start))


def report_from_child(fn):
    """Fork a child that runs fn; return (child pid, read end of its result pipe)."""
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
    return pid, r


def collect(pid, r):
    # Blocking read (Ginux lacks select() with a timeout); run()'s alarm
    # bounds a hang.
    try:
        res = os.read(r, 200).decode()
    except Hang:
        os.kill(pid, signal.SIGKILL)
        raise
    finally:
        os.close(r)
    os.waitpid(pid, 0)
    return res


# (1a) forked child blocks in accept; the parent connects after DELAY.
def accept_child_waits():
    s = listener()
    port = s.getsockname()[1]
    pid, r = report_from_child(lambda: timed(lambda: "accepted" if s.accept()[0] else "none"))
    time.sleep(DELAY)
    c = socket.create_connection((LOCAL, port))
    res = collect(pid, r)
    c.close()
    return res


# Control for (1a): the connection is already queued, so the child's accept
# does not block. Separates the blocking fix from Ginux fork/exit issues.
def accept_child_pending():
    s = listener()
    port = s.getsockname()[1]
    c = socket.create_connection((LOCAL, port))
    pid, r = report_from_child(lambda: timed(lambda: "accepted" if s.accept()[0] else "none"))
    res = collect(pid, r)
    c.close()
    return res


# (1b) the process itself blocks in accept; a forked child connects after DELAY.
def accept_parent_waits():
    s = listener()
    port = s.getsockname()[1]
    start = time.monotonic()
    pid = os.fork()
    if pid == 0:
        time.sleep(DELAY)
        c = socket.create_connection((LOCAL, port))
        time.sleep(1)
        c.close()
        os._exit(0)
    res = timed(lambda: "accepted" if s.accept()[0] else "none", start)
    os.waitpid(pid, 0)
    return res


def connected_pair():
    s = listener()
    c = socket.create_connection(s.getsockname())
    a, _ = s.accept()
    s.close()
    return a, c


# (2a) forked child blocks in recv; the parent sends after DELAY.
def recv_child_waits():
    a, c = connected_pair()
    pid, r = report_from_child(lambda: timed(lambda: a.recv(16)))
    time.sleep(DELAY)
    c.send(b"late")
    return collect(pid, r)


# (2b) the process itself blocks in recv; a forked child sends after DELAY.
def recv_parent_waits():
    a, c = connected_pair()
    start = time.monotonic()
    pid = os.fork()
    if pid == 0:
        time.sleep(DELAY)
        c.send(b"late")
        time.sleep(1)
        os._exit(0)
    res = timed(lambda: a.recv(16), start)
    os.waitpid(pid, 0)
    return res


# (3) SO_RCVTIMEO=1 s, no data: EAGAIN after about one second.
def recv_rcvtimeo():
    a, c = connected_pair()
    a.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 1, 0))
    return timed(lambda: a.recv(16))


def accept_rcvtimeo():
    s = listener()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 1, 0))
    return timed(lambda: s.accept())


# (4) nonblocking accept/recv with nothing pending: EAGAIN immediately.
def accept_nonblocking():
    s = listener(socket.SOCK_NONBLOCK)
    return timed(lambda: s.accept())


def recv_nonblocking():
    a, c = connected_pair()
    return timed(lambda: a.recv(16, socket.MSG_DONTWAIT))


# Reference for the restart mechanism this fix reuses: a forked child blocking
# in recv on a Unix socket (Ginux already restarts that syscall).
def unix_recv_child_waits():
    a, c = socket.socketpair()
    pid, r = report_from_child(lambda: timed(lambda: a.recv(16)))
    time.sleep(DELAY)
    c.send(b"late")
    return collect(pid, r)


TESTS = []
run_all = run


def run(name, fn):
    TESTS.append((name, fn))


run("unix_recv_child_blocks_until_data", unix_recv_child_waits)
run("accept_child_blocks_until_connect", accept_child_waits)
run("accept_child_pending_connection", accept_child_pending)
run("accept_blocks_until_connect", accept_parent_waits)
run("recv_child_blocks_until_data", recv_child_waits)
run("recv_blocks_until_data", recv_parent_waits)
run("recv_rcvtimeo_1s", recv_rcvtimeo)
run("accept_rcvtimeo_1s", accept_rcvtimeo)
run("accept_nonblocking", accept_nonblocking)
run("recv_nonblocking", recv_nonblocking)
# Each test name given on the command line runs alone (a fresh process per
# test keeps one Ginux crash from hiding the rest); no argument runs all.
for name, fn in TESTS:
    if len(sys.argv) < 2 or name in sys.argv[1:]:
        run_all(name, fn)
if len(sys.argv) < 2 or "done" in sys.argv[1:]:
    print("GT_DONE", flush=True)
