"""Issue 20 probe: poll/select on runtime pipes while a vforked child runs,
subprocess capture, and SIGKILL of a sleeping child.

Each line: GT <name> <result>. Run on Linux with GT_HOST=1 for reference
values, and inside Ginux (python:3.13-alpine domain). Every test runs in a
forked child with a watchdog so a hang only affects that row.
"""
import errno, os, select, signal, subprocess, sys, time

HOST = os.environ.get("GT_HOST") == "1"


def out(name, value):
    print("GT", name, value, flush=True)


def run_isolated(name, fn, limit=15.0):
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
    deadline = time.monotonic() + limit
    ready = []
    while time.monotonic() < deadline:
        ready, _, _ = select.select([r], [], [], max(0.0, deadline - time.monotonic()))
        if ready:
            break
    res = os.read(r, 300).decode() if ready else "HANG(>%ss)" % limit
    if not ready:
        os.kill(pid, signal.SIGKILL)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    os.close(r)
    out(name, res or "EMPTY")


SKIP = set(sys.argv[1].split(",")) if len(sys.argv) > 1 else set()


def run(name, fn):
    # Ginux runs a forked child first until it blocks, so a test that spins
    # forever also stalls the watchdog; skip such rows by name (argv[1]).
    if name in SKIP:
        out(name, "SKIPPED")
    else:
        run_isolated(name, fn)


def secs(t):
    # Coarse buckets so host and Ginux rows compare textually.
    return "%.1f" % (round(t * 2) / 2)


def capture_echo():
    r = subprocess.run(["/bin/echo", "hi"], capture_output=True)
    return "rc=%d out=%r err=%r" % (r.returncode, r.stdout, r.stderr)


def check_output_echo():
    return repr(subprocess.check_output(["/bin/echo", "co"]))


def popen_communicate_stdin():
    p = subprocess.Popen(["/bin/cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    o, _ = p.communicate(b"via-stdin\n")
    return "rc=%d out=%r" % (p.returncode, o)


def capture_stderr_and_stdout():
    r = subprocess.run(["/bin/sh", "-c", "echo out; echo err >&2; exit 3"],
                       capture_output=True)
    return "rc=%d out=%r err=%r" % (r.returncode, r.stdout, r.stderr)


def spawn_reader(cmd):
    # CPython's subprocess forks with vfork() and execs; the parent resumes
    # at the child's exec, before the exec'd writer ran.
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    return p.stdout.fileno(), p.pid


def poll_vfork_writer():
    r, pid = spawn_reader(["/bin/echo", "polled"])
    p = select.poll()
    p.register(r, select.POLLIN)
    ev = p.poll(-1)
    data = os.read(r, 100)
    os.waitpid(pid, 0)
    return "events=%s data=%r" % ([(e & select.POLLIN != 0) for _, e in ev], data)


def select_vfork_writer():
    r, pid = spawn_reader(["/bin/echo", "selected"])
    ready, _, _ = select.select([r], [], [])
    data = os.read(r, 100)
    os.waitpid(pid, 0)
    return "ready=%d data=%r" % (len(ready), data)


def poll_timeout_no_writer():
    r, w = os.pipe()
    p = select.poll()
    p.register(r, select.POLLIN)
    t = time.monotonic()
    ev = p.poll(500)
    return "n=%d t=%s" % (len(ev), secs(time.monotonic() - t))


def select_timeout_no_writer():
    r, w = os.pipe()
    t = time.monotonic()
    ready, _, _ = select.select([r], [], [], 0.5)
    return "n=%d t=%s" % (len(ready), secs(time.monotonic() - t))


def poll_infinite_late_writer():
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        time.sleep(1)
        os.write(w, b"late")
        os._exit(0)
    os.close(w)
    p = select.poll()
    p.register(r, select.POLLIN)
    t = time.monotonic()
    ev = p.poll(-1)
    el = time.monotonic() - t
    data = os.read(r, 100)
    os.waitpid(pid, 0)
    return "n=%d data=%r t=%s" % (len(ev), data, secs(el))


def poll_infinite_late_exec_writer():
    r, pid = spawn_reader(["/bin/sh", "-c", "sleep 1; echo late"])
    p = select.poll()
    p.register(r, select.POLLIN)
    t = time.monotonic()
    ev = p.poll(-1)
    el = time.monotonic() - t
    data = os.read(r, 100)
    os.waitpid(pid, 0)
    return "n=%d data=%r t=%s" % (len(ev), data, secs(el))


def kill_sleeping_child():
    pid = os.fork()
    if pid == 0:
        time.sleep(5)
        os._exit(1)
    time.sleep(0.2)
    os.kill(pid, signal.SIGKILL)
    _, st = os.waitpid(pid, 0)
    return "WIFSIGNALED=%s sig=%s raw=%d" % (
        os.WIFSIGNALED(st), os.WTERMSIG(st) if os.WIFSIGNALED(st) else "-", st)


def kill_sleeping_child_immediately():
    pid = os.fork()
    if pid == 0:
        time.sleep(5)
        os._exit(1)
    os.kill(pid, signal.SIGKILL)
    _, st = os.waitpid(pid, 0)
    return "WIFSIGNALED=%s sig=%s raw=%d" % (
        os.WIFSIGNALED(st), os.WTERMSIG(st) if os.WIFSIGNALED(st) else "-", st)


run("subprocess_capture_echo", capture_echo)
run("subprocess_check_output", check_output_echo)
run("popen_communicate_stdin", popen_communicate_stdin)
run("subprocess_capture_both", capture_stderr_and_stdout)
run("poll_vfork_exec_writer", poll_vfork_writer)
run("select_vfork_exec_writer", select_vfork_writer)
run("poll_500ms_no_writer", poll_timeout_no_writer)
run("select_500ms_no_writer", select_timeout_no_writer)
run("poll_inf_fork_writer_1s", poll_infinite_late_writer)
run("poll_inf_exec_writer_1s", poll_infinite_late_exec_writer)
def sleep_500ms():
    t = time.monotonic()
    time.sleep(0.5)
    return "t=%s" % secs(time.monotonic() - t)


def child_sleep_seen_by_parent():
    # The forked child sleeps 1s (absolute clock_nanosleep); the parent must
    # observe the full duration and a normal exit.
    t = time.monotonic()
    pid = os.fork()
    if pid == 0:
        time.sleep(1)
        os._exit(4)
    _, st = os.waitpid(pid, 0)
    return "exit=%s t=%s" % (os.waitstatus_to_exitcode(st), secs(time.monotonic() - t))


run("sleep_500ms", sleep_500ms)
run("child_sleep_1s_waited", child_sleep_seen_by_parent)
run("kill9_sleeping_child", kill_sleeping_child)
run("kill9_sleeping_child_now", kill_sleeping_child_immediately)
print("GT_DONE", flush=True)
