"""Probe 33: coherence of MAP_SHARED file mappings with read()/write(), with
other mappings of the same file, across fork() and between processes.

Prints 'GT <name> <result>'. Run on Linux with GT_HOST=1 for reference values.
"""
import errno, mmap, os, select, signal, time

BASE = "/tmp/gt33"
PAGE = mmap.PAGESIZE


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
        os.write(w, res.encode()[:300])
        os._exit(0)
    os.close(w)
    ok, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 300).decode() if ok else "HANG"
    if not ok:
        os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("GT", name, res, flush=True)


def fresh(name, size=2 * PAGE):
    path = os.path.join(BASE, name)
    with open(path, "wb") as f:
        f.write(b"." * size)
    return path


def t_write_seen_in_map():
    fd = os.open(fresh("a"), os.O_RDWR)
    m = mmap.mmap(fd, 2 * PAGE, mmap.MAP_SHARED)
    os.pwrite(fd, b"W", 10)
    os.pwrite(fd, b"X", PAGE + 5)
    return "page0=%s page1=%s" % (m[10:11] == b"W", m[PAGE + 5:PAGE + 6] == b"X")


def t_map_store_seen_by_read():
    fd = os.open(fresh("b"), os.O_RDWR)
    m = mmap.mmap(fd, 2 * PAGE, mmap.MAP_SHARED)
    m[20:21] = b"M"
    same_fd = os.pread(fd, 1, 20) == b"M"
    other = os.open(os.path.join(BASE, "b"), os.O_RDONLY)
    other_fd = os.pread(other, 1, 20) == b"M"
    m.flush()
    after_msync = os.pread(other, 1, 20) == b"M"
    return "same_fd=%s other_fd=%s after_msync=%s" % (same_fd, other_fd, after_msync)


def t_map_store_reaches_file_on_munmap():
    path = fresh("c")
    fd = os.open(path, os.O_RDWR)
    m = mmap.mmap(fd, 2 * PAGE, mmap.MAP_SHARED)
    m[30:31] = b"U"
    m.close()
    os.close(fd)
    return "after_munmap=%s" % (open(path, "rb").read()[30:31] == b"U")


def t_two_mappings_same_process():
    path = fresh("d")
    fd = os.open(path, os.O_RDWR)
    m1 = mmap.mmap(fd, 2 * PAGE, mmap.MAP_SHARED)
    m2 = mmap.mmap(fd, 2 * PAGE, mmap.MAP_SHARED)
    m1[40:41] = b"1"
    return "second_mapping_sees=%s" % (m2[40:41] == b"1")


def t_shared_file_map_across_fork():
    path = fresh("e")
    fd = os.open(path, os.O_RDWR)
    m = mmap.mmap(fd, 2 * PAGE, mmap.MAP_SHARED)
    pid = os.fork()
    if pid == 0:
        m[50:51] = b"C"
        os._exit(0)
    os.waitpid(pid, 0)
    child_store_seen = m[50:51] == b"C"
    m[60:61] = b"P"
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.write(w, b"1" if m[60:61] == b"P" else b"0")
        os._exit(0)
    os.waitpid(pid, 0)
    return "parent_sees_child=%s child_sees_parent=%s" % (child_store_seen, os.read(r, 1) == b"1")


def t_two_processes_map_same_file():
    path = fresh("f")
    r1, w1 = os.pipe(); r2, w2 = os.pipe()
    pid = os.fork()
    if pid == 0:
        cfd = os.open(path, os.O_RDWR)
        cm = mmap.mmap(cfd, 2 * PAGE, mmap.MAP_SHARED)
        os.write(w1, b"r")          # mapped
        os.read(r2, 1)               # wait until the parent stored
        os.write(w1, b"1" if cm[70:71] == b"Z" else b"0")
        os._exit(0)
    os.read(r1, 1)
    fd = os.open(path, os.O_RDWR)
    m = mmap.mmap(fd, 2 * PAGE, mmap.MAP_SHARED)
    m[70:71] = b"Z"
    os.write(w2, b"g")
    seen = os.read(r1, 1) == b"1"
    os.waitpid(pid, 0)
    return "independent_mapping_sees_store=%s" % seen


def t_write_by_other_process_seen_in_map():
    path = fresh("g")
    fd = os.open(path, os.O_RDWR)
    m = mmap.mmap(fd, 2 * PAGE, mmap.MAP_SHARED)
    pid = os.fork()
    if pid == 0:
        o = os.open(path, os.O_WRONLY)
        os.pwrite(o, b"Q", 80)
        os._exit(0)
    os.waitpid(pid, 0)
    return "seen=%s" % (m[80:81] == b"Q")


def t_anonymous_shared_across_fork():
    m = mmap.mmap(-1, PAGE, mmap.MAP_SHARED | mmap.MAP_ANONYMOUS)
    pid = os.fork()
    if pid == 0:
        m[0:1] = b"A"
        os._exit(0)
    os.waitpid(pid, 0)
    return "parent_sees_child=%s" % (m[0:1] == b"A")


def t_truncate_then_access():
    path = fresh("h")
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        fd = os.open(path, os.O_RDWR)
        m = mmap.mmap(fd, 2 * PAGE, mmap.MAP_SHARED)
        os.ftruncate(fd, 100)
        os.write(w, b"t")
        _ = m[PAGE + 1]
        os.write(w, b"r")
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    got = os.read(r, 4)
    return "read_past_eof=%s signal=%s" % (got == b"tr", os.WTERMSIG(status) if os.WIFSIGNALED(status) else 0)


def t_extend_then_access():
    path = fresh("i", PAGE)
    fd = os.open(path, os.O_RDWR)
    m = mmap.mmap(fd, PAGE, mmap.MAP_SHARED)
    os.ftruncate(fd, 2 * PAGE)
    os.pwrite(fd, b"E", 0)
    return "store_after_grow_seen=%s" % (m[0:1] == b"E")


def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True); os.makedirs(BASE)
    for n in sorted(k for k in globals() if k.startswith("t_")):
        run(n[2:], globals()[n])
    print("GT_DONE", flush=True)


if __name__ == "__main__":
    main()
