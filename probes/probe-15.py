"""Targeted file-system probe: timestamps, truncate stale data, hardlinks, nlink, ELOOP.

Prints 'GT <dir>:<name> <result>'. Values are normalised so Linux and Ginux lines compare 1:1.
"""
import errno, os, select, signal, time

HOST = bool(os.environ.get("GT_HOST"))


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
        os.write(w, res.encode())
        os._exit(0)
    os.close(w)
    ok, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 300).decode() if ok else "HANG"
    if not ok:
        os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("GT", name, res, flush=True)


def suite(base):
    os.makedirs(base, exist_ok=True)
    p = lambda n: os.path.join(base, n)
    tag = "tmp" if base.startswith("/tmp") else "root"

    def new_file_mtime_is_now():
        before = time.time()
        with open(p("fresh"), "wb") as f:
            f.write(b"x")
        st = os.stat(p("fresh"))
        return "mtime_recent=%s ctime_recent=%s" % (st.st_mtime >= before - 5, st.st_ctime >= before - 5)

    def write_bumps_mtime():
        with open(p("w"), "wb") as f:
            f.write(b"a")
        os.utime(p("w"), (1_000_000, 1_000_000))
        with open(p("w"), "ab") as f:
            f.write(b"b")
        return os.stat(p("w")).st_mtime > 1_000_000

    def truncate_bumps_mtime():
        with open(p("t"), "wb") as f:
            f.write(b"abc")
        os.utime(p("t"), (1_000_000, 1_000_000))
        os.truncate(p("t"), 1)
        return os.stat(p("t")).st_mtime > 1_000_000

    def utime_sets_ctime_now():
        with open(p("u"), "wb") as f:
            f.write(b"a")
        before = time.time()
        os.utime(p("u"), (1_000_000, 1_000_000))
        return "ctime_recent=%s" % (os.stat(p("u")).st_ctime >= before - 5)

    def truncate_regrow_is_zero():
        with open(p("z"), "wb") as f:
            f.write(b"A" * 100)
        os.truncate(p("z"), 10)
        os.truncate(p("z"), 100)
        data = open(p("z"), "rb").read()
        return "tail_zero=%s" % (data[10:] == b"\0" * 90)

    def pwrite_after_shrink_is_zero():
        with open(p("y"), "wb") as f:
            f.write(b"B" * 300)
        os.truncate(p("y"), 10)
        fd = os.open(p("y"), os.O_WRONLY)
        os.pwrite(fd, b"E", 200)
        os.close(fd)
        data = open(p("y"), "rb").read()
        return "gap_zero=%s size=%d" % (data[10:200] == b"\0" * 190, len(data))

    def hardlink_shares_data():
        with open(p("h1"), "wb") as f:
            f.write(b"x")
        os.link(p("h1"), p("h2"))
        with open(p("h2"), "ab") as f:
            f.write(b"y")
        return "nlink=%d shared=%s same_ino=%s" % (
            os.stat(p("h1")).st_nlink,
            open(p("h1"), "rb").read() == b"xy",
            os.stat(p("h1")).st_ino == os.stat(p("h2")).st_ino,
        )

    def unlinked_fstat_nlink():
        with open(p("gone"), "wb") as f:
            f.write(b"x")
        fd = os.open(p("gone"), os.O_RDONLY)
        os.unlink(p("gone"))
        n = os.fstat(fd).st_nlink
        os.close(fd)
        return n

    def dir_nlink():
        os.makedirs(p("dn/a"), exist_ok=True)
        os.makedirs(p("dn/b"), exist_ok=True)
        return os.stat(p("dn")).st_nlink

    def symlink_loop():
        if not os.path.lexists(p("l1")):
            os.symlink(p("l2"), p("l1"))
            os.symlink(p("l1"), p("l2"))
        open(p("l1"))
        return "opened"

    def link_rename_independent():
        with open(p("r1"), "wb") as f:
            f.write(b"x")
        os.link(p("r1"), p("r2"))
        os.rename(p("r2"), p("r3"))
        return "r1=%s r2=%s r3=%s nlink=%d same_ino=%s" % (
            os.path.exists(p("r1")), os.path.exists(p("r2")), os.path.exists(p("r3")),
            os.stat(p("r1")).st_nlink, os.stat(p("r1")).st_ino == os.stat(p("r3")).st_ino)

    def link_unlink_first_name():
        with open(p("u1"), "wb") as f:
            f.write(b"x")
        os.link(p("u1"), p("u2"))
        fd = os.open(p("u1"), os.O_RDONLY)
        os.unlink(p("u1"))
        with open(p("u2"), "ab") as f:
            f.write(b"y")
        seen = os.pread(fd, 10, 0)
        n_fd = os.fstat(fd).st_nlink
        os.close(fd)
        return "data=%s fd_sees=%s nlink=%d fd_nlink=%d" % (
            open(p("u2"), "rb").read(), seen, os.stat(p("u2")).st_nlink, n_fd)

    def link_three_names_unlink_all():
        with open(p("t1"), "wb") as f:
            f.write(b"x")
        os.link(p("t1"), p("t2"))
        os.link(p("t2"), p("t3"))
        a = os.stat(p("t3")).st_nlink
        os.unlink(p("t2"))
        b = os.stat(p("t1")).st_nlink
        fd = os.open(p("t3"), os.O_RDONLY)
        os.unlink(p("t1"))
        os.unlink(p("t3"))
        c = os.fstat(fd).st_nlink
        os.close(fd)
        return "%d,%d,%d exists=%s" % (a, b, c, os.path.exists(p("t3")))

    def rename_onto_own_link():
        with open(p("s1"), "wb") as f:
            f.write(b"x")
        os.link(p("s1"), p("s2"))
        os.rename(p("s1"), p("s2"))
        return "s1=%s s2=%s nlink=%d" % (
            os.path.exists(p("s1")), os.path.exists(p("s2")), os.stat(p("s2")).st_nlink)

    def symlink_chain2():
        if not os.path.lexists(p("c1")):
            with open(p("ct"), "wb") as f:
                f.write(b"z")
            os.symlink(p("c2"), p("c1"))
            os.symlink(p("ct"), p("c2"))
        return open(p("c1"), "rb").read()

    def image_layer_link():
        src = "/etc/alpine-release"
        before = open(src, "rb").read()
        os.link(src, p("rel"))
        with open(p("rel"), "ab") as f:
            f.write(b"Q")
        return "nlink=%d shared=%s same_ino=%s" % (
            os.stat(src).st_nlink, open(src, "rb").read() == before + b"Q",
            os.stat(src).st_ino == os.stat(p("rel")).st_ino)

    for name, fn in [
        ("new_file_times_now", new_file_mtime_is_now),
        ("write_bumps_mtime", write_bumps_mtime),
        ("truncate_bumps_mtime", truncate_bumps_mtime),
        ("utime_sets_ctime_now", utime_sets_ctime_now),
        ("truncate_regrow_zero", truncate_regrow_is_zero),
        ("pwrite_after_shrink_zero", pwrite_after_shrink_is_zero),
        ("hardlink_shares_data", hardlink_shares_data),
        ("unlinked_fstat_nlink", unlinked_fstat_nlink),
        ("dir_nlink_2_subdirs", dir_nlink),
        ("symlink_loop", symlink_loop),
        ("symlink_chain2", symlink_chain2),
        ("link_rename_independent", link_rename_independent),
        ("link_unlink_first_name", link_unlink_first_name),
        ("link_three_names_unlink_all", link_three_names_unlink_all),
        ("rename_onto_own_link", rename_onto_own_link),
    ]:
        run("%s:%s" % (tag, name), fn)
    if not HOST and tag == "root":
        run("root:image_layer_link", image_layer_link)
    for name, fn in [
    ]:
        run("%s:%s" % (tag, name), fn)


for base in ["/tmp/gtfs2", os.environ.get("GT_HOME_DIR", "/root/gtfs2")]:
    try:
        suite(base)
    except OSError as exc:
        print("GT", base, "SKIP", exc, flush=True)
print("GT_DONE", flush=True)
