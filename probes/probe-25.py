"""Probe 25: O_CREAT|O_EXCL (and the other create calls) on a final-component
symlink must fail with EEXIST and never create the link target.

Prints 'GT <name> <result>'. Run on Linux with GT_HOST=1; the "image" symlink
is then a link created in /tmp instead of one from the container image.
"""
import ctypes, errno, os, select, signal, stat, sys

HOST = os.environ.get("GT_HOST") == "1"
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
BASE = "/tmp/gtfs25"
EXCL = os.O_CREAT | os.O_EXCL | os.O_WRONLY


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


def attempt(fn):
    try:
        r = fn()
        if isinstance(r, int):
            os.close(r)
        return "0"
    except OSError as x:
        return errno.errorcode[x.errno]


def t_excl_dangling():
    os.symlink(p("nowhere"), p("dangling"))
    r = attempt(lambda: os.open(p("dangling"), EXCL, 0o600))
    return "%s target_created=%s" % (r, os.path.exists(p("nowhere")))


def t_excl_dangling_relative():
    os.symlink("nowhere_rel", p("dangling_rel"))
    r = attempt(lambda: os.open(p("dangling_rel"), EXCL, 0o600))
    return "%s target_created=%s cwd_created=%s" % (
        r, os.path.exists(p("nowhere_rel")), os.path.exists(os.path.join(os.getcwd(), "nowhere_rel")))


def t_excl_dangling_nofollow():
    os.symlink(p("nowhere_nf"), p("dangling_nf"))
    r = attempt(lambda: os.open(p("dangling_nf"), EXCL | os.O_NOFOLLOW, 0o600))
    return "%s target_created=%s" % (r, os.path.exists(p("nowhere_nf")))


def t_excl_dangling_dirfd():
    os.symlink("nowhere_at", p("dangling_at"))
    d = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
    r = attempt(lambda: os.open("dangling_at", EXCL, 0o600, dir_fd=d))
    return "%s target_created=%s" % (r, os.path.exists(p("nowhere_at")))


def t_creat_through_dangling():
    os.symlink(p("made"), p("dangling_c"))
    r = attempt(lambda: os.open(p("dangling_c"), os.O_CREAT | os.O_WRONLY, 0o600))
    return "%s target_created=%s" % (r, os.path.isfile(p("made")))


def t_creat_through_dangling_relative():
    # Not changed by patch 25: a relative target must resolve against the
    # link's directory, not against the caller's cwd.
    os.symlink("made_rel", p("dangling_crel"))
    r = attempt(lambda: os.open(p("dangling_crel"), os.O_CREAT | os.O_WRONLY, 0o600))
    return "%s target_created=%s cwd_created=%s" % (
        r, os.path.isfile(p("made_rel")), os.path.exists(os.path.join(os.getcwd(), "made_rel")))


def t_excl_symlink_to_file():
    mk(p("f1"), b"keep")
    os.symlink(p("f1"), p("sl_file"))
    r = attempt(lambda: os.open(p("sl_file"), EXCL | os.O_TRUNC, 0o600))
    return "%s data=%s" % (r, open(p("f1"), "rb").read().decode())


def t_excl_symlink_to_dir():
    os.mkdir(p("d1"))
    os.symlink(p("d1"), p("sl_dir"))
    return attempt(lambda: os.open(p("sl_dir"), EXCL, 0o600))


def t_excl_image_symlink_existing():
    # /usr/local/bin/python3 is a symlink to python3.13 in python:3.13-alpine.
    path = "/usr/local/bin/python3"
    if HOST:
        mk(p("py_target"))
        os.symlink("py_target", p("py_link"))
        path = p("py_link")
    return "islink=%s %s" % (os.path.islink(path), attempt(lambda: os.open(path, EXCL, 0o600)))


def t_excl_image_symlink_dangling():
    # First dangling relative symlink found in the image (none created by us).
    found = None
    if HOST:
        os.symlink("img_nowhere", p("img_dangling"))
        found = p("img_dangling")
    else:
        for top in ("/etc", "/usr/lib", "/usr/share", "/lib", "/usr/local/lib"):
            for root, dirs, files in os.walk(top):
                for n in files + dirs:
                    q = os.path.join(root, n)
                    if os.path.islink(q) and not os.path.exists(q) and not os.readlink(q).startswith("/proc"):
                        found = q
                        break
                if found:
                    break
            if found:
                break
    if not found:
        return "none_found"
    link = os.readlink(found)
    target = os.path.join(os.path.dirname(found), link)
    r = attempt(lambda: os.open(found, EXCL, 0o600))
    return "%s target_created=%s still_link=%s link=%s" % (
        r, os.path.exists(target), os.path.islink(found), "image" if not HOST else "tmp")


def t_other_creates_on_dangling():
    os.symlink(p("nowhere2"), p("dangling2"))
    mk(p("src"))
    out = []
    for name, fn in [("mkdir", lambda: os.mkdir(p("dangling2"))),
                     ("mknod_fifo", lambda: os.mknod(p("dangling2"), stat.S_IFIFO | 0o600)),
                     ("mkfifo", lambda: os.mkfifo(p("dangling2"))),
                     ("symlink", lambda: os.symlink("x", p("dangling2"))),
                     ("link", lambda: os.link(p("src"), p("dangling2")))]:
        out.append("%s=%s" % (name, attempt(fn)))
    out.append("target_created=%s" % os.path.lexists(p("nowhere2")))
    out.append("still_link=%s" % os.path.islink(p("dangling2")))
    return " ".join(out)


def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True); os.makedirs(BASE)
    for n, f in sorted(globals().items()):
        if n.startswith("t_") and callable(f):
            run(n[2:], f)
    print("GT_DONE", flush=True)


if __name__ == "__main__":
    main()
