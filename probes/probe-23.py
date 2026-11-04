"""Probe 23: by-path metadata changes (chmod, utime, chown, truncate) on image
(lower-layer) files and directories, and chmod through symlinks.

Prints 'GT <name> <result>'. Run it on Linux with GT_HOST=1: "lower" files are
then copies in /tmp instead of image files, so nothing on the host changes.
"""
import ctypes, errno, os, select, signal, stat, sys

HOST = os.environ.get("GT_HOST") == "1"
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
BASE = "/tmp/gt23"
LOW = "/tmp/gt23_lower"
AT_FDCWD = -100
AT_SYMLINK_NOFOLLOW = 0x100
AT_EMPTY_PATH = 0x1000
SYS_FCHMODAT = 268
SYS_FCHMODAT2 = 452
SYS_FCHOWNAT = 260
SYS_LCHOWN = 94


def sc(nr, *args):
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) if isinstance(a, int) else a for a in args])
    return -ctypes.get_errno() if r == -1 else r


def e(v):
    return ("-" + errno.errorcode.get(-v, str(-v))) if isinstance(v, int) and v < 0 else v


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


def mode(path, follow=True):
    return "%o" % stat.S_IMODE((os.stat if follow else os.lstat)(path).st_mode)


def lower(src):
    """An image file in Ginux; a /tmp stand-in with fixed content on the host."""
    if not HOST:
        return src
    dst = os.path.join(LOW, src.strip("/").replace("/", "_"))
    if not os.path.exists(dst):
        os.makedirs(LOW, exist_ok=True)
        with open(dst, "wb") as f:
            f.write(b"# stand-in for %s\nline two\nline three\n" % src.encode())
        os.chmod(dst, 0o644)
        os.utime(dst, (1_000_000, 1_000_000))
    return dst


def lower_symlink():
    """/etc/os-release is a relative symlink into /usr/lib in the alpine image."""
    if not HOST:
        return "/etc/os-release", "/usr/lib/os-release"
    target = lower("/usr/lib/os-release")
    link = os.path.join(LOW, "os-release-link")
    if not os.path.lexists(link):
        os.symlink(os.path.basename(target), link)
    return link, target


def lower_dir(name):
    """A non-empty image directory."""
    src = "/usr/local/lib/python3.13/" + name
    if not HOST:
        return src
    d = os.path.join(LOW, name)
    if not os.path.isdir(d):
        os.makedirs(d)
        for n in ("a.py", "b.py", "c.py"):
            with open(os.path.join(d, n), "wb") as f:
                f.write(b"x = 1\n")
        os.chmod(d, 0o755)
    return d


def snapshot(d):
    return sorted((n, os.path.getsize(os.path.join(d, n))) for n in os.listdir(d))


# ------------------------------------------------------- lower regular files
def t_lower_chmod():
    f = lower("/etc/profile"); data = open(f, "rb").read()
    os.chmod(f, 0o640)
    return "mode=%s data_kept=%s" % (mode(f), open(f, "rb").read() == data)


def t_lower_fchmodat_dirfd():
    f = lower("/etc/shells"); d = os.open(os.path.dirname(f), os.O_RDONLY | os.O_DIRECTORY)
    r = sc(SYS_FCHMODAT, d, os.path.basename(f).encode(), 0o600)
    return "ret=%s mode=%s" % (e(r), mode(f))


def t_lower_utime():
    f = lower("/etc/issue"); data = open(f, "rb").read()
    os.utime(f, (2_000_000, 3_000_000)); st = os.stat(f)
    return "atime=%d mtime=%d data_kept=%s" % (st.st_atime, st.st_mtime, open(f, "rb").read() == data)


def t_lower_touch_now():
    f = lower("/etc/fstab"); before = os.stat(f).st_mtime
    os.utime(f, None)
    return "mtime_bumped=%s" % (os.stat(f).st_mtime > before)


def t_lower_chown():
    f = lower("/etc/passwd"); st = os.stat(f)
    os.chown(f, st.st_uid, st.st_gid)
    r = sc(SYS_FCHOWNAT, AT_FDCWD, f.encode(), -1, -1, AT_SYMLINK_NOFOLLOW)
    return "chown=0 fchownat_nofollow=%s uid_same=%s" % (e(r), os.stat(f).st_uid == st.st_uid)


def t_lower_truncate_path():
    f = lower("/etc/group"); data = open(f, "rb").read()
    os.truncate(f, 4)
    return "len=%d prefix=%s" % (os.path.getsize(f), open(f, "rb").read() == data[:4])


# --------------------------------------------------------- lower symlinks
def t_lower_symlink_chmod_follows():
    link, target = lower_symlink(); data = open(target, "rb").read()
    os.chmod(link, 0o604)
    return "target=%s link_is_symlink=%s data_kept=%s" % (
        mode(target), os.path.islink(link), open(target, "rb").read() == data)


def t_lower_symlink_chown_nofollow():
    link, _ = lower_symlink()
    r = sc(SYS_LCHOWN, link.encode(), -1, -1)
    return "lchown=%s link_is_symlink=%s" % (e(r), os.path.islink(link))


def t_lower_symlink_fchmodat2_nofollow():
    link, target = lower_symlink(); before = mode(target)
    r = sc(SYS_FCHMODAT2, AT_FDCWD, link.encode(), 0o600, AT_SYMLINK_NOFOLLOW)
    return "ret=%s target_unchanged=%s" % (e(r), mode(target) == before)


# ------------------------------------------------------ lower directories
def t_lower_dir_chmod():
    d = lower_dir("json"); before = snapshot(d)
    os.chmod(d, 0o700)
    return "mode=%s entries_kept=%s" % (mode(d), snapshot(d) == before)


def t_lower_dir_utime():
    d = lower_dir("email"); before = snapshot(d)
    os.utime(d, (4_000_000, 5_000_000))
    return "mtime=%d entries_kept=%s" % (os.stat(d).st_mtime, snapshot(d) == before)


def t_lower_dir_chown():
    d = lower_dir("html"); before = snapshot(d)
    os.chown(d, -1, -1)
    return "ret=0 entries_kept=%s" % (snapshot(d) == before)


# --------------------------------------------- upper files and symlinks
def t_chmod_symlink_follows():
    f = p("f"); open(f, "wb").write(b"x"); os.chmod(f, 0o644); os.symlink(f, p("l"))
    os.chmod(p("l"), 0o604); first = mode(f)
    r = sc(SYS_FCHMODAT, AT_FDCWD, p("l").encode(), 0o640)
    return "chmod=%s fchmodat(%s)=%s link_is_symlink=%s" % (first, e(r), mode(f), os.path.islink(p("l")))


def t_fchmodat2():
    f = p("g"); open(f, "wb").write(b"x"); os.chmod(f, 0o644); os.symlink(f, p("gl"))
    out = ["nofollow_link=%s" % e(sc(SYS_FCHMODAT2, AT_FDCWD, p("gl").encode(), 0o600, AT_SYMLINK_NOFOLLOW))]
    out.append("target_unchanged=%s" % (mode(f) == "644"))
    out.append("nofollow_file=%s/%s" % (e(sc(SYS_FCHMODAT2, AT_FDCWD, f.encode(), 0o600, AT_SYMLINK_NOFOLLOW)), mode(f)))
    out.append("follow=%s/%s" % (e(sc(SYS_FCHMODAT2, AT_FDCWD, p("gl").encode(), 0o640, 0)), mode(f)))
    fd = os.open(f, os.O_RDONLY)
    out.append("empty_path=%s/%s" % (e(sc(SYS_FCHMODAT2, fd, b"", 0o604, AT_EMPTY_PATH)), mode(f)))
    out.append("bad_flag=%s" % e(sc(SYS_FCHMODAT2, AT_FDCWD, f.encode(), 0o600, 0x200)))
    return " ".join(out)


def t_chmod_errors():
    os.symlink(p("nowhere"), p("dangling"))
    return "missing=%s dangling=%s empty=%s" % (
        e(sc(SYS_FCHMODAT, AT_FDCWD, p("nope").encode(), 0o600)),
        e(sc(SYS_FCHMODAT, AT_FDCWD, p("dangling").encode(), 0o600)),
        e(sc(SYS_FCHMODAT, AT_FDCWD, b"", 0o600)))


def t_chown_errors():
    os.symlink(p("nowhere2"), p("dangling2"))
    return "missing=%s dangling=%s dangling_nofollow=%s empty=%s" % (
        e(sc(SYS_FCHOWNAT, AT_FDCWD, p("nope").encode(), -1, -1, 0)),
        e(sc(SYS_FCHOWNAT, AT_FDCWD, p("dangling2").encode(), -1, -1, 0)),
        e(sc(SYS_FCHOWNAT, AT_FDCWD, p("dangling2").encode(), -1, -1, AT_SYMLINK_NOFOLLOW)),
        e(sc(SYS_FCHOWNAT, AT_FDCWD, b"", -1, -1, 0)))


def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True); os.makedirs(BASE)
    if HOST:
        shutil.rmtree(LOW, ignore_errors=True)
    for n, f in sorted(globals().items()):
        if n.startswith("t_") and callable(f):
            run(n[2:], f)
    print("GT_DONE", flush=True)


if __name__ == "__main__":
    main()
