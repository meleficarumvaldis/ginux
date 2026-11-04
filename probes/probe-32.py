"""Probe 32: metadata changes on image (lower-layer) directories must not hide
their image entries.

utimensat/futimens, chmod/fchmod and chown/fchown on an image directory copy
it up. Afterwards the directory must still list and resolve its image entries
(merged, not opaque), new entries must appear, unlink of an image entry must
still hide it, rmdir must still see the image entries (ENOTEMPTY), and a
directory that was really emptied, removed and re-created must stay empty.
Also: busybox `touch /etc` and `tar -xf` of an archive with a `usr/` entry,
and st_ino across copy-up.

Prints 'GT <name> <result>'. Run it on Linux with GT_HOST=1: the probe then
builds a small lower tree under /tmp/gt32_ov, mounts a real overlayfs over it
in an unprivileged user+mount namespace (unshare -rm) and runs against that.
Nothing outside /tmp/gt32_ov changes on the host.
"""
import errno, io, os, select, shutil, signal, stat, sys, tarfile

HOST = os.environ.get("GT_HOST") == "1"
ROOT = os.environ.get("GT_ROOT", "/")
OV = "/tmp/gt32_ov"
PY = "usr/local/lib/python3.13"


def host_setup():
    """Build lower/upper/work dirs and re-exec this probe inside an overlayfs."""
    # overlayfs leaves work/work with mode 000
    os.system("chmod -R u+rwx %s 2>/dev/null; rm -rf %s" % (OV, OV))
    lower = OV + "/lower"
    stdlib = os.path.dirname(os.__file__)
    ign = shutil.ignore_patterns("__pycache__")
    for name in ["email", "json", "http", "logging", "urllib", "sqlite3", "wsgiref",
                 "__phello__", "html", "xmlrpc"]:
        shutil.copytree(os.path.join(stdlib, name), os.path.join(lower, PY, name), ignore=ign)
    os.makedirs(lower + "/etc")
    for name in ["passwd", "group", "shells", "profile", "hosts", "fstab"]:
        with open("/etc/" + name, "rb") as src, open(lower + "/etc/" + name, "wb") as dst:
            dst.write(src.read())
    for d in ["usr/bin", "usr/lib", "usr/sbin"]:
        os.makedirs(os.path.join(lower, d), exist_ok=True)
        open(os.path.join(lower, d, "f"), "wb").write(b"x")
    for d in ["upper", "work", "merged"]:
        os.makedirs(os.path.join(OV, d))
    cmd = ("mount -t overlay gt32 -o lowerdir=%s/lower,upperdir=%s/upper,workdir=%s/work,userxattr %s/merged"
           " && GT_ROOT=%s/merged exec %s %s" % (OV, OV, OV, OV, OV, sys.executable, os.path.abspath(__file__)))
    os.execvp("unshare", ["unshare", "-rm", "sh", "-c", cmd])


if HOST and "GT_ROOT" not in os.environ:
    host_setup()


def R(*n):
    return os.path.join(ROOT, *n)


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


def err(fn):
    try:
        r = fn()
        return "0" if r is None or isinstance(r, int) else str(r)
    except OSError as x:
        return errno.errorcode.get(x.errno, str(x.errno))


def names(d):
    return sorted(os.listdir(d))


def readable(path):
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except OSError:
        return False


def tool(name):
    # busybox applets in the domain; coreutils/tar on the host
    return "/bin/" + name if not HOST else shutil.which(name)


def spawn(argv, out_path="/tmp/gt32.out"):
    """fork+exec without pipes; returns (status, output)."""
    pid = os.fork()
    if pid == 0:
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.dup2(fd, 1); os.dup2(fd, 2)
        try:
            os.execv(argv[0], argv)
        finally:
            os._exit(127)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), open(out_path, "rb").read().decode(errors="replace")


# ------------------------------------------------------ top-level /etc
def t_touch_etc():
    d = R("etc"); before = names(d)
    rc, _ = spawn([tool("touch"), d])
    rc2, out = spawn([tool("ls"), d])
    return "touch_rc=%d entries_kept=%s ls_rc=%d ls_has_passwd=%s passwd_open=%s" % (
        rc, names(d) == before, rc2, "passwd" in out.split(), readable(R("etc", "passwd")))


def t_etc_after_copy_up():
    d = R("etc")
    os.utime(d, (3_000_000, 3_000_000))
    before = set(os.listdir(d))
    open(R("etc", "gt32-new"), "wb").write(b"n")
    new_listed = "gt32-new" in os.listdir(d)
    os.unlink(R("etc", "hosts"))
    after = set(os.listdir(d))
    return "has_passwd=%s new_listed=%s unlinked_listed=%s unlinked_stat=%s rest_kept=%s" % (
        "passwd" in before, new_listed, "hosts" in after, err(lambda: os.stat(R("etc", "hosts"))),
        (before - {"hosts"}) <= after)


def t_etc_dirfd_and_cwd():
    fd = os.open(R("etc"), os.O_RDONLY | os.O_DIRECTORY)
    rel_stat = err(lambda: os.stat("passwd", dir_fd=fd).st_size > 0)
    rel_open = err(lambda: os.close(os.open("passwd", os.O_RDONLY, dir_fd=fd)))
    fd_list = "passwd" in os.listdir(fd)
    os.close(fd)
    old = os.getcwd(); os.chdir(R("etc"))
    cwd_open = err(lambda: os.close(os.open("passwd", os.O_RDONLY)))
    cwd_list = "passwd" in os.listdir(".")
    os.chdir(old)
    fd = os.open(R("etc"), os.O_RDONLY | os.O_DIRECTORY)
    os.fchdir(fd); os.close(fd)
    fchdir_open = err(lambda: os.close(os.open("group", os.O_RDONLY)))
    os.chdir(old)
    return "dirfd_stat=%s dirfd_open=%s dirfd_list=%s cwd_open=%s cwd_list=%s fchdir_open=%s" % (
        rel_stat, rel_open, fd_list, cwd_open, cwd_list, fchdir_open)


# ------------------------------------------------- nested image directories
def t_utime_nested():
    d = R(PY, "email"); before = names(d)
    os.utime(d, (3_000_000, 3_000_000))
    return "entries_kept=%s mtime=%d lower_open=%s" % (
        names(d) == before, os.stat(d).st_mtime, readable(os.path.join(d, "__init__.py")))


def t_futimens_dir():
    d = R(PY, "json"); before = names(d)
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    os.utime(fd, (3_000_000, 3_000_000))
    via_fd = sorted(os.listdir(fd)) == before
    rel = err(lambda: os.stat("__init__.py", dir_fd=fd).st_size > 0)
    fmtime = os.fstat(fd).st_mtime
    os.close(fd)
    return "entries_kept=%s via_fd=%s dirfd_stat=%s fstat_mtime=%d" % (
        names(d) == before, via_fd, rel, fmtime)


def t_chmod_dir():
    d = R(PY, "http"); before = names(d)
    r = err(lambda: os.chmod(d, 0o750))
    return "chmod=%s mode=%o entries_kept=%s" % (
        r, stat.S_IMODE(os.stat(d).st_mode), names(d) == before)


def t_fchmod_dir():
    d = R(PY, "logging"); before = names(d)
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    r = err(lambda: os.fchmod(fd, 0o750))
    os.close(fd)
    return "fchmod=%s mode=%o entries_kept=%s" % (
        r, stat.S_IMODE(os.stat(d).st_mode), names(d) == before)


def t_chown_dir():
    d = R(PY, "urllib"); before = names(d)
    r1 = err(lambda: os.chown(d, os.getuid(), os.getgid()))
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    r2 = err(lambda: os.fchown(fd, os.getuid(), os.getgid()))
    os.close(fd)
    return "chown=%s fchown=%s entries_kept=%s" % (r1, r2, names(d) == before)


def t_rmdir_copied_up():
    d = R(PY, "wsgiref"); before = names(d)
    os.utime(d, (3_000_000, 3_000_000))
    r = err(lambda: os.rmdir(d))
    return "rmdir=%s still_dir=%s entries_kept=%s" % (r, os.path.isdir(d), names(d) == before)


def t_unlink_and_create_in_copied_up():
    d = R(PY, "sqlite3"); before = set(os.listdir(d))
    os.utime(d, (3_000_000, 3_000_000))
    os.unlink(os.path.join(d, "dump.py"))
    open(os.path.join(d, "gt32.py"), "wb").write(b"#")
    after = set(os.listdir(d))
    return "dump_listed=%s dump_exists=%s new_listed=%s rest_kept=%s" % (
        "dump.py" in after, os.path.exists(os.path.join(d, "dump.py")), "gt32.py" in after,
        (before - {"dump.py"}) <= after)


def t_emptied_recreated_dir():
    # Remove every entry of an image directory, rmdir it and mkdir it again:
    # the new directory must be empty (Linux makes it opaque).
    d = R(PY, "__phello__")
    os.utime(d, (3_000_000, 3_000_000))
    for top, dirs, files in os.walk(d, topdown=False):
        for f in files:
            os.unlink(os.path.join(top, f))
        for s in dirs:
            os.rmdir(os.path.join(top, s))
    left = len(os.listdir(d))
    r1 = err(lambda: os.rmdir(d))
    r2 = err(lambda: os.mkdir(d))
    return "left=%d rmdir=%s mkdir=%s listing=%s spam_exists=%s" % (
        left, r1, r2, ",".join(names(d)) or "-", os.path.exists(os.path.join(d, "spam.py")))


# -------------------------------------------------------------- tar scenario
def t_tar_usr_entry():
    # An archive with a directory entry for an existing image directory,
    # like any package or rootfs tarball: tar restores the directory's
    # mode/mtime after extracting.
    arch = "/tmp/gt32.tar"
    with tarfile.open(arch, "w") as t:
        info = tarfile.TarInfo("usr"); info.type = tarfile.DIRTYPE; info.mode = 0o755
        info.mtime = 4_000_000
        t.addfile(info)
        payload = b"tar\n"
        info = tarfile.TarInfo("usr/gt32-tar"); info.size = len(payload); info.mode = 0o644
        info.mtime = 4_000_000

        t.addfile(info, io.BytesIO(payload))
    before = names(R("usr"))
    rc, out = spawn([tool("tar"), "-xf", arch, "-C", ROOT])
    after = set(os.listdir(R("usr")))
    return "tar_rc=%d image_kept=%s new_listed=%s mtime=%d lower_open=%s" % (
        rc, set(before) <= after, "gt32-tar" in after, os.stat(R("usr")).st_mtime,
        readable(R(PY, "json", "__init__.py")))


# -------------------------------------------------------------- inode numbers
def t_ino_file_copy_up():
    f = R("etc", "profile")
    before = os.stat(f).st_ino
    with open(f, "ab") as h:
        h.write(b"\n# x\n")
    return "ino_same=%s" % (os.stat(f).st_ino == before)


def t_ino_dir_copy_up():
    d = R(PY, "html")
    before = os.stat(d).st_ino
    os.utime(d, (3_000_000, 3_000_000))
    return "ino_same=%s" % (os.stat(d).st_ino == before)


def t_dirent_ino_matches_stat():
    d = R(PY, "xmlrpc")
    os.utime(d, (3_000_000, 3_000_000))
    with os.scandir(d) as it:
        ents = list(it)
    bad = [e.name for e in ents if e.inode() != os.stat(os.path.join(d, e.name), follow_symlinks=False).st_ino]
    return "entries=%s mismatches=%d" % (len(ents) > 0, len(bad))


for name, fn in list(globals().items()):
    if name.startswith("t_") and callable(fn):
        run(name[2:], fn)
print("GT_DONE", flush=True)
