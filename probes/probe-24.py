"""Probe 24: path walk rules for non-directory components, trailing slashes
and "."/".." as the last component of rmdir/unlink.

Prints 'GT <name> <result>'. Run it on Linux with GT_HOST=1: "image" files
are then copies in /tmp and image symlinks are stand-ins in /tmp, so nothing
on the host changes.
"""
import errno, os

HOST = os.environ.get("GT_HOST") == "1"
BASE = "/tmp/gt24"


def run(name, fn):
    # In-process on purpose: these are plain path syscalls, and forking a
    # child per test ran into an unrelated Ginux fork capacity limit.
    try:
        res = str(fn())
    except OSError as exc:
        res = "-" + errno.errorcode.get(exc.errno, str(exc.errno))
    except Exception as exc:
        res = "EXC:%s:%s" % (type(exc).__name__, str(exc)[:60])
    print("GT", name, res, flush=True)


def p(*n):
    return os.path.join(BASE, *n)


def mk(path, data=b"hello"):
    with open(path, "wb") as f:
        f.write(data)
    return path


def lower(src):
    # Image files in Ginux, /tmp copies on the host.
    if not HOST:
        return src
    dst = "/tmp/gt24_lower" + src.replace("/", "_")
    if not os.path.exists(dst):
        os.makedirs("/tmp/gt24_lower", exist_ok=True)
        with open(src, "rb") as a, open(dst, "wb") as b:
            b.write(a.read())
    return dst


def image_link(src, target):
    # Image symlinks in Ginux (/bin/sh -> busybox, /var/run -> /run), stand-ins on the host.
    if not HOST:
        return src
    dst = "/tmp/gt24_lower" + src.replace("/", "_")
    if not os.path.lexists(dst):
        os.makedirs("/tmp/gt24_lower", exist_ok=True)
        os.symlink(target, dst)
    return dst


def res(fn):
    try:
        r = fn()
        if isinstance(r, int):
            os.close(r)
        return "0"
    except OSError as x:
        return errno.errorcode[x.errno]


def table(cases):
    return " ".join("%s=%s" % (n, res(f)) for n, f in cases)


C = os.O_CREAT | os.O_WRONLY


def families(f, new):
    """Every syscall family on the path `f` (existing) / `new` (to create)."""
    return [
        ("stat", lambda: os.stat(f)),
        ("lstat", lambda: os.lstat(f)),
        ("access", None),
        ("open", lambda: os.open(f, os.O_RDONLY)),
        ("open_creat", lambda: os.open(new, C, 0o600)),
        ("mkdir", lambda: os.mkdir(new)),
        ("mkfifo", lambda: os.mkfifo(new)),
        ("symlink", lambda: os.symlink("t", new)),
        ("unlink", lambda: os.unlink(f)),
        ("rmdir", lambda: os.rmdir(f)),
        ("rename_src", lambda: os.rename(f, p("rn_dst"))),
        ("chmod", lambda: os.chmod(f, 0o644)),
    ]


def access_errno(path):
    # os.access hides errno; use faccessat via a stat-free path check.
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    r = libc.faccessat(-100, path.encode(), 0, 0)
    return "0" if r == 0 else errno.errorcode[ctypes.get_errno()]


def fam_table(f, new):
    out = []
    for n, fn in families(f, new):
        if n == "access":
            out.append("access=" + access_errno(f))
            continue
        out.append("%s=%s" % (n, res(fn)))
    return " ".join(out)


# ---------------------------------------------------- non-directory components
def t_component_is_file():
    mk(p("f1"))
    return fam_table(p("f1", "x"), p("f1", "x")) + " rename_dst=" + res(
        lambda: os.rename(mk(p("f1src")), p("f1", "x"))) + " link_new=" + res(
        lambda: os.link(p("f1src"), p("f1", "x"))) + " exists=%s" % os.path.isfile(p("f1"))


def t_component_dot_dotdot():
    mk(p("f1d")); os.mkdir(p("dd"))
    return table([("stat_dot", lambda: os.stat(p("f1d") + "/.")),
                  ("stat_dotdot", lambda: os.stat(p("f1d") + "/../f1d")),
                  ("mkdir_dotdot", lambda: os.mkdir(p("f1d") + "/../nd")),
                  ("open_creat_dotdot", lambda: os.open(p("f1d") + "/../nf", C, 0o600)),
                  ("stat_dir_dotdot", lambda: os.stat(p("dd") + "/../f1d"))])


def t_image_component_is_file():
    f = lower("/etc/os-release")
    return fam_table(f + "/x", f + "/x") + " exists=%s" % os.path.isfile(f)


def t_image_symlink_file_component():
    sh = image_link("/bin/sh", "/bin/bash" if HOST else "/bin/busybox")
    return table([("stat_x", lambda: os.stat(sh + "/x")),
                  ("open_creat_x", lambda: os.open(sh + "/x", C, 0o600)),
                  ("mkdir_x", lambda: os.mkdir(sh + "/x")),
                  ("stat_slash", lambda: os.stat(sh + "/")),
                  ("open_slash", lambda: os.open(sh + "/", os.O_RDONLY))])


def t_image_symlink_dir():
    run_ = image_link("/var/run", "/run")
    st = os.stat(run_ + "/")
    lst = os.lstat(run_ + "/")
    return "stat_slash_dir=%s lstat_slash_dir=%s lstat_noslash_link=%s open_slash=%s" % (
        os.path.stat.S_ISDIR(st.st_mode), os.path.stat.S_ISDIR(lst.st_mode),
        os.path.stat.S_ISLNK(os.lstat(run_).st_mode), res(lambda: os.open(run_ + "/", os.O_RDONLY)))


# --------------------------------------------------------------- trailing slash
def t_trailing_slash_file():
    f = mk(p("f2")); s = f + "/"
    return fam_table(s, s) + " open_creat_existing=" + res(lambda: os.open(s, C, 0o600)) + \
        " open_creat_excl_new=" + res(lambda: os.open(p("new2") + "/", C | os.O_EXCL, 0o600)) + \
        " open_creat_new=" + res(lambda: os.open(p("new2") + "/", C, 0o600)) + \
        " new2_created=%s" % os.path.lexists(p("new2")) + \
        " rename_dst=" + res(lambda: os.rename(f, p("f2b") + "/")) + \
        " mkfifo_new=" + res(lambda: os.mkfifo(p("new3") + "/")) + \
        " symlink_new=" + res(lambda: os.symlink("t", p("new4") + "/")) + \
        " created=%s" % any(os.path.lexists(p(n)) for n in ("new3", "new4", "f2c")) + \
        " link_new=" + res(lambda: os.link(f, p("f2c") + "/")) + \
        " exists=%s" % os.path.isfile(f)


def t_trailing_slash_dir():
    os.mkdir(p("d2")); os.mkdir(p("d2r")); os.mkdir(p("d2m"))
    return table([("stat", lambda: os.stat(p("d2") + "/")),
                  ("open", lambda: os.open(p("d2") + "/", os.O_RDONLY)),
                  ("open_creat", lambda: os.open(p("d2") + "/", C, 0o600)),
                  ("unlink", lambda: os.unlink(p("d2") + "/")),
                  ("mkdir_existing", lambda: os.mkdir(p("d2") + "/")),
                  ("mkdir_new", lambda: os.mkdir(p("d2b") + "/")),
                  ("mkdir_new_slashes", lambda: os.mkdir(p("d2c") + "//")),
                  ("rename_both", lambda: os.rename(p("d2m") + "/", p("d2n") + "/")),
                  ("rmdir", lambda: os.rmdir(p("d2r") + "/")),
                  ("unlink_missing", lambda: os.unlink(p("nothere") + "/")),
                  ("stat_missing", lambda: os.stat(p("nothere") + "/"))]) + \
        " d2b=%s d2c=%s d2n=%s" % (os.path.isdir(p("d2b")), os.path.isdir(p("d2c")), os.path.isdir(p("d2n")))


def t_trailing_slash_symlinks():
    os.mkdir(p("d4")); mk(p("d4", "c")); mk(p("f4"))
    os.symlink(p("d4"), p("dlink")); os.symlink(p("f4"), p("flink")); os.symlink(p("none"), p("nolink"))
    out = table([("stat_flink_x", lambda: os.stat(p("flink") + "/x")),
                 ("open_creat_flink_x", lambda: os.open(p("flink") + "/x", C, 0o600)),
                 ("stat_flink_slash", lambda: os.stat(p("flink") + "/")),
                 ("open_flink_slash", lambda: os.open(p("flink") + "/", os.O_RDONLY)),
                 ("unlink_flink_slash", lambda: os.unlink(p("flink") + "/")),
                 ("stat_dlink_slash", lambda: os.stat(p("dlink") + "/")),
                 ("open_dlink_slash", lambda: os.open(p("dlink") + "/", os.O_RDONLY)),
                 ("unlink_dlink_slash", lambda: os.unlink(p("dlink") + "/")),
                 ("rmdir_dlink_slash", lambda: os.rmdir(p("dlink") + "/")),
                 ("rename_dlink_slash", lambda: os.rename(p("dlink") + "/", p("dlink2"))),
                 ("stat_nolink_slash", lambda: os.stat(p("nolink") + "/")),
                 ("stat_dlink_c", lambda: os.stat(p("dlink", "c")))])
    try:
        lst = str(os.path.stat.S_ISDIR(os.lstat(p("dlink") + "/").st_mode))
    except OSError as x:
        lst = errno.errorcode[x.errno]
    return out + " lstat_dlink_slash_isdir=%s links_left=%s" % (
        lst, all(os.path.islink(p(n)) for n in ("dlink", "flink", "nolink")))


def t_image_trailing_slash():
    f = lower("/etc/shells"); g = lower("/etc/profile")
    return table([("stat", lambda: os.stat(f + "/")),
                  ("open", lambda: os.open(f + "/", os.O_RDONLY)),
                  ("open_wronly", lambda: os.open(f + "/", os.O_WRONLY)),
                  ("open_creat", lambda: os.open(f + "/", C, 0o600)),
                  ("unlink", lambda: os.unlink(f + "/")),
                  ("rmdir", lambda: os.rmdir(f + "/")),
                  ("mkdir", lambda: os.mkdir(f + "/")),
                  ("rename_src", lambda: os.rename(g + "/", p("gp"))),
                  ("rename_dst", lambda: os.rename(g, p("gp2") + "/"))]) + \
        " exists=%s,%s" % (os.path.isfile(f), os.path.isfile(g))


def t_image_symlink_unlink_slash():
    # Last: in Ginux this may hide the image symlink /var/run.
    run_ = image_link("/var/run", "/run")
    return table([("unlink", lambda: os.unlink(run_ + "/")),
                  ("rmdir", lambda: os.rmdir(run_ + "/"))]) + " link_left=%s" % os.path.islink(run_)


# ---------------------------------------------------------- "." and ".." last
def t_dir_dot_last():
    os.mkdir(p("d3")); mk(p("d3", "c")); os.mkdir(p("d5"))
    return table([("rmdir_dot", lambda: os.rmdir(p("d3") + "/.")),
                  ("rmdir_dot_slash", lambda: os.rmdir(p("d3") + "/./")),
                  ("rmdir_empty_dot", lambda: os.rmdir(p("d5") + "/.")),
                  ("rmdir_dotdot", lambda: os.rmdir(p("d3") + "/..")),
                  ("unlink_dot", lambda: os.unlink(p("d3") + "/.")),
                  ("unlink_dotdot", lambda: os.unlink(p("d3") + "/.."))]) + \
        " d5_left=%s" % os.path.isdir(p("d5"))


def main():
    import shutil
    shutil.rmtree(BASE, ignore_errors=True); os.makedirs(BASE)
    if HOST:
        shutil.rmtree("/tmp/gt24_lower", ignore_errors=True)
    order = ["component_is_file", "component_dot_dotdot", "image_component_is_file",
             "image_symlink_file_component", "image_symlink_dir", "trailing_slash_file",
             "trailing_slash_dir", "trailing_slash_symlinks", "image_trailing_slash",
             "dir_dot_last", "image_symlink_unlink_slash"]
    for n in order:
        run(n, globals()["t_" + n])
    print("GT_DONE", flush=True)


if __name__ == "__main__":
    main()
