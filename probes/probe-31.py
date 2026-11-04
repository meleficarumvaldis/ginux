"""Probe 31: symlinks in the middle of a path and relative symlink targets.

Absolute and relative directory links used mid-path, chains of 2-3 and 40/41
links, links to "..", "/" and to a file, loops, dangling links, relative
targets for open/creat/stat/readlink/unlink/rename, overlay links to image
directories and image links to overlay directories, getcwd after chdir
through a link.

Prints 'GT <name> <result>'. Run on Linux with GT_HOST=1 (image paths are
then stand-ins in /tmp).
"""
import errno, os, select, shutil, signal, stat, sys

HOST = os.environ.get("GT_HOST") == "1"
BASE = "/tmp/gt31"


def err(fn):
    try:
        r = fn()
        return "0" if r is None else str(r)
    except OSError as x:
        return errno.errorcode.get(x.errno, str(x.errno))


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
        os.write(w, res.encode()[:400])
        os._exit(0)
    os.close(w)
    ok, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 400).decode() if ok else "HANG"
    if not ok:
        os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("GT", name, res, flush=True)


def fresh(name):
    d = os.path.join(BASE, name)
    os.mkdir(d)
    return d


def mk(path, data=b"hello"):
    with open(path, "wb") as f:
        f.write(data)
    return path


def rd(path):
    with open(path, "rb") as f:
        return f.read().decode()


def size(path):
    return os.stat(path).st_size


def creat(path):
    os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))


def kind(path):
    m = os.lstat(path).st_mode
    return "link" if stat.S_ISLNK(m) else "dir" if stat.S_ISDIR(m) else "file" if stat.S_ISREG(m) else "other"


def dirlink_base(name, target_kind):
    t = fresh(name)
    os.mkdir(os.path.join(t, "d"))
    mk(os.path.join(t, "d", "c"), b"C")
    if target_kind == "abs":
        os.symlink(os.path.join(t, "d"), os.path.join(t, "ln"))
    else:
        os.symlink("d", os.path.join(t, "ln"))
    return t


def t_mid(target_kind):
    def f():
        t = dirlink_base("mid_" + target_kind, target_kind)
        j = lambda *n: os.path.join(t, *n)
        o = []
        o.append("stat=%s" % err(lambda: size(j("ln", "c"))))
        o.append("lstat=%s" % err(lambda: kind(j("ln", "c"))))
        o.append("open=%s" % err(lambda: rd(j("ln", "c"))))
        o.append("access=%s" % err(lambda: os.access(j("ln", "c"), os.R_OK)))
        o.append("nofollow=%s" % err(lambda: os.close(os.open(j("ln", "c"), os.O_RDONLY | os.O_NOFOLLOW))))
        o.append("creat=%s" % err(lambda: creat(j("ln", "new"))))
        o.append("in_d=%s" % os.path.exists(j("d", "new")))
        o.append("beside=%s" % os.path.exists(j("new")))
        o.append("mkdir=%s" % err(lambda: os.mkdir(j("ln", "sub"))))
        o.append("mkdir_in_d=%s" % os.path.isdir(j("d", "sub")))
        o.append("symlink=%s" % err(lambda: os.symlink("c", j("ln", "sl"))))
        o.append("readlink=%s" % err(lambda: os.readlink(j("ln", "sl"))))
        o.append("via_inner=%s" % err(lambda: rd(j("ln", "sl"))))
        o.append("unlink_inner=%s" % err(lambda: os.unlink(j("ln", "sl"))))
        o.append("c_kept=%s" % os.path.exists(j("d", "c")))
        o.append("rename=%s" % err(lambda: os.rename(j("ln", "new"), j("ln", "new2"))))
        o.append("renamed=%s" % os.path.exists(j("d", "new2")))
        o.append("rename_out=%s" % err(lambda: os.rename(j("ln", "new2"), j("moved"))))
        o.append("moved=%s" % (os.path.exists(j("moved")) and not os.path.exists(j("d", "new2"))))
        o.append("chmod=%s" % err(lambda: os.chmod(j("ln", "c"), 0o640)))
        o.append("mode=%o" % (os.stat(j("d", "c")).st_mode & 0o777))
        o.append("listdir=%s" % err(lambda: ",".join(sorted(os.listdir(j("ln"))))))
        o.append("unlink_c=%s" % err(lambda: os.unlink(j("ln", "c"))))
        o.append("c_gone=%s" % (not os.path.exists(j("d", "c"))))
        o.append("unlink_link=%s" % err(lambda: os.unlink(j("ln"))))
        o.append("d_kept=%s" % os.path.isdir(j("d")))
        return " ".join(o)
    return f


def t_dirfd():
    t = dirlink_base("dirfd", "rel")
    dfd = os.open(t, os.O_RDONLY | os.O_DIRECTORY)
    o = ["openat=%s" % err(lambda: os.read(os.open("ln/c", os.O_RDONLY, dir_fd=dfd), 8).decode())]
    o.append("statat=%s" % err(lambda: os.stat("ln/c", dir_fd=dfd).st_size))
    o.append("creatat=%s" % err(lambda: os.close(os.open("ln/n", os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=dfd))))
    o.append("in_d=%s" % os.path.exists(os.path.join(t, "d", "n")))
    return " ".join(o)


def t_chains():
    t = fresh("chains")
    j = lambda *n: os.path.join(t, *n)
    os.mkdir(j("d")); mk(j("d", "c"), b"C")
    os.symlink("d", j("l1")); os.symlink("l1", j("l2")); os.symlink(j("l2"), j("l3"))
    o = []
    for n in ("l2", "l3"):
        o.append("%s_stat=%s" % (n, err(lambda: size(j(n, "c")))))
        o.append("%s_open=%s" % (n, err(lambda: rd(j(n, "c")))))
    o.append("l3_creat=%s" % err(lambda: creat(j("l3", "n"))))
    o.append("in_d=%s" % os.path.exists(j("d", "n")))
    # A link whose target has a link in the middle.
    os.symlink("l1/c", j("deep"))
    o.append("deep_open=%s" % err(lambda: rd(j("deep"))))
    os.symlink("l2/../d", j("deep2"))
    o.append("deep2_mid=%s" % err(lambda: rd(j("deep2", "c"))))
    return " ".join(o)


def t_final_chains():
    t = fresh("fchains")
    j = lambda *n: os.path.join(t, *n)
    mk(j("real"), b"R")
    os.symlink("real", j("f1")); os.symlink("f1", j("f2")); os.symlink(j("f2"), j("f3"))
    o = []
    for n in ("f1", "f2", "f3"):
        o.append("%s=%s" % (n, err(lambda: rd(j(n)))))
    return " ".join(o)


def t_limit():
    t = fresh("limit")
    j = lambda *n: os.path.join(t, *n)
    os.mkdir(j("d")); mk(j("d", "c"), b"C")
    for count, prefix in ((40, "a"), (41, "b")):
        for i in range(count):
            nxt = "d" if i == count - 1 else "%s%d" % (prefix, i + 1)
            os.symlink(nxt, j("%s%d" % (prefix, i)))
    return "links40=%s links41=%s" % (err(lambda: size(j("a0", "c"))), err(lambda: size(j("b0", "c"))))


def t_loops():
    t = fresh("loops")
    j = lambda *n: os.path.join(t, *n)
    os.symlink("self", j("self")); os.symlink("lb", j("la")); os.symlink("la", j("lb"))
    os.mkdir(j("d")); os.symlink(".", j("d", "dot"))
    o = []
    o.append("self_stat=%s" % err(lambda: os.stat(j("self", "x"))))
    o.append("pair_stat=%s" % err(lambda: os.stat(j("la", "x"))))
    o.append("pair_open=%s" % err(lambda: os.open(j("la", "x"), os.O_RDONLY)))
    o.append("pair_creat=%s" % err(lambda: creat(j("la", "x"))))
    o.append("pair_mkdir=%s" % err(lambda: os.mkdir(j("la", "x"))))
    # "." link: 40 hops resolve, 41 are too many.
    o.append("dot40=%s" % err(lambda: kind(j("d", *(["dot"] * 40 + ["dot"])) )))
    o.append("dot41=%s" % err(lambda: os.stat(j("d", *(["dot"] * 41 + ["x"])))))
    return " ".join(o)


def t_dotdot():
    t = fresh("dotdot")
    j = lambda *n: os.path.join(t, *n)
    os.makedirs(j("x", "y", "d")); mk(j("x", "y", "d", "c"), b"C")
    os.symlink("x/y/d", j("ln"))
    os.mkdir(j("e")); os.symlink("..", j("e", "up")); mk(j("top"), b"T")
    o = []
    # Linux: "ln/.." is the parent of the target (x/y), not t.
    o.append("ln_dotdot=%s" % err(lambda: size(j("ln", "..", "d", "c"))))
    o.append("ln_dotdot_lexical=%s" % err(lambda: os.stat(j("ln", "..", "top")) and None))
    o.append("up=%s" % err(lambda: rd(j("e", "up", "top"))))
    o.append("up_creat=%s" % err(lambda: creat(j("e", "up", "n"))))
    o.append("in_t=%s" % os.path.exists(j("n")))
    os.symlink("/", j("root"))
    o.append("root_mid=%s" % err(lambda: kind(j("root", "etc", "passwd"))))
    o.append("root_back=%s" % err(lambda: rd(os.path.join(j("root"), t.lstrip("/"), "top"))))
    return " ".join(o)


def t_bad_mid():
    t = fresh("badmid")
    j = lambda *n: os.path.join(t, *n)
    mk(j("f")); os.symlink("f", j("flink")); os.symlink("nowhere", j("dang"))
    o = []
    for n in ("flink", "dang"):
        o.append("%s_stat=%s" % (n, err(lambda: os.stat(j(n, "x")))))
        o.append("%s_open=%s" % (n, err(lambda: os.open(j(n, "x"), os.O_RDONLY))))
        o.append("%s_creat=%s" % (n, err(lambda: creat(j(n, "x")))))
        o.append("%s_mkdir=%s" % (n, err(lambda: os.mkdir(j(n, "x")))))
    o.append("nothing_made=%s" % (not os.path.exists(j("nowhere")) and not os.path.exists(j("x"))))
    return " ".join(o)


def t_relative_targets():
    t = fresh("reltarget")
    j = lambda *n: os.path.join(t, *n)
    os.makedirs(j("rl", "sub")); os.mkdir(j("cwd"))
    os.symlink("target_rel", j("rl", "sub", "link"))
    os.symlink("target_trunc", j("rl", "sub", "link_t"))
    mk(j("rl", "sub", "real"), b"R"); os.symlink("real", j("rl", "sub", "l2"))
    os.symlink("../sub/l2", j("rl", "sub", "l3"))
    os.chdir(j("cwd"))
    o = []
    o.append("creat=%s" % err(lambda: creat(j("rl", "sub", "link"))))
    o.append("next_to_link=%s" % os.path.exists(j("rl", "sub", "target_rel")))
    o.append("in_cwd=%s" % os.path.exists(j("cwd", "target_rel")))
    o.append("creat_trunc=%s" % err(lambda: os.close(os.open(j("rl", "sub", "link_t"), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600))))
    o.append("trunc_next=%s" % os.path.exists(j("rl", "sub", "target_trunc")))
    o.append("read=%s" % err(lambda: rd(j("rl", "sub", "l2"))))
    o.append("stat=%s" % err(lambda: size(j("rl", "sub", "l2"))))
    o.append("lstat=%s" % err(lambda: kind(j("rl", "sub", "l2"))))
    o.append("readlink=%s" % err(lambda: os.readlink(j("rl", "sub", "l2"))))
    o.append("chain_read=%s" % err(lambda: rd(j("rl", "sub", "l3"))))
    o.append("write=%s" % err(lambda: mk(j("rl", "sub", "l2"), b"W") and None))
    o.append("real_now=%s" % rd(j("rl", "sub", "real")))
    o.append("rel_cwd_path=%s" % err(lambda: rd(os.path.join("..", "rl", "sub", "l2"))))
    o.append("unlink=%s" % err(lambda: os.unlink(j("rl", "sub", "l2"))))
    o.append("link_gone=%s" % (not os.path.lexists(j("rl", "sub", "l2"))))
    o.append("target_kept=%s" % os.path.exists(j("rl", "sub", "real")))
    os.symlink("real", j("rl", "sub", "l4"))
    o.append("rename=%s" % err(lambda: os.rename(j("rl", "sub", "l4"), j("rl", "l4"))))
    o.append("moved_is_link=%s" % err(lambda: kind(j("rl", "l4"))))
    o.append("now_dangling=%s" % err(lambda: rd(j("rl", "l4"))))
    dfd = os.open(j("rl"), os.O_RDONLY | os.O_DIRECTORY)
    os.symlink("t3", j("rl", "sub", "link3"))
    o.append("creatat=%s" % err(lambda: os.close(os.open("sub/link3", os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=dfd))))
    o.append("creatat_next=%s" % os.path.exists(j("rl", "sub", "t3")))
    o.append("creatat_dirfd=%s" % os.path.exists(j("rl", "t3")))
    return " ".join(o)


def t_rename_through_link():
    t = dirlink_base("renlink", "rel")
    j = lambda *n: os.path.join(t, *n)
    mk(j("d", "a"), b"A")
    o = ["rename=%s" % err(lambda: os.rename(j("ln", "a"), j("ln", "b")))]
    o.append("in_d=%s" % (os.path.exists(j("d", "b")) and not os.path.exists(j("d", "a"))))
    o.append("rename_in=%s" % err(lambda: os.rename(j("d", "b"), j("ln", "..", "b2"))))
    o.append("b2_at_top=%s" % os.path.exists(j("b2")))
    return " ".join(o)


def t_getcwd():
    t = dirlink_base("cwdlink", "rel")
    j = lambda *n: os.path.join(t, *n)
    o = []
    o.append("chdir=%s" % err(lambda: os.chdir(j("ln"))))
    o.append("cwd=%s" % err(lambda: os.getcwd().replace(t, "T")))
    o.append("rel_read=%s" % err(lambda: rd("c")))
    os.chdir("/")
    o.append("chdir_dot=%s" % err(lambda: os.chdir(j("ln", "."))))
    o.append("cwd_dot=%s" % err(lambda: os.getcwd().replace(t, "T")))
    o.append("rel_read_dot=%s" % err(lambda: rd("c")))
    return " ".join(o)


def lower(name):
    """An image path on Ginux; a stand-in in /tmp on Linux."""
    return name if not HOST else "/tmp/gt31_lower" + name


def host_lower_setup():
    root = "/tmp/gt31_lower"
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root + "/usr/local/lib/python3.13")
    mk(root + "/usr/local/lib/python3.13/os.py", b"# os\n")
    os.makedirs(root + "/var"); os.makedirs(root + "/run")
    os.symlink("../run", root + "/var/run")
    os.makedirs(root + "/usr/lib/real")
    mk(root + "/usr/lib/real/f", b"F")
    os.symlink("real", root + "/usr/lib/imglink")


def image_dir_link():
    """An image symlink to an image directory with entries (Ginux only)."""
    if HOST:
        return lower("/usr/lib/imglink")
    skip = ("/proc", "/sys", "/dev", "/tmp", "/run", "/var/run", "/usr/local/lib/python3.13")
    for root, dirs, files in os.walk("/"):
        if root.count("/") > 3 or root.startswith(skip):
            dirs[:] = []
            continue
        dirs.sort()
        for n in sorted(dirs + files):
            p = os.path.join(root, n)
            if p not in skip and os.path.islink(p) and os.path.isdir(p):
                try:
                    if os.listdir(p):
                        return p
                except OSError:
                    pass
    return None


def t_mixed_overlay_to_image():
    t = fresh("mixo")
    j = lambda *n: os.path.join(t, *n)
    img = lower("/usr/local/lib/python3.13")
    os.symlink(img, j("olink"))
    os.symlink("olink", j("olink2"))
    o = []
    o.append("stat=%s" % err(lambda: kind(j("olink", "os.py"))))
    o.append("open=%s" % err(lambda: len(rd(j("olink", "os.py"))) > 0))
    o.append("chain=%s" % err(lambda: kind(j("olink2", "os.py"))))
    o.append("listdir=%s" % err(lambda: "os.py" in os.listdir(j("olink"))))
    o.append("creat=%s" % err(lambda: creat(j("olink", "zz_gt31"))))
    o.append("in_image_dir=%s" % os.path.exists(os.path.join(img, "zz_gt31")))
    o.append("unlink=%s" % err(lambda: os.unlink(j("olink", "zz_gt31"))))
    o.append("gone=%s" % (not os.path.exists(os.path.join(img, "zz_gt31"))))
    return " ".join(o)


def t_mixed_image_to_overlay():
    vr = lower("/var/run")
    run_dir = lower("/run")
    t = fresh("mixi")
    j = lambda *n: os.path.join(t, *n)
    o = ["is_image_link=%s" % os.path.islink(vr)]
    o.append("mkdir=%s" % err(lambda: os.mkdir(os.path.join(vr, "gt31d"))))
    o.append("dir_at_target=%s" % os.path.isdir(os.path.join(run_dir, "gt31d")))
    o.append("write=%s" % err(lambda: mk(os.path.join(vr, "gt31d", "c"), b"C") and None))
    o.append("stat_target=%s" % err(lambda: size(os.path.join(run_dir, "gt31d", "c"))))
    o.append("stat_via=%s" % err(lambda: size(os.path.join(vr, "gt31d", "c"))))
    o.append("listdir_via=%s" % err(lambda: ",".join(os.listdir(os.path.join(vr, "gt31d")))))
    # overlay link -> image link -> directory with overlay content
    os.symlink(vr, j("ol"))
    o.append("ov_img_chain=%s" % err(lambda: rd(j("ol", "gt31d", "c"))))
    o.append("unlink_via=%s" % err(lambda: os.unlink(os.path.join(vr, "gt31d", "c"))))
    o.append("rmdir_via=%s" % err(lambda: os.rmdir(os.path.join(vr, "gt31d"))))
    o.append("gone=%s" % (not os.path.exists(os.path.join(run_dir, "gt31d"))))
    return " ".join(o)


def t_mixed_image_link_mid():
    p = image_dir_link()
    if p is None:
        return "no_image_dir_link"
    first = sorted(os.listdir(p))[0]
    real = os.path.realpath(p)
    o = ["found=%s" % ("yes" if HOST else p)]
    o.append("stat=%s" % err(lambda: os.lstat(os.path.join(p, first)).st_mode == os.lstat(os.path.join(real, first)).st_mode))
    t = fresh("mixl")
    os.symlink(p, os.path.join(t, "ol"))
    o.append("ov_img_chain=%s" % err(lambda: os.lstat(os.path.join(t, "ol", first)).st_mode == os.lstat(os.path.join(real, first)).st_mode))
    return " ".join(o)


def main():
    shutil.rmtree(BASE, ignore_errors=True)
    os.mkdir(BASE)
    if HOST:
        host_lower_setup()
    run("mid_abs", t_mid("abs"))
    run("mid_rel", t_mid("rel"))
    run("mid_dirfd", t_dirfd)
    run("chains", t_chains)
    run("final_chains", t_final_chains)
    run("limit", t_limit)
    run("loops", t_loops)
    run("dotdot", t_dotdot)
    run("bad_mid", t_bad_mid)
    run("relative_targets", t_relative_targets)
    run("rename_through_link", t_rename_through_link)
    run("getcwd", t_getcwd)
    run("mixed_overlay_to_image", t_mixed_overlay_to_image)
    run("mixed_image_to_overlay", t_mixed_image_to_overlay)
    run("mixed_image_link_mid", t_mixed_image_link_mid)
    print("GT_DONE", flush=True)


main()
