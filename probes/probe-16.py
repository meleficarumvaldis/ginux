"""readdir of image (lower-layer) directories must reflect overlay changes.

In Ginux the paths are real image directories. With GT_HOST=1 an equivalent tree
is created under /tmp so Linux gives the reference values without touching /etc.
"""
import ctypes, os, struct

HOST = os.environ.get("GT_HOST") == "1"
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
root = "/tmp/gtfs5" if HOST else ""
if HOST:
    os.makedirs(root + "/etc", exist_ok=True)
    for name in ("shells", "motd", "issue", "hostname", "hosts"):
        open(root + "/etc/" + name, "w").close()
    os.makedirs(root + "/usr/share/misc", exist_ok=True)


def out(name, value):
    print("GT", name, value, flush=True)


def run(name, fn):
    try:
        out(name, fn())
    except Exception as exc:
        out(name, "EXC:" + type(exc).__name__ + ":" + str(exc)[:60])


def getdents(path, size):
    """Raw getdents64 (217) with a tiny buffer: returns [(name, d_type)] and call count."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    buf = ctypes.create_string_buffer(size)
    names, calls, offsets = [], 0, []
    try:
        while True:
            n = libc.syscall(ctypes.c_long(217), ctypes.c_long(fd), buf, ctypes.c_long(size))
            calls += 1
            if n < 0:
                return "ERR%d" % ctypes.get_errno(), calls, offsets
            if n == 0:
                break
            pos = 0
            while pos < n:
                ino, off, reclen, dtype = struct.unpack_from("QqHB", buf.raw, pos)
                name = buf.raw[pos + 19:pos + reclen].split(b"\0", 1)[0].decode()
                names.append((name, dtype))
                offsets.append(off)
                pos += reclen
            if calls > 100000:
                return "LOOP", calls, offsets
    finally:
        os.close(fd)
    return names, calls, offsets


def check_small(path):
    names, calls, offsets = getdents(path, 48)
    if isinstance(names, str):
        return names
    plain = [n for n, _ in names]
    want = set(os.listdir(path)) | {".", ".."}
    return "dup=%d missing=%d extra=%d multi_call=%s" % (
        len(plain) - len(set(plain)), len(want - set(plain)), len(set(plain) - want), calls > 3)


etc, share = root + "/etc", root + "/usr/share"
out("etc_baseline_small_buffer", check_small(etc))
open(etc + "/gt-new-file", "w").close()
out("new_file_listed", "gt-new-file" in os.listdir(etc))
os.unlink(etc + "/shells")
out("unlinked_file_hidden", "shells" not in os.listdir(etc))
out("unlinked_file_stat_enoent", not os.path.lexists(etc + "/shells"))
os.mkdir(share + "/gt-new-dir")
out("new_dir_listed", "gt-new-dir" in os.listdir(share))
with os.scandir(share) as it:
    out("new_dir_dtype_dir", [e.is_dir(follow_symlinks=False) for e in it if e.name == "gt-new-dir"])
try:
    os.rename(etc + "/motd", etc + "/motd.renamed")
    names = os.listdir(etc)
    out("rename_listing", "motd" not in names and "motd.renamed" in names)
except OSError as exc:
    out("rename_listing", "SKIP:" + os.strerror(exc.errno))
# copy-up (overlay entry with the same name as an image entry) must be listed once
with open(etc + "/issue", "a") as f:
    f.write("x")
out("copied_up_listed_once", os.listdir(etc).count("issue"))
with os.scandir(etc) as it:
    dup = len([e.name for e in it]) - len(set(os.listdir(etc)))
out("no_duplicate_entries", dup == 0)
# a new name in the overlay over a whited-out image name is listed once
open(etc + "/shells", "w").close()
out("recreated_listed_once", os.listdir(etc).count("shells"))
os.unlink(etc + "/shells")
out("etc_after_small_buffer", check_small(etc))
for i in range(20):
    open(share + "/gt-new-dir/f%02d" % i, "w").close()
out("overlay_dir_small_buffer", check_small(share + "/gt-new-dir"))
out("overlay_dir_count", len(os.listdir(share + "/gt-new-dir")))
out("share_small_buffer", check_small(share))
run("ls_wc_matches_listdir",
    lambda: int(os.popen("ls -a %s | wc -l" % etc).read().strip()) == len(os.listdir(etc)) + 2)
# lstat after whiteout of image files must not fall back to synthesized paths
for name in ("hostname", "hosts", "resolv.conf"):
    p = etc + "/" + name
    if not os.path.lexists(p):
        out("lstat_after_unlink_" + name, "ABSENT")
        continue
    try:
        os.unlink(p)
    except OSError as exc:
        out("lstat_after_unlink_" + name, "UNLINK:" + os.strerror(exc.errno))
        continue
    out("lstat_after_unlink_" + name, "enoent" if not os.path.lexists(p) else "still-there")
print("GT_DONE", flush=True)
