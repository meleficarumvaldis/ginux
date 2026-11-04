"""Issue 09 probe: memory-syscall argument edges (mmap/mprotect/madvise/msync/mremap/mincore).

Each line: GT <name> <result>. Run on Linux (GT_HOST=1) for reference and inside Ginux.
Every test runs in a forked child with a watchdog so a crash only affects that test.
"""
import ctypes, errno, os, select, signal, sys, time

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
HOST = os.environ.get("GT_HOST") == "1"
NR = dict(mmap=9, mprotect=10, munmap=11, mremap=25, msync=26, mincore=27, madvise=28,
          ftruncate=77)
PROT_R, PROT_W, PROT_X = 1, 2, 4
MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANON, MAP_NOREPLACE = 1, 2, 0x10, 0x20, 0x100000
MREMAP_MAYMOVE, MREMAP_FIXED = 1, 2
MADV_DONTNEED = 4
MS_SYNC = 4
PAGE = 4096


def sc(name, *args):
    a = [ctypes.c_long(x) if isinstance(x, int) else x for x in args]
    r = libc.syscall(ctypes.c_long(NR[name]), *a)
    if r == -1:
        e = ctypes.get_errno()
        return "-" + errno.errorcode.get(e, str(e))
    return r


def ok(r):
    return isinstance(r, int) and r > 0


def addr_or(r):
    return "ADDR" if ok(r) else r


def anon(length=PAGE, prot=3, flags=0, addr=0, fd=-1, off=0):
    return sc("mmap", addr, length, prot, MAP_PRIVATE | MAP_ANON | flags, fd, off)


def out(name, value):
    print("GT", name, value, flush=True)


def run(name, fn, limit=20.0):
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
    ready, _, _ = select.select([r], [], [], limit)
    res = os.read(r, 300).decode() if ready else "HANG(>%ss)" % limit
    if not ready:
        os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    if not res and os.WIFSIGNALED(status):
        res = "SIG%d" % os.WTERMSIG(status)
    out(name, res or "EMPTY")


def peek(a):
    return ctypes.c_ubyte.from_address(a).value


def poke(a, v):
    ctypes.c_ubyte.from_address(a).value = v


os.makedirs("/tmp/gt", exist_ok=True)
os.chdir("/tmp/gt")
with open("/tmp/gt/small", "wb") as f:
    f.write(b"S" * 100)

# ---- 1. prot subsets (gt.py rows + extras) ----
run("mmap_rwx_anon", lambda: addr_or(anon(prot=7)))
run("mmap_wonly_anon", lambda: addr_or(anon(prot=PROT_W)))


def wonly_write_read():
    p = anon(prot=PROT_W)
    if not ok(p):
        return p
    poke(p, 0x42)
    return "rw=%d" % peek(p)


run("mmap_wonly_write_then_read", wonly_write_read)
run("mmap_xonly_anon", lambda: addr_or(anon(prot=PROT_X)))
run("mmap_wx_anon", lambda: addr_or(anon(prot=PROT_W | PROT_X)))
run("mmap_r_sem_anon", lambda: addr_or(anon(prot=PROT_R | 8)))
run("mmap_prot_junk_bit", lambda: addr_or(anon(prot=PROT_R | 0x10)))


def mprotect_case(prot, length=PAGE, delta=0):
    def f():
        p = anon(length=2 * PAGE)
        return sc("mprotect", p + delta, length, prot)
    return f


run("mprotect_rwx", mprotect_case(7))
run("mprotect_wonly", mprotect_case(PROT_W))
run("mprotect_xonly", mprotect_case(PROT_X))
run("mprotect_r_sem", mprotect_case(PROT_R | 8))
run("mprotect_growsdown_growsup", mprotect_case(PROT_R | 0x3000000))
run("mprotect_growsdown_anon", mprotect_case(PROT_R | 0x1000000))
run("mprotect_len0", mprotect_case(PROT_R, 0))
run("mprotect_len0_unaligned", mprotect_case(PROT_R, 0, 1))
run("mprotect_len0_badprot", mprotect_case(0x80, 0))


def mprotect_wonly_write():
    p = anon()
    r = sc("mprotect", p, PAGE, PROT_W)
    poke(p, 7)
    return "%s val=%d" % (r, peek(p))


run("mprotect_wonly_then_write", mprotect_wonly_write)

# ---- 2. zero lengths / msync order ----
p = anon(length=2 * PAGE)
vec = ctypes.create_string_buffer(4)
run("madvise_len0", lambda: sc("madvise", p, 0, MADV_DONTNEED))
run("madvise_len0_unaligned", lambda: sc("madvise", p + 1, 0, MADV_DONTNEED))
run("madvise_len0_badadvice", lambda: sc("madvise", p, 0, 9999))
run("msync_len0", lambda: sc("msync", p, 0, MS_SYNC))
run("msync_unaligned", lambda: sc("msync", p + 1, PAGE, MS_SYNC))
run("msync_len0_badflags", lambda: sc("msync", p, 0, 0x100))
run("mincore_len0", lambda: sc("mincore", p, 0, ctypes.addressof(vec)))
run("mincore_len0_unaligned", lambda: sc("mincore", p + 1, 0, ctypes.addressof(vec)))

# ---- 3. mmap flags / precedence ----
run("mmap_anon_fd0", lambda: addr_or(anon(fd=0)))
run("mmap_anon_fd99_off8192", lambda: addr_or(anon(fd=99, off=8192)))
run("mmap_anon_unaligned_off", lambda: addr_or(anon(off=1)))


def fixed_and_noreplace():
    free = anon()
    sc("munmap", free, PAGE)
    r = anon(addr=free, flags=MAP_FIXED | MAP_NOREPLACE)
    again = anon(addr=free, flags=MAP_FIXED | MAP_NOREPLACE)
    return "%s at_hint=%s again=%s" % (addr_or(r), r == free, again)


run("mmap_fixed_and_noreplace", fixed_and_noreplace)


def file_case(path, length, prot, flags, off, mode=os.O_RDONLY):
    def f():
        fd = os.open(path, mode)
        r = sc("mmap", 0, length, prot, flags, fd, off)
        os.close(fd)
        return addr_or(r)
    return f


run("mmap_file_unaligned_off", file_case("/tmp/gt/small", PAGE, PROT_R, MAP_PRIVATE, 1))
run("mmap_badfd_len0", lambda: sc("mmap", 0, 0, PROT_R, MAP_PRIVATE, 99, 0))
run("mmap_badfd_unaligned_off", lambda: sc("mmap", 0, PAGE, PROT_R, MAP_PRIVATE, 99, 1))
run("mmap_file_len0", file_case("/tmp/gt/small", 0, PROT_R, MAP_PRIVATE, 0))

# ---- 4. mremap ----


def mremap_fixed_same_size():
    a = anon()
    b = anon()
    poke(a, ord("X"))
    r = sc("mremap", a, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, b)
    moved = r == b and peek(b) == ord("X")
    old_gone = sc("mincore", a, PAGE, ctypes.addressof(vec))
    return ("MOVED" if moved else ("SAME" if r == a else r)) + " old_mincore=%s" % old_gone


run("mremap_fixed_same_size", mremap_fixed_same_size)


def mremap_fixed_shrink():
    a = anon(length=2 * PAGE)
    b = anon(length=3 * PAGE)
    poke(a, ord("Y"))
    r = sc("mremap", a, 2 * PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, b)
    moved = r == b and peek(b) == ord("Y")
    tail = sc("mincore", b + PAGE, PAGE, ctypes.addressof(vec))  # old dest tail stays mapped
    old = sc("mincore", a, 2 * PAGE, ctypes.addressof(vec))
    return "%s dest_tail=%s old=%s" % ("MOVED" if moved else r, tail, old)


run("mremap_fixed_shrink", mremap_fixed_shrink)


def mremap_fixed_grow_over_mapped():
    a = anon()
    b = anon(length=2 * PAGE)
    poke(a, ord("Z"))
    poke(b + PAGE, 0x55)
    r = sc("mremap", a, PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, b)
    if r != b:
        return r
    return "MOVED first=%s second=%d" % (chr(peek(b)), peek(b + PAGE))


run("mremap_fixed_grow_over_mapped", mremap_fixed_grow_over_mapped)


def mremap_unmapped():
    q = anon()
    sc("munmap", q, PAGE)
    return sc("mremap", q, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0)


run("mremap_unmapped", mremap_unmapped)

# ---- 5. DONTNEED on PROT_NONE ----
run("madvise_dontneed_protnone", lambda: sc("madvise", anon(prot=0), PAGE, MADV_DONTNEED))


def dontneed_protnone_zero_fill():
    q = anon()
    poke(q, 0xA5)
    r1 = sc("mprotect", q, PAGE, 0)
    r2 = sc("madvise", q, PAGE, MADV_DONTNEED)
    r3 = sc("mprotect", q, PAGE, 3)
    return "%s %s %s val=%d" % (r1, r2, r3, peek(q))


run("madvise_dontneed_protnone_zero_fill", dontneed_protnone_zero_fill)

# ---- 6. file mmap at/after EOF ----


def mmap_empty_file():
    fd = os.open("/tmp/gt/empty", os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
    r = sc("mmap", 0, PAGE, PROT_R, MAP_PRIVATE, fd, 0)
    os.close(fd)
    return addr_or(r)


run("mmap_empty_file", mmap_empty_file)
run("mmap_file_offset_past_eof", file_case("/tmp/gt/small", PAGE, PROT_R, MAP_PRIVATE, 2 * PAGE))
run("mmap_file_huge_offset", file_case("/tmp/gt/small", PAGE, PROT_R, MAP_PRIVATE, (1 << 63) - PAGE))


def mmap_empty_access():
    fd = os.open("/tmp/gt/empty", os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
    r = sc("mmap", 0, PAGE, PROT_R, MAP_PRIVATE, fd, 0)
    os.close(fd)
    if not ok(r):
        return r
    return "read=%d" % peek(r)  # Linux: SIGBUS


run("mmap_empty_file_access", mmap_empty_access)


def create_mmap_ftruncate():
    path = "/tmp/gt/grow"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
    r = sc("mmap", 0, PAGE, 3, MAP_SHARED, fd, 0)
    if not ok(r):
        os.close(fd)
        return r
    t = sc("ftruncate", fd, PAGE)
    poke(r, ord("Q"))
    s = sc("msync", r, PAGE, MS_SYNC)
    sc("munmap", r, PAGE)
    os.close(fd)
    with open(path, "rb") as f:
        data = f.read(1)
    return "ftruncate=%s msync=%s file0=%r" % (t, s, data)


run("mmap_shared_empty_then_ftruncate", create_mmap_ftruncate)


def small_file_tail_page():
    fd = os.open("/tmp/gt/small", os.O_RDONLY)
    r = sc("mmap", 0, PAGE, PROT_R, MAP_PRIVATE, fd, 0)
    os.close(fd)
    return "first=%s tail=%d" % (chr(peek(r)), peek(r + 200)) if ok(r) else r


run("mmap_small_file_tail", small_file_tail_page)

# ---- optional: allocator reuse after munmap ----


def mmap_munmap_cycle(count, size):
    def f():
        t = time.time()
        for i in range(count):
            r = anon(length=size, flags=0x4000)
            if not ok(r):
                return "FAIL_AT_%d_%s" % (i, r)
            sc("munmap", r, size)
        return "OK%d %.2fs" % (count, time.time() - t)
    return f


run("mmap_munmap_1g_x1", mmap_munmap_cycle(1, 1 << 30), 120)
run("mmap_munmap_64m_x100", mmap_munmap_cycle(100, 64 << 20), 120)

print("GT_DONE", flush=True)
