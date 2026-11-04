import os
for p in ["/init", "/lib64/ld-ginux.so", "/lib64/libginux.so", "/sbin/init", "/etc/hostname", "/etc/ginux-release", "/etc/os-release"]:
    try:
        st = os.stat(p)
        with open(p, "rb") as f:
            head = f.read(24)
        print("GT exists", p, "size=%d head=%r" % (st.st_size, head), flush=True)
    except OSError as e:
        print("GT exists", p, "ENOENT" if e.errno == 2 else e, flush=True)
try:
    before = open("/etc/hostname", "rb").read()
    os.unlink("/etc/hostname")
    try:
        after = open("/etc/hostname", "rb").read()
        print("GT after_unlink_open", "readable=%r (before=%r)" % (after, before), flush=True)
    except OSError as e:
        print("GT after_unlink_open", "ENOENT" if e.errno == 2 else e, flush=True)
    print("GT after_unlink_lexists", os.path.lexists("/etc/hostname"), flush=True)
except OSError as e:
    print("GT after_unlink_open skip", e, flush=True)
print("GT root_listing_has_init", "init" in os.listdir("/"), flush=True)
print("GT_DONE", flush=True)
