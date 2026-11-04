# How to verify these patches (for the reviewing agent)

Every patch is **one self-contained commit on top of `origin/main`**, two for
issue 11 (11a, then 11b). Each one applies alone and passes `make check`.
22a and 22b need 18 first. Each patch is also published as a branch
`fix/<NN>-<slug>` in github.com/meleficarumvaldis/ginux, which is what the PRs
are opened from. They stack in the order given below. The combined series, 29
commits rebased and tested on `origin/main` c8d12653 (after #39), is
`git am`-able from the `series` of `fix/` branches (or ask for the mbox). Patch 21 is not part of it, because it is offered
for discussion.

All measurements were taken on an AMD Ryzen Threadripper PRO 5975WX (Zen 3),
openSUSE Tumbleweed, QEMU 11.1.2, KVM, openSUSE OVMF 4M firmware. The Linux
reference values come from running the same probe on Linux 7.3.0-rc5.

## 0. Environment notes

```sh
# A user-level ~/.cargo/config.toml with lto = "thin" overrides the
# workspace's lto = true and makes the controller exceed 64 KiB:
export CARGO_PROFILE_RELEASE_LTO=true
# Only needed without patch 04 on distributions whose OVMF path is not known:
export OVMF_CODE=/usr/share/qemu/ovmf-x86_64-4m-code.bin OVMF_VARS=/usr/share/qemu/ovmf-x86_64-4m-vars.bin
```

On AMD hosts under KVM, patch 01 is required before any QEMU test gets past
the Linux ELF probe. Patch 03 is required for `tests/qemu/boot.sh` to pass
under KVM. Patch 05 is required to unpack any image that contains the
`ca-certificates` package, which includes `python:3.13-alpine` used by the
probes below.

## 1. Per-patch checks

| Patch | Primary evidence | Command(s) |
|---|---|---|
| 01 AMD SYSRET SS RPL | KVM on AMD: panic `#GP(0x28)` before, boot passes after | `make test` (KVM, AMD host) |
| 02 fork child multi-exec, yield | new assertions in `verify_smp_process_scheduler`; domain experiments | `QEMU_ACCEL=tcg tests/qemu/boot.sh`; `probe-02-cmds.txt` via `domain-exp.sh` |
| 03 volume request exposure | KVM `boot.sh` 0/3 → 5/5 | `make build-verification && tests/qemu/boot.sh` (KVM) |
| 04 toolchain target, openSUSE OVMF | fresh checkout builds; `make doctor` finds OVMF | `make doctor; make check` |
| 05 OCI UTF-8 / space paths | unit test `accepts_utf8_and_space_names_…` | `cargo test -p ginux-oci` |
| 06 EFI image above 4 GiB | 9 new tests in `pe.rs`; boots at 4G/8G | `make check-pe`; `GINUX_MEMORY=8G make run` |
| 07 futex/time | boot checks updated/added; probe | `probe-07.py` |
| 08 shared mmap of read-only fd (security) | boot marker `shared file mapping write access validated` | `boot.sh` (TCG); `probe-08.py` |
| 09 memory syscall arguments | boot check `verify_linux_memory_argument_edges`; probe 40/45 rows | `probe-09.py` |
| 10 signals | boot probes updated (see commit); probe diff empty vs Linux | `probe-10.py` |
| 11a/11b overlay data loss, lookup, open flags | host test `strict_path_descendant`; probe | `cargo test -p ginux-kernel-policy`; `probe-11.py` |
| 12 posix_spawn, wait status, sched, creds | boot asserts in `verify_lifecycle_contract`, `verify_linux_scheduler_queries` | `probe-12.py` |
| 13 volume slot header digest / target | 4 unit tests (each fails on its mutant) | `cargo test -p ginux-volume-service`; `make test-storage test-oci-cache` |
| 14 overlay truncate / extension / times | probe rows /tmp and /root | `probe-fs2.py` |
| 15 overlay hard links, nlink, ELOOP | boot marker `overlay hard links share one inode` | `probe-15.py` |
| 16 merged readdir | 3 host tests (`merged_directory_next`) | `cargo test -p ginux-kernel-policy`; `probe-16.py` |
| 17 fault kills only the faulting process | boot check `verify_linux_fault_signals` | `probe-17.py` |
| 18 clone() thread ABI (musl pthread_create) | boot probe `child_thread_probe` now uses the real ABI | `probe-18.py` |
| 19 initramfs files in OCI domains | probe | `probe-19.py` |
| 20 poll/select run children (subprocess) | subprocess probe | `probe-20.py` |
| 22a/22b COW TLB shootdown, app-CPU futex wait and sleep (need 18) | A/B crash count; futex wake counts | `probe-22.py` |
| 23 chmod/chown by path on image files, chmod through symlinks, fchmodat2 flags | boot check `verify_linux_chmod_symlinks` (negative control: fails at SysV index 50) | `probe-23.py` |
| 24 path walk: ENOTDIR for file components, trailing slashes, `rmdir("d/.")` | 2 host tests (`path_last_component`, `path_has_trailing_slash`); boot check `verify_linux_path_walk_rules` (negative control: SysV index 51); 109/112 probe values match | `cargo test -p ginux-kernel-policy`; `probe-24.py` |
| 25 O_CREAT\|O_EXCL on an existing symlink (security) | probe: dangling link target no longer created, image link no longer replaced | `probe-25.py` |
| 26 renameat2(RENAME_EXCHANGE) | host test `exchanged_path_swaps_whole_subtrees`; boot marker `Linux renameat2 RENAME_EXCHANGE swapped names` | `probe-26.py` |
| 27 pwrite O_APPEND, SEEK_DATA/HOLE, fallocate, ftruncate | extended `verify_linux_memfd_seals`; probe | `probe-27.py` |
| 28 power-loss tests for the volume commits (tests only) | 3 quick tests in `make check`; one `#[ignore]`d full matrix; fails when the prepared-header flush is removed | `cargo test -p ginux-volume-service`; `cargo test -p ginux-volume-service --release -- --ignored crash_tests::full` |

## 2. Running a probe inside Ginux

The probes are plain Python 3 scripts using `ctypes` raw syscalls. Each test
runs in a forked child with a watchdog, except probe-24, which runs in-process.
Each test prints `GT <name> <result>`. All probes are in the `probes/`
directory of the `ginux-probes` branch of github.com/meleficarumvaldis/ginux.

```sh
# Linux reference (destructive tests are guarded by GT_HOST=1):
GT_HOST=1 python3 probe-NN.py > linux.out

# Ginux: build the normal image, start a python domain, fetch the probe:
make build
python3 -m http.server 19000 --bind 127.0.0.1 &      # serves the probe
GINUX_MEMORY=3G tools/qemu/run.sh                     # then at ginux>:
#   domain new py
#   domain set py image=python:3.13-alpine init=/bin/sh cpu=1 memory-mib=1024
#   domain start py --attach
#   wget -O /tmp/p.py http://10.0.2.2:19000/probe-NN.py
#   /usr/local/bin/python3 /tmp/p.py           # $PATH from the image config is not applied
diff <(grep ^GT linux.out) <(grep ^GT ginux.out)
```

`probes/domain-exp.sh` automates boot → domain → commands → marker.

The first `wget` in a fresh domain usually fails with
`ginux: socket receive timeout` / `error getting response`, even though the
host server answers 200. That is the blocking-socket budget from issue 21. Retry
it (`for i in 1 2 3 4 5; do wget … && break; sleep 2; done`), or paste the probe
into the domain shell with a heredoc. Run probe-22 with the `wget` retry at
least once, because only that timing reproduced the domain failure fixed by
22b's yield check (issue 22, section D).

## 3. Integration branch

Order used for stacking (conflicts resolved, see below):

```
01 04 05 03 13 06 02 07 08 09 10 12 17 11a 11b 14 15 16 19 18 20 22a 22b 23 24 25 26 27 28
```

Conflicts and their resolution:
- **12 × 17** (`execute_deferred_live_fork`): 12 introduces
  `linux_queue_child_exit_signal`, and 17 tolerates EAGAIN when queuing SIGCHLD
  under memory exhaustion. Combined: `matches!(linux_queue_child_exit_signal(…), 0 | LINUX_EAGAIN)`.
  The boot-check lists and constants are additive.
- **11a × 15** (`linux_renameat`): 11a's block is kept, and 15's same-inode
  no-op follows it, using the already-resolved `source` handle.
- **07 × 20** (`linux_clock_nanosleep_live_return`): 07 replaced the idle `hlt`
  loop with `linux_idle_until_ready()` (wake when a sibling thread becomes
  ready), and 20 restarts absolute sleeps of non-init processes after each tick
  so ancestors can run. Combined into one loop that does both. The futex path
  keeps using the helper.
- **20 × 22b** (same function): 22b first blocks a thread on the application
  CPU as a sleep waiter, because that CPU has no timer. The combined 07/20 loop
  follows for CPU 0.
- **20 × 22b semantic interaction:** this one is not a textual conflict. 20's
  restarted sleeps yield to the parent, and that yield replaces the global
  live thread table, so the threads 22b blocks lost their wakeups or entered the
  kernel with the parent's context. 22b therefore lets only single-threaded
  processes yield (issue 22, section D). It was found by bisecting:
  18+22a+22b plus 07 passed, plus 02 completed, and plus 20 hung.
- **23 × 08** (boot-check lists): additive.
- **24 × 23** (`linux_fchmodat`): 23's structure is kept. Its follow path is an
  `O_PATH` `linux_openat`, which already applies 24's trailing-slash rule. In
  the `AT_SYMLINK_NOFOLLOW` branch, the EOPNOTSUPP symlink check is skipped
  when the path ends in a slash, because the slash makes Linux follow the link.
- **24 × 11a** (`linux_renameat`): 24's trailing-slash ENOTDIR check runs before
  11a's merged overlay/image source lookup.
- **24 × 11b** (`linux_follow_overlay_symlink`): 11b followed overlay symlinks
  before the trailing-slash check and dropped the slash, so `stat("filelink/")`
  would have passed in the combination. The helper now keeps a trailing slash on
  the followed path. `newfstatat`, `statx` and `faccessat` follow an overlay
  symlink for a trailing slash even with `AT_SYMLINK_NOFOLLOW`. This also fixes
  `lstat("dlink/")` and `stat("dangling/")`, which standalone 24 left open.
- **24 × 11a/16** (kernel-policy helpers and tests, boot lists): additive.
- **25 × 15** (`linux_openat`): 25's O_CREAT|O_EXCL EEXIST check stays before
  15's symlink-chain loop. The logic is the same as standalone.
- **26 × 11a/16**: `LINUX_EXDEV` is defined once, and the RENAME_EXCHANGE
  dispatch comes before 11a's rename path. The kernel-policy additions are
  additive.
- **27 × 11b** (`linux_positioned_iov`): 27's RWF_APPEND/RWF_NOAPPEND handling
  follows 11b's negative-position checks. As a result, `pwritev2()` with
  pos == -1 and only an append flag returns EOPNOTSUPP, like every flagged
  pos == -1 call in 11b.
- **28**: no conflict (tests only, applies alone and on top of 13).

## 4. Known interaction when 07 and 20 are both applied

With 07, a relative `nanosleep({LLONG_MAX, 0})` really sleeps forever, where it
used to return EINVAL at once. With 20, only **absolute** sleeps of non-init
processes hand the CPU back to their ancestors. A forked child that does a huge
*relative* sleep therefore holds its parent until the deadline. That is the
cooperative inter-process executor already documented in 20 ("relative
nanosleep still idles"); any long finite relative sleep in a child behaved this
way before as well. The old survey probe `gt.py` stops at its `nanosleep_huge`
row for this reason. The real fix is per-process deadlines plus
`restart_syscall` (219), or preemption between Linux processes.

## 5. Integration results (all patches except 21)

The series was tested on `origin/main` d11670e4, then 7fdc880e, and last on
**c8d12653**. Probe rows are counted as "matches Linux / rows".

| Check | Upstream `main` on this AMD host | Series on c8d12653 |
|---|---|---|
| `make check` | pass | pass (01–28) |
| `tests/qemu/boot.sh` KVM | fails: panic #GP(0x28) (patch 01 missing); with patch 01 alone, native-volume failure in 3/3 runs | **2/2** with 01–22b; **2/2** with 23–27 on top (also 2/2 on 7fdc880e and d11670e4, 3/3 on 6324692b) |
| `tests/qemu/boot.sh` TCG | pass | 01–22b: 5/5. With 23–27 on top: **9/10**. The one failure was "recovery boot did not prove native volume IOMMU lifecycle isolation": the second boot stopped after the Linux runtime tests. It did not recur in 9 further runs, and we could not attribute it to a patch. We report it as possible TCG flakiness, not as fixed or explained |
| `python:3.13-alpine` image | does not unpack | runs |
| probe-07 futex/time | see issue 07 | **48/50**: the two documented rows, `futex_wake_op` ENOSYS and `nanosleep_bad_rmtp_interrupted` |
| probe-18 threads | `can't start new thread` | **5/5** |
| probe-20 subprocess/poll/select | `subprocess` capture hangs | **14/14** |
| probe-22 threads/futex/sleep | futex wakes 0/1, thread sleep hangs domain | **15/15**: 3/3 runs via heredoc on c8d12653, 2/2 via `wget` on 7fdc880e |

With 23–27 on top, every probe was rerun. No row changed against the standalone
"after" runs except the expected `probe-fs3 append_pwrite`. The rows that still
differ from Linux are all classified in the issues:

| Probe | Rows still differing | Why |
|---|---|---|
| probe-fs3 | 9 | musl `pwrite`+O_APPEND (27); FIFO ENXIO (not fixed, 27); 255-byte names (path capacity); image-dir rename EXDEV (by design); host artifacts |
| probe-23 | 2 | chmod on an image directory stays EROFS (by design, 23); `utime` on an image directory empties its listing (existing bug, see 23) |
| probe-24 | 1 | `stat("dlink/c")`: the overlay does not follow its own symlinks mid-path |
| probe-25 | 2 | relative dangling-link target resolved against the cwd (existing, see 15); host stand-in artifact |
| probe-26 | 6 | image-layer participants give EXDEV (by design) |
| probe-27 | 5 | musl append rows (2); FIFO ENXIO (2); a host artifact |

Measured on 7fdc880e and rerun unchanged with 23–27 on top:

| Probe | Rows matching Linux |
|---|---|
| probe-10 signals (measured on d11670e4) | 45/45 |
| probe-08 | 9/11 |
| probe-15 | 15/16 |
| probe-16 | 17/18 |
| probe-fs2 | 10/11 |
| probe-11 | 46/53 |

The remaining probe differences are listed in each issue under
"not changed / not fixed", or are host-environment differences. The Linux
reference ran as uid 1000 with systemd-coredump, a read-only `/root`, and a
different `/etc/os-release`.
