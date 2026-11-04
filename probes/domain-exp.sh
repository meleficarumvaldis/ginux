#!/usr/bin/env bash
# Boot Ginux, start an attached Alpine domain, feed shell commands, wait for a
# marker. Usage: domain-exp.sh <repo> <commands-file> <end-marker> <timeout-s> [cpu]
# Prints the serial log path and the lines matching EXP_* markers.
set -uo pipefail

repo_root=$(cd "$1" && pwd)
commands_file=$2
end_marker=$3
limit=$4
cpu=${5:-1}
work=$(mktemp -d "${TMPDIR:-/tmp}/ginux-exp.XXXXXX")
output_file="$work/serial.log"
touch "$output_file"
dd if=/dev/zero of="$work/volume.img" bs=1048576 count=1 2>/dev/null

wait_for() {
    local marker=$1 seconds=$2
    for ((i = 0; i < seconds; i++)); do
        tr -d '\r' <"$output_file" | grep -Eq "^${marker}\$" && return 0
        grep -Eq '^GINUX_(BOOT|KERNEL)_PANIC' "$output_file" && return 1
        sleep 1
    done
    return 1
}

{
    wait_for 'ginux> ?' 120 || grep -Fq 'ginux> ' "$output_file"
    sleep 1
    printf '%s\n' \
        'domain new alpine' \
        "domain set alpine image=alpine:latest init=/bin/sh cpu=$cpu" \
        'domain start alpine --attach'
    for ((i = 0; i < 180; i++)); do grep -Fq 'ginux: OCI image ready' "$output_file" && break; sleep 1; done
    sleep 2
    cat "$commands_file"
    if wait_for "$end_marker" "$limit"; then echo "RESULT: reached $end_marker" >"$work/result"; else echo "RESULT: TIMEOUT waiting for $end_marker" >"$work/result"; fi
    printf '\035'
    sleep 2
    printf '%s\n' 'shutdown'
    sleep 5
} | GINUX_VOLUME_IMAGE="$work/volume.img" GINUX_QEMU_PID_FILE="$work/qemu.pid" \
    timeout $((limit + 400)) "$repo_root/tools/qemu/run.sh" >"$output_file" 2>&1

cat "$work/result" 2>/dev/null || echo "RESULT: no result"
echo "LOG: $output_file"
tr -d '\r' <"$output_file" | grep -nE '^EXP_|unsupported syscall|exceeded sixty|PANIC' | cut -c1-200
