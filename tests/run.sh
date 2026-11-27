#!/bin/bash
# srep test suite. Every case is a round-trip that must give the input back byte
# for byte, plus the failures each patch in build/patch_srep.py exists for.
#
#   bash tests/run.sh [quick]
#
# Builds dist/ first if a binary is missing. Uses dist/srep64 always; dist/srep32
# and the Windows builds (through wine) when they are there. "quick" skips the
# slow parts (the race probe and the cross-word-size matrix).
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"
QUICK="${1:-}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
pass=0; fail=0
ok()  { pass=$((pass+1)); }
bad() { fail=$((fail+1)); echo "   FAIL: $*"; }

# SREP=<binary> tests that one as the main build (the CI runs each platform's
# native binary that way); otherwise dist/srep64, built if missing.
if [ -n "${SREP:-}" ]; then
  S64="$(cd "$(dirname "$SREP")" && pwd)/$(basename "$SREP")"   # the pipe cases cd elsewhere
else
  [ -x "$DIST/srep64" ] || bash build/build.sh linux >/dev/null || { echo "build failed"; exit 3; }
  S64="$DIST/srep64"
fi
S32=""; [ -x "$DIST/srep32" ] && S32="$DIST/srep32"
WINE=""; command -v wine >/dev/null && WINE=wine
export WINEDEBUG=-all

echo "== corpus"
python3 - "$W" <<'PY'
import os, random, sys
d = sys.argv[1]; random.seed(20261126)
w = lambda n, b: open(os.path.join(d, n), 'wb').write(b)
w('empty.bin', b'')
w('one.bin', b'x')
w('random1m.bin', random.randbytes(1 << 20))
w('zeros4m.bin', bytes(4 << 20))
pieces = [random.randbytes(random.randint(2000, 200000)) for _ in range(40)]
out = bytearray()
while len(out) < 12 << 20:
    out += random.choice(pieces)
    if random.random() < 0.3:
        out += random.randbytes(random.randint(100, 50000))
w('dups12m.bin', bytes(out))
unit = bytes((i * 31 + 7) & 0xFF for i in range(4096))
w('unit300k.bin', unit * 75)          # the input omega-srep caught the digest race on
a = random.randbytes(400000)
w('far.bin', a + random.randbytes(3000000) + a + random.randbytes(500000) + a)
PY
FILES="empty.bin one.bin random1m.bin zeros4m.bin dups12m.bin unit300k.bin far.bin"

rt() { # srep_enc srep_dec "options" file -> round-trip through files
  local e="$1" d="$2" o="$3" f="$W/$4"
  rm -f "$W/a.s" "$W/a.out"
  $e $o "$f" "$W/a.s" >/dev/null 2>&1 || { bad "$o $4: encode exit $?"; return; }
  $d -d "$W/a.s" "$W/a.out" >/dev/null 2>&1 || { bad "$o $4: decode exit $?"; return; }
  cmp -s "$f" "$W/a.out" && ok || bad "$o $4: decoded to different bytes"
}

echo "== methods x containers (files)"
for m in 0 1 2 3 4 5; do for c in "" f o; do for f in $FILES; do
  rt "$S64" "$S64" "-m$m$c" "$f"
done; done; done

echo "== pipes, as ytool runs it (-m<N>f - -, -d - -)"
for m in 1 2 3 4 5; do for f in $FILES; do
  ( cd "$W" && $S64 -m${m}f -temp="$W/t.tmp" - - < "$f" > p.s 2>/dev/null \
    && $S64 -d - - < p.s > p.out 2>/dev/null ) && cmp -s "$W/$f" "$W/p.out" && ok \
    || bad "pipe -m${m}f $f"
done; done
compgen -G "$W/srep-data*.tmp" >/dev/null && bad "pipe encode left srep-data*.tmp in the working directory"

echo "== hashes"
for h in vmac md5 sha1 sha512 siphash; do rt "$S64" "$S64" "-m3f -hash=$h" dups12m.bin; done
rt "$S64" "$S64" "-m3f -hash-" dups12m.bin

echo "== small blocks and threads"
for o in "-m5f -b64k -t16" "-m3f -b1mb -t1" "-m3 -b256k" "-m1f -b512k -t8"; do
  rt "$S64" "$S64" "$o" dups12m.bin; rt "$S64" "$S64" "$o" unit300k.bin
done

echo "== reproducible with SREP_SEED_HEX"
SEED=e765312fbb692a185e92603b4a1cbd9de481629f894d2212c69a6c1e254df35f
for m in -m1f -m3f -m5f; do
  SREP_SEED_HEX=$SEED $S64 $m "$W/dups12m.bin" "$W/r1.s" >/dev/null 2>&1
  SREP_SEED_HEX=$SEED $S64 $m "$W/dups12m.bin" "$W/r2.s" >/dev/null 2>&1
  cmp -s "$W/r1.s" "$W/r2.s" && ok || bad "$m: same seed, different archives"
done

echo "== damaged archives fail (non-zero exit), never decode silently"
$S64 -m3f "$W/dups12m.bin" "$W/g.s" >/dev/null 2>&1
python3 - "$W" <<'PY'
import sys; d = sys.argv[1]
b = bytearray(open(d + '/g.s', 'rb').read())
f = bytearray(b); f[len(f) // 2] ^= 0x55; open(d + '/g_flip.s', 'wb').write(f)
open(d + '/g_cut.s', 'wb').write(b[:len(b) * 2 // 3])
PY
for g in g_flip g_cut; do
  $S64 -d "$W/$g.s" "$W/$g.out" >/dev/null 2>&1 && bad "$g: decode exit 0" || ok
  $S64 -d - - < "$W/$g.s" > /dev/null 2>&1 && bad "$g (pipe): decode exit 0" || ok
done

echo "== a failed run leaves nothing behind (patches 20, 21, 26)"
# decode errors went through exit() and left the output and -temp= behind
rm -f "$W/left.out" "$W/left.tmp"
$S64 -d "$W/g_flip.s" "$W/left.out" >/dev/null 2>&1
[ -e "$W/left.out" ] && bad "a failed decode left its output" || ok
$S64 -d -temp="$W/left.tmp" - "$W/left.out" < "$W/g_flip.s" >/dev/null 2>&1
[ -e "$W/left.out" ] || [ -e "$W/left.tmp" ] && bad "a failed pipe decode left output or -temp=" || ok
$S64 -d -vmfile="$W/left.vm" -vmblock=1mb -mem1mb "$W/g_flip.s" "$W/left.out" >/dev/null 2>&1
[ -e "$W/left.vm" ] && bad "a failed decode left its -vmfile=" || ok
# SIGTERM in the middle of a decode
for i in 1 2 3 4 5 6 7 8; do cat "$W/dups12m.bin"; done > "$W/big96.bin"
$S64 -m3f "$W/big96.bin" "$W/big96.s" >/dev/null 2>&1
$S64 -d -temp="$W/kill.tmp" - "$W/kill.out" < "$W/big96.s" >/dev/null 2>&1 & kp=$!
for i in $(seq 50); do [ -e "$W/kill.tmp" ] && break; sleep 0.02; done
kill -TERM $kp 2>/dev/null; wait $kp 2>/dev/null
[ -e "$W/kill.out" ] || [ -e "$W/kill.tmp" ] && bad "SIGTERM left the output or -temp=" || ok
# a reader that goes away: exit 3 with a message, not SIGPIPE
$S64 -m3f "$W/big96.bin" - 2>/dev/null | head -c 100 >/dev/null; rc=${PIPESTATUS[0]}
[ "$rc" = 3 ] && ok || bad "closed pipe: exit $rc, wanted 3"
# default temporary names carry the process id: two pipe encodes at once in one folder
( cd "$W" && $S64 -m5f - - < big96.bin > c1.s 2>/dev/null & cd "$W" && $S64 -m5f - - < dups12m.bin > c2.s 2>/dev/null; wait )
( cd "$W" && $S64 -d - - < c1.s > c1.out 2>/dev/null && $S64 -d - - < c2.s > c2.out 2>/dev/null ) \
  && cmp -s "$W/big96.bin" "$W/c1.out" && cmp -s "$W/dups12m.bin" "$W/c2.out" && ok || bad "two pipe encodes in one folder"

echo "== --verify, --seed= (patches 22, 23)"
for m in -m1f -m3 -m3f -m4f -m5 -m5f -m3o; do
  $S64 $m "$W/dups12m.bin" "$W/vf.s" >/dev/null 2>&1
  $S64 --verify "$W/vf.s" >/dev/null 2>&1 && ok || bad "--verify $m: exit $?"
done
$S64 --verify "$W/g_flip.s" >/dev/null 2>&1 && bad "--verify accepted a damaged archive" || ok
$S64 --verify "$W/g_cut.s" >/dev/null 2>&1 && bad "--verify accepted a cut archive" || ok
$S64 --verify "$W/g.s" "$W/x.out" >/dev/null 2>&1 && bad "--verify with an output name accepted" || ok
$S64 -m3f --seed=$SEED "$W/dups12m.bin" "$W/sd1.s" >/dev/null 2>&1
SREP_SEED_HEX=$SEED $S64 -m3f "$W/dups12m.bin" "$W/sd2.s" >/dev/null 2>&1
cmp -s "$W/sd1.s" "$W/sd2.s" && ok || bad "--seed= differs from SREP_SEED_HEX"
$S64 -m3f --seed=abc "$W/one.bin" "$W/sd3.s" >/dev/null 2>&1 && bad "--seed=abc accepted" || ok
$S64 -m3f --seed=abcd "$W/dups12m.bin" "$W/sd3.s" >/dev/null 2>&1 && bad "a 2-byte seed accepted for vmac" || ok
[ -e "$W/sd3.s" ] && bad "a rejected seed left an archive" || ok

echo "== same file, changed input (patches 24, 25)"
cp "$W/dups12m.bin" "$W/same.bin"; ln -f "$W/same.bin" "$W/same-link.bin"
( cd "$W" && $S64 -m3f same.bin ./same.bin >/dev/null 2>&1 ) && bad "./same.bin accepted as the output of same.bin" || ok
$S64 -m3f "$W/same.bin" "$W/same-link.bin" >/dev/null 2>&1 && bad "a hard link accepted as the output" || ok
cmp -s "$W/same.bin" "$W/dups12m.bin" && ok || bad "the input was damaged by a same-file run"
for i in 1 2 3 4; do cat "$W/big96.bin"; done > "$W/chg.bin"   # big enough to still be running
$S64 -m5f "$W/chg.bin" "$W/chg.s" >/dev/null 2>&1 & cp=$!
# the output exists once srep has measured the input; paused there, the input
# changes under it, whatever the machine's speed
for i in $(seq 500); do [ -e "$W/chg.s" ] && break; sleep 0.01; done
kill -STOP $cp 2>/dev/null
printf 'XXXX' | dd of="$W/chg.bin" bs=1 seek=1000 conv=notrunc 2>/dev/null
python3 -c 'import os,sys,time; t=time.time()+60; os.utime(sys.argv[1],(t,t))' "$W/chg.bin"   # another mtime even on a coarse clock
kill -CONT $cp 2>/dev/null
wait $cp; rc=$?; rm -f "$W/chg.bin"
if [ "$rc" = 0 ]; then echo "   (changed input: srep finished before the change, not checked)"
else [ -e "$W/chg.s" ] && bad "changed input: archive left behind" || ok; fi

echo "== options (patches 9, 12, 13)"
$S64 -d -vmfile="$W/vm.tmp" -vmblock=1mb "$W/g.s" "$W/v.out" >/dev/null 2>&1 \
  && cmp -s "$W/dups12m.bin" "$W/v.out" && ok || bad "-vmfile=/-vmblock= not accepted"
$S64 -m3f -hash= "$W/one.bin" "$W/h.s" >/dev/null 2>&1 && bad "-hash= (empty) accepted" || ok
# -s1e6 used to be taken as a 1e6-second stats interval; now it is read as a size,
# which srep's parser does not accept in that notation: an error, not a silent
# wrong meaning. -s1.5 is still an interval.
$S64 -m3f -s1e6 "$W/random1m.bin" "$W/s.s" >/dev/null 2>&1 && bad "-s1e6 accepted as an interval" || ok
$S64 -m3f -s1.5 "$W/random1m.bin" "$W/s.s" >/dev/null 2>&1 && ok || bad "-s1.5 (interval) rejected"
banner="$($S64 --version 2>&1)"; [[ "$banner" == "SREP 3.96"* ]] && ok || bad "version string"

echo "== command line (patch 18)"
$S64 --help 2>&1 | grep -q "Exit codes" && ok || bad "--help"
$S64 -h >/dev/null 2>&1 && ok || bad "-h exit code"
$S64 -zz "$W/one.bin" "$W/z.s" >/dev/null 2>&1 && bad "-zz accepted" || ok
$S64 -m3f "$W/dups12m.bin" "$W/re.srep" >/dev/null 2>&1
$S64 -m3f "$W/re.srep" "$W/re2.srep" >/dev/null 2>&1 && bad "compressed a srep archive again without --recompress" || ok
$S64 -m3f --recompress "$W/re.srep" "$W/re2.srep" >/dev/null 2>&1 && ok || bad "--recompress refused"
$S64 --decompress "$W/re.srep" "$W/re.out" >/dev/null 2>&1 && cmp -s "$W/dups12m.bin" "$W/re.out" && ok || bad "--decompress"
$S64 --info "$W/re.srep" >/dev/null 2>&1 && ok || bad "--info"

if [ -n "$S32" ]; then
  echo "== 32-bit build (patches 4, 7)"
  for h in vmac md5 sha1 sha512; do rt "$S32" "$S32" "-m3f -hash=$h" dups12m.bin; rt "$S32" "$S64" "-m3f -hash=$h" dups12m.bin; done
  for m in -m1f -m2f -m3f -m5f -m3 -m3o; do rt "$S32" "$S32" "$m" dups12m.bin; done
  # Not asserted: byte-identical archives from the 32- and 64-bit builds. They
  # are for -m1/-m2/-m5 and for small inputs, but -m3/-m4 pick different (equally
  # valid) matches above ~16 MB (see TOOL-FIXES.md). Cross-decoding is what
  # matters, and is checked above and here:
  for m in -m1f -m3f -m4f -m5f; do rt "$S64" "$S32" "$m" dups12m.bin; done
fi

if [ -f "$DIST/srep-x86.exe" ] && command -v objdump >/dev/null; then
  echo "== srep-x86.exe imports only what Windows XP has"
  vista="$(LC_ALL=C objdump -p "$DIST/srep-x86.exe" | grep -oE "ConditionVariable|SRWLock|GetThreadId|InitOnce|GetTickCount64|FlsAlloc|CreateSymbolicLink|GetFinalPathName|InitializeCriticalSectionEx|CreateEventEx|GetFileInformationByHandleEx|SetFileInformationByHandle|QueryFullProcessImageName|libwinpthread" | sort -u | tr '\n' ' ')"
  [ -z "$vista" ] && ok || bad "srep-x86.exe imports what XP lacks: $vista"
fi

QEMU=""; command -v qemu-aarch64 >/dev/null && QEMU=qemu-aarch64
if [ -n "$QEMU" ] && [ -f "$DIST/srep-arm64" ] && [ "$(uname -m)" != aarch64 ] && [ "$QUICK" != quick ]; then
  echo "== srep-arm64 under qemu (patches 16, 17)"
  for m in -m0f -m1f -m3f -m5f -m3 -m3o; do
    rt "$QEMU $DIST/srep-arm64" "$S64" "$m" dups12m.bin
    rt "$S64" "$QEMU $DIST/srep-arm64" "$m" dups12m.bin
    # arm64 has the same CRC32-C step and VMAC as x86-64: same bytes.
    SREP_SEED_HEX=$SEED $QEMU "$DIST/srep-arm64" $m "$W/dups12m.bin" "$W/ar.s" >/dev/null 2>&1
    SREP_SEED_HEX=$SEED $S64 $m "$W/dups12m.bin" "$W/xr.s" >/dev/null 2>&1
    cmp -s "$W/ar.s" "$W/xr.s" && ok || bad "$m: arm64 and x86-64 archives differ (fixed seed)"
  done
fi

if [ -n "$WINE" ] && [ "$QUICK" != quick ]; then
  for exe in srep.exe srep-x86.exe; do
    [ -f "$DIST/$exe" ] || continue
    echo "== $exe under wine, both directions with srep64"
    for m in -m1f -m3f -m5f -m3o; do
      rt "$WINE $DIST/$exe" "$S64" "$m" dups12m.bin
      rt "$S64" "$WINE $DIST/$exe" "$m" dups12m.bin
    done
    rt "$WINE $DIST/$exe" "$WINE $DIST/$exe" "-m3f -hash=sha1" dups12m.bin
  done
fi

if [ "$QUICK" != quick ]; then
  echo "== digest race (patch 8): a probe build holds the window open"
  P="$W/probe"; mkdir -p "$P" && cp -a "$ROOT/Makefile" "$ROOT/Compression" "$P/"
  python3 build/patch_srep.py "$P" >/dev/null
  PO="-O3 -DSREP_RACE_PROBE -include unistd.h"
  case "$(uname -m)" in x86_64|i?86) PO="$PO -msse2" ;; esac
  if [ "$(uname -s)" = Darwin ]; then
    MK=(make CXX=clang++ STATIC= DEBUGGING= VERBOSITY= LDFLAGS="-lpthread -lc++" OPTIMISATION="$PO")
  else
    MK=(make OPTIMISATION="$PO")
  fi
  if ( cd "$P" && "${MK[@]}" >/dev/null 2>&1 ); then
    n=0
    for i in $(seq 1 40); do
      "$P/bin/srep" -m5f -b64k -t16 "$W/unit300k.bin" "$W/race.s" >/dev/null 2>&1
      "$P/bin/srep" -d "$W/race.s" "$W/race.out" >/dev/null 2>&1 && cmp -s "$W/unit300k.bin" "$W/race.out" || n=$((n+1))
    done
    [ "$n" = 0 ] && ok || bad "digest race: $n of 40 archives do not decode"
  else
    bad "probe build failed"
  fi
fi

echo "== golden archives (made by Linux x86-64, decoded here)"
python3 - "$W" <<'PY'
import random, sys
unit = bytes((i * 31 + 7) & 0xFF for i in range(4096)); random.seed(5)
open(sys.argv[1] + '/golden.bin', 'wb').write(unit * 75 + random.randbytes(40000) + unit * 20)
PY
for g in "$ROOT"/tests/golden/*.srep; do
  [ -f "$g" ] || continue
  $S64 -d "$g" "$W/golden.out" >/dev/null 2>&1 && cmp -s "$W/golden.bin" "$W/golden.out" && ok \
    || bad "golden $(basename "$g") does not decode here"
done

# Not a check: md5 of archives made with the fixed seed, to compare platforms
# (the CI prints one block per runner; equal lines = byte-identical archives).
echo "== fingerprints (SREP_SEED_HEX fixed, dups12m.bin)"
for m in -m1f -m3f -m5f -m3 -m3o; do
  SREP_SEED_HEX=$SEED $S64 $m "$W/dups12m.bin" "$W/fp.s" >/dev/null 2>&1
  # FP_DIR=<dir> keeps the input and these archives, to decode them elsewhere
  [ -n "${FP_DIR:-}" ] && { mkdir -p "$FP_DIR"; cp "$W/fp.s" "$FP_DIR/fp$m.srep"; cp "$W/dups12m.bin" "$FP_DIR/"; }
  if command -v md5sum >/dev/null; then h=$(md5sum < "$W/fp.s" | cut -c1-32); else h=$(md5 -q "$W/fp.s"); fi
  echo "   $m $h"
done

echo "== $pass OK, $fail FAIL"
[ "$fail" = 0 ]
