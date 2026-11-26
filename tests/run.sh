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

[ -x "$DIST/srep64" ] || bash build/build.sh linux >/dev/null || { echo "build failed"; exit 3; }
S64="$DIST/srep64"
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
[ -e "$W/srep-data.tmp" ] && bad "pipe encode left srep-data.tmp in the working directory"

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

echo "== options (patches 9, 12, 13)"
$S64 -d -vmfile="$W/vm.tmp" -vmblock=1mb "$W/g.s" "$W/v.out" >/dev/null 2>&1 \
  && cmp -s "$W/dups12m.bin" "$W/v.out" && ok || bad "-vmfile=/-vmblock= not accepted"
$S64 -m3f -hash= "$W/one.bin" "$W/h.s" >/dev/null 2>&1 && bad "-hash= (empty) accepted" || ok
# -s1e6 used to be taken as a 1e6-second stats interval; now it is read as a size,
# which srep's parser does not accept in that notation: an error, not a silent
# wrong meaning. -s1.5 is still an interval.
$S64 -m3f -s1e6 "$W/random1m.bin" "$W/s.s" >/dev/null 2>&1 && bad "-s1e6 accepted as an interval" || ok
$S64 -m3f -s1.5 "$W/random1m.bin" "$W/s.s" >/dev/null 2>&1 && ok || bad "-s1.5 (interval) rejected"
banner="$($S64 2>&1 </dev/null)"; [[ "$banner" == "SREP 3.94"* ]] && ok || bad "version string"

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
  if ( cd "$P" && make OPTIMISATION="-O3 -msse2 -DSREP_RACE_PROBE -include unistd.h" >/dev/null 2>&1 ); then
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

echo "== $pass OK, $fail FAIL"
[ "$fail" = 0 ]
