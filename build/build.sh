#!/bin/bash
# Builds SREP 3.93a beta (Bulat Ziganshin) from this tree, for personal use.
#
#   bash build/build.sh [linux|linux32|arm64|macos|win64|win32|all]     (default: linux)
#
# Outputs, in dist/ (gitignored):
#   linux -> srep64   linux32 -> srep32   arm64 -> srep-arm64   macos -> srep-macos
#   win64 -> srep.exe   win32 -> srep-x86.exe
# arm64 builds natively on an arm64 host and cross-compiles elsewhere
# (aarch64-linux-gnu-g++); macos builds only on macOS (clang, not static).
#
# The tree is copied to .work/ and patched there by build/patch_srep.py; each
# patch fixes a real failure (see TOOL-FIXES.md and OMEGA-IMPROVEMENTS.md).
#
# CLI trap worth knowing: srep needs the explicit `-d` on decode. Without it, it
# sees two filenames, re-compresses the compressed file and exits 0 with 100.04 %
# of its input.
#
# Windows: upstream kept only the Unix threading backend. build/win32-threads/
# adds ThreadsWin32.* (adapted from the public-domain LZMA SDK) and an empty
# Handle.h stub. Also needed: -DUNICODE/-D_UNICODE (Common.h assumes
# TCHAR=wchar_t), -lole32 -luuid (the Win7 taskbar progress code still links),
# and build/mingw-shims/ for <ShObjIdl.h> on a case-sensitive host.
# The vmac.c and CRC32 patches matter most on win32: that is the build where
# VMAC's portable 32-bit fallback is miscompiled under strict aliasing and where
# the "rm" asm constraint does not compile at all.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
CSRC="$ROOT/.work"
OUT="$ROOT/dist"
mkdir -p "$CSRC" "$OUT"
TARGET="${1:-linux}"
rc=0

[ -f "$ROOT/Makefile" ] || { echo "missing Makefile"; exit 1; }

# fresh patched copy of the source tree in $1
prepare() {
  rm -rf "$1" && mkdir -p "$1" && cp -a "$ROOT/Makefile" "$ROOT/Compression" "$1/" || return 1
  python3 "$ROOT/build/patch_srep.py" "$1" >/dev/null || {
    echo "   (patches did not apply)"; return 1; }
}

build_linux() {
  echo "==> srep (srep64)"
  local B="$CSRC/srep-build"
  prepare "$B" || return 1
  ( cd "$B" && make >/dev/null 2>&1 && cp bin/srep "$OUT/srep64" ) \
    && echo "   OK -> dist/srep64" || { echo "   (build failed)"; return 1; }
}

# Linux i686, static. Needs gcc's 32-bit multilib (g++ -m32, libc6-dev-i386,
# lib32stdc++-dev). The only build that compiles VMAC's SSE2 nh_16 asm and
# LibTomCrypt's i386 bswap asm with GCC, which is where patches 4 and 7 matter.
build_linux32() {
  echo "==> srep (srep32)"
  local B="$CSRC/srep-build-32"
  prepare "$B" || return 1
  ( cd "$B" && make OPTIMISATION="-O3 -mtune=generic -funroll-all-loops -msse2 -m32" \
      LDFLAGS="-m32 -lpthread -lstdc++ -static" >/dev/null 2>&1 && cp bin/srep "$OUT/srep32" ) \
    && echo "   OK -> dist/srep32" || { echo "   (build failed: g++ -m32 multilib?)"; return 1; }
}

# Linux arm64, static. Native on arm64, aarch64-linux-gnu-g++ elsewhere.
build_arm64() {
  echo "==> srep (srep-arm64)"
  local B="$CSRC/srep-build-arm64" cxx=aarch64-linux-gnu-g++
  [ "$(uname -m)" = aarch64 ] && cxx=g++
  command -v "$cxx" >/dev/null || { echo "   (falta $cxx)"; return 1; }
  prepare "$B" || return 1
  ( cd "$B" && make CXX="$cxx" OPTIMISATION="-O3 -funroll-all-loops" >/dev/null 2>&1 \
      && cp bin/srep "$OUT/srep-arm64" ) \
    && echo "   OK -> dist/srep-arm64" || { echo "   (build failed)"; return 1; }
}

# macOS (the host's architecture: arm64 on Apple Silicon). Apple's toolchain
# has no static libc, so not static; it links only system libraries.
build_macos() {
  echo "==> srep (srep-macos)"
  [ "$(uname -s)" = Darwin ] || { echo "   (solo en macOS)"; return 1; }
  local B="$CSRC/srep-build-macos"
  prepare "$B" || return 1
  ( cd "$B" && make CXX=clang++ STATIC= OPTIMISATION="-O3" DEBUGGING= VERBOSITY= \
      LDFLAGS="-lpthread -lc++" && cp bin/srep "$OUT/srep-macos" ) \
    && echo "   OK -> dist/srep-macos" || { echo "   (build failed)"; return 1; }
}

# $1 = compiler, $2 = scratch dir, $3 = output name
build_windows() {
  echo "==> srep ($3)"
  command -v "$1" >/dev/null || { echo "   (falta $1)"; return 1; }
  prepare "$2" || return 1
  cp "$ROOT/build/win32-threads/ThreadsWin32.h" "$ROOT/build/win32-threads/ThreadsWin32.c" \
    "$2/Compression/LZMA2/C/"
  cp "$ROOT/build/win32-threads/Handle.h" "$2/Compression/LZMA2/MultiThreading/"
  ( cd "$2" && "$1" -O3 -std=c++17 \
    -I"$ROOT/build/mingw-shims" \
    -ICompression -ICompression/_Encryption -ICompression/_Encryption/headers -ICompression/_Encryption/hashes \
    -DFREEARC_WIN -DFREEARC_INTEL_BYTE_ORDER -D_FILE_OFFSET_BITS=64 -DUNICODE -D_UNICODE \
    -Wno-write-strings -Wno-unused-result \
    Compression/Common.cpp Compression/SREP/srep.cpp \
    -static-libgcc -static-libstdc++ -lole32 -luuid -o "$OUT/$3" ) \
    && echo "   OK -> dist/$3" || { echo "   (build failed)"; return 1; }
}

case "$TARGET" in
  linux) build_linux || rc=1 ;;
  linux32) build_linux32 || rc=1 ;;
  arm64) build_arm64 || rc=1 ;;
  macos) build_macos || rc=1 ;;
  win64) build_windows x86_64-w64-mingw32-g++ "$CSRC/srep-build-w64" srep.exe || rc=1 ;;
  win32) build_windows i686-w64-mingw32-g++ "$CSRC/srep-build-x86" srep-x86.exe || rc=1 ;;
  all)
    build_linux || rc=1
    build_linux32 || rc=1
    build_arm64 || rc=1
    build_windows x86_64-w64-mingw32-g++ "$CSRC/srep-build-w64" srep.exe || rc=1
    build_windows i686-w64-mingw32-g++ "$CSRC/srep-build-x86" srep-x86.exe || rc=1 ;;
  *) echo "uso: $0 [linux|linux32|arm64|macos|win64|win32|all]"; exit 2 ;;
esac
exit $rc
