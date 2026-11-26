# srep-builds

Personal builds of **SREP**, the huge-dictionary LZ77 preprocessor by **Bulat
Ziganshin**: version **3.95**, which is SREP 3.93a beta (October 11, 2014) with
fixes, more platforms and a newer command line. The archive format is unchanged.
Built for [ytool](https://github.com/YadeWira/ytool), which runs srep as an
external program for `-dd1`..`-dd5`.

| Component | Status |
|---|---|
| CI | [![CI][ciBadge]][ciLink] |
| Latest release | [![Release][relBadge]][relLink] |
| Linux x86-64 | built and tested in CI |
| Linux x86 | built and tested in CI |
| Linux arm64 | built and tested in CI (native arm64 runner) |
| Windows x64 | built in CI, tested under wine; real Windows 7 |
| Windows x86 | built in CI, tested under wine; real Windows XP and 7 |
| macOS arm64 | built and tested in CI (Apple Silicon runner) |

```sh
srep -m3f big.tar big.tar.srep      # compress
srep -d big.tar.srep big.tar        # decompress, byte for byte
srep --help
```

## Rights

**SREP is not mine, and this repository grants no licence.**

Every SREP source file in `Compression/SREP/` begins with:

    // Copyright (C) 2009-2014 Bulat Ziganshin. All rights reserved.
    // Mail Bulat.Ziganshin@gmail.com if you have any questions or want to buy a
    // commercial license for the source code.

All rights remain with the original author. Nothing here is offered under an
open-source licence, and nothing here should be read as permission to use,
copy, modify or redistribute SREP. If you need rights to SREP, ask its author.

**If Bulat Ziganshin wishes it, this repository will be made private or removed.**
Open an issue or write to the repository owner and it will be done without
discussion.

The support code bundled in the tree has its own, permissive terms: VMAC/VHASH
(Ted Krovetz, Wei Dai) and the LZMA SDK threading code (Igor Pavlov) are public
domain; LibTomCrypt is "free for all purposes". The Win32 threading backend in
`build/win32-threads/` is adapted from the public-domain LZMA SDK.

## Downloads

[Releases](https://github.com/YadeWira/srep-builds/releases):

| File | Platform |
|---|---|
| `srep64` | Linux x86-64, static |
| `srep32` | Linux x86, static |
| `srep-arm64` | Linux arm64, static |
| `srep.exe` | Windows x64, Windows 7 or later |
| `srep-x86.exe` | Windows x86, Windows XP or later |
| `srep-macos` | macOS arm64 (Apple Silicon) |

For ytool, put it next to the ytool binary: `srep64` (or `srep`) on Linux,
`srep.exe` on Windows (rename `srep-x86.exe` for the x86 package).

With the same input and seed, Linux x86-64, Linux arm64 and Windows x64 write the
same bytes (measured on 48 MB, `-m1f`..`-m5f`). The x86 builds do too except for
`-m3`/`-m4` above roughly 16 MB, where they pick other, equally valid matches, and
macOS orders matches with the same source differently (its C++ library sorts ties
another way), so its `f` and index-LZ archives differ. Every build decodes every
other build's archives: macOS's were decoded by the five others, and CI has every
platform decode archives made on Linux x86-64 (`tests/golden/`). 32-bit builds
reading stdin need `-s<size>`: without it srep assumes 25 GB and asks for more
memory than a 32-bit process has.

## What changed since 3.93a

**3.95**
- Builds for Linux arm64, macOS arm64 and Windows XP (x86).
- arm64: VMAC took arm64 for big-endian, so `-hash=vmac` (the default) archives
  did not cross between arm64 and x86; the CRC32-C chunking step now uses
  arm64's own instruction, so archives are the same bytes on both.
- Command line: `-h`/`--help`, `--version`, `--decompress`/`--info`, a grouped
  help with examples and exit codes, a hint after an invalid option, and
  compressing a file that already is a srep archive is refused (`--recompress`
  forces it). Every old option works as before.

**3.94**
- Archives that did not decompress, with exit 0 (`-m3f`..`-m5f`): a block's
  checksum was copied after the background thread could overwrite it.
- `-hash=sha1` archives from Linux x86 failed their own checksum; Linux x86 did
  not compile.
- `-vmfile=`/`-vmblock=` were rejected, `-hash=` with no name disabled checksums,
  `-s1e6` was read as a progress interval, a spill that cannot progress hung.

Details and measurements: `CHANGELOG.md`, `TOOL-FIXES.md`,
`OMEGA-IMPROVEMENTS.md`.

## What this is

- The source: the last known commit of the former Mercurial repository, as
  repackaged at [Intensity/srep](https://github.com/Intensity/srep) (`48f4b97`).
  That repository's own README is kept as `UPSTREAM-README.md`.
- `build/patch_srep.py`: patches applied to a scratch copy at build time, each
  for a measured failure; the tree stays as upstream left it, except patches
  1-3, which it carries in place. `build/help.c` is the new help text.
- `tests/run.sh`: the test suite.

## Build

```bash
bash build/build.sh            # dist/srep64        Linux x86-64 (g++/clang++)
bash build/build.sh linux32    # dist/srep32        Linux x86 (g++ -m32 multilib)
bash build/build.sh arm64      # dist/srep-arm64    Linux arm64 (native, or aarch64-linux-gnu-g++)
bash build/build.sh macos      # dist/srep-macos    macOS (on a Mac, clang)
bash build/build.sh win64      # dist/srep.exe      Windows x64 (x86_64-w64-mingw32-g++)
bash build/build.sh win32      # dist/srep-x86.exe  Windows x86 (i686-w64-mingw32-g++-posix)
bash build/build.sh all        # everything but macos
```

## Test

```bash
bash tests/run.sh          # everything (wine and qemu-aarch64 when present)
bash tests/run.sh quick    # without the race probe, wine and qemu
SREP=path/to/srep bash tests/run.sh    # test that binary as the main build
```

Round-trips of every method (`-m0`..`-m5`) in every container (`""`, `f`, `o`)
on seven inputs, through files and through pipes; every hash; small blocks and
many threads; the same seed giving the same archive; damaged and truncated
archives failing with a non-zero exit; the option and command-line fixes; the
32-bit, arm64 and Windows builds against the 64-bit one, both ways; the XP
import table; golden archives from Linux x86-64; and a probe build that holds the
digest race open. About 255 checks with every build present.

[ciBadge]: https://github.com/YadeWira/srep-builds/actions/workflows/ci.yml/badge.svg "Continuous Integration"
[ciLink]: https://github.com/YadeWira/srep-builds/actions/workflows/ci.yml
[relBadge]: https://img.shields.io/github/v/release/YadeWira/srep-builds "Latest release"
[relLink]: https://github.com/YadeWira/srep-builds/releases/latest
