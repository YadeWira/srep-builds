# srep-builds

Personal builds of **SREP**, the huge-dictionary LZ77 preprocessor by **Bulat
Ziganshin**: version **3.94**, which is SREP 3.93a beta (October 11, 2014) with
the fixes listed below. Built for [ytool](https://github.com/YadeWira/ytool),
which runs srep as an external program for `-dd1`..`-dd5`.

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

## What this is

- The source: the last known commit of the former Mercurial repository, as
  repackaged at [Intensity/srep](https://github.com/Intensity/srep) (`48f4b97`).
  That repository's own README is kept as `UPSTREAM-README.md`.
- `build/`: the scripts used to build it for
  [ytool](https://github.com/YadeWira/ytool), which runs srep as an external
  program for `-dd<N>` (external deduplication). ytool does not include srep and
  builds without it.
- `build/patch_srep.py`: patches applied to a scratch copy at build time, each
  for a measured failure. The tree itself stays as upstream left it, except
  patches 1-3, which it already carries in place (`hashes.cpp`, `vmac.c`).
  Rationale for each: `TOOL-FIXES.md` (found here) and `OMEGA-IMPROVEMENTS.md`
  (taken from omega-srep's history).
- `tests/run.sh`: the test suite (below).

## What 3.94 fixes

The archive format is unchanged: 3.93a reads what 3.94 writes and the other way
round. With a fixed seed, the 64-bit builds write the same bytes as before
wherever 3.93a was not broken.

- **Archives that do not decompress, with exit 0** (`-m3f`..`-m5f`, every
  Future-LZ/Index-LZ mode): a block's checksum was copied after the background
  thread could already overwrite it. Rare on a normal run; with the race window
  held open, 140 of 140 archives failed. Fixed (patch 8).
- **`-hash=sha1` on Linux i686**: every archive failed its own checksum, because a
  patch meant to fix it only printed a note. Fixed for real (patch 7).
- **Linux i686 did not compile** (VMAC's SSE2 asm, patch 4 as first written).
- `-vmfile=` and `-vmblock=` were unreachable (`-v` matched first); `-hash=` with
  no name turned checksums off silently; `-s1e6` became a 11-day progress
  interval; a decode that runs out of memory while spilling could hang instead
  of failing (patches 9-13).
- New build: **Linux i686** (`srep32`), next to Linux x86-64 and Windows x64/x86.
## Build

```bash
bash build/build.sh            # dist/srep64          (Linux x86-64; make + g++/clang++)
bash build/build.sh linux32    # dist/srep32          (Linux i686; g++ -m32 multilib)
bash build/build.sh win64      # dist/srep.exe        (x86_64-w64-mingw32-g++)
bash build/build.sh win32      # dist/srep-x86.exe    (i686-w64-mingw32-g++)
bash build/build.sh all
```

Decode needs the explicit `-d`: without it srep re-compresses the compressed file
and exits 0.

## Test

```bash
bash tests/run.sh          # everything (about 30 s; wine for the Windows builds)
bash tests/run.sh quick    # without the race probe and the wine runs
```

Round-trips of every method (`-m0`..`-m5`) in every container (`""`, `f`, `o`)
on seven inputs, through files and through pipes as ytool uses it; every hash;
small blocks and many threads; the same seed giving the same archive; damaged
and truncated archives failing with a non-zero exit; the option fixes; the
32-bit build against the 64-bit one; the Windows builds under wine, both ways;
and a probe build that holds the digest race open (patch 8), where every archive
must still decode. 224 checks with every build present.

The Windows builds were also run on real Windows 7 (x64 and x86), alone and
under ytool (`-dd1`, `-dd3`, `-dd5`).
