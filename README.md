# srep-builds

Personal builds of **SREP 3.93a beta** (October 11, 2014), the huge-dictionary
LZ77 preprocessor by **Bulat Ziganshin**.

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
  for a reproducible failure (an i386 build that does not compile, an i686
  crash, silent cross-architecture corruption, a `-m5` crash, non-reproducible
  output). Rationale: `TOOL-FIXES.md`, `OMEGA-IMPROVEMENTS.md`. Note that the
  tree already carries patches 1-3 in place (`hashes.cpp`, `vmac.c`).

## Build

```bash
bash build/build.sh            # dist/srep64          (Linux x86-64; make + g++/clang++)
bash build/build.sh win64      # dist/srep.exe        (x86_64-w64-mingw32-g++)
bash build/build.sh win32      # dist/srep-x86.exe    (i686-w64-mingw32-g++)
```

Decode needs the explicit `-d`: without it srep re-compresses the compressed file
and exits 0.
