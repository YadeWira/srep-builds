# ytool's own fixes to srep

These are *not* from omega-srep. They were found by measuring this tree, and each
one addresses a limitation that made `-dd<N>` unusable, untrustworthy or
irreproducible. They are applied by `contrib/patch_srep.py`; this file explains why
each exists.

For the fixes that *were* taken from omega-srep, see `OMEGA-IMPROVEMENTS.md`.

## 1. `-m5` crashed on some inputs (heap-buffer-overflow)

**Symptom.** `srep -m5` / `-m5f` segfaulted (SIGSEGV) or aborted (SIGABRT) with no
message at all, on inputs of a few megabytes, while working fine on others. `-m0`
through `-m4` were unaffected.

**Reproduced.** Any 3.3 MB input containing two overlapping duplicated ranges. The
exit code was 139 or 134 depending on how the heap happened to be laid out.

**Root cause.** ASan located it precisely:

```
heap-buffer-overflow WRITE of size 4
  SliceHash::prepare_buffer   Compression/SREP/hash_table.cpp:68
  BG_COMPRESSION_THREAD::run  Compression/SREP/io.cpp:154
```

Two independent overruns in one loop:

- **a)** The outer loop runs while `p < buf+size`, but the inner loop always advances
  `slices_in_block * slice_size` = `L` bytes and writes one entry per iteration. When
  `size` is not a multiple of `L` the last iteration starts inside the buffer and
  writes an entry for a chunk that does not exist — and reads `hash(p, slice_size)`
  past the end to compute it.
- **b)** `h` is indexed by `chunk = offset/L`, an absolute file position, but it is
  allocated for `filesize/L` entries only. In future-LZ the reader runs ahead of what
  has been consumed, so `offset + size` can exceed `filesize`. Measured on a
  3,300,000-byte input with `-m5`: the loop wanted entry **45056** of **12890**.

**Fix.** Both bounds are enforced: the inner loop stops when the slice would leave the
buffer, and the write is skipped when the index would leave `h`. A chunk that does not
fit is simply not hashed. That can only cost a *missed* match check — `check()`
already returns true ("maybe large enough") when it has no hash — so correctness is
unaffected and this cannot make a wrong match be accepted.

**Verified.** The crashing input now round-trips; ASan reports nothing; `-m0`..`-m5`
all pass on four inputs that previously varied in behaviour.

## 2. Output was not reproducible (no way to fix the hash seed)

**Symptom.** Two identical runs of the same command on the same input produce
different bytes. Correct for a keyed hash — the VMAC key comes from
`systemRandomData()` plus `time()` — and hostile to everything else: a `.pmp`
cannot be reproduced, two builds cannot be diffed, and no test can pin an archive
by hash.

**Fix.** `SREP_SEED_HEX`, an environment variable holding 32 hex-encoded bytes (the
VMAC key length). When set and well-formed, it is used as the key instead of entropy.
An environment variable rather than a CLI flag because srep parses all its options in
one long prefix-matching `if`-chain, where a new prefix can shadow an existing option
— that class of bug already cost omega-srep a release (`-vmfile=` was swallowed by
`-v`).

**Why this is not a security weakening.** The seed is stored in the archive header
regardless; whoever decodes already has it. This exposes nothing new.

**Wired into ytool** as `-seed<64 hex chars>`, validated there rather than in srep,
because srep silently falls back to a random seed when the value is malformed — the
user would believe their build is reproducible when it is not. The value is passed
to the child through `TProcess.Environment`, so srep's argument parser is untouched.

**Verified.** Two `ytool precomp -mzlib -dd3 -seed<hex>` runs on the same input
produce byte-identical `.pmp` files that round-trip. With the seed fixed, a 64-bit
and a 32-bit build of srep produce **byte-identical** archives — which also proves
the CDC chunking is architecture-independent in the methods ytool uses.

## 3. Patch 7 did nothing, and `-hash=sha1` was broken on Linux i686

**Symptom.** Found by the first Linux i686 build (3.94). Every archive written with
`-hash=sha1` failed its own checksum on decode, on any decoder: `ERROR! Decompression
problem: checksum of decompressed data is not the same`, exit 4. md5, sha512 and vmac
were fine.

**Root cause.** Patch 7 was meant to add the `"memory"` clobber to LibTomCrypt's i386
`STORE32H`/`LOAD32H` asm (omega-srep 1.0.3), but it only printed a note and changed
nothing. Those macros write and read memory through a register operand without saying
so, and GCC moved loads and stores across them. The mingw i686 build did not show it
(it does not reach that asm the same way), which is how the no-op went unnoticed.

**Fix.** The clobber is now applied to the four asm statements (`STORE32H`, `LOAD32H`
and the x86_64-only `STORE64H`/`LOAD64H`, where nothing failed). **Verified**: sha1
archives from the i686 build decode on i686 and x86_64.

## 4. Patch 4 produced asm that does not compile

**Symptom.** The Linux i686 build stopped in `vmac.c`: `input operand constraint contains
'+'`. Patch 4 (omega-srep's `nh_16_func` read-write operands) added an output section
but left the original empty one (a lone `:`), so the asm had one section too many.
Nobody had compiled it: `nh_16_func` exists only with `-msse2`, and the mingw i686 build
is made without it. The lone `:` is now removed.

## 5. What 32-bit and 64-bit builds write

With the same seed, `-m1`, `-m2` and `-m5` archives are byte-identical between the
i686 and x86_64 builds, and so is everything on small inputs. `-m3` and `-m4` above
roughly 16 MB are not: the match finder hashes through `size_t` in more than one
place (`HashValue` in `hash_table.cpp` is one; pinning it alone did not make the
outputs equal), so the two builds pick different, equally valid matches. Each decodes
the other's archives (tested). Making them identical would mean auditing the whole
match finder, for no gain in correctness, so it is left as it is.

## 6. arm64 (3.95)

**VMAC took arm64 for big-endian.** The first arm64 build round-tripped on its own,
but its archives failed on x86 and x86's failed on arm64 ("checksum ... is not the
same"), with the default `-hash=vmac` only; md5, sha1 and no hash crossed.
`VMAC_ARCH_BIG_ENDIAN` is "none of x86_64, i386, x64, ARMEL, MIPSEL", and arm64
defines `__AARCH64EL__`, not `__ARMEL__`. Added to the list (patch 17), together
with the strict-aliasing pragma, since arm64 takes the same portable-C path that
was miscompiled on i386.

**CRC32-C.** `hashes.cpp` emitted the x86 `crc32b` instruction on any GCC target
and did not compile on arm64. arm64's `__crc32cb` is the same CRC32-C byte step,
so it is used there (patch 16), detected at run time on Linux, always present on
Apple Silicon. With it, `-m1`'s content-defined chunks fall in the same places,
and Linux arm64 and x86-64 archives are byte-identical with the same seed (48 MB,
`-m0f`..`-m5f`, `-m3`, `-m3o`).

## 7. Windows XP (3.95)

GCC 14's mingw libgcc, in its default win32 thread model, imports Vista's
condition variables and `GetThreadId` (`gthr-win32-cond.o`, `gthr-win32.o`), so
XP refused `srep-x86.exe` with `0xC0000139` before `main`. The x86 build now uses
mingw's posix variant (winpthreads, linked statically); its imports are all in
XP's kernel32. Checked on real XP: every method, sha1, and pipes. `tests/run.sh`
fails if the import table gains a post-XP function.

## 8. The command line (3.95)

The old CLI showed help only with no file names and a terminal on both ends; `-h`,
`--help` and `--version` were invalid options; and compressing a `.srep` without
`-d` compressed it again, with exit 0. Patch 18 adds `-h`/`--help`/`-?`,
`--version`/`-V`, `--decompress`/`--info`, the help in `build/help.c` (grouped,
with examples and exit codes), a hint after "Invalid option", and refuses to
compress a file that starts with srep's signature unless `--recompress` is given.
It changes no existing option.

## 9. A failed run left its files behind (3.96)

`error()` calls `exit()` directly, so only the errors that went through `goto cleanup`
removed the output. A corrupt archive decoded with `-temp=t.tmp` left the partial
output and `t.tmp`; Ctrl+C and SIGTERM (whose handler calls `error()`) too. Patch 20
registers every file srep creates as it opens it, and `error()` closes and removes
them first. Checked: a checksum error, a cut archive, SIGTERM mid-decode, a decode
spill. Patch 21 names the default temporaries per process (`srep-data-<pid>.tmp`),
since two runs in one folder shared one.

## 10. What fuzzing the decoder found (3.96)

`build/fuzz.py` mutates archives of every method (bit flips, header words, cuts,
inserted and duplicated bytes, zeroed runs), decodes them through files and pipes
under ASan/UBSan, and reports crashes, hangs, exit 0 with wrong output, and files
left behind. 20,000 cases on 3.95 found:

| Finding | Cause | Patch 27 |
|---|---|---|
| `fseek(NULL)` in `restore_from_disk` | A match of length 0 is the decoder's own "block on disk" mark; with no spill file open, it read through NULL | a 0-length match is bad data |
| null chunk in `MEMORY_MANAGER::save` | the same 0-length match: 0 bytes saved, then an invalid chunk written | same |
| division by zero | format v1 rounds lengths to the minimum match, and a header said 0 | refused |
| exit 0, empty output (`-m5`) | two zero words read as the end of the archive anywhere | the end must be where the index or the file ends |
| exit 0 without checking | a damaged hash number: "can't be checked" on stderr, then decoded | an error; `-hash-` to decode without checking |

After the fixes, 100,000 cases: no finding. `tests/run.sh` reproduces the header
cases and runs 600 fuzz cases on the build under test.

## 11. Speed (3.96: measured, not changed)

On 1 GB of mixed files (warm cache): `-m1f` 0.8 s, `-m3f` 2.3 s, `-m5f` 3.3 s, decode
0.4 s. `-t` changes neither the time nor the bytes for these methods: the main loop
is sequential. A callgrind profile of `-m3f` puts 70% in that loop (rolling hash,
hash table, match extension) and 20% in VMAC. LTO changed nothing measurable.

Looked at again after 3.96, on 870 MB of real files (an ISO, an installer, game data),
three runs each, same bytes every time:

| Build | `-m3f` | `-m5f` |
|---|---|---|
| as released (`-O3 -msse2`) | 2.35-2.73 s | 2.94-3.31 s |
| `-march=x86-64-v2` | 2.44-2.74 s | 3.08-3.35 s |
| `-march=x86-64-v3` (AVX2) | 2.42-2.59 s | 2.94-3.37 s |
| `-O2` | 2.65-2.88 s | 3.04-3.14 s |
| PGO (trained on -m1f/-m3/-m3f/-m5f) | 2.43-2.75 s | 2.98-3.20 s |

All within noise. The VMAC digests of `-m3` are already computed by the background
thread while the main thread works on the previous block, so they are off the
critical path; what remains is the main loop, bound by memory latency (a random read
of the bit array per position, then the hash table), not by instructions. It is
sequential because every chunk enters the table while the same block is searched:
splitting a block across threads would change which matches are found (still a valid
archive, but other bytes). Nothing was changed.

## Limitation that remains, and is not fixable from here

`-m1`, `-m2` and the other suffixes-less methods write an **index-LZ** footer (format
v4) that the decoder reaches by `file_seek` to end-of-file. `ytool` decodes through a
stdin pipe, which cannot seek, so those formats cannot be used by this project. The
`f` (future-LZ, v3) and `o` (I/O-LZ, v1/v2) suffixes are sequential and work fine;
`ytool` uses `f`.

This is a format property, not a bug: index-LZ trades a seek for a smaller index. Fixing
it would mean either changing `DecChunk` to decode from a temporary file instead of a
pipe, or adding a sequential variant of the v4 footer to srep. Both are larger changes
than the ones above, and neither is needed: `-m5f` is the best ratio of the set.

## What the numbers say about method choice

Measured on a 16 MB slice of real binaries (`/usr/bin/*` concatenated):

| Method | Output | Ratio | Time | Memory |
|---|---|---|---|---|
| `-m1f` | 7,942,344 | 47.3% | 0.04 s | 33 MB |
| `-m3f` | 6,231,112 | 37.1% | 0.05 s | 18 MB |
| `-m4f` | 6,007,254 | 35.8% | 0.05 s | 17 MB |
| `-m5f` | 5,903,476 | 35.2% | 0.06 s | 18 MB |

`-m5f` is ~26% smaller than `-m1f` and uses *less* memory in the same time. `ytool`'s
`-dd<N>` already selects the method directly (`-dd5` = `srep -m5f`), so the default
matters more than the range.
