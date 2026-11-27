# Changelog

## 3.98 — 2026-11-27

Same archive format. A bug-fix release: the encoder was fuzzed (random options
on odd inputs, under ASan/UBSan) and the library was called many times in one
process. What they found:

- **Archives srep wrote and could not decode** ("broken compressed data",
  "checksum ... is not the same"), every one an upstream bug:
  `-m3` with `-c` smaller than `-l` (`-m3 -l256 -c16`); `-l` that is not a power of 2
  with `-m3`/`-m4` (upstream printed "compressed file may be corrupt" and wrote it);
  `-m1`/`-m2` with `-l` above 512 together with `-c` (`-m1f -l1000 -c256`); `-m3` with a
  block size that is not a multiple of the chunk (`-b100000b`). Now L is a power of 2,
  the rounded format is used only when it can hold the matches, CDC stores lengths
  against its own minimum, and `-m3` blocks hold whole chunks.
- **`-index=F` never worked** with the default index-LZ methods (decode looked for the
  match list in the archive), and since 3.96 not with `f`/`o` either; a failed decode
  deleted the index file. All fixed, files and pipes.
- **Crashes and undefined behaviour on odd options**: `-m5` with `-l` below 16 (division
  by zero), `-l1`..`-l15` (match list overrun), `-aX/Y` with Y not a power of 2, above 64
  or above L (garbage, a 16 EB allocation, a read before the buffer), `-b` without a unit
  past 4 GB (wrapped). And four UBSan reports: `lb(0)`, a 32-bit shift by 32 in the
  slice hash (it also rejected real matches), unaligned loads in VMAC and SipHash.
- **Blocks above 8 MB**: the archive does not record `-b`, so anything made with
  `-b16mb` failed to decode without the same `-b`. Decode now reads the block size from
  the file; through a pipe the error says which `-b` to give.
- **libsrep, many calls in one process**: each call kept its buffers (RSS grew 120 MB per
  round of 11 methods; 2.4 GB in 20 rounds) and a descriptor on the input. Now a call
  frees everything it allocated, also when it fails: 50 rounds, RSS flat, no descriptor
  left, LSan clean (`tests/lib_loop.c`).
- Archives with the options that worked before are byte-identical to 3.97.
- `build/encfuzz.py`: the encoder fuzzer; 5,500 cases after the fixes, nothing found.
  `build/fuzz.py` gives each case its own folder (cases running at once shared one
  and saw each other's temporary files as leftovers).
  `tests/run.sh`: 330 checks.

## 3.97 — 2026-11-26

Same archive format. New: **libsrep**, srep as a library.

- `srep_run(argc, argv, in, out, err)` runs srep's own command line inside the
  calling process (`build/lib/srep_lib.h`): the same options, archives and exit
  codes, `-` meaning the handles given. Errors return their exit code instead of
  ending the caller; the output and temporary files are removed as the program
  does. Builds: `libsrep.so` (Linux x86-64, x86, arm64), `srep.dll` (Windows x64),
  `srep-x86.dll` (Windows x86), `libsrep.dylib` (macOS).
- ytool 0.9.9c uses it instead of starting srep when it finds it next to itself.
- The library writes the program's bytes (same seed), and the tests check it
  (`tests/lib_test.c`): files and pipes, a damaged archive returning 4, a seeded
  run after an unseeded one, two threads at once.
- Patch 28 makes the difference, all under `SREP_LIB`; the program is unchanged.

## 3.96 — 2026-11-26

Same archive format as 3.93a, 3.94 and 3.95.

- A failed run leaves nothing behind: the output, the `-temp=` copy, the index and
  the `-vmfile=` spill are removed on every error, Ctrl+C and SIGTERM (most
  errors exited before the cleanup and left them).
- Damaged archives always fail, found by fuzzing the decoder (100,000 mutated
  archives under ASan/UBSan, `build/fuzz.py`): a crash on a 0-length match, a
  division by zero on a v1 header, a damaged block header decoding to a short or
  empty file with exit 0, and a damaged hash number turning the checksums off with
  exit 0. After the fixes, 100,000 cases: no crash, hang or silent pass.
- `--verify`: decodes and checks every checksum, writing nothing.
- `--seed=HEX`: `SREP_SEED_HEX` on the command line. A seed shorter than the hash's
  key is an error (it was ignored); a longer one gives its first bytes, so 64 digits
  seed every hash.
- The same file under another name (`./a`, a hard link, other case on Windows) is
  refused as the output instead of being truncated; an input that changes while it
  is being compressed is an error.
- A closed pipe is exit 3 with a message (it was SIGPIPE); a failed final flush is an
  error; default temporary files carry the process ID, so two runs in one folder no
  longer share them.
- `tests/run.sh`: 288 checks, including a short fuzz pass.

## 3.95 — 2026-11-26

Same archive format as 3.93a and 3.94.

- New builds: Linux arm64 (static), macOS arm64, and Windows x86 now runs on
  Windows XP. CI builds and tests Linux x86-64/x86/arm64 and macOS arm64
  natively, and the Windows builds under wine.
- arm64: `-hash=vmac` archives did not cross between arm64 and x86 (VMAC took
  arm64 for big-endian); the CRC32-C chunking step uses arm64's instruction.
  Linux arm64 and x86-64 now write the same bytes.
- Windows x86 did not start on XP (Vista-only imports from GCC 14's libgcc):
  built with mingw's posix variant now.
- Command line: `-h`/`--help`/`-?`, `--version`/`-V`, `--decompress`, `--info`,
  a grouped help with examples and exit codes, a hint after an invalid option,
  and compressing a srep archive again needs `--recompress`.
- `tests/run.sh`: 250 checks, including arm64 under qemu and the XP import table.

## 3.94 — 2026-11-26

SREP 3.93a beta with fixes; the archive format is unchanged (3.93a and 3.94 decode each
other's archives, and with the same seed the 64-bit builds write the same bytes).

- Future-LZ/Index-LZ (`-m3f`..`-m5f`, `-m3`..`-m5`): a block could be written with
  another block's checksum, giving an archive that does not decompress, with exit 0.
- `-hash=sha1` archives from Linux i686 builds failed their own checksum.
- Linux i686 builds did not compile.
- `-vmfile=` and `-vmblock=` were rejected; `-hash=` with no name disabled checksums;
  `-s1e6` was read as a progress interval; a decode spill that cannot progress is an
  error instead of a hang.
- Version string: `SREP 3.94 (3.93a + ytool fixes)`.
- Builds: Linux x86-64, Linux i686 (new), Windows x64, Windows x86.
- `tests/run.sh`: 224 checks.

Details: `TOOL-FIXES.md`, `OMEGA-IMPROVEMENTS.md`.
