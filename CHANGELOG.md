# Changelog

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
