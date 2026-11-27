#!/usr/bin/env python3
"""Apply ytool's patches to the vendored Intensity/srep tree in vendor/srep/.

Every patch here corresponds to a failure that was reproduced, not to a style
preference. The set is derived from the fixes recorded in YadeWira/omega-srep's
changelog between the fork point (48f4b97) and its last C++ release (v1.0.7) —
that project had the same bugs and fixed several of them, so where a fix is a
plain correction with no format change it is carried here rather than
re-invented. Each one says where it came from.

Idempotent: every patch checks for its own marker before touching anything, so
this can run on a fresh copy or on an already-patched one.

Usage: contrib/patch_srep.py vendor/srep
"""
import sys
import os

MARK = "ytool patch"


def read(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        return fh.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(text)


def apply(path, name, old, new, marker=None):
    """Replace `old` with `new` once, unless `marker` is already present."""
    src = read(path)
    if marker and marker in src:
        print(f"   = {name}: already applied")
        return True
    if old not in src:
        print(f"   ! {name}: PATTERN NOT FOUND in {path}")
        return False
    write(path, src.replace(old, new, 1))
    print(f"   + {name}")
    return True


def patch_nh16(path):
    """Rewrite nh_16_func's asm operands to declare mp/kp/nw as read-write."""
    src = read(path)
    if "mp_scratch" in src:
        print("   = VMAC nh_16_func: already patched")
        return True

    lines = src.split("\n")
    # Locate nh_16_func, then the GCC asm opening and its operand list.
    try:
        fn = next(i for i, l in enumerate(lines) if "static void NOINLINE nh_16_func" in l)
    except StopIteration:
        print("   ! VMAC nh_16_func: function not found")
        return False

    asm = None
    for i in range(fn, min(fn + 80, len(lines))):
        if "__asm__ __volatile__" in lines[i]:
            asm = i
            break
    if asm is None:
        print("   ! VMAC nh_16_func: asm block not found")
        return False

    # The operand list is the pair of lines `: "S" (mp), "D" (kp), ...`.
    for i in range(asm, min(asm + 200, len(lines))):
        if '"S" (mp), "D" (kp), "c" (nw), "a" (rl), "d" (rh)' in lines[i]:
            indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
            lines[i] = (indent + '/* ytool patch: the body advances esi/edi by 16 bytes per iteration and\n'
                        + indent + '   decrements ecx as its loop counter, so declaring them as read-only\n'
                        + indent + '   inputs let -fipa-ra assume ecx survived the call (VMAC_TAG_LEN==128\n'
                        + indent + '   calls this twice back to back). "+" makes the modification visible. */\n'
                        + indent + ': "+S" (mp_scratch), "+D" (kp_scratch), "+c" (nw_scratch)\n'
                        + indent + ': "a" (rl), "d" (rh)')
            # The outputs were empty: a lone ':' line right above. The new
            # outputs take its place, or the asm gets one section too many.
            # (Unnoticed until a Linux i686 build: it is the only build that
            # compiles this SSE2-only function; mingw builds without -msse2.)
            if lines[i - 1].strip() == ":":
                del lines[i - 1]
            # Insert the scratch variables just before the asm statement.
            lines.insert(asm, '\t/* ytool patch: see the operand list at the end of this asm. */\n'
                              '\tconst uint64_t *mp_scratch = mp;\n'
                              '\tconst uint64_t *kp_scratch = kp;\n'
                              '\tsize_t nw_scratch = nw;')
            write(path, "\n".join(lines))
            print("   + VMAC nh_16_func: mp/kp/nw declared read-write")
            return True

    print("   ! VMAC nh_16_func: operand list not found")
    return False


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "vendor/srep"
    if not os.path.isdir(os.path.join(root, "Compression")):
        print(f"error: {root} does not look like an srep tree", file=sys.stderr)
        return 2

    hashes = os.path.join(root, "Compression/SREP/hashes.cpp")
    vmac = os.path.join(root, "Compression/_Encryption/hashes/vmac/vmac.c")
    srep = os.path.join(root, "Compression/SREP/srep.cpp")
    mt = os.path.join(root, "Compression/_Encryption/headers/tomcrypt_macros.h")

    ok = True

    # --- 1. CRC32 inline asm: "rm" -> "qm" + "cc" clobber ---------------------
    # Origin: i386 build failure. `value` is a byte; "rm" lets GCC pick ANY
    # general register for the "r" alternative, but on i386 only eax/ebx/ecx/edx
    # have 8-bit sub-registers, so allocation onto esi/edi/ebp/esp fails with
    # "unsupported size for integer register". "qm" restricts the register
    # alternative to the byte-addressable class. The "cc" clobber is defensive:
    # Intel documents CRC32 as affecting no flags, but it costs nothing.
    # Same fix and same reasoning as omega-srep's 1917589.
    ok &= apply(
        hashes,
        'CRC32 asm constraint "rm" -> "qm" + "cc"',
        'asm("crc32b %[value], %[crc]\\n" : [crc] "+r" (crc) : [value] "rm" (value));',
        'asm("crc32b %[value], %[crc]\\n" : [crc] "+r" (crc) : [value] "qm" (value) : "cc");',
        marker='"qm" (value)',
    )

    # --- 2. VHash::compute: unaligned 64-bit store through a cast -------------
    # Origin: UBSAN. `result` is a byte buffer with no alignment guarantee, and
    # `((uint64_t*)result)[0] = res` is undefined behaviour; on every compiler
    # that matters it compiles to the same store, so this is a correctness-of-
    # contract fix with no output change. Same fix as omega-srep's a17cc3c.
    ok &= apply(
        hashes,
        "VHash::compute: memcpy instead of misaligned uint64_t cast",
        """    ((uint64_t*)result)[0] = res;
    if (VMAC_TAG_LEN==128)
      ((uint64_t*)result)[1] = tagl;""",
        """    /* ytool patch: `result` has no 8-byte alignment guarantee, so storing
       through a uint64_t* is undefined behaviour (UBSAN-clean after this).
       Both compilers turn this into the same single store on x86-64. */
    memcpy(result, &res, sizeof(uint64_t));
    if (VMAC_TAG_LEN==128)
      memcpy((char*)result + sizeof(uint64_t), &tagl, sizeof(uint64_t));""",
        marker="ytool patch: `result` has no 8-byte alignment",
    )

    # --- 3. VMAC: i386 strict-aliasing miscompile of ADD128/PMUL64 -----------
    # Origin: the cross-architecture bug that motivated the whole omega-srep
    # detour. A win64-encoded -dd1 stream failed its own internal checksum when
    # decoded on i386. The architecture #if/#elif chain in this file only defines
    # GET_REVERSED_64 for i386 -- it does not provide its own ADD128/MUL64/PMUL64,
    # so i386 falls through to the generic portable-C fallback, whose type
    # punning -O2+ strict aliasing is entitled to break. x86_64 never reaches
    # this code (it has its own hand-written asm), which is why the bug was
    # one-directional. Narrowest fix: disable strict aliasing for this TU only.
    # Verified by bisection: -O1 clean, -O3 broken, -O3 -fno-strict-aliasing clean.
    ok &= apply(
        vmac,
        "VMAC: no-strict-aliasing for the i386 generic fallback",
        "#include <emmintrin.h>\n#endif\n",
        """#include <emmintrin.h>
#endif

/* ytool patch (32-bit VMAC checksum mismatch): on i386+GCC the architecture
 * #if/#elif chain below only defines GET_REVERSED_64 -- it does NOT provide its
 * own ADD128/MUL64/PMUL64, so i386 falls through to the generic portable-C
 * fallback further down this file. GCC's -O2+ strict-aliasing optimisations
 * miscompile that fallback, producing a wrong 128-bit tag: a win64-encoded
 * archive then fails its own checksum when decoded by an i386 build, while
 * same-architecture round-trips always pass. Confirmed by bisection (-O1 clean,
 * -O3 broken, -O3 -fno-strict-aliasing clean). x86_64 is unaffected: it uses
 * its own hand-written asm ADD128/MUL64 and never reaches this fallback.
 * Narrowest fix that keeps every optimisation level on. */
#if defined(__GNUC__) && defined(__i386__)
#pragma GCC optimize ("no-strict-aliasing")
#endif
""",
        marker="ytool patch (32-bit VMAC checksum mismatch)",
    )

    # --- 4. VMAC nh_16_func: undeclared register clobbers --------------------
    # Origin: i686 SIGSEGV. The asm body advances esi/edi and decrements ecx as
    # loop control, but the operands were declared as plain read-only inputs
    # ("S"/"D"/"c"). Per GCC's extended-asm contract an asm must not modify an
    # input operand's register unless it is also an output, so -fipa-ra was
    # allowed to assume ecx survived the call and skipped reloading it before the
    # second of the two back-to-back calls nh_vmac_nhbytes_2 makes when
    # VMAC_TAG_LEN==128 (what hashes.cpp configures). ecx then arrived as 0,
    # "sub ecx,2" underflowed and the MMX copy loop ran off the buffer. A bare
    # clobber list is rejected here ("impossible constraints") because those
    # registers are fixed inputs at the same time, so the fix routes them
    # through read-write "+" operands. Same fix as omega-srep's 22bbe43.
    ok &= patch_nh16(vmac)

    # --- 5. Reproducible output: SREP_SEED_HEX ---------------------------------
    # Origin: measured, not from omega-srep (it has a -seed flag; this does not).
    # Two identical runs of the same command produce different bytes, because the
    # VMAC key is filled from systemRandomData() plus time(). That is correct for
    # a crypto key and hostile to everything else: the same input cannot be made
    # to produce the same archive, so a .pmp cannot be reproduced, byte-diffed
    # across builds, or pinned by a test.
    #
    # The seed is stored in the archive header, so it is not a security boundary:
    # whoever decodes already has it. An env var rather than a CLI flag keeps the
    # argument parser untouched (all options are parsed in one long if-chain where
    # a new prefix can shadow an existing one -- see the -vmfile= bug that cost
    # omega-srep a release).
    ok &= apply(
        hashes,
        "reproducible output: SREP_SEED_HEX",
        """  if (!initialized)
  {
    fortuna_start(prng);""",
        """  /* ytool patch: reproducible output. If SREP_SEED_HEX is set to 2*size hex
     digits, use those bytes as the key instead of entropy. The seed is stored in
     the archive header anyway, so this exposes nothing that a decoder does not
     already have; it exists so the same input can produce the same .pmp. */
  const char *env_seed = getenv("SREP_SEED_HEX");
  if (!initialized && env_seed && strlen(env_seed) == 2*size)
  {
    for (size_t i = 0; i < size; i++)
    {
      unsigned byte = 0;
      sscanf(env_seed + 2*i, "%2x", &byte);
      ((unsigned char*)result)[i] = (unsigned char)byte;
    }
    return;
  }
  if (!initialized)
  {
    fortuna_start(prng);""",
        marker="SREP_SEED_HEX",
    )

    # --- 6. SliceHash::prepare_buffer: heap-buffer-overflow (-m5) ------------
    # Origin: measured. `srep -m5f` segfaults (SIGSEGV, sometimes SIGABRT) on
    # some inputs and not others, with no message. ASan puts it exactly:
    #
    #   heap-buffer-overflow WRITE of size 4
    #     SliceHash::prepare_buffer  Compression/SREP/hash_table.cpp:68
    #     BG_COMPRESSION_THREAD::run  Compression/SREP/io.cpp:154
    #
    # Two independent overruns in one loop:
    #
    #  a) The outer loop runs while `p < buf+size`, but the inner loop always
    #     advances `slices_in_block * slice_size` = L bytes and writes one entry
    #     per iteration. When `size` is not a multiple of L the last iteration
    #     starts inside the buffer and writes an entry for a chunk that does not
    #     exist -- and reads `hash(p, slice_size)` past the end to compute it.
    #
    #  b) `h` is indexed by `chunk = offset/L`, an absolute file position, but it
    #     is allocated for `filesize/L` entries only. In future-LZ the reader runs
    #     ahead of what has been consumed, so `offset + size` can exceed
    #     `filesize`; measured on a 3,300,000-byte input with -m5: the loop wanted
    #     entry 45056 of 12890.
    #
    # Fixed by bounding both: the inner loop stops when the slice would leave the
    # buffer, and the entry write is skipped when its index would leave `h`. A
    # chunk that does not fit is simply not hashed, which can only cost a missed
    # match check -- `check()` already returns true ("maybe large enough") when
    # it has no hash, so output stays correct and this cannot make a wrong match
    # be accepted.
    hash_table = os.path.join(root, "Compression/SREP/hash_table.cpp")
    ok &= apply(
        hash_table,
        "SliceHash: remember how many entries h has",
        "  entry *h;  // Array holding all slice hashes, one `entry` per L bytes\n  Offset memreq;",
        "  entry *h;  // Array holding all slice hashes, one `entry` per L bytes\n"
        "  Offset memreq;\n"
        "  /* ytool patch: how many entries h actually has. prepare_buffer indexes h by\n"
        "     an absolute file position, so it has to know the bound to respect it. */\n"
        "  Offset chunks_allocated;",
        marker="Offset chunks_allocated;",
    )
    ok &= apply(
        hash_table,
        "SliceHash: initialise chunks_allocated",
        "         memreq = 0;                                                   // no need in SliceHash since each potential match is almost guaranteed to have MIN_MATCH matched bytes\n"
        "    else memreq = filesize/L * sizeof(entry);                          // one `entry` per L input bytes",
        "         memreq = 0;                                                   // no need in SliceHash since each potential match is almost guaranteed to have MIN_MATCH matched bytes\n"
        "    else memreq = filesize/L * sizeof(entry);                          // one `entry` per L input bytes\n"
        "    chunks_allocated = memreq/sizeof(entry);   // ytool patch: bound used by prepare_buffer",
        marker="chunks_allocated = memreq/sizeof(entry);",
    )
    ok &= apply(
        hash_table,
        "SliceHash::prepare_buffer: bound both overruns",
        """    Chunk curchunk = offset/L;
    for (char *p = buf;  p < buf+size;  )
    {
      entry checksum = 0;
      for (int i=0;  i<slices_in_block;  i++, p+=slice_size)
        checksum  +=  hash(p,slice_size) << (i*BITS);
      h[curchunk++] = checksum;
    }""",
        """    Chunk curchunk = offset/L;
    /* ytool patch: see contrib/patch_srep.py -- two overruns here. `slices` is
       L/slices_in_block and the inner walk must not read past `buf+size`, while
       `h` only has filesize/L entries and `offset` is an absolute position that
       future-LZ can push past filesize. */
    for (char *p = buf;  p < buf+size;  )
    {
      entry checksum = 0;
      int i = 0;
      for (;  i<slices_in_block  &&  p+slice_size<=buf+size;  i++, p+=slice_size)
        checksum  +=  hash(p,slice_size) << (i*BITS);
      if (i < slices_in_block)   break;          // trailing partial chunk: no entry
      if (Offset(curchunk) >= chunks_allocated)   break; // ran ahead of the allocation
      h[curchunk++] = checksum;
    }""",
        marker="if (Offset(curchunk) >= chunks_allocated)",
    )

    # --- 7. LibTomCrypt STORE32H/LOAD32H: missing "memory" clobber -----------
    # Origin: -hash=sha1 failed its own verification on 32-bit builds. Only
    # sha1.c uses these big-endian macros (md5 uses the L-suffixed ones;
    # sha512's STORE64H is __x86_64__-only), and the hand-written asm read/wrote
    # through a pointer-held register without declaring the memory side effect,
    # the same bug class as VMAC above. Only present on i386, so this is a no-op
    # on x86_64. Same fix as omega-srep's 72e0b6c (1.0.3).
    # Until 3.94 this step only printed a note and changed nothing; measured on
    # a Linux i686 build, every -hash=sha1 archive then failed its own checksum
    # (exit 4, on any decoder). The win32 build did not show it.
    # The 64-bit STORE64H/LOAD64H asm (x86_64 only) has the same operand lists
    # and gets the same clobber; no failure was seen there.
    src = read(mt)
    if 'ytool patch: "memory" clobber' in src:
        print('   = LibTomCrypt STORE/LOAD asm: "memory" clobber: already applied')
    else:
        st = '::"r"(x), "r"(y));'
        ld = ':"=r"(x): "r"(y));'
        if src.count(st) == 2 and src.count(ld) == 2:
            src = src.replace(st, '::"r"(x), "r"(y) : "memory"); /* ytool patch: "memory" clobber */')
            src = src.replace(ld, ':"=r"(x): "r"(y) : "memory"); /* ytool patch: "memory" clobber */')
            write(mt, src)
            print('   + LibTomCrypt STORE/LOAD asm: "memory" clobber')
        else:
            print('   ! LibTomCrypt STORE/LOAD asm: PATTERN NOT FOUND')
            ok = False

    decomp = os.path.join(root, "Compression/SREP/decompress.cpp")
    cdc = os.path.join(root, "Compression/SREP/compress_cdc.cpp")

    # --- 8. Future-LZ/Index-LZ: block digest copied after the BG thread had it --
    # Origin: omega-srep 741e7b8 (1.0.7), re-measured here. The main thread
    # signals the background thread (bg_thread.write) and only then copies
    # header[] -- including header[3..], the block digest -- into the
    # COMPRESSED_BLOCK kept for the second pass. The BG thread's next-next
    # iteration reuses that header buffer, so the copy races its next digest
    # write: the archive gets another block's digest (or half of one), srep exits
    # 0, and decode fails with a checksum error. Rare on a normal build (0 of
    # 600 runs here); with a 2 ms pause inserted after the signal, 140 of 140
    # archives fail. Copy first, signal after. Same bytes when nothing races.
    # SREP_RACE_PROBE (a test build only) keeps that pause, so the regression
    # test can prove the fix holds with the window wide open.
    ok &= apply(
        srep,
        "Future-LZ digest race: copy the header before bg_thread.write",
        """        // Write compressed block to output file(s)
        bg_thread.write (header[2], stat, literal_bytes);
        if (bg_thread.errcode)  {errcode = bg_thread.errcode; goto cleanup;}

        // Store matches in memory
        if (FUTURE_LZ || INDEX_LZ)""",
        """        // Store matches in memory. ytool patch: BEFORE bg_thread.write, which
        // hands header[] (and the digest in header[3..]) back to the BG thread.
        if (FUTURE_LZ || INDEX_LZ)""",
        marker="ytool patch: BEFORE bg_thread.write",
    )
    ok &= apply(
        srep,
        "Future-LZ digest race: signal after the copy",
        """            compsize += sizeof(STAT);   // accounting for the future write of statsize_buf[]
        }

        // Update statistics""",
        """            compsize += sizeof(STAT);   // accounting for the future write of statsize_buf[]
        }

        // Write compressed block to output file(s)
        bg_thread.write (header[2], stat, literal_bytes);
        if (bg_thread.errcode)  {errcode = bg_thread.errcode; goto cleanup;}
#ifdef SREP_RACE_PROBE
        usleep(2000);   // test build only: hold the race window open
#endif

        // Update statistics""",
        marker="SREP_RACE_PROBE",
    )

    # --- 9. -vmfile= and -vmblock= were unreachable ---------------------------
    # Origin: omega-srep 1.0.6. Options are matched in one if-chain, and
    # start_with(argv[1],"-v") (verbosity) comes first, so "-vmfile=x" was read
    # as verbosity "mfile=x" and rejected: "Invalid option". Matched before -v now.
    src = read(srep)
    vm_opts = """    } else if (start_with(argv[1],"-vmfile=")) {
      vmfile_name = argv[1]+8;
    } else if (start_with(argv[1],"-vmblock=")) {
      vm_block = parseMem (argv[1]+9, &errcode, 'm');
"""
    verb = """    } else if (strequ(argv[1],"-v")) {
      verbosity = 1;
"""
    if "ytool patch: -vmfile= before -v" in src:
        print("   = -vmfile=/-vmblock= before -v: already applied")
    elif vm_opts in src and verb in src:
        src = src.replace(vm_opts, "", 1)
        src = src.replace(verb, "    // ytool patch: -vmfile= before -v, which used to swallow it\n" + vm_opts + verb, 1)
        write(srep, src)
        print("   + -vmfile=/-vmblock= before -v")
    else:
        print("   ! -vmfile=/-vmblock= before -v: PATTERN NOT FOUND")
        ok = False

    # --- 10. VM spill that cannot make progress hung forever ------------------
    # Origin: omega-srep 1.0.6/1.0.7. When decoding with less memory than the
    # matches need, save_to_disk() packs matches into one VM block; a match
    # longer than a block never fits, nothing is evicted, and the caller's
    # `while (not enough space) save_to_disk()` spins at 0% CPU forever while the
    # VM file grows. Now save_to_disk() says whether it freed anything, and a
    # spill that cannot progress is an error (exit 5) with a hint, not a hang.
    # Not reproduced here (a 400 KB match across 1 MB blocks decoded fine with
    # -mem=1mb -vmblock=64k); kept as a backstop because the loop has no other
    # exit, and it changes nothing when a spill does progress.
    ok &= apply(
        decomp,
        "VM spill: save_to_disk reports progress",
        """  void save_to_disk (MEMORY_MANAGER &mm, LZ_MATCH_HEAP &lz_matches)
  {""",
        """  // ytool patch: returns false when nothing could be moved to disk, so the
  // callers can stop instead of looping forever.
  bool save_to_disk (MEMORY_MANAGER &mm, LZ_MATCH_HEAP &lz_matches)
  {""",
        marker="bool save_to_disk",
    )
    ok &= apply(
        decomp,
        "VM spill: nothing saved = no progress",
        """    *(STAT*)p = 0;       // End-of-block mark
""",
        """    *(STAT*)p = 0;       // End-of-block mark
    if (p == vmbuf)  return false;   // ytool patch: no match fit in a block
""",
        marker="if (p == vmbuf)  return false;",
    )
    ok &= apply(
        decomp,
        "VM spill: return true after a block is written",
        """    lz_matches.insert(mark);
  }""",
        """    lz_matches.insert(mark);
    return true;
  }""",
        marker="lz_matches.insert(mark);\n    return true;",
    )
    for old, new, nm in (
        ("    while (mm.available_space() < VMBLOCK_SIZE)   save_to_disk (mm, lz_matches);",
         "    while (mm.available_space() < VMBLOCK_SIZE)   if (!save_to_disk (mm, lz_matches))  vm_stuck();",
         "VM spill: restore_from_disk stops when stuck"),
        ("        while (lz_match.len > mm.available_space())   vm.save_to_disk (mm, lz_matches);",
         "        while (lz_match.len > mm.available_space())   if (!vm.save_to_disk (mm, lz_matches))  vm_stuck();",
         "VM spill: future-match store stops when stuck"),
    ):
        ok &= apply(decomp, nm, old, new, marker=new)
    ok &= apply(
        decomp,
        "VM spill: vm_stuck()",
        """struct VIRTUAL_MEMORY_MANAGER
{""",
        """// ytool patch: a spill that cannot free memory used to loop forever.
static void vm_stuck()
{
  error (ERROR_MEMORY, "Not enough memory to decompress: a match does not fit one -vmblock. Use a larger -mem or -vmblock");
}

struct VIRTUAL_MEMORY_MANAGER
{""",
        marker="static void vm_stuck()",
    )

    # --- 11. CDC rolling hash: size_t made -m1 depend on the word size --------
    # Origin: omega-srep 1.0.5, where it corrupted archives across word sizes.
    # In 3.93a it does not: decode never recomputes chunk boundaries, and -m1
    # only uses this hash on CPUs without SSE4.2 (otherwise CrcRollingHash
    # <uint32>). Measured: -m1f/-m2f/-m3f/-m5f archives from the 64-bit and
    # 32-bit builds are byte-identical with a fixed seed, and decode on the
    # other word size, before and after. What remains is that on a CPU without
    # SSE4.2 the two word sizes would cut chunks differently (mod 2^32 vs 2^64),
    # so the same input would give different archives. Pinned to uint64, which
    # is what size_t already is on 64-bit: no 64-bit output changes.
    src = read(cdc)
    if "ytool patch: uint64 CDC hash" in src:
        print("   = CDC rolling hash uint64: already applied")
    elif "PolynomialRollingHash<size_t>" in src and "fast_find_chunks<size_t," in src:
        src = src.replace("PolynomialRollingHash<size_t>", "PolynomialRollingHash<uint64>")
        src = src.replace("fast_find_chunks<size_t,", "fast_find_chunks<uint64,")
        src = "// ytool patch: uint64 CDC hash (was size_t: word-size dependent chunking)\n" + src
        write(cdc, src)
        print("   + CDC rolling hash uint64")
    else:
        print("   ! CDC rolling hash uint64: PATTERN NOT FOUND")
        ok = False

    # --- 12. -hash= with no name silently turned checksums off ------------------
    # Origin: omega-srep 1.0.7. hash_by_name("") is the "no hash" entry, which
    # -hash- selects on purpose; "-hash=" (a typo, an empty variable) got the same
    # and wrote archives with no checksums. It is a command-line error now.
    ok &= apply(
        srep,
        "-hash= with no name is an error",
        """    } else if (start_with(argv[1],"-hash=")) {
      selected_hash = hash_by_name(argv[1]+6, errcode);""",
        """    } else if (start_with(argv[1],"-hash=")) {
      if (argv[1][6] == 0)  errcode = ERROR_CMDLINE;   // ytool patch: use -hash- to disable
      else
      selected_hash = hash_by_name(argv[1]+6, errcode);""",
        marker="use -hash- to disable",
    )

    # --- 13. -s1e6 read as a stats interval ------------------------------------
    # Origin: omega-srep 1.0.7. Any -s value containing 'e' was taken as the
    # progress interval, so "-s1e6" (a size in scientific notation) became an
    # interval of 1e6 seconds instead of a 1,000,000-byte file size. Only a
    # fractional value is an interval now; "-s1e6" is then read as a size,
    # which parseMem64 does not take in that notation, so it is an error
    # instead of a silently wrong meaning.
    ok &= apply(
        srep,
        "-s with 'e' is a size, not an interval",
        """(start_with(argv[1],"-s") && (strchr(argv[1],'.')||strchr(argv[1],'e')))""",
        """(start_with(argv[1],"-s") && strchr(argv[1],'.'))   /* ytool patch: '1e6' is a size */""",
        marker="'1e6' is a size",
    )

    # --- 16. arm64: CRC32-C without x86 asm ------------------------------------
    # srep 3.95 builds for Linux arm64 and macOS arm64. hashes.cpp used the x86
    # crc32b instruction whenever GCC >= 4.3, whatever the target. arm64 has the
    # same CRC32-C (Castagnoli) byte step as __crc32cb, so -m1's content-defined
    # chunking cuts in the same places on x86 and ARM, and archives match.
    # Other targets get the table-driven fallback that was already there.
    ok &= apply(
        hashes,
        "CRC32-C: x86 asm only on x86, __crc32cb on arm64",
        """#if GCC_VERSION >= 403

// Requires GCC4.3 and SSE4.2-enabled CPU; and of course compatible only with Crc32CastagnoliPolynom
#include <x86intrin.h>""",
        """#if GCC_VERSION >= 403 && defined(__aarch64__)

// ytool patch (3.95): arm64. __crc32cb is the CRC32-C byte step, the same
// operation as x86's crc32b, so -m1 chunks identically on both.
#include <arm_acle.h>
#ifdef __linux__
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif
__attribute__((target("+crc"))) uint32 a_mm_crc32_u8(uint32 crc, uint8 value) {
  return __crc32cb(crc, value);
}
#define update_CRC(crc,CRCTable,c)  (a_mm_crc32_u8((crc),(c)))

bool crc32c()  /* arm64 CRC instructions: optional in ARMv8.0, always on Apple */
{
#if defined(__APPLE__)
  return true;
#elif defined(__linux__)
  return (getauxval(AT_HWCAP) & HWCAP_CRC32) != 0;
#else
  return false;
#endif
}

#elif GCC_VERSION >= 403 && (defined(__x86_64__) || defined(__i386__))

// Requires GCC4.3 and SSE4.2-enabled CPU; and of course compatible only with Crc32CastagnoliPolynom
#include <x86intrin.h>""",
        marker="__crc32cb",
    )

    # --- 17. VMAC on arm64: little-endian, and the strict-aliasing pragma ------
    # Measured with the first arm64 build under qemu: every archive with the
    # default -hash=vmac decoded on arm64 but not on x86 (and the other way
    # round): "checksum ... is not the same". md5/sha1/no hash crossed fine.
    # VMAC_ARCH_BIG_ENDIAN is "not one of x86_64, i386, x64, ARMEL, MIPSEL", and
    # arm64 defines __aarch64__/__AARCH64EL__, not __ARMEL__, so VMAC read its
    # words byte-swapped. __AARCH64EL__ (little-endian arm64) joins the list.
    # arm64 also takes the portable-C 64-bit arithmetic that patch 3 found
    # miscompiled under strict aliasing on i386; the pragma covers it too.
    ok &= apply(
        vmac,
        "VMAC: arm64 is little-endian",
        """    (!(__x86_64__ || __i386__ || _M_IX86 || \\
       _M_X64 || __ARMEL__ || __MIPSEL__))""",
        """    (!(__x86_64__ || __i386__ || _M_IX86 || \\
       _M_X64 || __ARMEL__ || __MIPSEL__ || __AARCH64EL__))  /* ytool patch: arm64 */""",
        marker="ytool patch: arm64 */",
    )
    ok &= apply(
        vmac,
        "VMAC: no-strict-aliasing also on arm64",
        "#if defined(__GNUC__) && defined(__i386__)\n#pragma GCC optimize (\"no-strict-aliasing\")",
        "#if defined(__GNUC__) && (defined(__i386__) || defined(__aarch64__))  /* ytool patch: + arm64 */\n#pragma GCC optimize (\"no-strict-aliasing\")",
        marker="ytool patch: + arm64",
    )

    # --- 18. A command line for today, with every old option kept ------------
    # 3.95. srep only showed its help with no file names and a terminal on both
    # ends; -h, --help and --version were "Invalid option", and compressing a
    # .srep without -d silently compressed it a second time (exit 0). Added,
    # without changing any existing option: -h/--help/-?, --version/-V,
    # --decompress and --info (= -d, -i), a grouped help with examples and exit
    # codes, a hint after "Invalid option", and a refusal to compress a file
    # that already is a srep archive (--recompress to do it anyway).
    src = read(srep)
    if "ytool patch: modern CLI" in src:
        print("   = modern CLI: already applied")
    else:
        old_loop = """  while(argv[1])
  {
    char cur_option[1000] = "";
    if (strequ(argv[1],"-d")) {"""
        new_loop = """  bool show_help = false, allow_recompress = false;   // ytool patch: modern CLI
  while(argv[1])
  {
    char cur_option[1000] = "";
    if (strequ(argv[1],"--decompress"))  argv[1] = (char*)"-d";
    if (strequ(argv[1],"--info"))        argv[1] = (char*)"-i";
    if (strequ(argv[1],"-h") || strequ(argv[1],"--help") || strequ(argv[1],"-?") || strequ(argv[1],"/?")) {
      show_help = true;  argv++;  continue;
    }
    if (strequ(argv[1],"--version") || strequ(argv[1],"-V")) {
      printf ("%s (%s)\\n", program_version, program_date);
      exit (NO_ERRORS);
    }
    if (strequ(argv[1],"--recompress")) {
      allow_recompress = true;  argv++;  continue;
    }
    if (strequ(argv[1],"-d")) {"""
        old_err = """      error (ERROR_CMDLINE, "Invalid option: %s",  (*cur_option? cur_option : argv[1]));"""
        new_err = """      error (ERROR_CMDLINE, "Invalid option: %s\\n  (srep --help lists the options)",  (*cur_option? cur_option : argv[1]));"""
        i = src.find("  if (filenames[1]==NULL) {\n    printf (")
        j = src.find("    exit (NO_ERRORS);\n  }\n", i)
        old_check = """  if (!strequ(finame,"-") && strequ(finame,foutname))
    error (ERROR_IO, "Input and output files should have different names");
"""
        new_check = old_check + """
  // ytool patch: compressing an archive again is almost always a missing -d.
  if (cmdmode==COMPRESSION && !allow_recompress && !strequ(finame,"-"))
  {
    FILE *probe = fopen (finame, "rb");
    uint32 sig[2] = {0,0};
    if (probe)  {if (fread (sig, 1, sizeof(sig), probe) != sizeof(sig))  sig[0] = 0;  fclose (probe);}
    if (sig[0]==BULAT_ZIGANSHIN_SIGNATURE && sig[1]==SREP_SIGNATURE)
      error (ERROR_CMDLINE, "%s is already a srep archive: use -d to decompress it\\n  (--recompress compresses it again)", finame);
  }
"""
        if old_loop in src and old_err in src and i > 0 and j > i and old_check in src:
            help_c = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "help.c")).read()
            src = src[:i] + help_c + src[j + len("    exit (NO_ERRORS);\n  }\n"):]
            src = src.replace(old_loop, new_loop, 1).replace(old_err, new_err, 1).replace(old_check, new_check, 1)
            write(srep, src)
            print("   + modern CLI")
        else:
            print("   ! modern CLI: PATTERN NOT FOUND")
            ok = False

    # --- 19. macOS ---------------------------------------------------------------
    # 3.95 builds on macOS (Apple Silicon, clang). Two Linux-isms stopped it:
    # <malloc.h> does not exist there (malloc is in <stdlib.h>), and
    # getrusage(RUSAGE_THREAD) is Linux-only; the per-thread CPU time it feeds
    # is only shown in statistics, so the process figure stands in.
    common = os.path.join(root, "Compression/Common.cpp")
    ok &= apply(
        srep,
        "macOS: no <malloc.h>",
        "#include <malloc.h>\n",
        "#ifdef __APPLE__   /* ytool patch: macOS has no <malloc.h> */\n#include <stdlib.h>\n#else\n#include <malloc.h>\n#endif\n",
        marker="macOS has no <malloc.h>",
    )
    ok &= apply(
        common,
        "macOS: no RUSAGE_THREAD",
        "  int res = getrusage (RUSAGE_THREAD, &usage);",
        "#ifdef RUSAGE_THREAD   /* ytool patch: Linux-only; the process time elsewhere */\n  int res = getrusage (RUSAGE_THREAD, &usage);\n#else\n  int res = getrusage (RUSAGE_SELF, &usage);\n#endif",
        marker="ytool patch: Linux-only; the process time",
    )

    # --- 20. A failed run leaves no output and no temporary files -----------
    # 3.96, from omega-srep (it removes what it created). error() calls exit()
    # directly, so only the few errors that went through `goto cleanup` removed
    # the output: a checksum error, a truncated archive, Ctrl+C or SIGTERM left
    # a partial output file, the -temp= copy and the -vmfile= spill behind.
    # Measured on 3.95: a corrupt archive decoded with -temp= left out.bin and
    # t.tmp. Every file srep creates is registered as it is opened, and error()
    # (which the signal handler also calls) closes and removes them first.
    decomp = os.path.join(root, "Compression/SREP/decompress.cpp")
    io = os.path.join(root, "Compression/SREP/io.cpp")
    ok &= apply(
        srep,
        "partial files: registry",
        "void error (int ExitCode, char *ErrmsgFormat...);   // Exit on error\n",
        """void error (int ExitCode, char *ErrmsgFormat...);   // Exit on error

// ytool patch: what srep created, removed if it stops on an error (error() and
// the signal handler end in exit(), skipping main's cleanup). "-" is never here.
static FILE *partial_fout = NULL, *partial_ftemp = NULL, *partial_fstat = NULL;
static const char *partial_out = NULL, *partial_temp = NULL, *partial_index = NULL, *partial_vm = NULL;
static void remove_partial_files (void)
{
  static volatile int done = 0;
  if (done)  return;
  done = 1;
  // closed first: Windows cannot remove an open file
  if (partial_ftemp)  fclose (partial_ftemp);
  if (partial_fstat)  fclose (partial_fstat);
  if (partial_fout)   fclose (partial_fout);
  if (partial_temp)   remove (partial_temp);
  if (partial_index)  remove (partial_index);
  if (partial_out)    remove (partial_out);
  if (partial_vm)     remove (partial_vm);
}
""",
        marker="static void remove_partial_files",
    )
    ok &= apply(
        io,
        "partial files: removed by error()",
        """  va_end(argp);

  exit(ExitCode);""",
        """  va_end(argp);

  remove_partial_files();   // ytool patch: no partial output after an error
  exit(ExitCode);""",
        marker="remove_partial_files();   // ytool patch",
    )
    ok &= apply(
        decomp,
        "partial files: the -vmfile= spill",
        """    if (!vmfile)   vmfile = fopen(vmfile_name, "w+b");""",
        """    if (!vmfile)  {vmfile = fopen(vmfile_name, "w+b");  partial_vm = vmfile_name;   // ytool patch: removed on error
                   if (!vmfile)  error (ERROR_IO, "Can't open %s for write", vmfile_name);}""",
        marker="partial_vm = vmfile_name;",
    )
    ok &= apply(
        srep,
        "partial files: output and index registered",
        """  FILE *fstat = *index_file? fopen (index_file, cmdmode==COMPRESSION? "wb" : "rb") : (cmdmode==COMPRESSION? fout : fin);""",
        """  // ytool patch: registered for remove_partial_files(); the null device is not
  if (fout != stdout && !strequ (foutname, NULL_FILENAME))  partial_fout = fout,  partial_out = foutname;
  FILE *fstat = *index_file? fopen (index_file, cmdmode==COMPRESSION? "wb" : "rb") : (cmdmode==COMPRESSION? fout : fin);
  if (*index_file && cmdmode==COMPRESSION && fstat)  partial_fstat = fstat,  partial_index = index_file;""",
        marker="registered for remove_partial_files()",
    )
    src = read(srep)
    n = src.count("""    if (ftemp == NULL)  error (ERROR_IO, "Can't open tempfile %s for write", tempfile);""")
    if "partial_ftemp = ftemp" in src:
        print("   = partial files: temp copies: already applied")
    elif n == 2:
        src = src.replace("""    if (ftemp == NULL)  error (ERROR_IO, "Can't open tempfile %s for write", tempfile);""",
                          """    if (ftemp == NULL)  error (ERROR_IO, "Can't open tempfile %s for write", tempfile);
    if (tempfile && *tempfile)  partial_ftemp = ftemp,  partial_temp = tempfile;   // ytool patch""")
        write(srep, src)
        print("   + partial files: temp copies")
    else:
        print(f"   ! partial files: temp copies: {n} sites, expected 2")
        ok = False
    # main's own cleanup closes and removes them; nothing is left to do twice
    ok &= apply(
        srep,
        "partial files: cleared by main's cleanup",
        """cleanup:
  clear_window_title();""",
        """cleanup:
  partial_fout = partial_ftemp = partial_fstat = NULL;   // ytool patch: main closes them below
  partial_out = partial_temp = partial_index = partial_vm = NULL;
  clear_window_title();""",
        marker="main closes them below",
    )

    # --- 21. Default temporary files named per process ------------------------
    # 3.96. srep-data.tmp (stdin copy when compressing, stdout copy when
    # decoding) and srep-virtual-memory.tmp (decode spill) had fixed names in
    # the current folder: two srep runs there shared them. ytool hit the same
    # bug in its own temporaries. The process ID goes in the name; -temp= and
    # -vmfile= still name them exactly.
    ok &= apply(
        srep,
        "temp names: per process",
        """  char *index_file="",  *tempfile=NULL,  *DEFAULT_TEMPFILE="srep-data.tmp",  *vmfile_name="srep-virtual-memory.tmp",  *option_s="+";""",
        """  // ytool patch: the default temporary names carry the process ID
  static char default_temp_buf[64], default_vm_buf[64];
  snprintf (default_temp_buf, sizeof(default_temp_buf), "srep-data-%u.tmp", unsigned(srep_getpid()));
  snprintf (default_vm_buf,   sizeof(default_vm_buf),   "srep-virtual-memory-%u.tmp", unsigned(srep_getpid()));
  char *index_file="",  *tempfile=NULL,  *DEFAULT_TEMPFILE=default_temp_buf,  *vmfile_name=default_vm_buf,  *option_s="+";""",
        marker="default_temp_buf",
    )
    ok &= apply(
        srep,
        "temp names: getpid",
        "#include \"Common.h\"\n",
        """#include "Common.h"
#ifdef _WIN32   // ytool patch: srep_getpid for per-process temporary names
#include <process.h>
#define srep_getpid _getpid
#else
#include <unistd.h>
#define srep_getpid getpid
#endif
""",
        marker="#define srep_getpid",
    )

    # --- 22..23. --verify and --seed= ------------------------------------------
    # 3.96, from omega-srep. --verify decodes and checks every checksum without
    # writing anything (output to the null device; when the decoder must reread
    # its output, the same temporary copy as decoding to stdout). --seed=<hex>
    # is SREP_SEED_HEX (patch 5) on the command line; a seed of the wrong length
    # is an error instead of being ignored.
    ok &= apply(
        srep,
        "--verify, --seed=: options",
        """    if (strequ(argv[1],"--recompress")) {
      allow_recompress = true;  argv++;  continue;
    }""",
        """    if (strequ(argv[1],"--recompress")) {
      allow_recompress = true;  argv++;  continue;
    }
    if (strequ(argv[1],"--verify")) {   // ytool patch: --verify, --seed=
      verify = true;  cmdmode = DECOMPRESSION;  argv++;  continue;
    }
    if (start_with(argv[1],"--seed=")) {
      const char *hex = argv[1]+7;
      size_t n = strlen(hex);
      bool good = n>0 && n%2==0;
      for (size_t i=0; good && i<n; i++)
        good = (hex[i]>='0' && hex[i]<='9') || (hex[i]>='a' && hex[i]<='f') || (hex[i]>='A' && hex[i]<='F');
      if (!good)  error (ERROR_CMDLINE, "--seed= takes hex digits, an even number of them (64 for -hash=vmac): %s", hex);
      static char seed_env[600];
      if (n > sizeof(seed_env)-20)  error (ERROR_CMDLINE, "--seed= is too long");
      snprintf (seed_env, sizeof(seed_env), "SREP_SEED_HEX=%s", hex);
      putenv (seed_env);
      argv++;  continue;
    }""",
        marker="ytool patch: --verify, --seed=",
    )
    ok &= apply(
        srep,
        "--verify: flag",
        "  bool show_help = false, allow_recompress = false;   // ytool patch: modern CLI",
        "  bool show_help = false, allow_recompress = false, verify = false;   // ytool patch: modern CLI, --verify",
        marker="verify = false;",
    )
    ok &= apply(
        srep,
        "--verify: no output",
        "  char *foutname = (cmdmode==INFORMATION? (char*)NULL_FILENAME : filenames[2]);",
        """  if (verify && filenames[2])   // ytool patch: --verify writes nothing
    error (ERROR_CMDLINE, "--verify takes one file name, the archive: %s", filenames[2]);
  char *foutname = (cmdmode==INFORMATION || verify? (char*)NULL_FILENAME : filenames[2]);""",
        marker="--verify writes nothing",
    )
    ok &= apply(
        srep,
        "--verify: reread through a temporary copy",
        """    if ((IO_LZ || maximum_save!=unsigned(-1))  &&  strequ(foutname,"-"))""",
        """    if ((IO_LZ || maximum_save!=unsigned(-1))  &&  (strequ(foutname,"-") || verify))   // ytool patch: + --verify""",
        marker="+ --verify",
    )
    ok &= apply(
        srep,
        "--verify: says so",
        """  if (warnings==0 && delete_input_files && !strequ(finame,"-"))""",
        """  if (verify)   // ytool patch
    fprintf (stderr, "Verified: %s decompresses and its checksums match\\n", finame);
  if (warnings==0 && delete_input_files && !strequ(finame,"-"))""",
        marker="decompresses and its checksums match",
    )
    ok &= apply(
        hashes,
        "--seed=: wrong length is an error",
        """  const char *env_seed = getenv("SREP_SEED_HEX");
  if (!initialized && env_seed && strlen(env_seed) == 2*size)""",
        """  const char *env_seed = getenv("SREP_SEED_HEX");
  if (!initialized && env_seed && *env_seed && strlen(env_seed) != 2*size)   // ytool patch (3.96): not ignored
    error (ERROR_CMDLINE, "the seed (--seed= or SREP_SEED_HEX) must be %d hex digits for this hash", int(2*size));
  if (!initialized && env_seed && strlen(env_seed) == 2*size)""",
        marker="must be %d hex digits for this hash",
    )

    # --- 24. Input and output are the same file, under different names --------
    # 3.96, from omega-srep. Only identical spellings were refused: srep a ./a
    # (or a hard link, or another case on Windows) truncated the input before
    # reading it. Compared by device and inode (volume serial and file index on
    # Windows), before the output is opened. The index file too.
    ok &= apply(
        srep,
        "same file: helper",
        "static void remove_partial_files (void)\n{",
        """// ytool patch: true if both names are one existing file
#ifdef _WIN32
#include <windows.h>
static bool same_file (const char *a, const char *b)
{
  HANDLE ha = CreateFileA (a, 0, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (ha == INVALID_HANDLE_VALUE)  return false;
  HANDLE hb = CreateFileA (b, 0, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (hb == INVALID_HANDLE_VALUE)  {CloseHandle (ha);  return false;}
  BY_HANDLE_FILE_INFORMATION ia, ib;
  bool same = GetFileInformationByHandle (ha, &ia) && GetFileInformationByHandle (hb, &ib)
           && ia.dwVolumeSerialNumber==ib.dwVolumeSerialNumber
           && ia.nFileIndexHigh==ib.nFileIndexHigh && ia.nFileIndexLow==ib.nFileIndexLow;
  CloseHandle (ha);  CloseHandle (hb);
  return same;
}
#else
#include <sys/stat.h>
static bool same_file (const char *a, const char *b)
{
  struct stat sa, sb;
  return stat (a, &sa)==0 && stat (b, &sb)==0 && sa.st_dev==sb.st_dev && sa.st_ino==sb.st_ino;
}
#endif

static void remove_partial_files (void)
{""",
        marker="static bool same_file",
    )
    ok &= apply(
        srep,
        "same file: checked",
        """  if (!strequ(finame,"-") && strequ(finame,foutname))
    error (ERROR_IO, "Input and output files should have different names");
""",
        """  if (!strequ(finame,"-") && strequ(finame,foutname))
    error (ERROR_IO, "Input and output files should have different names");
  // ytool patch: the same file under another name (./a, a link) was truncated
  if (!strequ(finame,"-") && !strequ(foutname,"-") && same_file (finame, foutname))
    error (ERROR_IO, "%s and %s are the same file", finame, foutname);
  if (*index_file && ((!strequ(finame,"-") && same_file (index_file, finame)) || (!strequ(foutname,"-") && same_file (index_file, foutname))))
    error (ERROR_IO, "the index file %s is the input or the output", index_file);
""",
        marker="the same file under another name",
    )

    # --- 25. The input changed while it was being compressed ------------------
    # 3.96, from omega-srep. srep reads a file input more than once (-m4/-m5
    # reread it, future-LZ reads it twice); a file that grew or was rewritten
    # meanwhile gave an archive of a mix of both, with exit 0. Size and
    # modification time are compared before and after; a change is an error and
    # the archive is removed.
    ok &= apply(
        srep,
        "input changed: before",
        """  FILE *fin = strequ (finame, "-")? stdin : fopen (finame, "rb");""",
        """  // ytool patch: the input's size and time, compared when compression ends
#ifdef _WIN32
  struct _stati64 input_before;  bool have_input_before = cmdmode==COMPRESSION && !strequ(finame,"-") && _stati64 (finame, &input_before)==0;
#else
  struct stat input_before;      bool have_input_before = cmdmode==COMPRESSION && !strequ(finame,"-") && stat (finame, &input_before)==0;
#endif
  FILE *fin = strequ (finame, "-")? stdin : fopen (finame, "rb");""",
        marker="compared when compression ends",
    )
    ok &= apply(
        srep,
        "input changed: after; output close checked",
        """  fclose(fin);
  fclose(fout);
  if (fstat!=fin && fstat!=fout)""",
        """  fclose(fin);
  // ytool patch: a failed final flush (disk full, closed pipe) was exit 0
  if (fclose(fout) != 0  &&  !errcode  &&  cmdmode!=INFORMATION)
    {fprintf (stderr, "\\n  ERROR! Can't write to output file (disk full or closed pipe?)\\n");  errcode = ERROR_IO;}
  if (have_input_before && !errcode)
  {
#ifdef _WIN32
    struct _stati64 input_after;  bool got = _stati64 (finame, &input_after)==0;
#else
    struct stat input_after;      bool got = stat (finame, &input_after)==0;
#endif
    if (!got || input_after.st_size!=input_before.st_size || input_after.st_mtime!=input_before.st_mtime)
      {fprintf (stderr, "\\n  ERROR! %s changed while it was being compressed\\n", finame);  errcode = ERROR_IO;}
  }
  if (fstat!=fin && fstat!=fout)""",
        marker="a failed final flush",
    )

    # --- 26. A closed pipe is an error, not a signal ----------------------------
    # 3.96. Writing to a pipe whose reader has gone killed srep with SIGPIPE
    # (exit 141, no message) and left its temporary files. Ignored, the write
    # fails and srep stops with its I/O error, exit 3, cleaned up.
    ok &= apply(
        srep,
        "SIGPIPE ignored",
        """  setbuf(stderr,NULL);    // Disable buffering even if stderr is redirected to file/pipe""",
        """  setbuf(stderr,NULL);    // Disable buffering even if stderr is redirected to file/pipe
#ifdef SIGPIPE
  signal (SIGPIPE, SIG_IGN);   // ytool patch: a closed pipe is a write error (exit 3)
#endif""",
        marker="a closed pipe is a write error",
    )

    # --- 14. Version ------------------------------------------------------------
    ok &= apply(
        srep,
        "version: SREP 3.96",
        'char *program_version     = "SREP 3.93a beta", *program_date = "October 11, 2014";',
        'char *program_version     = "SREP 3.96 (3.93a + ytool fixes)", *program_date = "November 26, 2026";',
        marker="SREP 3.96",
    )

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
