#!/usr/bin/env python3
"""Mutation fuzzer for srep's decoder. Usage: fuzz.py <srep> <workdir> <iterations> [jobs]

Seeds: archives of one input with every method. Each case mutates a seed and
decodes it (file -> file, and stdin -> stdout for the future-LZ ones). Findings:
  crash   a sanitizer report, or death by a signal
  hang    no exit within the timeout
  silent  exit 0 with output different from the input
Anything else (exit 3/4/5 with a message) is the right answer to bad data.
"""
import os, random, subprocess, sys, hashlib, shutil
from concurrent.futures import ProcessPoolExecutor

SREP, WD, N = sys.argv[1], sys.argv[2], int(sys.argv[3])
JOBS = int(sys.argv[4]) if len(sys.argv) > 4 else os.cpu_count()
SEED = "e765312fbb692a185e92603b4a1cbd9de481629f894d2212c69a6c1e254df35f"
TIMEOUT = 30
ENV = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=99",
           UBSAN_OPTIONS="print_stacktrace=1:exitcode=98", SREP_SEED_HEX=SEED)

METHODS = ["-m0", "-m1f", "-m1", "-m2", "-m3", "-m3f", "-m3o", "-m4f", "-m4", "-m5", "-m5f",
           "-m3f -hash=md5", "-m3f -hash-", "-m5f -b64k", "-m3f -b256k -l64",
           "-m1f -hash=sha1", "-m5f -hash=siphash", "-m3o -b1mb", "-m5 -b64k", "-m2 -hash=sha512"]


def make_input(path):
    r = random.Random(7)
    pieces = [r.randbytes(r.randint(500, 40000)) for _ in range(20)]
    out = bytearray()
    while len(out) < 1_500_000:
        out += r.choice(pieces)
        if r.random() < 0.3:
            out += r.randbytes(r.randint(10, 5000))
    open(path, "wb").write(out)


def setup():
    os.makedirs(WD, exist_ok=True)
    inp = os.path.join(WD, "input.bin")
    make_input(inp)
    seeds = []
    for i, m in enumerate(METHODS):
        out = os.path.join(WD, f"seed{i}.srep")
        subprocess.run([SREP] + m.split() + [inp, out], env=ENV, capture_output=True, check=True)
        seeds.append((m, out))
    return inp, seeds


def mutate(data, r):
    b = bytearray(data)
    kind = r.choice(["flip", "flip", "word", "head", "cut", "junk", "dup", "zero"])
    if kind == "flip":
        for _ in range(r.randint(1, 8)):
            i = r.randrange(len(b)); b[i] ^= 1 << r.randrange(8)
    elif kind in ("word", "head"):
        lim = min(len(b) - 4, 96) if kind == "head" else len(b) - 4
        for _ in range(r.randint(1, 3)):
            i = r.randrange(0, max(1, lim)) & ~3
            v = r.choice([0, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 1, r.getrandbits(32),
                          int.from_bytes(b[i:i+4], "little") + r.choice([-1, 1, 4096, -4096])])
            b[i:i+4] = (v & 0xFFFFFFFF).to_bytes(4, "little")
    elif kind == "cut":
        b = b[:r.randrange(len(b))]
    elif kind == "junk":
        i = r.randrange(len(b)); b[i:i] = r.randbytes(r.randint(1, 200))
    elif kind == "dup":
        i = r.randrange(len(b)); j = min(len(b), i + r.randint(1, 5000)); b[j:j] = b[i:j]
    elif kind == "zero":
        i = r.randrange(len(b)); j = min(len(b), i + r.randint(1, 2000)); b[i:j] = bytes(j - i)
    return bytes(b), kind


def run_case(args):
    n, seedfile, method, inp_hash = args
    r = random.Random(n)
    data, kind = mutate(open(seedfile, "rb").read(), r)
    d = os.path.join(WD, "w", str(n % 512)); os.makedirs(d, exist_ok=True)
    arc = os.path.join(d, "m.srep"); out = os.path.join(d, "m.out")
    open(arc, "wb").write(data)
    results = []
    modes = ["file"] + (["pipe"] if "f" in method.split()[0] else [])
    for mode in modes:
        if os.path.exists(out): os.remove(out)
        try:
            if mode == "file":
                p = subprocess.run([SREP, "-d", "-mem64mb", arc, out], env=ENV, capture_output=True,
                                   timeout=TIMEOUT, cwd=d)
                rc, err = p.returncode, p.stderr
                got = open(out, "rb").read() if (rc == 0 and os.path.exists(out)) else None
            else:
                with open(arc, "rb") as fi:
                    p = subprocess.run([SREP, "-d", "-mem64mb", "-", "-"], stdin=fi, env=ENV,
                                       capture_output=True, timeout=TIMEOUT, cwd=d)
                rc, err = p.returncode, p.stderr
                got = p.stdout if rc == 0 else None
        except subprocess.TimeoutExpired:
            results.append(("hang", mode, None, b"")); continue
        e = err.decode("latin-1")
        if "AddressSanitizer" in e or "runtime error:" in e or rc < 0 or rc in (98, 99):
            results.append(("crash", mode, rc, err[-3000:]))
        elif rc == 0 and "-hash-" not in method and hashlib.sha256(got or b"").hexdigest() != inp_hash:
            results.append(("silent", mode, rc, err[-500:]))
        if mode == "file":
            leftovers = [f for f in os.listdir(d) if f.endswith(".tmp")] + (["m.out"] if rc not in (0,) and os.path.exists(out) else [])
            if leftovers:
                results.append(("leftover", mode, rc, " ".join(leftovers).encode()))
                for f in leftovers:
                    try: os.remove(os.path.join(d, f))
                    except OSError: pass
    if results:
        keep = os.path.join(WD, "findings", f"{n}")
        os.makedirs(keep, exist_ok=True)
        shutil.copy(arc, os.path.join(keep, "case.srep"))
        with open(os.path.join(keep, "info.txt"), "w") as fh:
            fh.write(f"seed method: {method}\nmutation: {kind}\n")
            for k, mode, rc, e in results:
                fh.write(f"\n== {k} ({mode}) rc={rc}\n{e.decode('latin-1')}\n")
    return n, method, kind, [(k, mode, rc) for k, mode, rc, _ in results]


def main():
    inp, seeds = setup()
    h = hashlib.sha256(open(inp, "rb").read()).hexdigest()
    cases = [(n, seeds[n % len(seeds)][1], seeds[n % len(seeds)][0], h) for n in range(N)]
    counts = {}
    with ProcessPoolExecutor(JOBS) as ex:
        for n, method, kind, res in ex.map(run_case, cases, chunksize=8):
            for k, mode, rc in res:
                key = (k, method, mode)
                counts[key] = counts.get(key, 0) + 1
                if counts[key] <= 3:
                    print(f"{k:8} case {n:6} {method:18} {mode:4} {kind:5} rc={rc}", flush=True)
    print("== totals")
    for key, c in sorted(counts.items()):
        print(f"   {c:6}  {key}")
    print(f"== {N} cases")


if __name__ == "__main__":
    main()
