#!/usr/bin/env python3
"""Encoder fuzzer for srep (3.98). Usage: build/encfuzz.py <srep> <workdir> <cases> [jobs]

Each case builds an odd input (empty, tiny, block-boundary sizes, periodic,
random, mixed), picks random options, compresses (file or stdin), then
decodes (file, and pipes for future-LZ) and --verify. Findings:
  crash      sanitizer report or death by signal
  hang       no exit within the timeout
  roundtrip  compress exit 0 but decode failed or gave other bytes
  refused    compress failed without a message
"""
import os, random, subprocess, sys, hashlib, shutil
from concurrent.futures import ProcessPoolExecutor

SREP, WD, N = sys.argv[1], sys.argv[2], int(sys.argv[3])
JOBS = int(sys.argv[4]) if len(sys.argv) > 4 else os.cpu_count()
TIMEOUT = 120
SEED = "--seed=e765312fbb692a185e92603b4a1cbd9de481629f894d2212c69a6c1e254df35f"
ENV = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=99:quarantine_size_mb=16:malloc_context_size=8",
           UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:exitcode=98")
MARKS = ["AddressSanitizer", "runtime error:", "UndefinedBehavior"]


def make_input(r):
    kind = r.choice(["empty", "tiny", "random", "periodic", "zeros", "mixed", "mixed",
                     "boundary", "longrep"])
    if kind == "empty":
        return b"", kind
    if kind == "tiny":
        return r.randbytes(r.randint(1, 600)), kind
    if kind == "random":
        return r.randbytes(r.randint(1000, 300000)), kind
    if kind == "zeros":
        return bytes(r.choice([1, 511, 512, 513, 65536, 65537, 1 << 20, 3 << 20])), kind
    if kind == "periodic":
        p = r.randbytes(r.choice([1, 2, 7, 31, 32, 33, 255, 256, 511, 512, 513, 4096, 65535]))
        n = r.randint(1, 3 << 20)
        return (p * (n // len(p) + 1))[:n], kind
    if kind == "boundary":
        base = r.choice([65536, 262144, 1 << 20])
        n = base * r.randint(1, 4) + r.choice([-1, 0, 1, -512, 512])
        pieces = [r.randbytes(r.randint(600, 20000)) for _ in range(5)]
        out = bytearray()
        while len(out) < n:
            out += r.choice(pieces)
        return bytes(out[:max(0, n)]), kind
    if kind == "longrep":
        a = r.randbytes(r.randint(100000, 1500000))
        return a + r.randbytes(r.randint(0, 5000)) + a + a[:r.randint(0, len(a))], kind
    pieces = [r.randbytes(r.randint(100, 60000)) for _ in range(r.randint(2, 30))]
    out = bytearray()
    lim = r.randint(10000, 4 << 20)
    while len(out) < lim:
        out += r.choice(pieces)
        if r.random() < 0.3:
            out += r.randbytes(r.randint(1, 3000))
        if r.random() < 0.1:
            i = r.randrange(len(out)); out[i] ^= 0xFF
    return bytes(out), kind


def make_opts(r):
    m = r.choice(["0", "1", "2", "3", "4", "5"])
    if m != "0":
        m += r.choice(["", "f", "o"])
    o = ["-m" + m]
    if r.random() < 0.5:
        o.append("-l" + str(r.choice([1, 4, 8, 15, 16, 17, 32, 33, 64, 100, 128, 256, 512, 513, 1000, 4096])))
    if r.random() < 0.25:
        o.append("-c" + str(r.choice([16, 32, 64, 128, 256, 512])))
    if r.random() < 0.25:
        o.append(r.choice(["-a0", "-a1", "-a2", "-a4/4", "-a8/2", "-a16", "-a4/3", "-a4/128", "-a2/64", "-a64/64", "-a100/100", "-a4/0"]))
    if r.random() < 0.4:
        o.append("-b" + r.choice(["64k", "128k", "256k", "1mb", "8mb", "100000", "3mb", "65537"]))
    if r.random() < 0.4:
        o.append("-t" + str(r.choice([1, 2, 4, 8])))
    if r.random() < 0.3:
        o.append(r.choice(["-hash=md5", "-hash=sha1", "-hash=sha512", "-hash=siphash", "-hash-"]))
    if r.random() < 0.2:
        o.append(r.choice(["-d1mb", "-d4mb", "-d16mb -dl64", "-d2mb -dc32", "-d1mb -dl8", "-d1mb -dl1000 -dc100"]))
    if r.random() < 0.1:
        o.append("-ia-")
    if r.random() < 0.1:
        o.append("-mmap")
    return o


def run(args, d, stdin=None, stdout=None):
    return subprocess.run([SREP] + args, cwd=d, env=ENV, stdin=stdin, stdout=stdout or subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=TIMEOUT)


def bad(p):
    e = p.stderr.decode("latin-1")
    return p.returncode < 0 or p.returncode in (98, 99) or any(m in e for m in MARKS)


def run_case(n):
    r = random.Random(n)
    data, kind = make_input(r)
    opts = make_opts(r)
    use_stdin = r.random() < 0.25
    use_index = (not use_stdin) and r.random() < 0.1
    d = os.path.join(WD, "w", str(n)); shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    inp = os.path.join(d, "in.bin"); arc = os.path.join(d, "a.srep"); out = os.path.join(d, "o.bin")
    open(inp, "wb").write(data)
    h = hashlib.sha256(data).digest()
    copts = opts + [SEED] + (["-index=idx"] if use_index else [])
    res = None; stage = "compress"
    try:
        if use_stdin:
            with open(inp, "rb") as fi, open(arc, "wb") as fo:
                p = run(copts + ["-s" + str(max(1, len(data)) * r.choice([1, 1, 2])), "-", "-"], d, fi, fo)   # never the 25gb default: GBs of tables per process
        else:
            p = run(copts + ["in.bin", "a.srep"], d)
        if bad(p):
            res = ("crash", p.returncode, p.stderr.decode("latin-1")[-1500:])
        elif p.returncode != 0:
            if not p.stderr.strip():
                res = ("refused", p.returncode, "")
        else:
            dopts = ["-d"] + (["-index=idx"] if use_index else [])
            if r.random() < 0.2:
                dopts.append(r.choice(["-mem1mb", "-mem10%", "-m4096", "-m100000"]))
            stage = "decode"
            q = run(dopts + ["a.srep", "o.bin"], d)
            got = hashlib.sha256(open(out, "rb").read()).digest() if os.path.exists(out) else None
            if bad(q):
                res = ("crash", q.returncode, q.stderr.decode("latin-1")[-1500:])
            elif q.returncode != 0 or got != h:
                res = ("roundtrip", q.returncode, q.stderr.decode("latin-1")[-800:])
            elif "f" in opts[0]:
                stage = "decode-pipe"
                os.remove(out)
                with open(arc, "rb") as fi, open(out, "wb") as fo:
                    q = run(["-d"] + (["-index=idx"] if use_index else []) + ["-", "-"], d, fi, fo)
                got = hashlib.sha256(open(out, "rb").read()).digest()
                if bad(q):
                    res = ("crash", q.returncode, q.stderr.decode("latin-1")[-1500:])
                elif q.returncode != 0 or got != h:
                    res = ("roundtrip", q.returncode, q.stderr.decode("latin-1")[-800:])
            if not res and not use_index:
                stage = "verify"
                q = run(["--verify", "a.srep"], d)
                if bad(q):
                    res = ("crash", q.returncode, q.stderr.decode("latin-1")[-1500:])
                elif q.returncode != 0:
                    res = ("roundtrip", q.returncode, q.stderr.decode("latin-1")[-800:])
    except subprocess.TimeoutExpired:
        res = ("hang", None, "")
    desc = f"{kind} {len(data)} {'stdin ' if use_stdin else ''}{'index ' if use_index else ''}{' '.join(opts)}"
    if res:
        keep = os.path.join(WD, "findings", str(n)); os.makedirs(keep, exist_ok=True)
        shutil.copy(inp, os.path.join(keep, "in.bin"))
        with open(os.path.join(keep, "info.txt"), "w") as fh:
            fh.write(f"{desc}\n== {res[0]} in {stage} rc={res[1]}\n{res[2]}\n")
    shutil.rmtree(d, ignore_errors=True)
    if res:
        return n, desc, res[0], stage, res[1], res[2][-200:].replace("\n", " | ")
    return n, desc, None, None, None, None


def main():
    os.makedirs(WD, exist_ok=True)
    counts = {}
    with ProcessPoolExecutor(JOBS) as ex:
        for n, desc, k, stage, rc, tail in ex.map(run_case, range(N), chunksize=2):
            if k:
                key = (k, stage)
                counts[key] = counts.get(key, 0) + 1
                if counts[key] <= 5:
                    print(f"{k:9} {stage:11} case {n:5} rc={rc} [{desc}] {tail}", flush=True)
    print("== totals")
    for key, c in sorted(counts.items()):
        print(f"   {c:6}  {key}")
    print(f"== {N} cases")


if __name__ == "__main__":
    main()
