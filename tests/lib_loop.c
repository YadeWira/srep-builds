/* tests/lib_loop.c <libsrep> <input> <workdir> <rounds>: libsrep called many times in one process.
   Each round: several methods, file->file compress, decode through pipes and files,
   a damaged archive, a bad command line. Checks: every round-trip exact, the
   expected exit codes, no file descriptor left open, RSS stable, and (under
   ASan/LSan) no leak at exit. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <pthread.h>

typedef int (*run_t)(int, char **, intptr_t, intptr_t, intptr_t);
static run_t srep_run;
static int fails = 0, passes = 0;
#define CHECK(c, ...) do { if (c) passes++; else { fails++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } } while (0)

/* portable: no /proc on macOS */
static int count_fds (void)
{
  int n = 0;
  for (int fd = 0; fd < 4096; fd++) if (fcntl(fd, F_GETFD) != -1) n++;
  return n;
}
static long rss_kb (void)   /* current RSS where /proc has it, else the peak (getrusage) */
{
  FILE *f = fopen("/proc/self/status", "r"); char line[256]; long v = -1;
  if (f) { while (fgets(line, sizeof line, f)) if (!strncmp(line, "VmRSS:", 6)) v = atol(line + 6); fclose(f); }
  if (v < 0) { struct rusage u; getrusage(RUSAGE_SELF, &u);
#ifdef __APPLE__
    v = u.ru_maxrss / 1024;   /* bytes there */
#else
    v = u.ru_maxrss;
#endif
  }
  return v;
}
static int files_equal (const char *a, const char *b)
{
  FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb"); int ok = fa && fb;
  while (ok) { int ca = fgetc(fa), cb = fgetc(fb); if (ca != cb) ok = 0; if (ca == EOF || cb == EOF) break; }
  if (fa) fclose(fa); if (fb) fclose(fb); return ok;
}
static int run_args (const char **args)
{
  char *argv[16] = {(char*)"srep"}; int n = 1;
  for (; args[n-1]; n++) argv[n] = (char*)args[n-1];
  argv[n] = NULL;
  return srep_run(n, argv, -1, -1, -1);
}
struct pump { int fd; const char *path; int write; };
static void *pump (void *p)
{
  struct pump *q = p; char buf[65536]; ssize_t n;
  if (q->write) { FILE *in = fopen(q->path, "rb"); size_t k;
    while ((k = fread(buf, 1, sizeof buf, in)) > 0) if (write(q->fd, buf, k) != (ssize_t)k) break;
    fclose(in); }
  else { FILE *out = fopen(q->path, "wb");
    while ((n = read(q->fd, buf, sizeof buf)) > 0) fwrite(buf, 1, n, out);
    fclose(out); }
  close(q->fd); return NULL;
}
/* srep -d - - through pipes: archive in, output out */
static int decode_pipes (const char *arc, const char *out)
{
  int pin[2], pout[2]; if (pipe(pin) || pipe(pout)) return -1;
  struct pump a = {pin[1], arc, 1}, b = {pout[0], out, 0}; pthread_t ta, tb;
  pthread_create(&ta, NULL, pump, &a); pthread_create(&tb, NULL, pump, &b);
  char *argv[] = {"srep", "-d", "-s-", "-", "-", NULL};
  int rc = srep_run(5, argv, pin[0], pout[1], -1);
  pthread_join(ta, NULL); pthread_join(tb, NULL); return rc;
}

int main (int argc, char **argv)
{
  if (argc < 5) { fprintf(stderr, "usage: libloop <libsrep> <input> <workdir> <rounds>\n"); return 2; }
  void *h = dlopen(argv[1], RTLD_NOW);
  if (!h) { printf("dlopen: %s\n", dlerror()); return 2; }
  srep_run = (run_t)dlsym(h, "srep_run");
  const char *in = argv[2]; int rounds = atoi(argv[4]);
  if (chdir(argv[3])) return 2;
  const char *methods[] = {"-m0", "-m1f", "-m2", "-m3", "-m3f", "-m3o", "-m4f", "-m5", "-m5f", "-m3f -hash=siphash", "-m5f -b64k -t1"};
  int nm = sizeof methods / sizeof *methods;
  int fd0 = -1; long rss1 = 0, rss_last = 0;
  for (int r = 0; r < rounds; r++)
  {
    for (int m = 0; m < nm; m++)
    {
      char opt[64]; strcpy(opt, methods[m]);
      const char *a[12]; int k = 0; char *tok = strtok(opt, " ");
      while (tok) { a[k++] = tok; tok = strtok(NULL, " "); }
      const char *seed = "--seed=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
      a[k++] = seed; a[k++] = "-s-"; a[k++] = in; a[k++] = "a.srep"; a[k] = NULL;
      int rc = run_args(a);
      CHECK(rc == 0, "round %d %s: compress rc=%d", r, methods[m], rc);
      const char *d[] = {"-d", "-s-", "a.srep", "o.bin", NULL};
      rc = run_args(d);
      CHECK(rc == 0 && files_equal(in, "o.bin"), "round %d %s: decode file rc=%d", r, methods[m], rc);
      if (strchr(methods[m], 'f')) {
        rc = decode_pipes("a.srep", "p.bin");
        CHECK(rc == 0 && files_equal(in, "p.bin"), "round %d %s: decode pipes rc=%d", r, methods[m], rc);
      }
      /* damaged archive: must fail with 3/4, remove its output, and leave the process sane */
      FILE *f = fopen("a.srep", "r+b"); fseek(f, 0, SEEK_END); long sz = ftell(f);
      fseek(f, sz / 2, SEEK_SET); int c = fgetc(f); fseek(f, sz / 2, SEEK_SET); fputc(c ^ 0x5a, f); fclose(f);
      const char *dd[] = {"-d", "-s-", "a.srep", "x.bin", NULL};
      rc = run_args(dd);
      CHECK(rc != 0 && access("x.bin", F_OK) != 0, "round %d %s: damaged rc=%d, output %s", r, methods[m], rc,
            access("x.bin", F_OK) == 0 ? "left" : "removed");
      unlink("x.bin");
    }
    const char *bad[] = {"-zzz", "-s-", in, "b.srep", NULL};
    CHECK(run_args(bad) == 2, "round %d: bad option did not give 2", r);
    const char *missing[] = {"-s-", "does-not-exist", "b.srep", NULL};
    { int mrc = run_args(missing); CHECK(mrc != 0 && access("b.srep", F_OK) != 0, "round %d: missing input rc=%d, b.srep %s", r, mrc, access("b.srep", F_OK) == 0 ? "left" : "absent"); unlink("b.srep"); }
    int fds = count_fds();
    if (r == 0) fd0 = fds, rss1 = rss_kb();
    CHECK(fds == fd0, "round %d: %d fds open, %d after round 0", r, fds, fd0);
    rss_last = rss_kb();
  }
  printf("rss after round 0: %ld kB, after round %d: %ld kB\n", rss1, rounds - 1, rss_last);
  CHECK(rounds < 3 || rss_last < rss1 + 65536, "RSS grew %ld kB over the rounds", rss_last - rss1);
  unlink("a.srep"); unlink("o.bin"); unlink("p.bin");
  printf("== %d OK, %d FAIL\n", passes, fails);
  return fails ? 1 : 0;
}
