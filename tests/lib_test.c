/* tests/lib_test.c <libsrep> <srep program> <input> <workdir>: libsrep against the program. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>

typedef int (*run_t)(int, char **, intptr_t, intptr_t, intptr_t);
static run_t srep_run;
static int fails = 0, passes = 0;
#define CHECK(c, ...) do { if (c) passes++; else { fails++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int files_equal (const char *a, const char *b)
{
  FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb"); int ok = fa && fb;
  while (ok) { int ca = fgetc(fa), cb = fgetc(fb); if (ca != cb) ok = 0; if (ca == EOF || cb == EOF) break; }
  if (fa) fclose(fa); if (fb) fclose(fb); return ok;
}
/* runs srep_run with file names (no handles) */
static int run_files (const char *a1, const char *a2, const char *a3, const char *a4, const char *a5)
{
  char *argv[8] = {(char*)"srep"}; int n = 1;
  const char *a[] = {a1, a2, a3, a4, a5};
  for (int i = 0; i < 5; i++) if (a[i]) argv[n++] = (char*)a[i];
  argv[n] = NULL;
  return srep_run(n, argv, -1, -1, -1);
}
/* decodes archive -> output through pipes: a writer thread feeds stdin */
struct feed { int fd; const char *path; };
static void *feeder (void *p)
{
  struct feed *f = p; FILE *in = fopen(f->path, "rb"); char buf[65536]; size_t n;
  while ((n = fread(buf, 1, sizeof buf, in)) > 0) if (write(f->fd, buf, n) != (ssize_t)n) break;
  fclose(in); close(f->fd); return NULL;
}
struct drain { int fd; const char *path; };
static void *drainer (void *p)
{
  struct drain *d = p; FILE *out = fopen(d->path, "wb"); char buf[65536]; ssize_t n;
  while ((n = read(d->fd, buf, sizeof buf)) > 0) fwrite(buf, 1, n, out);
  fclose(out); close(d->fd); return NULL;
}
static int run_pipes (char **argv, int argc, const char *in_path, const char *out_path, const char *err_path)
{
  int pin[2], pout[2], perr[2]; pipe(pin); pipe(pout); pipe(perr);
  struct feed f = {pin[1], in_path}; struct drain d = {pout[0], out_path}, e = {perr[0], err_path};
  pthread_t tf, td, te;
  pthread_create(&tf, NULL, feeder, &f); pthread_create(&td, NULL, drainer, &d); pthread_create(&te, NULL, drainer, &e);
  int rc = srep_run(argc, argv, pin[0], pout[1], perr[1]);
  pthread_join(tf, NULL); pthread_join(td, NULL); pthread_join(te, NULL);
  return rc;
}
struct par { const char *in, *out; int rc; };
static void *par_run (void *p)
{
  struct par *q = p; q->rc = run_files("-m3f", "--seed=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", q->in, q->out, NULL); return NULL;
}

int main (int argc, char **argv)
{
  void *lib = dlopen(argv[1], RTLD_NOW);
  if (!lib) { printf("dlopen: %s\n", dlerror()); return 2; }
  srep_run = (run_t)dlsym(lib, "srep_run");
  const char *(*ver)(void) = dlsym(lib, "srep_version");
  printf("%s\n", ver());
  const char *prog = argv[2], *in = argv[3], *w = argv[4];
  char a[512], b[512], c[512], cmd[2048];
  const char *seed = "--seed=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
  const char *methods[] = {"-m1f", "-m3f", "-m5f", "-m3", "-m3o"};
  for (int i = 0; i < 5; i++)
  {
    snprintf(a, sizeof a, "%s/lib%s.srep", w, methods[i]);
    snprintf(b, sizeof b, "%s/prog%s.srep", w, methods[i]);
    int rc = run_files(methods[i], seed, in, a, NULL);
    snprintf(cmd, sizeof cmd, "'%s' %s %s '%s' '%s' 2>/dev/null", prog, methods[i], seed, in, b);
    int prc = system(cmd);
    CHECK(rc == 0 && prc == 0 && files_equal(a, b), "%s: library and program archives differ (rc %d)", methods[i], rc);
    snprintf(c, sizeof c, "%s/lib%s.out", w, methods[i]);
    rc = run_files("-d", a, c, NULL, NULL);
    CHECK(rc == 0 && files_equal(c, in), "%s: library decode", methods[i]);
  }
  /* pipes, as ytool runs it: compress stdin -> stdout, decode stdin -> stdout */
  snprintf(a, sizeof a, "%s/pipe.srep", w); snprintf(b, sizeof b, "%s/pipe.err", w); snprintf(c, sizeof c, "%s/pipe.out", w);
  char tmp[512]; snprintf(tmp, sizeof tmp, "-temp=%s/pipe.tmp", w);
  char *ea[] = {(char*)"srep", (char*)"-m5f", (char*)seed, tmp, (char*)"-", (char*)"-", NULL};
  int rc = run_pipes(ea, 6, in, a, b);
  char *da[] = {(char*)"srep", (char*)"-d", (char*)"-", (char*)"-", NULL};
  int rc2 = run_pipes(da, 4, a, c, b);
  CHECK(rc == 0 && rc2 == 0 && files_equal(c, in), "pipes: rc %d/%d", rc, rc2);
  /* a damaged archive: exit code 4, the caller goes on, no output left */
  snprintf(a, sizeof a, "%s/lib-m3f.srep", w); snprintf(b, sizeof b, "%s/bad.srep", w);
  FILE *fa = fopen(a, "rb"), *fb = fopen(b, "wb"); int ch, pos = 0;
  while ((ch = fgetc(fa)) != EOF) { if (pos++ == 5000) ch ^= 0x55; fputc(ch, fb); }
  fclose(fa); fclose(fb);
  snprintf(c, sizeof c, "%s/bad.out", w);
  rc = run_files("-d", b, c, NULL, NULL);
  CHECK(rc == 4 && access(c, F_OK) != 0, "damaged archive: rc %d, output %s", rc, access(c, F_OK) == 0? "left" : "removed");
  rc = run_files("--bogus", in, c, NULL, NULL);
  CHECK(rc == 2, "bad option: rc %d", rc);
  /* after errors, a seeded run still gives the program's bytes */
  snprintf(a, sizeof a, "%s/again.srep", w); snprintf(b, sizeof b, "%s/prog-m3f.srep", w);
  rc = run_files("-m3f", seed, in, a, NULL);
  CHECK(rc == 0 && files_equal(a, b), "seeded run after errors differs");
  /* an unseeded run, then a seeded one: the seed must count */
  rc = run_files("-m3f", in, a, NULL, NULL);
  rc = run_files("-m3f", seed, in, a, NULL);
  CHECK(rc == 0 && files_equal(a, b), "seed ignored after an unseeded run");
  /* two threads at once: serialized, both right */
  struct par p1 = {in, NULL, -1}, p2 = {in, NULL, -1};
  char o1[512], o2[512]; snprintf(o1, sizeof o1, "%s/t1.srep", w); snprintf(o2, sizeof o2, "%s/t2.srep", w);
  p1.out = o1; p2.out = o2; pthread_t t1, t2;
  pthread_create(&t1, NULL, par_run, &p1); pthread_create(&t2, NULL, par_run, &p2);
  pthread_join(t1, NULL); pthread_join(t2, NULL);
  CHECK(p1.rc == 0 && p2.rc == 0 && files_equal(o1, b) && files_equal(o2, b), "two threads at once");
  printf("== %d OK, %d FAIL\n", passes, fails);
  return fails != 0;
}
