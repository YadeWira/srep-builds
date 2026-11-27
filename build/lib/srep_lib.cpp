// libsrep: the srep program as a library (see srep_lib.h). It compiles srep's
// own main (renamed) with SREP_LIB, which build/patch_srep.py (patch 28) uses
// to turn exits into exceptions and "-" into the handles given here.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#  include <io.h>
#  include <fcntl.h>
#  include <windows.h>
#else
#  include <unistd.h>
#  include <pthread.h>
#endif

#define SREP_LIB 1
FILE *srep_lib_in = NULL, *srep_lib_out = NULL, *srep_lib_err = NULL;
char srep_lib_seed[600] = "";

#define main srep_cli_main
#include "SREP/srep.cpp"
#undef main

#include "srep_lib.h"

#ifdef _WIN32
static CRITICAL_SECTION run_lock;
static volatile LONG run_lock_ready = 0;
static void lock_run (void)
{
  if (InterlockedCompareExchange (&run_lock_ready, 1, 0) == 0)
    InitializeCriticalSection (&run_lock), run_lock_ready = 2;
  while (run_lock_ready != 2)  Sleep (0);
  EnterCriticalSection (&run_lock);
}
static void unlock_run (void)  {LeaveCriticalSection (&run_lock);}
static FILE *open_handle (intptr_t h, int write)
{
  if (h == -1)  return fopen (NULL_FILENAME, write? "wb" : "rb");
  int fd = _open_osfhandle (h, (write? _O_WRONLY : _O_RDONLY) | _O_BINARY);
  return fd < 0? NULL : _fdopen (fd, write? "wb" : "rb");
}
#else
static pthread_mutex_t run_lock = PTHREAD_MUTEX_INITIALIZER;
static void lock_run (void)    {pthread_mutex_lock (&run_lock);}
static void unlock_run (void)  {pthread_mutex_unlock (&run_lock);}
static FILE *open_handle (intptr_t h, int write)
{
  if (h == -1)  return fopen (NULL_FILENAME, write? "wb" : "rb");
  return fdopen ((int)h, write? "wb" : "rb");
}
#endif

extern "C" SREP_API const char *srep_version (void)
{
  return program_version;
}

extern "C" SREP_API int srep_run (int argc, char **argv, intptr_t in_handle,
                                  intptr_t out_handle, intptr_t err_handle)
{
  int rc;
  lock_run();
  srep_lib_in  = open_handle (in_handle,  0);
  srep_lib_out = open_handle (out_handle, 1);
  srep_lib_err = open_handle (err_handle, 1);
  srep_lib_seed[0] = 0;
  partial_done = 0;
  partial_fout = partial_ftemp = partial_fstat = partial_fin = NULL;
  partial_out = partial_temp = partial_index = partial_vm = NULL;
  if (!srep_lib_in || !srep_lib_out || !srep_lib_err)
    rc = ERROR_IO;
  else
  {
    setbuf (srep_lib_err, NULL);
    try                           {rc = srep_cli_main (argc, argv);}
    catch (srep_lib_exit &e)      {rc = e.code;}
    catch (std::bad_alloc &)      {fprintf (srep_lib_err, "\n  ERROR! Not enough memory\n");  rc = ERROR_MEMORY;}
    catch (...)                   {fprintf (srep_lib_err, "\n  ERROR! Internal error\n");  rc = ERROR_MEMORY;}
  }
  if (srep_lib_out && fflush (srep_lib_out) != 0 && rc == NO_ERRORS)  rc = ERROR_IO;
  if (srep_lib_in)   fclose (srep_lib_in);
  if (srep_lib_out)  fclose (srep_lib_out);
  if (srep_lib_err)  fclose (srep_lib_err);
  srep_lib_in = srep_lib_out = srep_lib_err = NULL;
  srep_lib_seed[0] = 0;
  unlock_run();
  return rc;
}
