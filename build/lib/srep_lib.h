/* libsrep: srep (by Bulat Ziganshin, "All rights reserved") as a library.
   Personal builds, as the program: https://github.com/YadeWira/srep-builds

   srep_run runs srep's own command line inside the calling process: the same
   options, archives and exit codes as the srep program (0 done, 1 warnings,
   2 command line, 3 I/O, 4 bad data, 5 memory). argv[0] is ignored.

   A file name "-" means the handles given: in_handle for input, out_handle for
   output (POSIX: file descriptors; Windows: HANDLEs, as from CreatePipe).
   err_handle receives what the program would write on stderr (progress, and
   "ERROR! ..." on a failure); -1 discards it. srep_run takes ownership of the
   three handles and closes them before it returns, as a child process closes
   its ends of the pipes when it exits.

   One call runs at a time: concurrent calls wait for each other. A damaged
   archive or any other error returns its exit code, never ends the caller; the
   output and temporary files are removed, as the program does. */
#ifndef SREP_LIB_H
#define SREP_LIB_H

#include <stdint.h>

#if defined(_WIN32)
#  define SREP_API __declspec(dllexport)
#else
#  define SREP_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

SREP_API int srep_run (int argc, char **argv, intptr_t in_handle,
                       intptr_t out_handle, intptr_t err_handle);

/* "SREP 3.98 (3.93a + ytool fixes)" */
SREP_API const char *srep_version (void);

#ifdef __cplusplus
}
#endif

#endif
