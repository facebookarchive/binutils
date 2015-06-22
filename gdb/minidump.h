#ifndef MINIDUMP_H
#define MINIDUMP_H

#include "bfd.h"
#include "gdb_bfd.h"
#include "target.h"

/* Determine whether ABFD represents a minidump.  */
int minidump_p (bfd *abfd);

struct minidump_thread_info {
  int thread_id;
  const void *regdata;
  size_t regsize;
};

typedef void (*minidump_thread_enumerator)(
  bfd *abfd,
  const struct minidump_thread_info *ti,
  void *data);

/* Call ENUMERATOR for each thread in the minidump.  */
void minidump_enumerate_threads (
  bfd *abfd,
  minidump_thread_enumerator enumerator,
  void* data);

enum target_xfer_status minidump_query (
  bfd *abfd,
  enum target_object object,
  const char *annex,
  gdb_byte *readbuf,
  ULONGEST offset,
  ULONGEST len,
  ULONGEST *xfered_len);

struct minidump_exception_info {
  int thread_id;
  int signum;
  CORE_ADDR faulting_address;
};

struct minidump_exception_info minidump_read_exception_info (bfd *abfd);

#endif
