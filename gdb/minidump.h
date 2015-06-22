#ifndef MINIDUMP_H
#define MINIDUMP_H

#include "bfd.h"
#include "gdb_bfd.h"

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

#endif
