/* Routines for working with Windows minidump files.

   Some of this code is similar to BFD's minidump parsing code
   (particularly the constant tables), but since the error handling
   mechanisms are completely different, and since we understand a much
   bigger portion of the minidump format, it's best to keep the
   components separate.

 */

#include "defs.h"
#include "utils.h"
#include "minidump.h"

#define	HOSTIZE(ptr)					\
  (*(ptr) = bfd_get (8*sizeof *(ptr), (abfd), (ptr)))

ATTRIBUTE_NORETURN
static void
throw_bfd_error (void)
{
  error ("%s", bfd_errmsg (bfd_get_error ()));
}

#define READ(ptr)							\
  do {									\
    bfd_size_type _s = bfd_bread ((ptr), sizeof *(ptr), (abfd));	\
    if (_s != sizeof *(ptr))						\
      throw_bfd_error ();						\
    HOSTIZE ((ptr));							\
  } while (0)

#define SEEK(rva)						\
  do {								\
    if (bfd_seek (abfd, (rva), SEEK_SET) != 0)			\
      throw_bfd_error ();					\
  } while (0)

enum minidump_stream_type {
  unused_stream = 0,
  reserved_stream_0 = 1,
  reserved_stream_1 = 2,
  thread_list_stream = 3,
  module_list_stream = 4,
  memory_list_stream = 5,
  exception_stream = 6,
  system_info_stream = 7,
  thread_ex_list_stream = 8,
  memory_64_list_stream = 9,
  comment_stream_a = 10,
  comment_stream_w = 11,
  handle_data_stream = 12,
  function_table_stream = 13,
  unloaded_module_list_stream = 14,
  misc_info_stream = 15,
  memory_info_list_stream = 16,
  thread_info_list_stream = 17,
  handle_operation_list_stream = 18,
  breakpad_info_stream = 0x47670001,
  assertion_info_stream = 0x47670002,
  linux_cpu_info_stream = 0x47670003,
  linux_proc_status_stream = 0x47670004,
  linux_lsb_release_stream = 0x47670005,
  linux_cmd_line_stream = 0x47670006,
  linux_environ_stream = 0x47670007,
  linux_auxv_stream = 0x47670008,
  linux_maps_stream = 0x47670009,
  linux_dso_debug_stream = 0x4767000A,
};

typedef uint32_t rva;

struct minidump_location_descriptor {
  uint32_t data_size;
  rva rva;
};

struct minidump_memory_descriptor {
  uint64_t start_of_memory_range;
  struct minidump_location_descriptor memory;
};

struct minidump_thread {
  uint32_t thread_id;
  uint32_t suspend_count;
  uint32_t priority_class;
  uint32_t priority;
  uint64_t teb;
  struct minidump_memory_descriptor stack;
  struct minidump_location_descriptor thread_context;
};

static asection *
minidump_get_section_by_type (bfd *abfd, enum minidump_stream_type type)
{
  char section_name[sizeof ("md_0xXXXXXXXX")];
  snprintf (section_name, sizeof (section_name), "md_0x%08X", type);
  return bfd_get_section_by_name (abfd, section_name);
}

static void
read_location_descriptor (
  bfd *abfd,
  struct minidump_location_descriptor* locdesc)
{
  READ (&locdesc->data_size);
  READ (&locdesc->rva);
}

static void
read_memory_descriptor (
  bfd *abfd,
  struct minidump_memory_descriptor* memdesc)
{
  READ (&memdesc->start_of_memory_range);
  read_location_descriptor (abfd, &memdesc->memory);
}

int
minidump_p (bfd *abfd)
{
  return bfd_get_flavour (abfd) == bfd_target_minidump_flavour;
}

static void
minidump_enumerate_threads_1 (bfd *abfd,
	   minidump_thread_enumerator enumerator,
	   void *data)
{
  struct cleanup *cleanup;
  struct minidump_thread thread;
  struct minidump_thread_info ti;
  file_ptr saved_pos;
  void *regdata;

  READ (&thread.thread_id);
  READ (&thread.suspend_count);
  READ (&thread.priority_class);
  READ (&thread.priority);
  READ (&thread.teb);
  read_memory_descriptor (abfd, &thread.stack);
  read_location_descriptor (abfd, &thread.thread_context);

  memset (&ti, 0, sizeof (ti));
  ti.thread_id = thread.thread_id;
  ti.regsize = thread.thread_context.data_size;

  regdata = xmalloc (ti.regsize);
  cleanup = make_cleanup (xfree, regdata);
  saved_pos = bfd_tell (abfd);
  SEEK (thread.thread_context.rva);
  if (bfd_bread (regdata, ti.regsize, abfd) != ti.regsize)
    throw_bfd_error ();
  SEEK (saved_pos);
  ti.regdata = regdata;
  enumerator (abfd, &ti, data);
  do_cleanups (cleanup);
}

void
minidump_enumerate_threads (
  bfd *abfd,
  minidump_thread_enumerator enumerator,
  void *data)
{
  asection *asect = minidump_get_section_by_type (abfd, thread_list_stream);
  if (asect != NULL)
    {
      uint32_t number_of_threads;
      uint32_t i;

      SEEK (asect->filepos);
      READ (&number_of_threads);

      for (i = 0; i < number_of_threads; ++i)
	minidump_enumerate_threads_1 (abfd, enumerator, data);
    }
}
