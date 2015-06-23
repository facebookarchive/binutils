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
#include "osabi.h"

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

enum minidump_os {
  minidump_os_win32s = 0,
  minidump_os_win32_windows = 1,
  minidump_os_win32_nt = 2,
  minidump_os_win32_ce = 3,
  minidump_os_unix = 0x8000,
  minidump_os_mac_os_x = 0x8101,
  minidump_os_ios = 0x8102,
  minidump_os_linux = 0x8202,
  minidump_os_android = 0x8203,
  minidump_os_ps3 = 0x8204,
  minidump_os_nacl = 0x8205,
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

struct minidump_fixed_file_info {
  uint32_t signature;
  uint32_t struct_version;
  uint32_t file_version_hi;
  uint32_t file_version_lo;
  uint32_t product_version_hi;
  uint32_t product_version_lo;
  uint32_t file_flags_mask;
  uint32_t file_flags;
  uint32_t file_os;
  uint32_t file_type;
  uint32_t file_subtype;
  uint32_t file_date_hi;
  uint32_t file_date_lo;
};

struct minidump_module {
  uint64_t base_of_image;
  uint32_t size_of_image;
  uint32_t checksum;
  uint32_t time_date_stamp;
  rva module_name_rva;
  struct minidump_fixed_file_info version_info;
  struct minidump_location_descriptor cv_record;
  struct minidump_location_descriptor misc_record;
  uint32_t unused[4];
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

typedef void (*minidump_int_module_enumerator)(
  struct bfd *abfd,
  struct minidump_module *module,
  void *data);

struct minidump_system_info {
  uint16_t processor_architecture;
  uint16_t processor_level;
  uint16_t processor_revision;
  uint8_t number_of_processors;
  uint8_t product_type;
  uint32_t major_version;
  uint32_t minor_version;
  uint32_t build_number;
  uint32_t platform_id;
};

static void
minidump_int_enumerate_modules (
  bfd *abfd,
  minidump_int_module_enumerator enumerator,
  void *data);

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

  saved_pos = bfd_tell (abfd);
  enumerator (abfd, &ti, data);
  SEEK (saved_pos);

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

static void
read_fixed_file_info (bfd *abfd,
		      struct minidump_fixed_file_info *ffi)
{
  READ (&ffi->signature);
  READ (&ffi->struct_version);
  READ (&ffi->file_version_hi);
  READ (&ffi->file_version_lo);
  READ (&ffi->product_version_hi);
  READ (&ffi->product_version_lo);
  READ (&ffi->file_flags_mask);
  READ (&ffi->file_flags);
  READ (&ffi->file_os);
  READ (&ffi->file_type);
  READ (&ffi->file_subtype);
  READ (&ffi->file_date_hi);
  READ (&ffi->file_date_lo);
}

static void
minidump_int_enumerate_modules_1 (
  bfd *abfd,
  minidump_int_module_enumerator enumerator,
  void *data)
{
  struct minidump_module module;
  file_ptr saved_pos;

  READ (&module.base_of_image);
  READ (&module.size_of_image);
  READ (&module.checksum);
  READ (&module.time_date_stamp);
  READ (&module.module_name_rva);
  read_fixed_file_info (abfd, &module.version_info);
  read_location_descriptor (abfd, &module.cv_record);
  read_location_descriptor (abfd, &module.misc_record);
  READ (&module.unused[0]);
  READ (&module.unused[1]);
  READ (&module.unused[2]);
  READ (&module.unused[3]);

  saved_pos = bfd_tell (abfd);
  enumerator (abfd, &module, data);
  SEEK (saved_pos);
}

void
minidump_int_enumerate_modules (
  bfd *abfd,
  minidump_int_module_enumerator enumerator,
  void *data)
{
  asection *asect = minidump_get_section_by_type (abfd, module_list_stream);
  uint32_t number_of_modules;
  uint32_t i;

  if (asect == NULL)
    return;

  SEEK (asect->filepos);
  READ (&number_of_modules);

  for (i = 0; i < number_of_modules; ++i)
    minidump_int_enumerate_modules_1 (abfd, enumerator, data);
}

enum target_xfer_status
minidump_query (
  bfd *abfd,
  enum target_object object,
  const char *annex,
  gdb_byte *readbuf,
  ULONGEST offset,
  ULONGEST len,
  ULONGEST *xfered_len)
{
  switch (object)
    {
    case TARGET_OBJECT_LIBRARIES_SVR4: {
      (void) minidump_int_enumerate_modules;
      return TARGET_XFER_UNAVAILABLE;
    }

    case TARGET_OBJECT_AUXV: {
      static asection *section;
      bfd_size_type size;

      if (readbuf == NULL)
	return TARGET_XFER_E_IO;

      section = minidump_get_section_by_type (abfd, linux_auxv_stream);
      if (section == NULL)
	return TARGET_XFER_E_IO;

      size = bfd_section_size (core_bfd, section);
      if (offset >= size)
	return TARGET_XFER_EOF;
      size -= offset;
      if (size > len)
	size = len;

      if (size == 0)
	return TARGET_XFER_EOF;
      if (!bfd_get_section_contents (abfd, section, readbuf,
				     (file_ptr) offset, size))
	  return TARGET_XFER_E_IO;

      *xfered_len = (ULONGEST) size;
      return TARGET_XFER_OK;
    }

    default:
      return TARGET_XFER_UNAVAILABLE;
    }
}



static struct minidump_system_info
minidump_read_system_info (bfd *abfd)
{
  struct minidump_system_info system_info;
  asection *asect;

  asect = minidump_get_section_by_type (abfd, system_info_stream);
  if (asect == NULL)
    error (_("minidump does not contain system type information"));

  SEEK (asect->filepos);
  READ (&system_info.processor_architecture);
  READ (&system_info.processor_level);
  READ (&system_info.processor_revision);
  READ (&system_info.number_of_processors);
  READ (&system_info.product_type);
  READ (&system_info.major_version);
  READ (&system_info.minor_version);
  READ (&system_info.build_number);
  READ (&system_info.platform_id);

  return system_info;
}

static enum gdb_osabi
minidump_osabi_sniffer (bfd *abfd)
{
  struct minidump_system_info system_info;

  TRY
    {
      system_info = minidump_read_system_info (abfd);
    }
  CATCH (except, RETURN_MASK_ERROR)
    {
      return GDB_OSABI_UNKNOWN;
    }
  END_CATCH;

  switch (system_info.platform_id)
    {
    case minidump_os_win32s:
    case minidump_os_win32_windows:
    case minidump_os_win32_nt:
      return GDB_OSABI_CYGWIN;
    case minidump_os_win32_ce:
      return GDB_OSABI_WINCE;
    case minidump_os_mac_os_x:
    case minidump_os_ios:
      return GDB_OSABI_DARWIN;
    case minidump_os_linux:
    case minidump_os_android:
    case minidump_os_ps3:
      return GDB_OSABI_LINUX;
    default:
      return GDB_OSABI_UNKNOWN;
    }
}

struct minidump_exception_info
minidump_read_exception_info (bfd *abfd)
{
  asection *asect;
  struct minidump_exception_info ei;
  uint32_t thread_id;
  uint32_t align;
  uint32_t exception_code;
  uint32_t exception_flags;
  uint64_t exception_record;
  uint64_t exception_address;

  asect = minidump_get_section_by_type (abfd, exception_stream);
  if (asect == NULL)
    error (_("minidump contains no exception information"));

  SEEK (asect->filepos);
  READ (&thread_id);
  READ (&align);
  READ (&exception_code);
  READ (&exception_flags);
  READ (&exception_record);
  READ (&exception_address);

  memset (&ei, 0, sizeof (ei));
  ei.thread_id = (int) thread_id;
  ei.signum = (int) exception_code;
  ei.faulting_address = (CORE_ADDR) exception_address;
  return ei;
}



extern initialize_file_ftype _initialize_minidump;

void
_initialize_minidump (void)
{
  gdbarch_register_osabi_sniffer (bfd_arch_unknown /* wildcard */,
				  bfd_target_minidump_flavour,
				  minidump_osabi_sniffer);
}
