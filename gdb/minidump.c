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
#include "gdbcore.h"

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

#define MD_CVINFOPDB70_SIGNATURE 0x53445352

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

typedef void (*minidump_module_enumerator)(
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

struct minidump_link_map_32 {
  uint32_t addr;
  rva name_rva;
  uint32_t ld;
};

struct minidump_debug_32 {
  uint32_t version;
  rva link_map_rva;
  uint32_t dso_count;
  uint32_t brk;
  uint32_t ldbase;
  uint32_t dynamic;
};

struct minidump_link_map_64 {
  uint64_t addr;
  rva name_rva;
  uint32_t align;
  uint64_t ld;
};

struct minidump_debug_64 {
  uint32_t version;
  rva link_map_rva;
  uint32_t dso_count;
  uint32_t align;
  uint64_t brk;
  uint64_t ldbase;
  uint64_t dynamic;
};

struct minidump_cv_pdb70 {
  uint32_t cv_signature;
  uint8_t signature[16];
  uint32_t age;
};

static void minidump_enumerate_modules (
  bfd *abfd,
  minidump_module_enumerator enumerator,
  void *data);

static char* minidump_read_string (bfd *abfd);
static struct so_list * minidump_current_sos (void);

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
minidump_enumerate_modules_1 (
  bfd *abfd,
  minidump_module_enumerator enumerator,
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
minidump_enumerate_modules (
  bfd *abfd,
  minidump_module_enumerator enumerator,
  void *data)
{
  asection *asect;
  uint32_t number_of_modules;
  uint32_t i;

  asect = minidump_get_section_by_type (abfd, module_list_stream);
  if (asect == NULL)
    return;

  SEEK (asect->filepos);
  READ (&number_of_modules);

  for (i = 0; i < number_of_modules; ++i)
    minidump_enumerate_modules_1 (abfd, enumerator, data);
}

static struct minidump_link_map_64
minidump_read_link_map (bfd *abfd)
{
  struct minidump_link_map_64 map64;

  if (bfd_get_arch_size (abfd) == 64)
    {
      READ (&map64.addr);
      READ (&map64.name_rva);
      READ (&map64.align);
      READ (&map64.ld);
    }
  else
    {
      struct minidump_link_map_32 map32;
      gdb_assert (bfd_get_arch_size (abfd) == 32);

      READ (&map32.addr);
      READ (&map32.name_rva);
      READ (&map32.ld);

      map64.addr = map32.addr;
      map64.name_rva = map32.name_rva;
      map64.ld = map32.ld;
    }

  return map64;
}

static struct minidump_debug_64
minidump_get_debug (bfd *abfd)
{
  asection *asect;
  struct minidump_debug_64 debug64;

  asect = minidump_get_section_by_type (abfd, linux_dso_debug_stream);
  if (asect == NULL)
    error (_ ("no DSO debug section in minidump"));

  SEEK (asect->filepos);
  if (bfd_get_arch_size (abfd) == 64)
    {
      READ (&debug64.version);
      READ (&debug64.link_map_rva);
      READ (&debug64.dso_count);
      READ (&debug64.align);
      READ (&debug64.brk);
      READ (&debug64.ldbase);
      READ (&debug64.dynamic);
    }
  else
    {
      struct minidump_debug_32 debug32;
      gdb_assert (bfd_get_arch_size (abfd) == 32);
      READ (&debug32.version);
      READ (&debug32.link_map_rva);
      READ (&debug32.dso_count);
      READ (&debug32.brk);
      READ (&debug32.ldbase);
      READ (&debug32.dynamic);

      debug64.version = debug32.version;
      debug64.link_map_rva = debug32.link_map_rva;
      debug64.dso_count = debug32.dso_count;
      debug64.brk = debug32.brk;
      debug64.ldbase = debug32.ldbase;
      debug64.dynamic = debug32.dynamic;
    }

  return debug64;
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
  switch (object) {
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


/* Minidump-specific shared library operations. */

struct target_so_ops minidump_so_ops;

struct lm_info {
  char *name;
  struct so_search_hints hints;
  void *build_id;
  size_t build_id_length;
};

static void
minidump_relocate_section_addresses (struct so_list *so,
				     struct target_section *sec)
{
  if (so->lm_info && so->lm_info->hints.base_addr_valid)
    {
      sec->addr += so->lm_info->hints.base_addr;
      sec->endaddr += so->lm_info->hints.base_addr;

      /* Best effort to set addr_high/addr_low.  This is used only by
	 'info sharedlibary'.  */
      if (so->addr_high == 0)
	{
	  so->addr_low = sec->addr;
	  so->addr_high = sec->endaddr;
	}
      if (sec->endaddr > so->addr_high)
	so->addr_high = sec->endaddr;
      if (sec->addr < so->addr_low)
	so->addr_low = sec->addr;
    }
}

static void
minidump_free_so (struct so_list *so)
{
  if (so->lm_info) {
    xfree (so->lm_info->build_id);
    xfree (so->lm_info->name);
    xfree (so->lm_info);
  }
}

static void
minidump_clear_solib (void)
{
}

static void
minidump_solib_create_inferior_hook (int from_tty)
{
}

static void
minidump_special_symbol_handling (void)
{
}

static void
do_cleanup_so_list (void *data)
{
  struct so_list **head_ptr = data;
  struct so_list *head = *head_ptr;
  struct so_list *so;
  while (head != NULL)
    {
      so = head;
      head = head->next;
      free_so (so);
    }
}

static struct minidump_cv_pdb70
minidump_read_cv_pdb70 (struct bfd *abfd)
{
  struct minidump_cv_pdb70 pdb70;
  READ (&pdb70.cv_signature);
  if (bfd_bread (&pdb70.signature, sizeof (pdb70.signature), abfd)
      != sizeof (pdb70.signature))
    {
      error (_ ("truncated minidump"));
    }
  READ (&pdb70.age);
  return pdb70;
}

static struct so_list *
minidump_make_so (
  struct bfd *abfd,
  const struct minidump_module *module,
  const struct minidump_link_map_64 *map /* optional */)
{
  struct so_list *so = NULL;
  struct cleanup *cleanup = make_cleanup (do_cleanup_so_list, &so);

  so = XCNEW (struct so_list);
  so->lm_info = XCNEW (struct lm_info);
  /* Cleanup covered under do_cleanup_so_list.  */
  SEEK (module->module_name_rva);
  so->lm_info->name = minidump_read_string (abfd);
  snprintf (so->so_original_name,
	    sizeof (so->so_original_name),
	    "%s",
	    so->lm_info->name);
  snprintf (so->so_name,
	    sizeof (so->so_name),
	    "%s",
	    so->lm_info->name);

  if (module->cv_record.rva != 0 &&
      module->cv_record.data_size != 0)
    {
      uint32_t cv_signature;
      SEEK (module->cv_record.rva);
      READ (&cv_signature);
      if (cv_signature == MD_CVINFOPDB70_SIGNATURE)
	{
	  struct minidump_cv_pdb70 pdb70;
	  SEEK (module->cv_record.rva);
	  pdb70 = minidump_read_cv_pdb70 (abfd);
	  so->lm_info->build_id = xmalloc (sizeof (pdb70.signature));
	  memcpy (so->lm_info->build_id,
		  &pdb70.signature,
		  sizeof (pdb70.signature));
	  so->lm_info->hints.minidump_id.bytes = so->lm_info->build_id;
	  so->lm_info->hints.minidump_id.length = sizeof (pdb70.signature);
	  so->lm_info->hints.minidump_id_valid = 1;
	}
    }

  if (map != NULL)
    {
      if (map->addr != 0)
	{
	  so->lm_info->hints.base_addr = map->addr;
	  so->lm_info->hints.base_addr_valid = 1;
	}
      if (map->ld != 0)
	{
	  so->lm_info->hints.l_ld = map->ld;
	  so->lm_info->hints.l_ld_valid = 1;
	}
    }

  discard_cleanups (cleanup);
  return so;
}

static void
minidump_describe_lm_info (struct so_search_hints *hints,
			   struct lm_info *lm_info)
{
  if (lm_info != NULL)
    *hints = lm_info->hints;
}

static char *
minidump_exec_file_find (char *in_pathname, int *fd)
{
  const struct so_search_hints *main_exe_hints = NULL;
  struct so_list *so;
  struct cleanup *so_cleanup;
  char *ret;

  so = minidump_current_sos ();
  so_cleanup = make_cleanup (do_cleanup_so_list, &so);
  if (so != NULL)
    main_exe_hints = &so->lm_info->hints;

  ret = exec_file_find2 (in_pathname, fd, main_exe_hints);
  do_cleanups (so_cleanup);
  return ret;
}


static void
minidump_current_sos_enumerator (
  struct bfd *abfd,
  struct minidump_module *module,
  void *data)
{
  struct so_list **head_ptr = data;
  struct so_list *so;

  so = minidump_make_so (abfd, module, NULL);
  so->next = *head_ptr;
  *head_ptr = so;
}

struct find_addr_context {
  uint64_t addr;
  struct minidump_module *module;
  int found;
};

static void
find_addr_enumerator (bfd *abfd,
		      struct minidump_module *module,
		      void *data)
{
  struct find_addr_context *context = data;
  if (module->base_of_image <= context->addr &&
      context->addr < module->base_of_image + module->size_of_image)
    {
      memcpy (context->module, module, sizeof (*module));
      context->found = 1;
    }
}

static int
find_module_for_address (bfd *abfd,
			 uint64_t addr,
			 struct minidump_module *module)
{
  struct find_addr_context context;
  context.addr = addr;
  context.module = module;
  context.found = 0;

  minidump_enumerate_modules (abfd, find_addr_enumerator, &context);
  return context.found;
}

static struct so_list *
minidump_current_sos_via_module_list (bfd *abfd)
{
  struct so_list *head = NULL;
  struct cleanup *head_cleanup;
  head_cleanup = make_cleanup (do_cleanup_so_list, &head);
  minidump_enumerate_modules (
    core_bfd,
    minidump_current_sos_enumerator,
    &head);
  discard_cleanups (head_cleanup);
  return head;
}

static struct so_list *
minidump_current_sos_via_dso_debug (bfd *abfd)
{
  uint32_t dso_nr;
  struct minidump_debug_64 debug;
  struct minidump_link_map_64 map;
  struct minidump_module module;
  file_ptr savedpos;
  char *name;
  int have_module;
  uint64_t search_addr;
  struct so_list *head = NULL;
  struct cleanup *head_cleanup;
  struct so_list *so;

  debug = minidump_get_debug (abfd);
  if (debug.link_map_rva == 0)
    return NULL;

  head_cleanup = make_cleanup (do_cleanup_so_list, &head);
  SEEK (debug.link_map_rva);
  savedpos = bfd_tell (abfd);
  for (dso_nr = 0; dso_nr < debug.dso_count; ++dso_nr)
    {
      SEEK (savedpos);
      map = minidump_read_link_map (abfd);
      savedpos = bfd_tell (abfd);
      SEEK (map.name_rva);
      name = minidump_read_string (abfd);
      search_addr = map.addr;
      if (search_addr == 0)
	search_addr = map.ld;
      have_module = find_module_for_address (abfd, search_addr, &module);
      if (!have_module)
	continue;

      so = minidump_make_so (abfd, &module, &map);
      so->next = head;
      head = so;
    }

  discard_cleanups (head_cleanup);
  return head;
}

static struct so_list *
reverse_so_list (struct so_list *head)
{
  struct so_list *new_head = NULL;
  struct so_list *so;
  while (head) {
    so = head;
    head = head->next;
    so->next = new_head;
    new_head = so;
  }
  return new_head;
}

static struct so_list *
minidump_current_sos (void)
{
  struct so_list *head = NULL;
  if (core_bfd == NULL || !minidump_p (core_bfd)) {
    warning ("minidump_current_sos called without minidump");
    return NULL;
  }

  if (minidump_get_section_by_type (core_bfd, linux_dso_debug_stream))
    head = minidump_current_sos_via_dso_debug (core_bfd);

  if (head == NULL)
    head = minidump_current_sos_via_module_list (core_bfd);

  if (head != NULL)
    head = reverse_so_list (head);

  return head;
}

static int
open_symbol_file_object (void *from_ttyp)
{
  return 0;
}

static int
minidump_in_dynsym_resolve_code (CORE_ADDR pc)
{
  return 0;
}



#ifdef HAVE_WCHAR_H

static unsigned int
utf16_mbtouc (wchar_t * puc, const uint16_t * s, unsigned int n)
{
  unsigned short c = * s;

  if (sizeof (wchar_t) == sizeof (uint16_t))
    {
      return 1;
    }

  if (c < 0xd800 || c >= 0xe000)
    {
      *puc = c;
      return 1;
    }

  if (c < 0xdc00)
    {
      if (n >= 2)
        {
          if (s[1] >= 0xdc00 && s[1] < 0xe000)
            {
              *puc = 0x10000 + ((c - 0xd800) << 10) + (s[1] - 0xdc00);
              return 2;
            }
        }
      else
        {
          /* Incomplete multibyte character.  */
          *puc = 0xfffd;
          return n;
        }
    }

  /* Invalid multibyte character.  */
  *puc = 0xfffd;
  return 1;
}

/**
 * Translate UTF-16 string STR to a string in the current LC_CTYPE
 * locale.  Return NULL on failure.  The returned string is
 * heap-allocated.  STR is a pointer to string characters, LENGTH is
 * its length in characters.
 */
static char *
convert_utf16_string_to_mb (const uint16_t *str, size_t length)
{
  wchar_t *wctrans = NULL;
  char *mb = NULL;
  const wchar_t *wctrans_ptr;
  size_t i, j;
  size_t mblen;
  mbstate_t ps;
  struct cleanup *cleanup;
  struct cleanup *mb_cleanup;

  wctrans = xcalloc (length+1, sizeof (wchar_t));
  cleanup = make_cleanup (xfree, wctrans);

  i = 0;
  j = 0;
  while (i < length)
    i += utf16_mbtouc (&wctrans[j++], str + i, length - i);
  wctrans[j] = 0;

  memset (&ps, 0, sizeof (ps));
  wctrans_ptr = wctrans;
  mblen = wcsrtombs (NULL, &wctrans_ptr, 0, &ps);
  if (mblen == (size_t) -1)
    error (_ ("invalid minidump string"));

  mb = xmalloc (mblen+1);
  mb_cleanup = make_cleanup (xfree, mb);
  memset (&ps, 0, sizeof (ps));
  wctrans_ptr = wctrans;
  mblen = wcsrtombs (mb, &wctrans_ptr, mblen+1, &ps);
  if (mblen == (size_t) -1)
    error (_ ("invalid minidump string"));

  discard_cleanups (mb_cleanup);
  do_cleanups (cleanup);
  return mb;
}
#else
static char *
convert_utf16_string_to_mb (const uint16_t *str, size_t length)
{
  char *ret = NULL;
  size_t i;

  if (length == (size_t) -1)
    error (_("overlong strong"));

  ret = xcalloc (length+1);
  for (i = 0; i < length; ++i)
    {
      uint16_t c = str[i];
      ret[i] = c > 127 ? '?' : (char) c;
    }

  ret[i] = '\0';
  return ret;
}
#endif

static char*
minidump_read_string (bfd *abfd)
{
  uint32_t length_bytes;
  uint16_t* rawstr;
  struct cleanup *cleanup;
  char *mb;

  READ (&length_bytes);

  rawstr = xmalloc (length_bytes);
  cleanup = make_cleanup (xfree, rawstr);
  if (bfd_bread (rawstr, length_bytes, abfd) != length_bytes)
    error (_ ("could not read minidump string"));
  mb = convert_utf16_string_to_mb (rawstr, length_bytes / 2);
  do_cleanups (cleanup);
  return mb;
}



/* Read the Linux mapping data included in the core dump.  If it's
   there, return a heap-allocated string containing the entire mapping
   blob, which is literally /proc/pid/maps.  Otherwise, return
   NULL.  */
char *
minidump_read_linux_mappings (bfd *abfd)
{
  asection *asect;
  char *mappings;
  size_t mappings_length;
  struct cleanup *cleanup;

  asect = minidump_get_section_by_type (abfd, linux_maps_stream);
  if (asect == NULL)
    return NULL;

  mappings_length = bfd_get_section_size (asect);
  if (mappings_length == (size_t) -1)
    error (_("malformed maps section: too long"));

  mappings = xmalloc (mappings_length + 1);
  cleanup = make_cleanup (xfree, mappings);

  if (! bfd_get_section_contents (abfd, asect, mappings,
				  (file_ptr) 0, mappings_length))
    throw_bfd_error ();

  mappings[mappings_length] = '\0';
  discard_cleanups (cleanup);
  return mappings;
}



extern initialize_file_ftype _initialize_minidump;

void
_initialize_minidump (void)
{
  minidump_so_ops.relocate_section_addresses = minidump_relocate_section_addresses;
  minidump_so_ops.free_so = minidump_free_so;
  minidump_so_ops.clear_solib = minidump_clear_solib;
  minidump_so_ops.solib_create_inferior_hook = minidump_solib_create_inferior_hook;
  minidump_so_ops.special_symbol_handling = minidump_special_symbol_handling;
  minidump_so_ops.current_sos = minidump_current_sos;
  minidump_so_ops.open_symbol_file_object = open_symbol_file_object;
  minidump_so_ops.in_dynsym_resolve_code = minidump_in_dynsym_resolve_code;
  minidump_so_ops.bfd_open2 = solib_bfd_open2;
  minidump_so_ops.describe_lm_info = minidump_describe_lm_info;
  minidump_so_ops.exec_file_find = minidump_exec_file_find;

  gdbarch_register_osabi_sniffer (bfd_arch_unknown /* wildcard */,
				  bfd_target_minidump_flavour,
				  minidump_osabi_sniffer);
}
