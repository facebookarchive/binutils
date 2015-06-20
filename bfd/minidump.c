/* BFD back end for Windows-format minidump files.

For a description of the minidump format, see
https://msdn.microsoft.com/en-us/library/windows/desktop/ms680378%28v=vs.85%29.aspx

Most of the smart parsing logic actually lives in GDB.  Here, we
understand just enough of the file format to implement the generic
core dump interface and mark memory references as loadable sections.

*/

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "bfd_stdint.h"

#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif

const bfd_target *minidump_core_file_p (bfd *abfd);
char * minidump_core_file_failing_command (bfd *abfd);
int minidump_core_file_failing_signal (bfd *abfd);
#define minidump_core_file_matches_executable_p generic_core_file_matches_executable_p
#define minidump_core_file_pid _bfd_nocore_core_file_pid
static void swap_abort (void);
static char* minidump_strdup (bfd *abfd, const char *str);
static bfd_boolean parse_memory_descriptor (bfd *, const char *);

#define ARRAY_SIZE(x) (sizeof ((x)) / sizeof ((x)[0]))

#define	HOSTIZE(ptr)						\
  (*(ptr) = bfd_get (8*sizeof *(ptr), (abfd), (ptr)))

#define READ(ptr)							\
  do {									\
    bfd_size_type _s = bfd_bread ((ptr), sizeof *(ptr), (abfd));	\
    if (_s != sizeof *(ptr))						\
      {									\
	bfd_set_error (bfd_error_wrong_format);				\
	goto out;							\
      }									\
    HOSTIZE ((ptr));							\
  } while (0)

#define SEEK(rva)						\
  do {								\
    if (bfd_seek (abfd, (rva), SEEK_SET) != 0)			\
      {								\
	bfd_set_error (bfd_error_wrong_format);			\
	goto out;						\
      }								\
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

#define MINIDUMP_SIGNATURE 0x504d444d
#define MINIDUMP_VERSION 0xA793

enum minidump_processor_architecture {
  minidump_cpu_x86 = 0,
  minidump_cpu_mips = 1,
  minidump_cpu_alpha = 2,
  minidump_cpu_ppc = 3,
  minidump_cpu_shx = 4,
  minidump_cpu_arm = 5,
  minidump_cpu_ia64 = 6,
  minidump_cpu_alpha64 = 7,
  minidump_cpu_msil = 8,
  minidump_cpu_amd64 = 9,
  minidump_cpu_x86_win64 = 10,
  minidump_cpu_sparc = 0x8001,
  minidump_cpu_ppc64 = 0x8002,
  minidump_cpu_arm64 = 0x8003
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

static const struct {
  enum minidump_processor_architecture minidump_cpu;
  enum bfd_architecture arch;
  unsigned long mach;
} minidump_to_bfd_arch_map[] = {
  { minidump_cpu_x86, bfd_arch_i386, bfd_mach_i386_i386 },
  { minidump_cpu_mips, bfd_arch_mips, 0 },
  { minidump_cpu_alpha, bfd_arch_alpha, 0 },
  { minidump_cpu_ppc, bfd_arch_powerpc, bfd_mach_ppc },
  /* No equivalent for minidump_cpu_shx?  */
  { minidump_cpu_arm, bfd_arch_arm, 0 },
  { minidump_cpu_ia64, bfd_arch_ia64, 0 },
  { minidump_cpu_alpha64, bfd_arch_alpha, 0 },
  /* No equivalent for minidump_cpu_msil.  */
  { minidump_cpu_amd64, bfd_arch_i386, bfd_mach_x86_64 },
  { minidump_cpu_x86_win64, bfd_arch_i386, bfd_mach_i386_i386 },
  { minidump_cpu_sparc, bfd_arch_sparc,	0 },
  { minidump_cpu_ppc64, bfd_arch_powerpc, bfd_mach_ppc64 },
  { minidump_cpu_arm64, bfd_arch_aarch64, 0 }
};

typedef uint32_t rva;

struct minidump_header {
  uint32_t signature;
  uint16_t version_low;
  uint16_t version_high;
  uint32_t number_of_streams;
  rva stream_directory_rva;
  uint32_t checksum;
  uint32_t time_date_stamp;
  uint64_t flags;
};

struct minidump_location_descriptor {
  uint32_t data_size;
  rva rva;
};

struct minidump_directory {
  uint32_t stream_type;
  struct minidump_location_descriptor location;
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

static bfd_boolean
parse_thread (bfd *abfd)
{
  bfd_boolean ret = 0;
  struct minidump_thread thread;
  char buf[64];
  char *bufcpy;

  memset (&thread, 0, sizeof (thread));

  READ (&thread.thread_id);
  READ (&thread.suspend_count);
  READ (&thread.priority_class);
  READ (&thread.priority);
  READ (&thread.teb);

  snprintf (buf, sizeof (buf), "stack_%u", (unsigned) thread.thread_id);
  bufcpy = minidump_strdup (abfd, buf);
  if (bufcpy == NULL)
    goto out;

  if (!parse_memory_descriptor (abfd, bufcpy))
    goto out;

  READ (&thread.thread_context.data_size);
  READ (&thread.thread_context.rva);

  ret = 1;

 out:

  return ret;
}

static bfd_boolean
parse_thread_list_stream (bfd *abfd)
{
  bfd_boolean ret = 0;
  uint32_t number_of_threads;
  uint32_t i;

  READ (&number_of_threads);

  for (i = 0; i < number_of_threads; ++i)
    if (!parse_thread (abfd))
      goto out;

  ret = 1;

 out:

  return ret;
}

char*
minidump_strdup (bfd *abfd, const char *str)
{
  size_t length = strlen (str);
  char *nstr = bfd_alloc (abfd, length + 1);
  if (nstr != NULL)
    memcpy (nstr, str, length + 1);
  return nstr;
}

static bfd_boolean
parse_memory_descriptor (bfd *abfd, const char *section_name)
{
  bfd_boolean ret = 0;
  int flags;
  asection *mem_asect;
  struct minidump_memory_descriptor memdesc;

  memset (&memdesc, 0, sizeof (memdesc));
  READ (&memdesc.start_of_memory_range);
  READ (&memdesc.memory.data_size);
  READ (&memdesc.memory.rva);

  flags = SEC_LOAD | SEC_HAS_CONTENTS | SEC_ALLOC;
  mem_asect = bfd_make_section_anyway_with_flags (
    abfd, section_name, flags);

  if (mem_asect == NULL)
    goto out;

  mem_asect->size = memdesc.memory.data_size;
  mem_asect->vma = memdesc.start_of_memory_range;
  mem_asect->filepos = memdesc.memory.rva;

  ret = 1;

 out:

  return ret;
}

static bfd_boolean
parse_memory_list_stream (bfd *abfd)
{
  bfd_boolean ret = 0;
  uint32_t number_of_memory_ranges;
  uint32_t i;

  READ (&number_of_memory_ranges);

  for (i = 0; i < number_of_memory_ranges; ++i)
    if (!parse_memory_descriptor (abfd, "mem"))
      goto out;

  ret = 1;

 out:
  return ret;
}

static bfd_boolean
parse_system_info_stream (bfd *abfd)
{
  bfd_boolean ret = 0;
  unsigned i = 0;

  struct {
    uint16_t processor_architecture;
    uint16_t processor_level;
    uint16_t processor_revision;
    uint8_t  number_of_processors;
    uint8_t  product_type;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t build_number;
    uint32_t platform_id;
  } system_info;

  READ (&system_info.processor_architecture);
  READ (&system_info.processor_level);
  READ (&system_info.processor_revision);
  READ (&system_info.number_of_processors);
  READ (&system_info.product_type);
  READ (&system_info.major_version);
  READ (&system_info.minor_version);
  READ (&system_info.build_number);
  READ (&system_info.platform_id);

  for (i = 0; i < ARRAY_SIZE (minidump_to_bfd_arch_map); ++i) {
    if (minidump_to_bfd_arch_map[i].minidump_cpu ==
	system_info.processor_architecture)
      {
	enum bfd_architecture arch = minidump_to_bfd_arch_map[i].arch;
	unsigned long mach = minidump_to_bfd_arch_map[i].mach;

	if (system_info.platform_id == minidump_os_nacl)
	  {
	    if (arch == bfd_arch_i386 && mach == bfd_mach_i386_i386)
	      mach = bfd_mach_i386_nacl;

	    if (arch == bfd_arch_i386 && mach == bfd_mach_x86_64)
	      mach = bfd_mach_x86_64_nacl;
	  }

	bfd_default_set_arch_mach (abfd, arch, mach);
	break;
      }
  }

  ret = 1;

 out:
  return ret;
}

const bfd_target *
minidump_core_file_p (bfd *abfd)
{
  bfd_size_type i;
  struct minidump_header h;
  const bfd_target *ret = NULL;

  memset (&h, 0, sizeof (h));
  READ (&h.signature);
  READ (&h.version_low);
  READ (&h.version_high);
  READ (&h.number_of_streams);
  READ (&h.stream_directory_rva);
  READ (&h.checksum);
  READ (&h.time_date_stamp);
  READ (&h.flags);

  if (h.signature != MINIDUMP_SIGNATURE)
    goto out;

  if (h.version_low != MINIDUMP_VERSION)
    goto out;

  SEEK (h.stream_directory_rva);

  for (i = 0; i < h.number_of_streams; ++i)
    {
      struct minidump_directory dir;
      asection *asect;
      int flags;
      char section_name[sizeof ("md_0xXXXXXXXX")];
      char *section_name_copy;

      memset (&dir, 0, sizeof (dir));
      READ (&dir.stream_type);
      READ (&dir.location.data_size);
      READ (&dir.location.rva);

      snprintf (section_name, sizeof (section_name),
		"md_0x%08X", dir.stream_type);
      section_name_copy = minidump_strdup (abfd, section_name);
      if (section_name_copy == NULL)
	goto out;

      flags = SEC_READONLY | SEC_HAS_CONTENTS;

      asect = bfd_make_section_anyway_with_flags (
	abfd, section_name_copy, flags);

      if (asect == NULL)
	goto out;

      asect->size = dir.location.data_size;
      asect->vma = 0;
      asect->filepos = dir.location.rva;
      asect->alignment_power = 0;

      if (dir.stream_type == memory_list_stream)
	{
	  file_ptr saved_pos = bfd_tell (abfd);
	  SEEK (asect->filepos);
	  if (!parse_memory_list_stream (abfd))
	    goto out;
	  SEEK (saved_pos);
	}

      if (dir.stream_type == system_info_stream)
	{
	  file_ptr saved_pos = bfd_tell (abfd);
	  SEEK (asect->filepos);
	  if (!parse_system_info_stream (abfd))
	    goto out;
	  SEEK (saved_pos);
	}

      if (dir.stream_type == thread_list_stream)
	{
	  file_ptr saved_pos = bfd_tell (abfd);
	  SEEK (asect->filepos);
	  if (!parse_thread_list_stream (abfd))
	    goto out;
	  SEEK (saved_pos);
	}

    }

  ret = abfd->xvec;

 out:

  return ret;
}

static char *
minidump_read_cmdline1 (bfd *abfd)
{
  char *ret = NULL;
  bfd_byte *cmdline = NULL;
  size_t length;
  asection *asect;

  asect = minidump_get_section_by_type (abfd, linux_cmd_line_stream);
  if (asect == NULL)
    goto out;

  if (!bfd_malloc_and_get_section (abfd, asect, &cmdline))
    goto out;

  length = strnlen ((const char*) cmdline, asect->size);
  ret = bfd_alloc (abfd, length + 1);
  if (ret == NULL)
    goto out;

  memcpy (ret, cmdline,	length);
  ret[length] = '\0';

 out:
  free (cmdline);
  return ret;
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
  char *ret = NULL;
  char *mb = NULL;
  const wchar_t *wctrans_ptr;
  size_t i, j;
  size_t mblen;
  mbstate_t ps;

  wctrans = bfd_malloc2 (length+1, sizeof (wchar_t));
  if (wctrans == NULL)
    goto out;

  i = 0;
  j = 0;
  while (i < length)
    i += utf16_mbtouc (&wctrans[j++], str + i, length - i);
  wctrans[j] = 0;

  memset (&ps, 0, sizeof (ps));
  wctrans_ptr = wctrans;
  mblen = wcsrtombs (NULL, &wctrans_ptr, 0, &ps);
  if (mblen == (size_t) -1)
    goto out;

  mb = bfd_malloc (mblen+1);
  if (mb == NULL)
    goto out;

  memset (&ps, 0, sizeof (ps));
  wctrans_ptr = wctrans;
  mblen = wcsrtombs (mb, &wctrans_ptr, mblen+1, &ps);
  if (mblen == (size_t) -1)
    goto out;

  ret = mb;
  mb = NULL;

 out:
  free (wctrans);
  free (mb);
  return ret;
}
#else
static char *
convert_utf16_string_to_mb (const uint16_t *str, size_t length)
{
  char *ret = NULL;
  size_t i;

  if (length == (size_t) -1)
    goto out;

  ret = bfd_malloc (length+1);
  if (ret == NULL)
    goto out;

  for (i = 0; i < length; ++i)
    {
      uint16_t c = str[i];
      ret[i] = c > 127 ? '?' : (char) c;
    }

  ret[i] = '\0';

 out:

  return ret;
}
#endif

static char *
minidump_read_first_module_name (bfd *abfd)
{
  char *ret = NULL;
  asection *asect;

  uint32_t number_of_modules;

  uint64_t base_of_image;
  uint32_t size_of_image;
  uint32_t checksum;
  uint32_t time_date_stamp;
  rva module_name_rva;

  uint32_t name_utf16_length_in_bytes;
  uint16_t *name_utf16 = NULL;
  char *name = NULL;
  uint16_t c;
  uint32_t i;

  asect = minidump_get_section_by_type (abfd, module_list_stream);
  if (asect == NULL)
    goto out;

  SEEK (asect->filepos);
  READ (&number_of_modules);
  if (number_of_modules == 0)
    goto out;

  READ (&base_of_image);
  READ (&size_of_image);
  READ (&checksum);
  READ (&time_date_stamp);
  READ (&module_name_rva);

  SEEK (module_name_rva);
  READ (&name_utf16_length_in_bytes);
  name_utf16 = bfd_malloc (name_utf16_length_in_bytes);
  if (name_utf16 == NULL)
    goto out;

  for (i = 0; i < name_utf16_length_in_bytes / 2; ++i)
    {
      READ (&c);
      name_utf16[i] = c;
    }

  name = convert_utf16_string_to_mb (
    name_utf16, name_utf16_length_in_bytes / 2);

  if (name == NULL)
    goto out;

  ret = minidump_strdup (abfd, name);

 out:
  free (name_utf16);
  free (name);
  return ret;
}

char *
minidump_core_file_failing_command (bfd *abfd)
{
  char *ret;

  ret = minidump_read_first_module_name (abfd);
  if (ret != NULL)
    return ret;

  ret = minidump_read_cmdline1 (abfd);
  if (ret != NULL)
    return ret;

  return NULL;
}

int
minidump_core_file_failing_signal (bfd *abfd)
{
  int ret = 0;
  uint32_t thread_id;
  uint32_t padding;
  uint32_t exception_code;
  asection *asect;

  asect = minidump_get_section_by_type (abfd, exception_stream);
  if (asect != NULL)
    {
      SEEK (asect->filepos);
      READ (&thread_id);
      READ (&padding);
      READ (&exception_code);
      ret = (int) exception_code;
    }

 out:

  return ret;
}

/* If somebody calls any byte-swapping routines, shoot them.  */
static void
swap_abort (void)
{
  abort (); /* This way doesn't require any declaration for ANSI to fuck up */
}

#define	NO_PUT ((void (*) (bfd_vma, void *)) swap_abort)
#define	NO_PUT64 ((void (*) (bfd_uint64_t, void *)) swap_abort)

const bfd_target minidump_generic_le_vec =
  {
    "minidump-generic-le",
    bfd_target_unknown_flavour,
    BFD_ENDIAN_LITTLE,		/* target byte order */
    BFD_ENDIAN_LITTLE,		/* target headers byte order */
    (HAS_RELOC | EXEC_P |	/* object flags */
     HAS_LINENO | HAS_DEBUG |
     HAS_SYMS | HAS_LOCALS | WP_TEXT | D_PAGED),
    (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_LOAD | SEC_RELOC), /* section flags */
    0,				/* symbol prefix */
    ' ',			/* ar_pad_char */
    16,				/* ar_max_namelen */
    0,				/* match priority.  */

    bfd_getl64, bfd_getl_signed_64, NO_PUT64,
    bfd_getl32, bfd_getl_signed_32, NO_PUT,
    bfd_getl16, bfd_getl_signed_16, NO_PUT, /* data */

    bfd_getl64, bfd_getl_signed_64, NO_PUT64,
    bfd_getl32, bfd_getl_signed_32, NO_PUT,
    bfd_getl16, bfd_getl_signed_16, NO_PUT, /* hdrs */

    {				/* bfd_check_format */
      _bfd_dummy_target,		/* unknown format */
      _bfd_dummy_target,		/* object file */
      _bfd_dummy_target,		/* archive */
      minidump_core_file_p		/* a core file */
    },
    {				/* bfd_set_format */
      bfd_false, bfd_false,
      bfd_false, bfd_false
    },
    {				/* bfd_write_contents */
      bfd_false, bfd_false,
      bfd_false, bfd_false
    },

    BFD_JUMP_TABLE_GENERIC (_bfd_generic),
    BFD_JUMP_TABLE_COPY (_bfd_generic),
    BFD_JUMP_TABLE_CORE (minidump),
    BFD_JUMP_TABLE_ARCHIVE (_bfd_noarchive),
    BFD_JUMP_TABLE_SYMBOLS (_bfd_nosymbols),
    BFD_JUMP_TABLE_RELOCS (_bfd_norelocs),
    BFD_JUMP_TABLE_WRITE (_bfd_generic),
    BFD_JUMP_TABLE_LINK (_bfd_nolink),
    BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

    NULL,

    NULL			/* backend_data */
  };

const bfd_target minidump_generic_be_vec =
  {
    "minidump-generic-be",
    bfd_target_unknown_flavour,
    BFD_ENDIAN_BIG,		/* target byte order */
    BFD_ENDIAN_BIG,		/* target headers byte order */
    (HAS_RELOC | EXEC_P |	/* object flags */
     HAS_LINENO | HAS_DEBUG |
     HAS_SYMS | HAS_LOCALS | WP_TEXT | D_PAGED),
    (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_LOAD | SEC_RELOC), /* section flags */
    0,				/* symbol prefix */
    ' ',			/* ar_pad_char */
    16,				/* ar_max_namelen */
    0,				/* match priority.  */

    bfd_getb64, bfd_getb_signed_64, NO_PUT64,
    bfd_getb32, bfd_getb_signed_32, NO_PUT,
    bfd_getb16, bfd_getb_signed_16, NO_PUT, /* data */

    bfd_getb64, bfd_getb_signed_64, NO_PUT64,
    bfd_getb32, bfd_getb_signed_32, NO_PUT,
    bfd_getb16, bfd_getb_signed_16, NO_PUT, /* hdrs */

    {				/* bfd_check_format */
      _bfd_dummy_target,		/* unknown format */
      _bfd_dummy_target,		/* object file */
      _bfd_dummy_target,		/* archive */
      minidump_core_file_p		/* a core file */
    },
    {				/* bfd_set_format */
      bfd_false, bfd_false,
      bfd_false, bfd_false
    },
    {				/* bfd_write_contents */
      bfd_false, bfd_false,
      bfd_false, bfd_false
    },

    BFD_JUMP_TABLE_GENERIC (_bfd_generic),
    BFD_JUMP_TABLE_COPY (_bfd_generic),
    BFD_JUMP_TABLE_CORE (minidump),
    BFD_JUMP_TABLE_ARCHIVE (_bfd_noarchive),
    BFD_JUMP_TABLE_SYMBOLS (_bfd_nosymbols),
    BFD_JUMP_TABLE_RELOCS (_bfd_norelocs),
    BFD_JUMP_TABLE_WRITE (_bfd_generic),
    BFD_JUMP_TABLE_LINK (_bfd_nolink),
    BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

    NULL,

    NULL			/* backend_data */
  };
