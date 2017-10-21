AC_PREREQ(2.60)
AC_INIT([tbstack], [0.1])
AM_INIT_AUTOMAKE([
	foreign
	1.11
	subdir-objects
	-Wall
	-Wno-portability
	tar-pax
	no-dist-gzip
	dist-xz
])
AM_SILENT_RULES([yes])

AC_GNU_SOURCE
AC_PROG_CC

AC_SYS_LARGEFILE

AC_SEARCH_LIBS([elf_begin], [elf], [], [
	AC_MSG_ERROR([unable to find the elf_begin() in libelf])
])
AC_ARG_ENABLE([ptrace],
	AS_HELP_STRING([--disable-ptrace], [Disable libunwind ptrace (default enabled)]),
	[use_ptrace=$enableval], [use_ptrace=yes])

AS_IF(test "$use_ptrace" == yes,
	[PKG_CHECK_MODULES([LIBUNWIND], [libunwind-ptrace])],
	[PKG_CHECK_MODULES([LIBUNWIND], [libunwind-generic])
	 AC_DEFINE([NO_LIBUNWIND_PTRACE], [1], [Don't use libunwind's ptrace support])]
)

echo -n "Checking for dwarf unwind support... "
SAVED_LDFLAGS="$LDFLAGS"
LDFLAGS=$LIBUNWIND_LIBS
AC_LINK_IFELSE([
	AC_LANG_SOURCE([[
#include <dwarf.h>
#include <libunwind.h>

#define dwarf_find_debug_frame UNW_OBJ(dwarf_find_debug_frame)

extern int
UNW_OBJ(dwarf_find_debug_frame)(int found, unw_dyn_info_t *di_debug,
                                unw_word_t ip,
                                unw_word_t segbase,
                                const char *obj_name, unw_word_t start,
                                unw_word_t end);
int main(void)
{
	dwarf_find_debug_frame(0, 0, 0, 0, 0, 0, 0);
	return 0;
}
]])], [dwarf_debug_frame=yes])
LDFLAGS="$SAVED_LDFLAGS"

if test "$dwarf_debug_frame" != yes; then
	echo "no"
else
	echo "yes"
	AC_DEFINE([HAVE_DWARF],[1],[DWARF debug_frame support in libunwind])
fi

AC_CHECK_DECLS([ELF_C_READ_MMAP], [], [], [#include <libelf.h>])

AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
