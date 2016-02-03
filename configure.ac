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

AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
