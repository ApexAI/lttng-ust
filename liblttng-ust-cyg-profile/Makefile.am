AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS += -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-cyg-profile.la \
	liblttng-ust-cyg-profile-fast.la

liblttng_ust_cyg_profile_la_SOURCES = \
	lttng-ust-cyg-profile.c \
	lttng-ust-cyg-profile.h

liblttng_ust_cyg_profile_la_LIBADD = \
	-L$(top_builddir)/liblttng-ust/.libs \
	-llttng-ust \
	$(DL_LIBS)

liblttng_ust_cyg_profile_fast_la_SOURCES = \
	lttng-ust-cyg-profile-fast.c \
	lttng-ust-cyg-profile-fast.h

liblttng_ust_cyg_profile_fast_la_LIBADD = \
	-L$(top_builddir)/liblttng-ust/.libs \
	-llttng-ust \
	$(DL_LIBS)

noinst_SCRIPTS = run run-fast
EXTRA_DIST = run run-fast
