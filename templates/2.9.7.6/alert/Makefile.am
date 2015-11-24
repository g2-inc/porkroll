## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include

noinst_libdir = ${exec_prefix}/lib/snort_dynamicrules

noinst_lib_LTLIBRARIES = lib_~~SIDNAME~~.la

lib_~~SIDNAME~~_la_LDFLAGS = -export-dynamic @XCCFLAGS@

BUILT_SOURCES = \
sfsnort_dynamic_detection_lib.c \
sfsnort_dynamic_detection_lib.h

nodist_lib_~~SIDNAME~~_la_SOURCES = \
sfsnort_dynamic_detection_lib.c \
sfsnort_dynamic_detection_lib.h \
rules.c \
~~SIDNAME~~.c \
detection_lib_meta.h

EXTRA_DIST = \
rules.c \
~~SIDNAME~~.c \
detection_lib_meta.h

sfsnort_dynamic_detection_lib.c: ../include/sfsnort_dynamic_detection_lib.c
	cp $? $@

sfsnort_dynamic_detection_lib.h: ../include/sfsnort_dynamic_detection_lib.h
	cp $? $@

clean-local:
	rm -f $(BUILT_SOURCES)

