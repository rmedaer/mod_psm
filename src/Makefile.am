SUBDIRS =

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = mod_psm.la

mod_psm_la_CPPFLAGS = -std=c99 -D_GNU_SOURCE -Werror
mod_psm_la_LDFLAGS  = -module

OBJECTS = \
    mod_psm.c \
    mod_psm_cookies.c \
    mod_psm_driver_redis.c \
    mod_psm_utils.c

HFILES = \
    mod_psm.h \
    mod_psm_cookies.h \
    mod_psm_driver_redis.h \
    mod_psm_utils.h

mod_psm_la_SOURCES = $(HFILES) $(OBJECTS)

all: mod_psm.la

install-libLTLIBRARIES:
	@: # override

install-exec-local: mod_psm.la
	$(MKDIR_P) $(DESTDIR)/@LIBEXEC_DIR@
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)/@LIBEXEC_DIR@ -n psm mod_psm.la
