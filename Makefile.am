## Process this with automake to create Makefile.in

AUTOMAKE_OPTIONS = foreign

SUBDIRS = src conf templates scripts

install-data-local:
	mkdir -p -m 777 $(DESTDIR)$(NTRIPCASTER_LOGDIR_INST)
	mkdir -p -m 777 $(DESTDIR)$(NTRIPCASTER_VARDIR_INST)

EXTRA_DIST = README CHANGES INSTALL COPYING FAQ ntripcaster.spec NtripCaster.pdf
