# includes append to these:
SUFFIXES =
TESTS =
CLEANFILES =
DISTCLEANFILES =
bin_PROGRAMS =
noinst_HEADERS =
lib_LTLIBRARIES =
man_MANS =
noinst_LTLIBRARIES =
noinst_PROGRAMS =
include_HEADERS =
nobase_include_HEADERS =
check_PROGRAMS =
EXTRA_HEADERS =
BUILT_SOURCES =
EXTRA_DIST =
noinst_SCRIPTS =
check_SCRIPTS =
dist_noinst_SCRIPTS =
dist_doc_DATA =


#includes additional rules from aminclude.am
@INC_AMINCLUDE@
DISTCLEANFILES+= aminclude.am

exampledir = $(docdir)/example
dist_example_DATA=

ACLOCAL_AMFLAGS= -I m4


include src/include.am
include wolfmqtt/include.am
include examples/include.am
include scripts/include.am
include IDE/include.am

EXTRA_DIST+= README.md
EXTRA_DIST+= LICENSE
EXTRA_DIST+= wolfmqtt.sln
EXTRA_DIST+= wolfmqtt.vcxproj
EXTRA_DIST+= wolfmqtt.vcxproj.filters
EXTRA_DIST+= autogen.sh

TEST_EXTENSIONS=.test
TESTS += $(check_PROGRAMS)

check_SCRIPTS+= $(dist_noinst_SCRIPTS)
TESTS += $(check_SCRIPTS)

test: check

DISTCLEANFILES+= wolfmqtt-config


maintainer-clean-local:
	-rm Makefile.in
	-rm aclocal.m4
	-rm build-aux/compile
	-rm build-aux/config.guess
	-rm build-aux/config.sub
	-rm build-aux/depcomp
	-rm build-aux/install-sh
	-rm build-aux/ltmain.sh
	-rm build-aux/missing
	-rm wolfmqtt-config
	-rmdir build-aux
	-rm configure
	-rm config.log
	-rm config.status
	-rm config.in
	-rm m4/libtool.m4
	-rm m4/ltoptions.m4
	-rm m4/ltsugar.m4
	-rm m4/ltversion.m4
	-rm m4/lt~obsolete.m4
	find . -type f -name '*~' -exec rm -f '{}' \;
	-rm -f @PACKAGE@-*.tar.gz
	-rm -f @PACKAGE@-*.rpm

# !!!! first line of rule has to start with a hard (real) tab, not spaces
egs:
	$(MAKE) examples/mqttclient/mqttclient;

install-exec-local:	install-generic-config

install-generic-config:
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	$(INSTALL_SCRIPT) @GENERIC_CONFIG@ $(DESTDIR)$(bindir)

uninstall-local:
	-rm -f $(DESTDIR)$(bindir)/@GENERIC_CONFIG@

merge-clean:
	@find ./ | $(GREP) \.gcda | xargs rm -f
	@find ./ | $(GREP) \.gcno | xargs rm -f
	@find ./ | $(GREP) \.gz | xargs rm -f
	@find ./ | $(GREP) \.orig | xargs rm -f
	@find ./ | $(GREP) \.rej | xargs rm -f
	@find ./ | $(GREP) \.rpm | xargs rm -f
	@find ./ | $(GREP) \.THIS | xargs rm -f
	@find ./ | $(GREP) \.OTHER | xargs rm -f
	@find ./ | $(GREP) \.BASE | xargs rm -f
	@find ./ | $(GREP) \~$$ | xargs rm -f
