ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = $(JNI_INCLUDES) -I$(top_srcdir) -I$(top_builddir)

JAVA_FILES = \
	src/main/java/org/opennms/protocols/icmp6/ICMPv6Packet.java \
	src/main/java/org/opennms/protocols/icmp6/ICMPv6EchoPacket.java \
	src/main/java/org/opennms/protocols/icmp6/ICMPv6EchoRequest.java \
	src/main/java/org/opennms/protocols/icmp6/ICMPv6EchoReply.java \
	src/main/java/org/opennms/protocols/icmp6/ICMPv6Socket.java

classdir=classes
VPATH += $(classdir)

JICMP_SOURCES = byteswap.h ICMPv6Socket.h ICMPv6Socket.c
JICMP_LDFLAGS = -module -avoid-version -no-undefined $(JAVA_SHREXT_COMMAND) $(NOEXECSTACK_LDFLAGS)

if WIN32
lib_LTLIBRARIES = jicmp6.la
jicmp6_la_SOURCES = $(JICMP_SOURCES)
jicmp6_la_LDFLAGS = $(JICMP_LDFLAGS)
jicmp6_la_LIBADD = -lws2_32
else
lib_LTLIBRARIES = libjicmp6.la
libjicmp6_la_SOURCES = $(JICMP_SOURCES)
libjicmp6_la_LDFLAGS = $(JICMP_LDFLAGS)
endif

TESTS_ENVIRONMENT = $(LIBTOOL) --mode=execute -dlopen $(top_builddir)/libjicmp6.la
TESTS = tests.sh
MAINTAINERCLEANFILES = aclocal.m4 config.guess config.sub configure depcomp install-sh ltmain.sh Makefile.in missing config.h.in *~ *.tar.gz
CLEANFILES = org_*.h jicmp6.jar

.PHONY: clean-local

clean-local:
	-rm -rf $(classdir) target java.built *.tar.gz

java-classes: java.built

java.built: $(JAVA_FILES)
	-mkdir -p $(classdir)
	$(JAVAC) $(JAVACFLAGS) -source 1.5 -target 1.5 -d $(classdir) $(JAVA_FILES) && touch java.built

ICMPv6Socket.c: org_opennms_protocols_icmp6_ICMPv6Socket.h

org_opennms_protocols_icmp6_ICMPv6Socket.h: java.built
	$(JAVAH) -classpath $(classdir) org.opennms.protocols.icmp6.ICMPv6Socket

jicmp6.jar: java.built
	cd $(classdir) && \
	$(JAR) cvf ../$@ *

jardir=$(datadir)/java
jar_DATA = jicmp6.jar

deploy:
	mvn deploy:deploy-file

.PHONY: deploy rpm srpm

EXTRA_DIST = ChangeLog $(JAVA_FILES) win32/icmp.h \
	tests.sh \
	tests/*.java \
	m4/* \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/dirs \
	debian/getjava \
	debian/rules \
	solaris/README \
	solaris/pkginfo* \
	solaris/Makefile \
	solaris/prototype.*

if MAKE_RPMS
rpm: @RPM_TARGET@

srpm: @SRPM_TARGET@

EXTRA_DIST += jicmp6.spec

$(RPM_TARGET): $(DISTFILES)
	${MAKE} dist
	-mkdir -p $(SRPM_DIR)
	-mkdir -p `dirname $(RPM_TARGET)`
	$(RPMBUILD_PROG) --define 'version $(VERSION)' --define 'rel $(RELEASE)' $(RPM_ARGS) $(RPM_TARBALL)
	@echo "$(RPM_TARGET) created"

$(SRPM_TARGET): $(DISTFILES)
	${MAKE} dist
	-mkdir -p $(SRPM_DIR)
	$(RPMBUILD_PROG) --define 'version $(VERSION)' --define 'rel $(RELEASE)' $(SRPM_ARGS) $(RPM_TARBALL)
	@echo "$(SRPM_TARGET) created"
endif
