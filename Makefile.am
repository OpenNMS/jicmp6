ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = $(JNI_INCLUDES) -I$(top_srcdir) -I$(top_builddir)

CLASS_FILES = org/opennms/protocols/icmp/AddressMaskReply.class \
	org/opennms/protocols/icmp/AddressMaskRequest.class \
	org/opennms/protocols/icmp/ErrorMessage.class \
	org/opennms/protocols/icmp/ICMPEchoPacket.class \
	org/opennms/protocols/icmp/ICMPHeader.class \
	org/opennms/protocols/icmp/IcmpSocket.class \
	org/opennms/protocols/icmp/TimestampReply.class \
	org/opennms/protocols/icmp/TimestampRequest.class \
	org/opennms/protocols/ip/IPHeader.class \
	org/opennms/protocols/ip/IPv4Address.class \
	org/opennms/protocols/ip/OC16ChecksumProducer.class \
	org/opennms/protocols/ip/UnknownIPVersionException.class

JAVA_FILES = org/opennms/protocols/icmp/AddressMaskReply.java \
	org/opennms/protocols/icmp/AddressMaskRequest.java \
	org/opennms/protocols/icmp/ErrorMessage.java \
	org/opennms/protocols/icmp/ICMPEchoPacket.java \
	org/opennms/protocols/icmp/ICMPHeader.java \
	org/opennms/protocols/icmp/IcmpSocket.java \
	org/opennms/protocols/icmp/TimestampReply.java \
	org/opennms/protocols/icmp/TimestampRequest.java \
	org/opennms/protocols/ip/IPHeader.java \
	org/opennms/protocols/ip/IPv4Address.java \
	org/opennms/protocols/ip/OC16ChecksumProducer.java \
	org/opennms/protocols/ip/UnknownIPVersionException.java

classdir=classes
VPATH += $(classdir)

JICMP_SOURCES = byteswap.h IcmpSocket.h IcmpSocket.c
JICMP_LDFLAGS = -module -avoid-version -no-undefined $(JAVA_SHREXT_COMMAND)

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

IcmpSocket.c: org_opennms_protocols_icmp_IcmpSocket.h

org_opennms_protocols_icmp_IcmpSocket.h: java.built
	$(JAVAH) -classpath $(classdir) org.opennms.protocols.icmp.IcmpSocket

jicmp6.jar: java.built
	cd $(classdir) && \
	$(JAR) cvf ../$@ *

jardir=$(datadir)/java
jar_DATA = jicmp6.jar

deploy:
	mvn deploy:deploy-file

.PHONY: deploy rpm

EXTRA_DIST = ChangeLog solaris/pkginfo $(JAVA_FILES) win32/icmp.h CMakeLists.txt config.h.cmake \
	tests.sh \
	tests/*.java \
	m4/* \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/dirs \
	debian/getjava \
	debian/rules

if MAKE_RPMS
rpm: @RPM_TARGET@

EXTRA_DIST += jicmp6.spec

$(RPM_TARGET): $(DISTFILES)
	${MAKE} dist
	-mkdir -p $(RPM_DIR)/SRPMS
	-mkdir -p `dirname $(RPM_TARGET)`
	$(RPMBUILD_PROG) $(RPM_ARGS) $(RPM_TARBALL)
	@echo "$(RPM_TARGET) created"
endif
