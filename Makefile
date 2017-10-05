VERSION=5.0
PACKAGE=libpve-access-control
PKGREL=7

DESTDIR=
PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc/${PACKAGE}
MAN1DIR=${MANDIR}/man1/
BASHCOMPLDIR=${PREFIX}/share/bash-completion/completions/

export PERLDIR=${PREFIX}/share/perl5

export SOURCE_DATE_EPOCH ?= $(shell dpkg-parsechangelog -STimestamp)

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
GITVERSION:=$(shell cat .git/refs/heads/master)

DEB=${PACKAGE}_${VERSION}-${PKGREL}_${ARCH}.deb

# this requires package pve-doc-generator
export NOVIEW=1
include /usr/share/pve-doc-generator/pve-doc-generator.mk

all:

.PHONY: dinstall
dinstall: deb
	dpkg -i ${DEB}

pveum.bash-completion: PVE/CLI/pveum.pm
	perl -I. -T -e "use PVE::CLI::pveum; PVE::CLI::pveum->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

.PHONY: install
install: pveum.1 oathkeygen pveum.bash-completion
	install -d ${DESTDIR}${BINDIR}
	install -d ${DESTDIR}${SBINDIR}
	install -m 0755 pveum ${DESTDIR}${SBINDIR}
	install -m 0755 oathkeygen ${DESTDIR}${BINDIR}
	make -C PVE install
	install -d ${DESTDIR}/${MAN1DIR}
	install -d ${DESTDIR}/${DOCDIR}
	install -m 0644 pveum.1 ${DESTDIR}/${MAN1DIR}
	gzip -9 -n ${DESTDIR}/${MAN1DIR}/pveum.1
	install -m 0644 -D pveum.bash-completion ${DESTDIR}${BASHCOMPLDIR}/pveum

.PHONY: test
test:
	perl -I. ./pveum verifyapi
	perl -I. -T -e "use PVE::CLI::pveum; PVE::CLI::pveum->verify_api();"

.PHONY: deb
deb: ${DEB}
${DEB}:
	rm -rf build
	rsync -a * build
	echo "git clone git://git.proxmox.com/git/pve-access-control.git\\ngit checkout ${GITVERSION}" >build/debian/SOURCE
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEB}

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh repoman@repo.proxmox.com -- upload --product pve --dist stretch --arch ${ARCH}

.PHONY: clean
clean:
	make cleanup-docgen
	rm -rf build *.deb *.buildinfo *.changes
	find . -name '*~' -exec rm {} ';'

.PHONY: distclean
distclean: clean
