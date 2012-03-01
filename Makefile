RELEASE=2.0

VERSION=1.0
PACKAGE=libpve-access-control
PKGREL=17

DESTDIR=
PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc/${PACKAGE}
PODDIR=${DOCDIR}/pod
MAN1DIR=${MANDIR}/man1/
export PERLDIR=${PREFIX}/share/perl5

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
DEB=${PACKAGE}_${VERSION}-${PKGREL}_${ARCH}.deb

all: ${DEB}

.PHONY: dinstall
dinstall: deb
	dpkg -i ${DEB}

%.1.gz: %.1.pod
	rm -f $@
	cat $<|pod2man -n $* -s 1 -r ${VERSION} -c "Proxmox Documentation"|gzip -c9 >$@.tmp
	mv $@.tmp $@

pveum.1.pod: pveum
	perl -I. ./pveum printmanpod >$@.tmp
	mv $@.tmp $@

.PHONY: install
install: pveum.1.pod pveum.1.gz
	install -d ${DESTDIR}${BINDIR}
	install -d ${DESTDIR}${SBINDIR}
	install -m 0755 pveum ${DESTDIR}${SBINDIR}
	make -C PVE install
	perl -I. ./pveum verifyapi 
	install -d ${DESTDIR}/usr/share/man/man1
	install -d ${DESTDIR}${PODDIR}
	install -m 0644 pveum.1.gz ${DESTDIR}/usr/share/man/man1/
	install -m 0644 pveum.1.pod ${DESTDIR}/${PODDIR}

.PHONY: deb ${DEB}
deb ${DEB}:
	rm -rf build
	mkdir build
	make DESTDIR=`pwd`/build install
	install -d -m 0755 build/DEBIAN
	sed -e s/@@VERSION@@/${VERSION}/ -e s/@@PKGRELEASE@@/${PKGREL}/ -e s/@@ARCH@@/${ARCH}/ <control.in >build/DEBIAN/control
	install -D -m 0644 copyright build/${DOCDIR}/copyright
	install -m 0644 changelog.Debian build/${DOCDIR}/
	gzip -9 build/${DOCDIR}/changelog.Debian
	dpkg-deb --build build	
	mv build.deb ${DEB}
	#rm -rf build
	lintian ${DEB}

.PHONY: upload
upload: ${DEB}
	umount /pve/${RELEASE}; mount /pve/${RELEASE} -o rw 
	mkdir -p /pve/${RELEASE}/extra
	rm -f /pve/${RELEASE}/extra/${PACKAGE}_*.deb
	rm -f /pve/${RELEASE}/extra/Packages*
	cp ${DEB} /pve/${RELEASE}/extra
	cd /pve/${RELEASE}/extra; dpkg-scanpackages . /dev/null > Packages; gzip -9c Packages > Packages.gz
	umount /pve/${RELEASE}; mount /pve/${RELEASE} -o ro

.PHONY: clean
clean: 	
	rm -rf build *~ *.deb ${PACKAGE}-*.tar.gz pveum.1.pod pveum.1.gz
	find . -name '*~' -exec rm {} ';'

.PHONY: distclean
distclean: clean
