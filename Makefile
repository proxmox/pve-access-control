RELEASE=2.0

VERSION=1.0
PACKAGE=libpve-access-control
PKGREL=1

DESTDIR=
PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc
MAN1DIR=${MANDIR}/man1/
export PERLDIR=${PREFIX}/share/perl5

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
DEB=${PACKAGE}_${VERSION}-${PKGREL}_${ARCH}.deb

all: ${DEB}

.PHONY: dinstall
dinstall: deb
	dpkg -i ${DEB}

.PHONY: install
install:
	install -d ${DESTDIR}${BINDIR}
	install -d ${DESTDIR}${SBINDIR}
	install -m 0755 pveum ${DESTDIR}${SBINDIR}
	make -C PVE install
	perl -I. ./pveum verifyapi 
	install -d ${DESTDIR}/usr/share/man/man1
	pod2man -n pveum -s 1 -r "proxmox 2.0" -c "Proxmox Documentation" <pveum | gzip -9 > ${DESTDIR}/usr/share/man/man1/pveum.1.gz

.PHONY: deb ${DEB}
deb ${DEB}:
	rm -rf debian
	mkdir debian
	make DESTDIR=${CURDIR}/debian install
	install -d -m 0755 debian/DEBIAN
	sed -e s/@@VERSION@@/${VERSION}/ -e s/@@PKGRELEASE@@/${PKGREL}/ -e s/@@ARCH@@/${ARCH}/ <control.in >debian/DEBIAN/control
	install -D -m 0644 copyright debian/${DOCDIR}/${PACKAGE}/copyright
	install -m 0644 changelog.Debian debian/${DOCDIR}/${PACKAGE}/
	gzip -9 debian/${DOCDIR}/${PACKAGE}/changelog.Debian
	install -m 0644 ChangeLog debian/${DOCDIR}/${PACKAGE}/changelog
	gzip -9 debian/${DOCDIR}/${PACKAGE}/changelog
	dpkg-deb --build debian	
	mv debian.deb ${DEB}
	#rm -rf debian
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
	rm -rf debian *~ *.deb ${PACKAGE}-*.tar.gz
	find . -name '*~' -exec rm {} ';'

.PHONY: distclean
distclean: clean
