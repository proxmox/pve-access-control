include /usr/share/dpkg/pkg-info.mk
include /usr/share/dpkg/architecture.mk

PACKAGE=libpve-access-control

DEB=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}_all.deb
DSC=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}.dsc

BUILDDIR ?= ${PACKAGE}-${DEB_VERSION_UPSTREAM}

GITVERSION:=$(shell git rev-parse HEAD)

all:

.PHONY: dinstall
dinstall: deb
	dpkg -i ${DEB}

${BUILDDIR}:
	rm -rf ${BUILDDIR}
	cp -a src ${BUILDDIR}
	cp -a debian ${BUILDDIR}/
	echo "git clone git://git.proxmox.com/git/pve-access-control.git\\ngit checkout ${GITVERSION}" > ${BUILDDIR}/debian/SOURCE

.PHONY: deb
deb: ${DEB}
${DEB}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -b -us -uc
	lintian ${DEB}

.PHONY: dsc
dsc: ${DSC}
${DSC}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -S -us -uc -d
	lintian ${DSC}

.PHONY: upload
upload: ${DEB}
	tar cf - ${DEB} | ssh repoman@repo.proxmox.com -- upload --product pve --dist buster --arch ${DEB_BUILD_ARCH}

.PHONY: clean
clean:
	rm -rf ${BUILDDIR} *.deb *.buildinfo *.changes ${PACKAGE}*.tar.gz *.dsc
	find . -name '*~' -exec rm {} ';'

.PHONY: distclean
distclean: clean
