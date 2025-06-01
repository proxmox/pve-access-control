include /usr/share/dpkg/default.mk

PACKAGE=libpve-access-control

DEB=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION)_all.deb
DSC=$(PACKAGE)_$(DEB_VERSION_UPSTREAM_REVISION).dsc

BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION_UPSTREAM)

GITVERSION:=$(shell git rev-parse HEAD)

all:

.PHONY: dinstall
dinstall: deb
	dpkg -i $(DEB)

.PHONY: tidy
tidy:
	git ls-files ':*.p[ml]'| xargs -n4 -P0 proxmox-perltidy

$(BUILDDIR):
	rm -rf $(BUILDDIR)
	cp -a src $(BUILDDIR)
	cp -a debian $(BUILDDIR)/
	echo "git clone git://git.proxmox.com/git/pve-access-control.git\\ngit checkout $(GITVERSION)" > $(BUILDDIR)/debian/SOURCE

.PHONY: deb
deb: $(DEB)
$(DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEB)

.PHONY: dsc
dsc: $(DSC)
$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -S -us -uc -d
	lintian $(DSC)

sbuild: $(DSC)
	sbuild $(DSC)

.PHONY: upload
upload: UPLOAD_DIST ?= $(DEB_DISTRIBUTION)
upload: $(DEB)
	tar cf - $(DEB) | ssh repoman@repo.proxmox.com -- upload --product pve --dist $(UPLOAD_DIST)

.PHONY: clean distclean
distclean: clean
clean:
	rm -rf $(PACKAGE)-[0-9]*/
	rm -f *.dsc *.deb *.buildinfo *.build *.changes $(PACKAGE)*.tar.*
