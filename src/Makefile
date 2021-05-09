include /usr/share/dpkg/pkg-info.mk
include /usr/share/dpkg/architecture.mk

PACKAGE=libpve-access-control

BUILDDIR ?= ${PACKAGE}-${DEB_VERSION_UPSTREAM}

DESTDIR=
PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc/${PACKAGE}
MAN1DIR=${MANDIR}/man1/
BASHCOMPLDIR=${PREFIX}/share/bash-completion/completions/
ZSHCOMPLDIR=${PREFIX}/share/zsh/vendor-completions/

export PERLDIR=${PREFIX}/share/perl5
-include /usr/share/pve-doc-generator/pve-doc-generator.mk

all:

pveum.bash-completion: PVE/CLI/pveum.pm
	perl -I. -T -e "use PVE::CLI::pveum; PVE::CLI::pveum->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

pveum.zsh-completion: PVE/CLI/pveum.pm
	perl -I. -T -e "use PVE::CLI::pveum; PVE::CLI::pveum->generate_zsh_completions();" >$@.tmp
	mv $@.tmp $@

.PHONY: install
install: pveum.1 oathkeygen pveum.bash-completion pveum.zsh-completion
	install -d ${DESTDIR}${BINDIR}
	install -d ${DESTDIR}${SBINDIR}
	install -m 0755 pveum ${DESTDIR}${SBINDIR}
	install -m 0755 oathkeygen ${DESTDIR}${BINDIR}
	make -C PVE install
	install -d ${DESTDIR}/${MAN1DIR}
	install -d ${DESTDIR}/${DOCDIR}
	install -m 0644 pveum.1 ${DESTDIR}/${MAN1DIR}
	install -m 0644 -D pveum.bash-completion ${DESTDIR}${BASHCOMPLDIR}/pveum
	install -m 0644 -D pveum.zsh-completion ${DESTDIR}${ZSHCOMPLDIR}/_pveum

.PHONY: test
test:
	perl -I. ./pveum verifyapi
	perl -I. -T -e "use PVE::CLI::pveum; PVE::CLI::pveum->verify_api();"
	make -C test check

.PHONY: clean distclean
distclean: clean
clean:
	make cleanup-docgen
	find . -name '*~' -exec rm {} ';'
