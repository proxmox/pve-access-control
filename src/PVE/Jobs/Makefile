SOURCES=RealmSync.pm

.PHONY: install
install: ${SOURCES}
	install -d -m 0755 ${DESTDIR}${PERLDIR}/PVE/Jobs
	for i in ${SOURCES}; do install -D -m 0644 $$i ${DESTDIR}${PERLDIR}/PVE/Jobs/$$i; done
