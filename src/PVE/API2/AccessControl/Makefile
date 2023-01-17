API2_SOURCES= 	\
	RealmSync.pm	\

.PHONY: install
install:
	for i in ${API2_SOURCES}; do install -D -m 0644 $$i ${DESTDIR}${PERLDIR}/PVE/API2/AccessControl/$$i; done
