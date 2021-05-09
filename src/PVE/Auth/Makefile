
AUTH_SOURCES= 		 	\
	Plugin.pm 		\
	PVE.pm		 	\
	PAM.pm		 	\
	AD.pm		 	\
	LDAP.pm

.PHONY: install
install:
	for i in ${AUTH_SOURCES}; do install -D -m 0644 $$i ${DESTDIR}${PERLDIR}/PVE/Auth/$$i; done
