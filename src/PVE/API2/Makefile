
API2_SOURCES= 		 	\
	AccessControl.pm 	\
	Domains.pm	 	\
	RealmSync.pm	 	\
	ACL.pm		 	\
	Role.pm		 	\
	Group.pm	 	\
	User.pm			\
	TFA.pm			\
	OpenId.pm

SUBDIRS=AccessControl

.PHONY: install
install:
	for i in $(API2_SOURCES); do install -D -m 0644 $$i $(DESTDIR)$(PERLDIR)/PVE/API2/$$i; done
	set -e && for i in $(SUBDIRS); do $(MAKE) -C $$i $@; done
