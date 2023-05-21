
API2_SOURCES= 		 	\
	AccessControl.pm 	\
	Domains.pm	 	\
	ACL.pm		 	\
	Role.pm		 	\
	Group.pm	 	\
	User.pm			\
	TFA.pm			\
	OpenId.pm

.PHONY: install
install:
	for i in $(API2_SOURCES); do install -D -m 0644 $$i $(DESTDIR)$(PERLDIR)/PVE/API2/$$i; done
