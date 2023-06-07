SOURCES = \
	RealmSync.pm \

.PHONY: install
install:
	for i in $(SOURCES); do install -D -m 0644 $$i $(DESTDIR)$(PERLDIR)/PVE/API2/Jobs/$$i; done
