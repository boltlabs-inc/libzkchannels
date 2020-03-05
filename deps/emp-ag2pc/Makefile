.PHONY: all clean local

VERSION=0.1
TMP=$(shell mktemp -d build-XXXX)

all: package emp-ag2pc-$(VERSION)/.built

emp-ag2pc-$(VERSION)/.built: emp-ag2pc-${VERSION}
	cd $(TMP); \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$(ZK_DEPS_INSTALL) ../$<; \
	make && \
	make install && \
	cp bin/* $(ZK_DEPS_INSTALL)/bin/ && \
	touch ../$@ && \
	../fix_rpath_osx.sh libtokenm-utils

emp-ag2pc-$(VERSION): emp-ag2pc-$(VERSION).tar.gz
	tar xf $^

local: emp-ag2pc-$(VERSION).git
	./download_emp_ag2pc.sh emp-ag2pc-$(VERSION) local
	make emp-ag2pc-$(VERSION)
	make emp-ag2pc-$(VERSION)/.built

package: checkenv
	./download_emp_ag2pc.sh emp-ag2pc-$(VERSION)

clean:
	rm -rf emp-ag2pc-$(VERSION) build-*

distclean:
	rm -rf emp-ag2pc-$(VERSION)* build-*

checkenv:
ifeq ($(origin ZK_DEPS_INSTALL), undefined)
	$(info "ZK_DEPS_INSTALL not set. Try in root: . ./env")
	exit 1
endif
