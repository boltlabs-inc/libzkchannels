.PHONY: all clean local

VERSION=0.1
TMP=$(shell mktemp -d build-XXXX)

all: package update-state-$(VERSION)/.built

update-state-$(VERSION)/.built: update-state-${VERSION}
	cd $(TMP); \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$(ZK_DEPS_INSTALL) ../$<; \
	make && \
	make install && \
	cp bin/* $(ZK_DEPS_INSTALL)/bin/ && \
	touch ../$@ && \
	../fix_rpath_osx.sh libtoken-utils && \
	../fix_rpath_osx.sh libtokenm-utils && \
	../fix_rpath_osx.sh libtest-e2e && \
	../../root/bin/generate-circuit && \
	cp tokens.circuit.txt $(ZK_DEPS_INSTALL)/include/emp-tool/circuits/files/ && \
	chmod 640 $(ZK_DEPS_INSTALL)/include/emp-tool/circuits/files/tokens.circuit.txt

update-state-$(VERSION): update-state-$(VERSION).tar.gz
	tar xf $^

local: update-state-$(VERSION).git
	./download_update_state.sh update-state-$(VERSION) local
	make update-state-$(VERSION)
	make update-state-$(VERSION)/.built

package: checkenv
	./download_update_state.sh update-state-$(VERSION)

clean:
	rm -rf update-state-$(VERSION) build-*

distclean:
	rm -rf update-state-$(VERSION)* build-*

checkenv:
ifeq ($(origin ZK_DEPS_INSTALL), undefined)
	$(info "ZK_DEPS_INSTALL not set. Try in root: . ./env")
	exit 1
endif
