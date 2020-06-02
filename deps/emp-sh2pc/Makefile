.PHONY: all clean local

VERSION=0.1
TMP=$(shell mktemp -d build-XXXX)

all: package emp-sh2pc-$(VERSION)/.built

emp-sh2pc-$(VERSION)/.built: emp-sh2pc-${VERSION}
	cd $(TMP); \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$(ZK_DEPS_INSTALL) ../$<; \
	make && \
	make install && \
	cp bin/* $(ZK_DEPS_INSTALL)/bin/ && \
	touch ../$@ && \
	../fix_rpath_osx.sh libtoken-utils && \
	../../root/bin/generate-circuit && \
	cp tokens.circuit.txt $(ZK_DEPS_INSTALL)/include/emp-tool/circuits/files/ && \
	chmod 640 $(ZK_DEPS_INSTALL)/include/emp-tool/circuits/files/tokens.circuit.txt

emp-sh2pc-$(VERSION): emp-sh2pc-$(VERSION).tar.gz
	tar xf $^

local: emp-sh2pc-$(VERSION).git
	./download_emp_sh2pc.sh emp-sh2pc-$(VERSION) local
	make emp-sh2pc-$(VERSION)
	make emp-sh2pc-$(VERSION)/.built

package: checkenv
	./download_emp_sh2pc.sh emp-sh2pc-$(VERSION)

clean:
	rm -rf emp-sh2pc-$(VERSION) build-*

distclean:
	rm -rf emp-sh2pc-$(VERSION)* build-*

checkenv:
ifeq ($(origin ZK_DEPS_INSTALL), undefined)
	$(info "ZK_DEPS_INSTALL not set. Try in root: . ./env")
	exit 1
endif
