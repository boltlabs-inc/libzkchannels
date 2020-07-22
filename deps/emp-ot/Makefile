.PHONY: all clean local

VERSION=0.1
TMP=$(shell mktemp -d build-XXXX)

all: package emp-ot-$(VERSION)/.built

emp-ot-$(VERSION)/.built: emp-ot-${VERSION}
	cd $(TMP); \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$(ZK_DEPS_INSTALL) ../$<; \
	make && \
	make install && \
	touch ../$@

emp-ot-$(VERSION): emp-ot-$(VERSION).tar.gz
	tar xf $^

local: emp-ot-$(VERSION).git
	./download_emp_ot.sh emp-ot-$(VERSION) local
	make emp-ot-$(VERSION)
	make emp-ot-$(VERSION)/.built

package: checkenv
	./download_emp_ot.sh emp-ot-$(VERSION)

clean:
	rm -rf emp-ot-$(VERSION) build-*

distclean:
	rm -rf emp-ot-$(VERSION)* build-*

checkenv:
ifeq ($(origin ZK_DEPS_INSTALL), undefined)
	$(info "ZK_DEPS_INSTALL not set. Try in root: . ./env")
	exit 1
endif

