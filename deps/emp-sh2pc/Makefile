.PHONY: all clean

VERSION=0.1
TMP=$(shell mktemp -d build-XXXX)

all: package emp-sh2pc-$(VERSION)/.built

emp-sh2pc-$(VERSION)/.built: emp-sh2pc-${VERSION}
	cd $(TMP); \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$(ZK_DEPS_INSTALL) ../$<; \
	make && \
	make install && \
	cp bin/* $(ZK_DEPS_INSTALL)/bin/ && \
	touch ../$@

emp-sh2pc-$(VERSION): emp-sh2pc-$(VERSION).tar.gz
	tar xf $^

package:
	./download_emp_sh2pc.sh emp-sh2pc-$(VERSION)

clean:
	rm -rf emp-sh2pc-$(VERSION) build-*

distclean:
	rm -rf emp-sh2pc-$(VERSION)* build-*
