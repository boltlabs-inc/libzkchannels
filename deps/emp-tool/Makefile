.PHONY: all clean

VERSION=0.1
TMP=$(shell mktemp -d build-XXXX)

all: package emp-tool-$(VERSION)/.built

emp-tool-$(VERSION)/.built: emp-tool-${VERSION}
	cd $(TMP); \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$(ZK_DEPS_INSTALL) ../$<; \
	make && \
	make install && \
	touch ../$@

emp-tool-$(VERSION): emp-tool-$(VERSION).tar.gz
	tar xf $^

package:
	./download_emp_tool.sh emp-tool-$(VERSION)

clean:
	rm -rf emp-tool-$(VERSION) build-*

distclean:
	rm -rf emp-tool-$(VERSION)* build-*
