.PHONY: all clean

VERSION := 1.9

all: package time-$(VERSION)/.built

package: checkenv
	./download_time.sh $(VERSION)

time-$(VERSION)/.built: time-$(VERSION)
	cd $<; \
	./configure --prefix=${ZK_DEPS_INSTALL} && \
	make && \
	make install && \
	touch .built

time-$(VERSION): time-$(VERSION).tar.gz
	tar zxvf $^

clean:
	rm -rf time-$(VERSION)

distclean:
	rm -rf time-$(VERSION)*

checkenv:
ifeq ($(origin ZK_DEPS_INSTALL), undefined)
	$(info "ZK_DEPS_INSTALL not set. Try in root: . ./env")
	exit 1
endif

