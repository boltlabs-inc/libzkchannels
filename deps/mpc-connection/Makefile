.PHONY: all clean checkenv

VERSION=0.1
TMP=$(shell mktemp -d build-XXXX)

all: mpc-connection-$(VERSION)/.built

mpc-connection-$(VERSION)/.built:
	go build -buildmode=c-shared -o $(TMP)/libgo_io_channel.dylib go_io_channel.go && \
	cp $(TMP)/libgo_io_channel.dylib $(ZK_DEPS_INSTALL)/lib/libgo_io_channel.dylib && \
	cp $(TMP)/libgo_io_channel.h $(ZK_DEPS_INSTALL)/include/libgo_io_channel.h && \
	../fix_rpath_osx.sh libgo_io_channel

clean:
	rm -rf mpc-connection-$(VERSION) build-*

distclean:
	rm -rf mpc-connection-$(VERSION)* build-*

checkenv:
ifeq ($(origin ZK_DEPS_INSTALL), undefined)
	$(info "ZK_DEPS_INSTALL not set. Try in root: . ./env")
	exit 1
endif