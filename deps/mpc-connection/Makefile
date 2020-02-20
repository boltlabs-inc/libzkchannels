
all:
go build -buildmode=c-shared go_io_channel.go && \
rm go_io_channel && \
cp go_io_channel.h $(ZK_DEPS_INSTALL)/include/libgo_io_channel.h

checkenv:
ifeq ($(origin ZK_DEPS_INSTALL), undefined)
	$(info "ZK_DEPS_INSTALL not set. Try in root: . ./env")
	exit 1
endif