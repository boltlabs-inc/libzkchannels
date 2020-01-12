.PHONY: all deps mpc debug bench test mpctest mpcgotests update doc clean distclean

all:
	export RUSTFLAGS=-Awarnings
	cargo +nightly build
	cargo +nightly test
	cargo +nightly run --example zkchannels_zkproofs

mpc:
	cargo +nightly build --features mpc-bitcoin

debug:
	export RUST_BACKTRACE=1 
	cargo +nightly build
	cargo +nightly run --example zkchannels_zkproofs

release:
	cargo +nightly build --release
	cargo +nightly run --release --example zkchannels_zkproofs

bench:
	cargo +nightly bench

test:
	# runs the unit test suite
	cargo +nightly test --release #-- --nocapture

mpctest:
	cargo +nightly test --release --features mpc-bitcoin -- --nocapture
	./test_mpcwrapper.sh
	./test_channels_mpc.sh

update:
	cargo +nightly update

doc:
	# generates the documentation
	cargo +nightly doc

deps:
	make -C deps

#pythontests:
#	cargo +nightly clean
#	cargo +nightly update
#	cargo +nightly build --release
#	python py/libbolt.py
#	python py/libbolt_tests.py

#cpptests:
#	@cargo +nightly build --release
#	@g++ cpp/libbolt.cpp -L ./target/release/ -lbolt -I ./include -o cpp_test
#	@LD_LIBRARY_PATH=./target/release/ ./cpp_test
#	@rm cpp_test

mpcgotests:
	cargo +nightly build --release --features=mpc-bitcoin
	go test -v go/libzkchannels.go go/libzkchannels_test.go
	#go test go/libzkchannels.go go/libzkchannels_test.go -run Test_fullProtocol -v

#alltests:
#	cargo +nightly clean
#	cargo +nightly update
#	cargo +nightly build --release
#	cargo +nightly test --release #-- --nocapture
#	python py/libbolt.py
#	python py/libbolt_tests.py
#	go test go/libbolt.go go/libbolt_test.go

clean:
	cargo +nightly clean

distclean:
	make -C deps distclean

