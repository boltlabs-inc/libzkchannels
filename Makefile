.PHONY: all deps mpc debug bench test mpctest mpcgotest update doc clean distclean

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
	cargo +nightly build --release --features mpc-bitcoin
	cargo +nightly run --release --example zkchannels_zkproofs

bench:
	cargo +nightly bench

test:
	# runs the unit test suite
	cargo +nightly test --release 

mpctest:
	./test_mpcwrapper.sh
	./test_channels_mpc.sh
	cargo test --release --features mpc-bitcoin -- --ignored --nocapture

update:
	cargo +nightly update

doc:
	# generates the documentation
	cargo +nightly doc

deps:
	make -C deps

mpcgotest:
	cargo build --release --features=mpc-bitcoin
	./test_gowrapper.sh

clean:
	cargo +nightly clean

distclean:
	make -C deps distclean

