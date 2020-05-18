.PHONY: all deps mpc debug bench test mpctest mpcgotest update doc clean distclean

all:
	export RUSTFLAGS=-Awarnings
	cargo build
	cargo test

debug:
	export RUST_BACKTRACE=1 
	cargo build
	cargo run --example zkchannels_zkproofs

release:
	cargo build --release
	cargo run --release --example zkchannels_zkproofs

bench:
	cargo bench

test:
	cargo test --release 

mpctest:
	cargo build --release
	./test_mpcwrapper.sh
	./test_channels_mpc.sh
	redis-cli flushdb
	cargo test --release -- --ignored --nocapture

update:
	cargo update

doc:
	# generates the documentation
	cargo doc

deps:
	make -C deps

mpcgotest:
	cargo build --release
	./test_gowrapper.sh

clean:
	cargo clean

distclean:
	make -C deps distclean

