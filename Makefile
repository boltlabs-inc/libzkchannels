.PHONY: all debug bench test update doc clean

all:
	export RUSTFLAGS=-Awarnings
	cargo +nightly build
	cargo +nightly test
	cargo +nightly run --example zkchannels_test

debug:
	export RUST_BACKTRACE=1 
	cargo +nightly build
	cargo +nightly run --example zkchannels_test

release:
	cargo +nightly build --release
	cargo +nightly run --release --example zkchannels_test

bench:
	cargo +nightly bench

test:
	# runs the unit test suite
	cargo +nightly test --release #-- --nocapture

update:
	cargo +nightly update

doc:
	# generates the documentation
	cargo +nightly doc

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

#gotests:
#	cargo +nightly build --release
#	go test go/libbolt.go go/libbolt_test.go

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
