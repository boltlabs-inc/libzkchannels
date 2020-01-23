FROM rust:1.37

RUN USER=root cargo new --bin libzkchannels
WORKDIR /libzkchannels

# copy over your manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# copy src/deps/build
COPY ./build.rs ./build.rs
COPY ./cbindgen.toml ./cbindgen.toml
COPY ./env ./env
COPY ./src ./src
COPY ./examples ./examples
COPY ./deps ./deps
COPY Makefile Makefile
COPY ./go ./go
COPY ./test_emp.sh ./test_emp.sh
COPY ./test_mpcwrapper.sh ./test_mpcwrapper.sh
COPY ./test_channels_mpc.sh ./test_channels_mpc.sh

RUN . ./env && make deps
RUN . ./env && cargo build --release --features mpc-bitcoin
RUN . ./env && make mcptest

# binary "/libzkchannels/target/release/zkchannels_mpc -h"
CMD ["/bin/bash"]
