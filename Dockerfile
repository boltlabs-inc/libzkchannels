FROM rust:1.42

RUN apt-get update && apt-get -y install sudo systemd
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
COPY ./test_emp.sh ./test_emp.sh
COPY ./setup_redis.sh ./setup_redis.sh
COPY ./test_mpcwrapper.sh ./test_mpcwrapper.sh
COPY ./test_channels_mpc.sh ./test_channels_mpc.sh

RUN . ./env && make deps
RUN ./setup_redis.sh
RUN . ./env && cargo build --release
RUN . ./env && make mpctest

# binary "/libzkchannels/target/release/zkchannels_mpc -h"
CMD ["/bin/bash"]
