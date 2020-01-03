#!/bin/bash

cargo +nightly test --release --features mpc-bitcoin --lib mpcwrapper -- --nocapture
