#!/bin/bash

cargo test --release --features mpc-bitcoin --lib mpcwrapper -- --nocapture
