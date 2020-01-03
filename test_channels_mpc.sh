#!/bin/bash

cargo +nightly test --release --features mpc-bitcoin --lib channels_mpc -- --nocapture
