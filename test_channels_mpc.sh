#!/bin/bash

cargo test --release --features mpc-bitcoin --lib channels_mpc -- --nocapture
