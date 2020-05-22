#!/bin/bash

redis-cli flushdb
cargo test --release -- --ignored --nocapture
