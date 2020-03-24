#!/bin/bash

cargo +nightly test --release --lib database -- --nocapture
