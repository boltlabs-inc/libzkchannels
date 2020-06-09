#!/bin/bash

redis-cli flushdb
cargo test --release -- --ignored --nocapture
cargo test --release --package zkchannels --lib -- tests::test_unlink_and_pay_is_correct --exact --nocapture
echo "Done!"
