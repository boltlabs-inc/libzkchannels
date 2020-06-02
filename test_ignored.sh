#!/bin/bash

redis-cli flushdb
cargo test --release -- --ignored --nocapture
cargo test --package zkchannels --lib -- tests::test_customer_activated_and_unlinked_correctly --exact --nocapture &
cargo test --package zkchannels --lib -- tests::test_merchant_activated_and_unlinked_correctly --exact --nocapture &
wait
echo "Done!"
