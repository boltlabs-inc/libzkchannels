#!/bin/bash

redis-cli flushdb
cargo test --release --package zkchannels --lib -- test_mpc::tests::test_channel_activated_correctly --exact --nocapture --ignored
cargo test --release --package zkchannels --lib -- test_mpc::tests::test_unlink_and_pay_is_correct --exact --nocapture --ignored
cargo test --release --package zkchannels --lib -- test_mpc::tests::test_unlink_fail_as_expected --exact --nocapture --ignored
echo "Done!"
