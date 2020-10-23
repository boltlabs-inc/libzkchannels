# Testing contracts in Tezos sandbox

1. Copy the target from this folder to `/path/to/tezos/tests_python/`

        cp -r working_pssigs/ /path/to/tezos/tests_python/

2. From your `tezos/tests_python/` directory, run a sandbox test as follows (for example, pssigs with a zkchannel contract):

        ./working_pssigs/run_test.sh working_pssigs/test_zkchannel_pssig.py working_pssigs/cust_close.json
