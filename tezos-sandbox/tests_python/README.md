# Testing contracts in Tezos sandbox

1. copy the target dir to `/path/to/tezos/tests_python/`

        cp working_pssigs/ /path/to/tezos/tests_python/

2. run a sandbox test as follows (for example, pssigs with a mock zkchannel contract):

        ./working_pssigs/run_test.sh working_pssigs/test_zkchannel_pssig.py working_pssigs/cust_close.json
