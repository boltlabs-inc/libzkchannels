import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox

BAKE_ARGS = ['--minimal-timestamp']

def form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal0, merch_bal0, rev_lock, self_delay):

    return '(Pair (Pair (Pair \"{chan_id}\" (Pair \"{cust_addr}\" 0)) (Pair {cust_bal0} (Pair \"{cust_pk}\" "0"))) (Pair (Pair \"{merch_addr}\" (Pair 0 {merch_bal0})) (Pair (Pair \"{merch_pk}\" {rev_lock}) (Pair {self_delay} "awaitingFunding"))))'.format(chan_id=chan_id, cust_addr=cust_addr, cust_pk=cust_pk, merch_addr=merch_addr, merch_pk=merch_pk, cust_bal0=cust_bal0, merch_bal0=merch_bal0, self_delay=self_delay, rev_lock=rev_lock)

def form_closing_state(chan_id, cust_addr, merch_addr, cust_bal_mt, merch_bal_mt, new_rev_lock):

    return '(Pair (Pair \"{chan_id}\" (Pair \"{cust_addr}\" \"{merch_addr}\")) (Pair {cust_bal_mt} (Pair {merch_bal_mt} {rev_lock})))'.format(chan_id=chan_id, cust_addr=cust_addr, merch_addr=merch_addr, cust_bal_mt=cust_bal_mt, merch_bal_mt=merch_bal_mt, rev_lock=new_rev_lock)

def form_mutual_state(chan_id, cust_addr, merch_addr, cust_bal_mt, merch_bal_mt):

    return '(Pair (Pair \"{chan_id}\" \"{cust_addr}\") (Pair \"{merch_addr}\" (Pair {cust_bal_mt} {merch_bal_mt} )))'.format(chan_id=chan_id, cust_addr=cust_addr, merch_addr=merch_addr, cust_bal_mt=cust_bal_mt, merch_bal_mt=merch_bal_mt)


def scenario_basic_call():
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))

        # Launch a baker associated to node 0, baking on behalf of delegate
        # baker5
        sandbox.add_baker(0, 'baker5', proto=constants.ALPHA_DAEMON)
        # Wait for second node to update its protocol to alpha, if not
        # it may not know yet the `wait_for_inclusion` operation which is
        # protocol specific

        # (Originally this sleep was 15 seconds)
        time.sleep(5)

        # Originate the zkchannel contract with hard coded values (without any funding)

        # Define initial storage and channel variables
        contract_external = "external_contract.tz"

        contract_external_name = "external_contract"
        burncap = "9"
        args = ["--init", "Unit", "--burn-cap", burncap]
        sandbox.client(0).originate(contract_external_name, 0, "bootstrap1", contract_external, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)


        contract_main = "main_contract.tz"

        contract_main_name = "main_contract"
        burncap = "9"
        args = ["--init", "False", "--burn-cap", burncap]
        sandbox.client(0).originate(contract_main_name, 0, "bootstrap1", contract_main, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        external_contract_addr = sandbox.client(0).get_contract_address(contract_external_name)

        sandbox.client(0).get_contract_entrypoint_type("run", contract_main_name)

        amt = 0
        storage = '(Pair "{addr}" 23)'.format(addr=external_contract_addr)
        sandbox.client(0).transfer(amt, 'bootstrap1', contract_main_name,
                                   ['--entrypoint', 'run',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        sandbox.client(0).bake('baker5', BAKE_ARGS)


if __name__ == "__main__":
    scenario_basic_call()
