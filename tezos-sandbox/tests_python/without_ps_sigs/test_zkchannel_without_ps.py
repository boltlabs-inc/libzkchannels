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


def scenario_reclaim_funding():
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'baker5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # Define initial storage and channel variables
        contract = "zkchannel_without_ps.tz"

        contract_name = "mychannel"
        chan_id = "randomchanid"
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Add customer's funds
        sandbox.client(0).transfer(cust_bal, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Add customer withdraws funding before channel is opened
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'reclaimFunding',
                                    '--burn-cap', burncap])

        
def scenario_merch_close():
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'baker5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # Define initial storage and channel variables
        contract = "zkchannel_without_ps.tz"

        contract_name = "mychannel"
        chan_id = "randomchanid"
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Add customer's funds
        sandbox.client(0).transfer(cust_bal, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        # Add merchant's funds
        sandbox.client(0).transfer(merch_bal, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Merchant initiates merch close
        sandbox.client(0).transfer(0, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'merchClose',
                                    '--burn-cap', burncap])

        # Each baked block increments the timestamp by 2 seconds. With a 
        # self_delay of 3 seconds, the customer will be able to claim their
        # balance.
        sandbox.client(0).bake('baker5', BAKE_ARGS)
        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Custer claims their balance with custClaim
        sandbox.client(0).transfer(0, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'merchClaim',
                                    '--burn-cap', burncap])
        
        
def scenario_cust_close():
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'baker5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # Define initial storage and channel variables
        contract = "zkchannel_without_ps.tz"

        contract_name = "mychannel"
        chan_id = "randomchanid"
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Add customer's funds
        sandbox.client(0).transfer(cust_bal, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        # Add merchant's funds
        sandbox.client(0).transfer(merch_bal, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Merchant initiates merch close
        sandbox.client(0).transfer(0, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'merchClose',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # A final payment happens - Merchant signs off on chanID, balances,
        # revlock (and for now addresses, although that may change)
        new_cust_bal_mt = 1 * 1000000
        new_merch_bal_mt = 29 * 1000000
        # # secret_final = 0x123456789ccc
        rev_lock_final = "0x90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729"
        
        # Merch signs off on custState
        closing_state = form_closing_state(chan_id, cust_addr, merch_addr, new_cust_bal_mt, new_merch_bal_mt, rev_lock_final)
        cust_close_type = 'pair (pair string (pair address address)) (pair mutez (pair mutez bytes))'
        packed = sandbox.client(0).pack(closing_state, cust_close_type)
        merch_sig = sandbox.client(0).sign_bytes_of_string(packed, "bootstrap2")

        # Customer broadcasts custClose with the merchant's signature
        storage = '(Pair (Pair \"{merch_sig}\" {cust_bal_mt}) (Pair {merch_bal_mt} {new_rev_lock}))'.format(merch_sig=merch_sig, cust_bal_mt=new_cust_bal_mt, merch_bal_mt=new_merch_bal_mt, new_rev_lock=rev_lock_final)
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        # Each baked block increments the timestamp by 2 seconds. With a 
        # self_delay of 3 seconds, the customer will be able to claim their
        # balance.
        sandbox.client(0).bake('baker5', BAKE_ARGS)
        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Custer claims their balance with custClaim
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClaim',
                                    '--burn-cap', burncap])
        
def scenario_mutual_close():
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'baker5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # Define initial storage and channel variables
        contract = "zkchannel_without_ps.tz"

        contract_name = "mychannel"
        chan_id = "randomchanid"
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3
        burncap = "9"

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Add customer's funds
        sandbox.client(0).transfer(cust_bal, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        # Add merchant's funds
        sandbox.client(0).transfer(merch_bal, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('baker5', BAKE_ARGS)
        
        # Create the mutual close state that customer and merchant settle on
        new_cust_bal_mt = 1 * 1000000
        new_merch_bal_mt = 29 * 1000000
        mutual_state = form_mutual_state(chan_id, cust_addr, merch_addr, new_cust_bal_mt, new_merch_bal_mt)

        # Cust and Merch signs off on mutual close state
        mutual_type = 'pair (pair string address) (pair address (pair mutez mutez))'
        packed = sandbox.client(0).pack(mutual_state, mutual_type)
        cust_sig = sandbox.client(0).sign_bytes_of_string(packed, "bootstrap1")
        merch_sig = sandbox.client(0).sign_bytes_of_string(packed, "bootstrap2")

        storage = '(Pair (Pair \"{cust_sig}\" \"{merch_sig}\") (Pair {cust_bal_mt} {merch_bal_mt}))'.format(cust_sig=cust_sig, merch_sig=merch_sig, cust_bal_mt=new_cust_bal_mt, merch_bal_mt=new_merch_bal_mt)

        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'mutualClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

def scenario_merch_dispute():
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'baker5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # Define initial storage and channel variables
        contract = "zkchannel_without_ps.tz"

        contract_name = "mychannel"
        chan_id = "randomchanid"
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Add customer's funds
        sandbox.client(0).transfer(cust_bal, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        # Add merchant's funds
        sandbox.client(0).transfer(merch_bal, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Customer makes a payment
        new_cust_bal_mt = 10 * 1000000
        new_merch_bal_mt = 20 * 1000000
        secret = "0x123456789ccc"
        rev_lock = "0x90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729"

        # Merch signs off on custState
        closing_state = form_closing_state(chan_id, cust_addr, merch_addr, new_cust_bal_mt, new_merch_bal_mt, rev_lock)
        cust_close_type = 'pair (pair string (pair address address)) (pair mutez (pair mutez bytes))'
        packed = sandbox.client(0).pack(closing_state, cust_close_type)
        merch_sig = sandbox.client(0).sign_bytes_of_string(packed, "bootstrap2")

        # At this point, the customer makes another payment and revokes this
        # state by sharing the secret (0x123456789ccc) with the merchant.

        # Customer broadcasts custClose on the revoked state
        storage = '(Pair (Pair \"{merch_sig}\" {cust_bal_mt}) (Pair {merch_bal_mt} {rev_lock}))'.format(merch_sig=merch_sig, cust_bal_mt=new_cust_bal_mt, merch_bal_mt=new_merch_bal_mt, rev_lock=rev_lock)
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        sandbox.client(0).bake('baker5', BAKE_ARGS)
        
        # Merchant broadcasts merchDispute

        # # Fails if merchant provides an incorrect secret
        # incorrect_secret = "0x111111111111"
        # sandbox.client(0).transfer(0, 'bootstrap2', contract_name,
        #                            ['--entrypoint', 'merchDispute',
        #                             '--burn-cap', burncap,
        #                             '--arg', incorrect_secret])

        # Merchant can dispute customer's balance with correct revocation secret
        sandbox.client(0).transfer(0, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'merchDispute',
                                    '--burn-cap', burncap,
                                    '--arg', secret])

if __name__ == "__main__":
    scenario_reclaim_funding() 
    scenario_merch_close() 
    scenario_cust_close() 
    scenario_mutual_close() 
    scenario_merch_dispute()