
import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox

BAKE_ARGS = ['--minimal-timestamp']

def form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal0, merch_bal0, rev_lock, self_delay, pssig_addr):

    return '(Pair (Pair (Pair {chan_id} (Pair \"{cust_addr}\" 0)) (Pair (Pair {cust_bal0} \"{cust_pk}\") (Pair "0" \"{merch_addr}\"))) (Pair (Pair 0 (Pair {merch_bal0} \"{merch_pk}\")) (Pair (Pair \"{pssig_addr}\"  {rev_lock}) (Pair {self_delay} "awaitingFunding"))))'.format(chan_id=chan_id, cust_addr=cust_addr, cust_pk=cust_pk, merch_addr=merch_addr, merch_pk=merch_pk, cust_bal0=cust_bal0, merch_bal0=merch_bal0, self_delay=self_delay, rev_lock=rev_lock, pssig_addr = pssig_addr)

def form_closing_state(chan_id, cust_addr, merch_addr, cust_bal_mt, merch_bal_mt, new_rev_lock):

    return '(Pair (Pair \"{chan_id}\" (Pair \"{cust_addr}\" \"{merch_addr}\")) (Pair {cust_bal_mt} (Pair {merch_bal_mt} {rev_lock})))'.format(chan_id=chan_id, cust_addr=cust_addr, merch_addr=merch_addr, cust_bal_mt=cust_bal_mt, merch_bal_mt=merch_bal_mt, rev_lock=new_rev_lock)

def form_mutual_state(chan_id, cust_addr, merch_addr, cust_bal_mt, merch_bal_mt):

    return '(Pair (Pair \"{chan_id}\" \"{cust_addr}\") (Pair \"{merch_addr}\" (Pair {cust_bal_mt} {merch_bal_mt} )))'.format(chan_id=chan_id, cust_addr=cust_addr, merch_addr=merch_addr, cust_bal_mt=cust_bal_mt, merch_bal_mt=merch_bal_mt)

        
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

        # Originate mock pssigs contract
        pssig_contract = "mock_pssig3.tz"
        pssig_name = "pssig_contract"
        args = ["--init", "Unit", "--burn-cap", burncap]
        sandbox.client(0).originate(pssig_name, 0, "bootstrap1", pssig_contract, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Originate the zkchannel contract with hard coded values (without any funding)
        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        print('cust balance')
        sandbox.client(0).get_balance(cust_addr)
        print('merch balance')
        sandbox.client(0).get_balance(merch_addr)

        # Define initial storage and channel variables
        contract = "zkchannel_mock_ps3.tz"

        contract_name = "my_zkchannel"
        chan_id = "0x123456789ccc"
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
        # Balance in mutez as bytes
        cust_bal_b = "0x01312D00" 
        merch_bal_b = "0x00989680"
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        pssig_addr = sandbox.client(0).get_contract_address(pssig_name)

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay, pssig_addr)
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

        print('cust balance')
        sandbox.client(0).get_balance(cust_addr)
        print('merch balance')
        sandbox.client(0).get_balance(merch_addr)

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
        rev_lock_final_b = "0x80d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d728"

        s1 = "0x12345678fff1"
        s2 = "0x12345678fff2"
        g2 = "0x12345678fff3"
        merchPk0 = "0x12345678fff4"
        merchPk1 = "0x12345678fff5"
        merchPk2 = "0x12345678fff6"
        merchPk3 = "0x12345678fff7"
        merchPk4 = "0x12345678fff8"

        storage = '(Pair (Pair (Pair {custBal} (Pair {custBalB} {g2})) (Pair (Pair {merchBal} {merchBalB}) (Pair {merchPk0} {merchPk1}))) (Pair (Pair {merchPk2} (Pair {merchPk3} {merchPk4})) (Pair (Pair {rev_lock_final} {rev_lock_final_b}) (Pair {s1} {s2}))))'.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, rev_lock_final=rev_lock_final, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt, custBalB=cust_bal_b, merchBalB=merch_bal_b, rev_lock_final_b=rev_lock_final_b)

        # Customer broadcasts custClose with the merchant's signature
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        # Each baked block increments the timestamp by 2 seconds. With a 
        # self_delay of 3 seconds, the customer will be able to claim their
        # balance.
        sandbox.client(0).bake('baker5', BAKE_ARGS)
        sandbox.client(0).bake('baker5', BAKE_ARGS)

        print('cust balance')
        sandbox.client(0).get_balance(cust_addr)
        print('merch balance')
        sandbox.client(0).get_balance(merch_addr)

        # Custer claims their balance with custClaim
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClaim',
                                    '--burn-cap', burncap])
        
        sandbox.client(0).bake('baker5', BAKE_ARGS)

        print('cust balance')
        sandbox.client(0).get_balance(cust_addr)
        print('merch balance')
        sandbox.client(0).get_balance(merch_addr)

                
def scenario_cust_close_fail():
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'baker5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        # Originate mock pssigs contract
        pssig_contract = "mock_pssig3.tz"
        pssig_name = "pssig_contract"
        args = ["--init", "Unit", "--burn-cap", burncap]
        sandbox.client(0).originate(pssig_name, 0, "bootstrap1", pssig_contract, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Originate the zkchannel contract with hard coded values (without any funding)
        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        print('cust balance')
        sandbox.client(0).get_balance(cust_addr)
        print('merch balance')
        sandbox.client(0).get_balance(merch_addr)

        # Define initial storage and channel variables
        contract = "zkchannel_mock_ps3.tz"

        contract_name = "my_zkchannel"
        chan_id = "0x123456789ccc"
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
        # Balance in mutez as bytes
        cust_bal_b = "0x01312D00" 
        merch_bal_b = "0x00989680"
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        pssig_addr = sandbox.client(0).get_contract_address(pssig_name)

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay, pssig_addr)
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

        print('cust balance')
        sandbox.client(0).get_balance(cust_addr)
        print('merch balance')
        sandbox.client(0).get_balance(merch_addr)

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
        rev_lock_final_b = "0x80d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d728"

        s1 = "0x12"
        s2 = "0x12"
        g2 = "0x12"
        merchPk0 = "0xf4"
        merchPk1 = "0xf5"
        merchPk2 = "0xf6"
        merchPk3 = "0xf7"
        merchPk4 = "0xf8"

        storage = '(Pair (Pair (Pair {custBal} (Pair {custBalB} {g2})) (Pair (Pair {merchBal} {merchBalB}) (Pair {merchPk0} {merchPk1}))) (Pair (Pair {merchPk2} (Pair {merchPk3} {merchPk4})) (Pair (Pair {rev_lock_final} {rev_lock_final_b}) (Pair {s1} {s2}))))'.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, rev_lock_final=rev_lock_final, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt, custBalB=cust_bal_b, merchBalB=merch_bal_b, rev_lock_final_b=rev_lock_final_b)

        # Customer broadcasts custClose with the merchant's signature
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        # Each baked block increments the timestamp by 2 seconds. With a 
        # self_delay of 3 seconds, the customer will be able to claim their
        # balance.
        sandbox.client(0).bake('baker5', BAKE_ARGS)
        sandbox.client(0).bake('baker5', BAKE_ARGS)

        print('cust balance')
        sandbox.client(0).get_balance(cust_addr)
        print('merch balance')
        sandbox.client(0).get_balance(merch_addr)

        # Custer claims their balance with custClaim
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClaim',
                                    '--burn-cap', burncap])
        
        sandbox.client(0).bake('baker5', BAKE_ARGS)

        print('cust balance')
        sandbox.client(0).get_balance(cust_addr)
        print('merch balance')
        sandbox.client(0).get_balance(merch_addr)

if __name__ == "__main__":
    scenario_cust_close() 
    # scenario_cust_close_fail() 