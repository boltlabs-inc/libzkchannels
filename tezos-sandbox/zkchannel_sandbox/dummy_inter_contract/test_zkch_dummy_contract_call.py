import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox

BAKE_ARGS = ['--minimal-timestamp']

def form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal0, merch_bal0, rev_lock, self_delay, pssig_addr):

    return '(Pair (Pair (Pair \"{chan_id}\" (Pair \"{cust_addr}\" 0)) (Pair (Pair {cust_bal0} \"{cust_pk}\") (Pair "0" \"{merch_addr}\"))) (Pair (Pair 0 (Pair {merch_bal0} \"{merch_pk}\")) (Pair (Pair \"{pssig_addr}\"  {rev_lock}) (Pair {self_delay} "awaitingFunding"))))'.format(chan_id=chan_id, cust_addr=cust_addr, cust_pk=cust_pk, merch_addr=merch_addr, merch_pk=merch_pk, cust_bal0=cust_bal0, merch_bal0=merch_bal0, self_delay=self_delay, rev_lock=rev_lock, pssig_addr = pssig_addr)

# (Pair (Pair (Pair "randomstring" (Pair "tz1WxrQuZ4CK1MBUa2GqUWK1yJ4J6EtG1Gwi" 0)) (Pair 20000000 (Pair "edpkuvNy6TuQ2z8o9wnoaTtTXkzQk7nhegCHfxBc4ecsd4qG71KYNG" "0"))) (Pair (Pair "tz1Rp4Bv8iUhYnNoCryHQgNzN2D7i3L1LF9C" (Pair 0 10000000)) (Pair (Pair "edpkufVmvzkm4oFQ7WcF5NJbq9BFB2mWRsm4Dyh2spMDuDxWSQWHuT" 0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49) (Pair 86400 "awaitingFunding"))))

#     return '(Pair (Pair (Pair \"{chan_id}\" (Pair \"{cust_addr}\" 0)) (Pair {cust_bal0} (Pair \"{cust_pk}\" "0"))) (Pair (Pair \"{merch_addr}\" (Pair 0 {merch_bal0})) (Pair (Pair \"{merch_pk}\" {rev_lock}) (Pair {self_delay} "awaitingFunding"))))'.format(chan_id=chan_id, cust_addr=cust_addr, cust_pk=cust_pk, merch_addr=merch_addr, merch_pk=merch_pk, cust_bal0=cust_bal0, merch_bal0=merch_bal0, self_delay=self_delay, rev_lock=rev_lock, pssig_addr = pssig_addr)

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

        # Originate dummy pssigs contract
        pssig_contract = "dummy_pssig.tz"
        pssig_name = "pssig_contract"
        args = ["--init", "Unit", "--burn-cap", burncap]
        sandbox.client(0).originate(pssig_name, 0, "bootstrap1", pssig_contract, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Originate the zkchannel contract with hard coded values (without any funding)
        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # Define initial storage and channel variables
        contract = "zkchannel_dummy_contractcall.tz"

        contract_name = "my_zkchannel"
        chan_id = "randomchanid"
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
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
        rev_lock_final = "0x5d33df275854dc7aea1323eab177a195935d0af0cb7fa727c5b491d41244d42c"

        # Merch signs off on custState
        # closing_state = form_closing_state(chan_id, cust_addr, merch_addr, new_cust_bal_mt, new_merch_bal_mt, rev_lock_final)
        # cust_close_type = 'pair (pair string (pair address address)) (pair mutez (pair mutez bytes))'
        # packed = sandbox.client(0).pack(closing_state, cust_close_type)

        s1 = "dummy_s1"
        s2 = "dummy_s2"
        g2 = "dummy_g2"
        merchSig1 = "dummy_merchSig1"
        merchSig2 = "dummy_merchSig2"
        merchSig3 = "dummy_merchSig3"
        merchSig4 = "dummy_merchSig4"
        merchSig5 = "dummy_merchSig5"
        merchSig6 = "dummy_merchSig6"
        
        storage = '(Pair (Pair (Pair \"{g2}\" (Pair \"{merchSig1}\" \"{merchSig2}\")) (Pair \"{merchSig3}\" (Pair \"{merchSig4}\" \"{merchSig5}\"))) (Pair (Pair \"{merchSig6}\" (Pair {custBal} {merchBal})) (Pair {rev_lock_final} (Pair \"{s1}\" \"{s2}\"))))'.format(s1=s1, s2=s2, g2=g2, merchSig1=merchSig1, merchSig2=merchSig2, merchSig3=merchSig3, merchSig4=merchSig4, merchSig5=merchSig5, merchSig6=merchSig6, rev_lock_final=rev_lock_final, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt)

        # Customer broadcasts custClose with the merchant's signature
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        # Each baked block increments the timestamp by 2 seconds. With a 
        # self_delay of 3 seconds, the customer will be able to claim their
        # balance.
        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Custer claims their balance with custClaim
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClaim',
                                    '--burn-cap', burncap])
        
        sandbox.client(0).bake('baker5', BAKE_ARGS)

if __name__ == "__main__":
    scenario_cust_close() 