import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox

BAKE_ARGS = ['--minimal-timestamp']

def form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal0, merch_bal0, rev_lock, self_delay, pssig_addr):

    return '(Pair (Pair (Pair \"{chan_id}\" (Pair \"{cust_addr}\" 0)) (Pair (Pair {cust_bal0} \"{cust_pk}\") (Pair "0" \"{merch_addr}\"))) (Pair (Pair 0 (Pair {merch_bal0} \"{merch_pk}\")) (Pair (Pair \"{pssig_addr}\"  {rev_lock}) (Pair {self_delay} "awaitingFunding"))))'.format(chan_id=chan_id, cust_addr=cust_addr, cust_pk=cust_pk, merch_addr=merch_addr, merch_pk=merch_pk, cust_bal0=cust_bal0, merch_bal0=merch_bal0, self_delay=self_delay, rev_lock=rev_lock, pssig_addr = pssig_addr)

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

        # Originate mock zkchannel contract
        contract = "zkchannel_mock.tz"
        contract_name = "my_zkchannel"
        chan_id = "randomchanid"
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        pssig_addr = sandbox.client(0).get_contract_address(pssig_name)
        initial_storage = '(Pair 0 (Pair 0 {rev_lock0}))'.format(rev_lock0=rev_lock0)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)
        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Define parameters for closing state
        new_cust_bal_mt = 1 * 1000000
        new_merch_bal_mt = 29 * 1000000
        # # secret_final = 0x123456789ccc
        revLock = "0x5d33df275854dc7aea1323eab177a195935d0af0cb7fa727c5b491d41244d42c"

        # Merchant's PS signature on closing state (dummy variables)
        s1 = "dummy_s1"
        s2 = "dummy_s2"
        g2 = "dummy_g2"
        merchPk0 = "dummy_merchPk0"
        merchPk1 = "dummy_merchPk1"
        merchPk2 = "dummy_merchPk2"
        merchPk3 = "dummy_merchPk3"
        merchPk4 = "dummy_merchPk4"

        # Format storage for PSSig contract
        main_addr = sandbox.client(0).get_contract_address(contract_name)
        main_addr = main_addr + "%" + "receiveCall"
        storage = '(Pair (Pair (Pair \"{chanID}\" (Pair {custBal} \"{g2}\")) (Pair \"{main_addr}\" (Pair {merchBal} \"{merchPk0}\"))) (Pair (Pair \"{merchPk1}\"(Pair \"{merchPk2}\" \"{merchPk3}\")) (Pair (Pair \"{merchPk4}\" {revLock}) (Pair \"{s1}\" \"{s2}\"))))'.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, revLock=revLock, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt, main_addr=main_addr, chanID=chan_id)
        
        # Contract call to PSSig contract
        sandbox.client(0).transfer(0, 'bootstrap1', pssig_name,
                                   ['--burn-cap', burncap,
                                    '--arg', storage])

        sandbox.client(0).bake('baker5', BAKE_ARGS)


if __name__ == "__main__":
    scenario_cust_close() 
