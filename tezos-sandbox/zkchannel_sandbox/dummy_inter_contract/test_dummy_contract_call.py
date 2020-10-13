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

        # Originate the zkchannel contract with hard coded values (without any funding)
        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # Define initial storage and channel variables
        contract = "zkchannel_mock.tz"

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


        # A final payment happens - Merchant signs off on chanID, balances,
        # revlock (and for now addresses, although that may change)
        new_cust_bal_mt = 1 * 1000000
        new_merch_bal_mt = 29 * 1000000
        # # secret_final = 0x123456789ccc
        revLock = "0x5d33df275854dc7aea1323eab177a195935d0af0cb7fa727c5b491d41244d42c"
        main_addr = sandbox.client(0).get_contract_address(contract_name)

        # Merch signs off on custState
        # closing_state = form_closing_state(chan_id, cust_addr, merch_addr, new_cust_bal_mt, new_merch_bal_mt, rev_lock_final)
        # cust_close_type = 'pair (pair string (pair address address)) (pair mutez (pair mutez bytes))'
        # packed = sandbox.client(0).pack(closing_state, cust_close_type)

        s1 = "dummy_s1"
        s2 = "dummy_s2"
        g2 = "dummy_g2"
        merchPk0 = "dummy_merchPk0"
        merchPk1 = "dummy_merchPk1"
        merchPk2 = "dummy_merchPk2"
        merchPk3 = "dummy_merchPk3"
        merchPk4 = "dummy_merchPk4"

        # main_addr = main_addr + "%" + "receiveCall"
        # main_addr = "0x01cc1617470600f567cb531e4cc52d5dba6a5e719e007265636569766543616c6c"
        # storage = '(Pair (Pair (Pair \"{chanID}\" (Pair {custBal} \"{g2}\")) (Pair {main_addr} (Pair (Pair {newCustBal} {newMerchBal}) (Pair {newRevLock} {valid}))) (Pair {merchBal} \"{merchPk0}\")) (Pair (Pair \"{merchPk1}\"(Pair \"{merchPk2}\" \"{merchPk3}\")) (Pair (Pair \"{merchPk4}\" {revLock}) (Pair \"{s1}\" \"{s2}\"))))'.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, revLock=revLock, newRevLock=revLock, newCustBal=new_cust_bal_mt, newMerchBal=new_merch_bal_mt, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt, main_addr=main_addr, chanID=chan_id, valid=False)

        storage = '(Pair (Pair (Pair "randomchanid" (Pair 1000000 "dummy_g2")) (Pair 0x01f2cda3a2d4bef9757da173d4b79808e1885ade4e007265636569766543616c6c (Pair 29000000 "dummy_merchPk0"))) (Pair (Pair "dummy_merchPk1" (Pair "dummy_merchPk2" "dummy_merchPk3")) (Pair (Pair "dummy_merchPk4" 0x5d33df275854dc7aea1323eab177a195935d0af0cb7fa727c5b491d41244d42c) (Pair "dummy_s1" "dummy_s2"))))'
        
        # Customer broadcasts custClose with the merchant's signature
        sandbox.client(0).transfer(0, 'bootstrap1', pssig_name,
                                   ['--burn-cap', burncap,
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



    # (Pair 
    #     (Pair 
    #         (Pair \"{chanID}\"
    #             (Pair {custBal} \"{g2}\"
    #             )
    #         ) 
    #         (Pair 
    #             \"{mainAddr}\"
    #                 (Pair 
    #                     (Pair 
    #                         {newCustBal} {newMerchBal}
    #                     ) 
    #                     (Pair {newRevLock} {valid}
    #                     )
    #                 )
    #             ) 
    #             (Pair 
    #                 {merchBal} \"{merchPk0}\"
    #             )
    #         )
    #     ) 
    #     (Pair 
    #         (Pair 
    #             \"{merchPk1}\"
    #             (Pair 
    #                 \"{merchPk2}\" \"{merchPk3}\"
    #             )
    #         ) 
    #         (Pair 
    #             (Pair \"{merchPk4}\" {revLock}
    #             ) 
    #             (Pair \"{s1}\" \"{s2}\"
    #             )
    #         )
    #     )
    # )

#### ACTUAL
    # (Pair 
    #     (Pair 
    #         (Pair 
    #             \"{chanID}\"
    #             (Pair {custBal} \"{g2}\"
    #             )
    #         ) 
    #         (Pair 
    #             \"{mainAddr}\"
    #             (Pair 
    #                 (Pair 
    #                     {newCustBal} {newMerchBal}
    #                 ) 
    #                 (Pair {newRevLock} {valid}
    #                 )
    #             )
    #         ) 
    #         (Pair 
    #             {merchBal} \"{merchPk0}\"
    #         )
    #     )
    # ) 
    # (Pair 
    #     (Pair 
    #         \"{merchPk1}\"
    #         (Pair \"{merchPk2}\" \"{merchPk3}\"
    #         )
    #     ) 
    #     (Pair 
    #         (Pair \"{merchPk4}\" {revLock}
    #         ) 
    #         (Pair \"{s1}\" \"{s2}\"
    #         )
    #     )
    # )


    # (pair 
    #     (pair 
    #         (pair 
    #             (string %chanID) 
    #             (pair 
    #                 (mutez %custBal) 
    #                 (string %g2)
    #             )
    #         ) 
    #         (pair 
    #             (contract %k 
    #                 (pair 
    #                     (pair 
    #                         (mutez %newCustBal) 
    #                         (mutez %newMerchBal)
    #                     ) 
    #                     (pair 
    #                         (bytes %newRevLock) 
    #                         (bool %valid)
    #                     )
    #                 )
    #             ) 
    #             (pair 
    #                 (mutez %merchBal) 
    #                 (string %merchPk0)
    #             )
    #         )
    #     ) 
    #     (pair 
    #         (pair 
    #             (string %merchPk1) 
    #             (pair 
    #                 (string %merchPk2) 
    #                 (string %merchPk3)
    #             )
    #         ) 
    #         (pair 
    #             (pair 
    #                 (string %merchPk4) 
    #                 (bytes %revLock)
    #             ) 
    #             (pair 
    #                 (string %s1) 
    #                 (string %s2)
    #             )
    #         )
    #     )
    # );
    




