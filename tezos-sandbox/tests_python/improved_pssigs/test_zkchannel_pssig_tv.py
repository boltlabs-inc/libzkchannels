
import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox
import sys

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

        # Originate pssigs contract
        pssig_contract = "pssig_v2.tz"
        pssig_name = "pssig_contract"
        args = ["--init", "Unit", "--burn-cap", burncap]
        sandbox.client(0).originate(pssig_name, 0, "bootstrap1", pssig_contract, args)
    
        # TODO: insert code here to test pssig in isolation

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
        contract = "zkchannel_main_v2.tz"

        contract_name = "my_zkchannel"
        chan_id = "0x67a6833570f081f32b47b8f56e95f5b627f7ea78d08d49f5a1e1c16e6eadcd37"
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
        # Balance in mutez as bytes
        cust_bal_b = "0xa1c2c937b7c9b1840e66c177c19a3d14668df0252719cddccc9230c44fd48d58" 
        merch_bal_b = "0x5b81b9f14659c653d0a13844839989f5558a3c8f9fd8b7081fd79504a6cb775c"
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
        rev_lock_final_b = "0xc498a81ec499243e5cee4befdcbc26d44a2295f27580cbff5df093853d210e29"

        # sample signature, merch-pk and g2 
        s1 = "0x09992a607f59d7bbaa4f330ba4c04b88398efa7b2c0ed53fb4e251affa1961b19a08af4e47631a88f92e58b6493e74ec0d5d0f95bacd38499785cc13a7115f0a23039d622aeb267bffb482d87e19a0ecddad2184041c4dbb0ec7a0c6b20f9c76"
        s2 = "0x187b86422d9d0b6265be8da52f620f2b1c1bc07d33afe19a8fd13ed497c543aaeae9e551608d20f44bbbd5f6470af82b0d4198761aa2e6a481ecd2e37a30f566ddf9dd6a3c4c0d1c29c24c49db0bb88c2ea6df31c5deee65e21f07e2fd4c9014"
        g2 = "0x14fbddce30e1a72f7e8e6360386deb0281f7bde1f190af3158e3219007476d3d035adbfcb0396f85e211c882d08911e814a64fd55aee07b7cbd29e12c0a99389466031d96ac46c6117ad9faca9fdf3c481d422ee9dddd8c3dfa9edb9e4c487bb0675eba5a9396b97f1a7a3fea208df03a3f238d98d1c3dbb37b500c29ebf2a12cf54be35f3793dfb740cbaf45b9cbef819b3a4fe8f63c3f3bcdf981e9d23620b957fbeb4471f082fd7e0a804de11bf97594b7dc278d5d0bfcfb97f0d82915bfa"
        merchPk0 = "0x14bc48335fb2c240909738c6ba97b9f114ac38885fc4c8f680bd949fad3155bb34dc14c6f9f1903f331e3733abde83e310435fc07d517b5da3c0ced536dbd9e822609c711e5b5a849c9e618b7796242153e83ec54ed8ca680773e6f462d4b5aa0bdda52cb19242c83bc7169d0dcbd7645a282398b43b77002db7ada3ce53e032e0e71c7cb72470794ad3257f80f9042814208a7724e1a3cd4520004faf3a8a4285ce1a8942c19e5c94a3534ea1d05ef46c0b678332ee6b7ed751ff40e652a78b"
        merchPk1 = "0x0550c8512ce93251f150f81985c9b2c3be3c4b7617c6601c410b4cffd13aee90d191cbac85d20a13256a448cdf1bcac10b0e25ee79c90dc3799ac0f3445ccbb3c7539a5cdade982cc950b49904c08224ab8cf06fb1465b5406a97e2ba7262a5214400ca4eced14f40b1334abec9ef8748f609d7c666daf5862c5fd77a6a247dd1ac689caff84e10bdcfdb8c9085db1bf095a420c53cf0685e047934eba48d57f1f19f9353749be41b364ca3c363aa649b1b8f027d2ac682f105d6166c8b96bd1"
        merchPk2 = "0x0a6ca6e607695904f8d7ae72edb683a30f5aeecdf4fe59a398c31d101e1de82a47588915854a8bb20d74f04f035e48db0603ba448c69177ae2c174c28745a6fb358a14fb90a410e8d5ce112c267b9713c68ce8ac12af0c08475369c88e627f02098234f30d97ad897a54cc976dcb0011663aeaff54d3de8937d96d337db0f7c838e7b39dc7ea3fb2a209ab856a64efe01428405899293b2c7b10b663b4c0eeadf3d5a6c418ead604b8cd06f31bd4acf3dc5640b789acc5d42ab11a642eeeebe0"
        merchPk3 = "0x0726b43a27056142000f9e8851ac51972852cf6b34cff087a66ff6fc1b00d0639fa4b0732a36bce3f82e0f976403817802ecec5ffb38649706bb332a456113c7a84bdea3f5b82b421aae5e8fbce5e29bbf96f940474c38ef741b8084e6e2202506cb23fbf89c51e1ae0a9b5930cf04903bc8c12230bed6ec683fa8026598ea48e31f8e5ebc7a21e3e6a54725d45af0460603ed333407d65cb304940bff127c36e066a7839dce8a251488ac90f09c8a0fa8a58a57c555864f38cded716f1ff4a7"
        merchPk4 = "0x0787339d3c4a6871a5d1ce22bc500fb76513c688d2a9ef87b903f59c2c8942d5836675da315a444829fb74e9b95f8afa18df13c5d73badef85a8e742b29bf055e4b73123c8ed4c5f4536f9fd4675b4a267604b5b5d44e77707d6865c51c3c4b515b31f55f5255a78f4f182f68d11c8d923ad57eb3c7cda93f308495df7e397a1abc1ac98e9a12e68e37fc5cb900bb52f126d1dbc0fd839a78d937c2c7662002442865d8fffba016f105c9a145a54212bb9d4f15836ba32b79013eb1354f628db"

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
