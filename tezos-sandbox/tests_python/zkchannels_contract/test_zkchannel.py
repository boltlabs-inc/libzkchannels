import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox
import sys, json

BAKE_ARGS = ['--minimal-timestamp']

def form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal0, merch_bal0, rev_lock, self_delay, pubkey):
    g2 = pubkey.get("g2") 
    merchPk0 = pubkey.get("Y0") 
    merchPk1 = pubkey.get("Y1") 
    merchPk2 = pubkey.get("Y2") 
    merchPk3 = pubkey.get("Y3") 
    merchPk4 = pubkey.get("X") 

    return '(Pair (Pair (Pair (Pair {chan_id} \"{cust_addr}\") (Pair 0 {cust_bal0})) (Pair (Pair \"{cust_pk}\" "0") (Pair {g2} (Pair \"{merch_addr}\" 0)))) (Pair (Pair (Pair {merch_bal0} \"{merch_pk}\") (Pair {merchPk0} (Pair {merchPk1} {merchPk2}))) (Pair (Pair {merchPk3} {merchPk4}) (Pair {rev_lock} (Pair {self_delay} 0)))))'.format(chan_id=chan_id, cust_addr=cust_addr, cust_pk=cust_pk, merch_addr=merch_addr, merch_pk=merch_pk, cust_bal0=cust_bal0, merch_bal0=merch_bal0, self_delay=self_delay, rev_lock=rev_lock, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4)


def form_mutual_state(chan_id, cust_addr, merch_addr, cust_bal_mt, merch_bal_mt):
    return '(Pair (Pair {chan_id} \"{cust_addr}\") (Pair {cust_bal_mt} (Pair \"{merch_addr}\" {merch_bal_mt} )))'.format(chan_id=chan_id, cust_addr=cust_addr, merch_addr=merch_addr, cust_bal_mt=cust_bal_mt, merch_bal_mt=merch_bal_mt)

def read_json_file(json_file):
    f = open(json_file)
    s = f.read()
    f.close()
    return json.loads(s)

def add_hex_prefix(s):
    if s[:2] == "0x":
        return s
    return "0x" + s

def get_cust_close_token(data):
    merch_pk = data.get("merch_pk")
    pubkey = {}
    for k,v in merch_pk.items():
        pubkey[k] = "0x" + str(v)
    m = data.get("message")
    message = [ 
        add_hex_prefix(m["channel_id"]), 
        add_hex_prefix(m["rev_lock"]),
        add_hex_prefix(int(m["cust_bal"]).to_bytes(32, 'little').hex()),
        add_hex_prefix(int(m["merch_bal"]).to_bytes(32, 'little').hex()),
    ]
    sig = data.get("signature")
    s1 = add_hex_prefix(sig.get("s1"))
    s2 = add_hex_prefix(sig.get("s2"))

    balances = {"cust_bal": int(m["cust_bal"]), "merch_bal": int(m["merch_bal"])}

    signature = [s1, s2]
    print("Merch PK: %s" % pubkey)
    print("Message: %s" % message)
    print("Signature: %s" % signature)
    return (pubkey, message, signature, balances)

def scenario_cust_close(contract_path, pubkey, message, signature, balances):
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'bootstrap5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1) # sleep after baking to prevent the error of blocks being produced in the future

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # We'll keep track of the total tezos fees/gas costs incurred by the customer
        entrypoint_cost = dict()
        cust_bal_start = sandbox.client(0).get_balance(cust_addr)

        # Define initial storage and channel variables
        contract = contract_path + "zkchannel_contract.tz"
        chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message
        sig_s1, sig_s2 = signature

        contract_name = "my_zkchannel"
        chan_id = chan_id_fr
        init_bal = balances["cust_bal"] + balances["merch_bal"]
        cust_bal = init_bal / 1000000
        merch_bal = 0
        cust_bal_mt = int(cust_bal * 1000000)
        merch_bal_mt = int(merch_bal * 1000000)
        # Balance in mutez as bytes
        cust_bal_b = cust_bal_fr 
        merch_bal_b = merch_bal_fr 
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay, pubkey)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)
        
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        old_bal = cust_bal_start
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["zkchannel"] = old_bal - current_bal

        # Add customer's funds
        sandbox.client(0).transfer(cust_bal, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        # Add merchant's funds
        sandbox.client(0).transfer(merch_bal, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        merch_old_bal = sandbox.client(0).get_balance(merch_addr)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["addFunding"] = old_bal - cust_bal - current_bal

        # Merchant initiates merch close
        sandbox.client(0).transfer(0, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'merchClose',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        merch_current_bal = sandbox.client(0).get_balance(merch_addr)
        entrypoint_cost["merchClose"]  = merch_old_bal - merch_current_bal

        # A final payment happens - Merchant signs off on chanID, balances,
        # revlock (and for now addresses, although that may change)
        new_cust_bal = balances["cust_bal"] / 1000000
        new_merch_bal = balances["merch_bal"] / 1000000
        new_cust_bal_mt = int(new_cust_bal * 1000000)
        new_merch_bal_mt = int(new_merch_bal * 1000000)        
        rev_lock_final = rev_lock_fr

        # sample signature, merch-pk and g2 
        s1 = sig_s1 
        s2 = sig_s2 

        storage = 'Pair (Pair {custBal} {merchBal}) {rev_lock_final} {s1} {s2}'.format(s1=s1, s2=s2, rev_lock_final=rev_lock_final, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt)

        # Customer broadcasts custClose with the merchant's signature
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        # Each block takes two seconds, so with a self_delay of 3 seconds, the 
        # customer will be able to claim their balance after two blocks.
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["custClose"] = old_bal - current_bal

        # Custer claims their balance with custClaim
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClaim',
                                    '--burn-cap', burncap])
        
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["custClaim"] = old_bal - (current_bal - new_cust_bal)

        # Make sure every tez has been accounted for
        assert cust_bal_start == (
            current_bal
            + sum(entrypoint_cost.values()) - entrypoint_cost["merchClose"]
            + cust_bal
            - new_cust_bal
            )

        print("Cost incurred when calling the following entrypoints (tez):")
        for k, v in entrypoint_cost.items():
            print(k + ": " + str(v))

        return 

def scenario_mutual_close(contract_path, pubkey):
    """ a private tezos network, initialized with network parameters
        and some accounts. """    
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'bootstrap5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1) # sleep after baking to prevent the error of blocks being produced in the future

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']

        # We'll keep track of the total tezos fees/gas costs incurred by the customer
        entrypoint_cost = dict()
        cust_bal_start = sandbox.client(0).get_balance(cust_addr)

        # Define initial storage and channel variables
        contract = contract_path + "zkchannel_contract.tz"
        chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message
        sig_s1, sig_s2 = signature

        contract_name = "my_zkchannel"
        chan_id = chan_id_fr
        init_bal = balances["cust_bal"] + balances["merch_bal"]
        cust_bal = init_bal / 1000000
        merch_bal = 0
        cust_bal_mt = int(cust_bal * 1000000)
        merch_bal_mt = int(merch_bal * 1000000)
        # Balance in mutez as bytes
        cust_bal_b = cust_bal_fr 
        merch_bal_b = merch_bal_fr 
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay, pubkey)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)
        
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["zkchannel"] = cust_bal_start - current_bal

        # Add customer's funds
        sandbox.client(0).transfer(cust_bal, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        # Add merchant's funds
        sandbox.client(0).transfer(merch_bal, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'addFunding',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        time.sleep(1)

        merch_old_bal = sandbox.client(0).get_balance(merch_addr)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["addFunding"] = old_bal - cust_bal - current_bal

        # Create the mutual close state that customer and merchant settle on
        new_cust_bal = 19960 / 1000000
        new_merch_bal = 1040 / 1000000
        new_cust_bal_mt = int(new_cust_bal * 1000000)
        new_merch_bal_mt = int(new_merch_bal * 1000000)
        mutual_state = form_mutual_state(chan_id, cust_addr, merch_addr, new_cust_bal_mt, new_merch_bal_mt)

        # Cust and Merch signs off on mutual close state
        mutual_type = 'pair (pair bls12_381_fr address) (pair mutez (pair address mutez))'
        packed = sandbox.client(0).pack(mutual_state, mutual_type)
        cust_sig = sandbox.client(0).sign_bytes_of_string(packed, "bootstrap1")
        merch_sig = sandbox.client(0).sign_bytes_of_string(packed, "bootstrap2")

        storage = '(Pair (Pair {cust_bal_mt} \"{cust_sig}\") (Pair {merch_bal_mt} \"{merch_sig}\"))'.format(cust_sig=cust_sig, merch_sig=merch_sig, cust_bal_mt=new_cust_bal_mt, merch_bal_mt=new_merch_bal_mt)

        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'mutualClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["mutualClose"] = old_bal + new_cust_bal - current_bal

        # Make sure every tez has been accounted for
        assert cust_bal_start == (
            current_bal
            + sum(entrypoint_cost.values())
            + cust_bal
            - new_cust_bal
            )
        
        print("Cost incurred when calling the following entrypoints (tez):")
        for k, v in entrypoint_cost.items():
            print(k + ": " + str(v))

        return 

if __name__ == "__main__":
    contract_path = sys.argv[1]
    cust_close_token = sys.argv[2]
    if contract_path[:-1] != "/":
        contract_path += "/"
    print("Contract Path: ", contract_path)
    print("Close token json: ", cust_close_token)
    cust_close_json = read_json_file(cust_close_token)
    (merch_pk, message, signature, balances) = get_cust_close_token(cust_close_json)
    print("merch-pk: ", json.dumps(merch_pk, indent=4))
    print("message: ", message)
    print("signature: ", signature)

    scenario_cust_close(contract_path, merch_pk, message, signature, balances)
    scenario_mutual_close(contract_path, merch_pk)


