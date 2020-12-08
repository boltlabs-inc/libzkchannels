
import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox
import sys, json

BAKE_ARGS = ['--minimal-timestamp']

def form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal0, merch_bal0, rev_lock, self_delay, pssig_addr):

    return '(Pair (Pair (Pair {chan_id} (Pair \"{cust_addr}\" 0)) (Pair (Pair {cust_bal0} \"{cust_pk}\") (Pair "0" \"{merch_addr}\"))) (Pair (Pair 0 (Pair {merch_bal0} \"{merch_pk}\")) (Pair (Pair \"{pssig_addr}\"  {rev_lock}) (Pair {self_delay} "awaitingFunding"))))'.format(chan_id=chan_id, cust_addr=cust_addr, cust_pk=cust_pk, merch_addr=merch_addr, merch_pk=merch_pk, cust_bal0=cust_bal0, merch_bal0=merch_bal0, self_delay=self_delay, rev_lock=rev_lock, pssig_addr = pssig_addr)

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

def convert_to_little_endian(s):
    t = s
    if s[:2] == "0x":
        t = s[2:]
    return bytes.fromhex(t)[::-1].hex()

def get_cust_close_token(data):
    merch_pk = data.get("merch_pk")
    pubkey = {}
    for k,v in merch_pk.items():
        pubkey[k] = "0x" + str(v)
    m = data.get("message")
    channel_id = convert_to_little_endian(m["channel_id"])
    rev_lock = convert_to_little_endian(m["rev_lock"])
    message = [ 
        add_hex_prefix(channel_id), 
        add_hex_prefix(rev_lock),
        add_hex_prefix(int(m["cust_bal"]).to_bytes(32, 'little').hex()),
        add_hex_prefix(int(m["merch_bal"]).to_bytes(32, 'little').hex()),
    ]
    sig = data.get("signature")
    s1 = add_hex_prefix(sig.get("s1"))
    s2 = add_hex_prefix(sig.get("s2"))

    signature = [s1, s2]
    print("Merch PK: %s" % pubkey)
    print("Message: %s" % message)
    print("Signature: %s" % signature)
    return (pubkey, message, signature)

def scenario_cust_close(contract_path, pubkey, message, signature):
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'bootstrap5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']
        
        cust_bal_start = sandbox.client(0).get_balance(cust_addr)

        # Originate pssigs contract
        pssig_contract = contract_path + "pssig_v2.tz"
        pssig_name = "pssig_contract"
        args = ["--init", "Unit", "--burn-cap", burncap]

        sandbox.client(0).originate(pssig_name, 0, "bootstrap1", pssig_contract, args)
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        entrypoint_cost = dict()
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["pssig"] = cust_bal_start - current_bal

        # Define initial storage and channel variables
        contract = contract_path + "zkchannel_main.tz"
        chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message
        sig_s1, sig_s2 = signature

        contract_name = "my_zkchannel"
        chan_id = chan_id_fr
        cust_bal = 21000 / 1000000
        merch_bal = 0
        cust_bal_mt = int(cust_bal * 1000000)
        merch_bal_mt = int(merch_bal * 1000000)
        # Balance in mutez as bytes
        cust_bal_b = cust_bal_fr 
        merch_bal_b = merch_bal_fr 
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        pssig_addr = sandbox.client(0).get_contract_address(pssig_name)

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay, pssig_addr)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)
        
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        old_bal = current_bal
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

        merch_old_bal = sandbox.client(0).get_balance(merch_addr)

        old_bal = current_bal
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["addFunding"] = old_bal - cust_bal - current_bal

        # Merchant initiates merch close
        sandbox.client(0).transfer(0, 'bootstrap2', contract_name,
                                   ['--entrypoint', 'merchClose',
                                    '--burn-cap', burncap])

        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)


        merch_current_bal = sandbox.client(0).get_balance(merch_addr)
        entrypoint_cost["merchClose"]  = merch_old_bal - merch_current_bal
        
        # A final payment happens - Merchant signs off on chanID, balances,
        # revlock (and for now addresses, although that may change)
        new_cust_bal = 19960 / 1000000
        new_merch_bal = 1040 / 1000000
        new_cust_bal_mt = int(new_cust_bal * 1000000)
        new_merch_bal_mt = int(new_merch_bal * 1000000)
        # # secret_final = 0x123456789ccc
        rev_lock_final = "0x90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729"
        rev_lock_final_b = rev_lock_fr

        # sample signature, merch-pk and g2 
        s1 = sig_s1 
        s2 = sig_s2 
        g2 = pubkey.get("g2") 
        merchPk0 = pubkey.get("Y0") 
        merchPk1 = pubkey.get("Y1") 
        merchPk2 = pubkey.get("Y2") 
        merchPk3 = pubkey.get("Y3") 
        merchPk4 = pubkey.get("X") 

        storage = '(Pair (Pair (Pair {custBal} (Pair {custBalB} {g2})) (Pair (Pair {merchBal} {merchBalB}) (Pair {merchPk0} {merchPk1}))) (Pair (Pair {merchPk2} (Pair {merchPk3} {merchPk4})) (Pair (Pair {rev_lock_final} {rev_lock_final_b}) (Pair {s1} {s2}))))'.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, rev_lock_final=rev_lock_final, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt, custBalB=cust_bal_b, merchBalB=merch_bal_b, rev_lock_final_b=rev_lock_final_b)

        # Customer broadcasts custClose with the merchant's signature
        sandbox.client(0).transfer(0, 'bootstrap1', contract_name,
                                   ['--entrypoint', 'custClose',
                                    '--burn-cap', burncap,
                                    '--arg', storage])

        # Each baked block increments the timestamp by 2 seconds. With a 
        # self_delay of 3 seconds, the customer will be able to claim their
        # balance.
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

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

def scenario_mutual_close(contract_path, message):
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        sandbox.add_baker(0, 'bootstrap5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)
        burncap = "9"

        cust_addr = constants.IDENTITIES['bootstrap1']['identity']
        cust_pk = constants.IDENTITIES['bootstrap1']['public']
        merch_addr = constants.IDENTITIES['bootstrap2']['identity']
        merch_pk = constants.IDENTITIES['bootstrap2']['public']
        
        cust_bal_start = sandbox.client(0).get_balance(cust_addr)

        # Originate pssigs contract
        pssig_contract = contract_path + "pssig_v2.tz"
        pssig_name = "pssig_contract"
        args = ["--init", "Unit", "--burn-cap", burncap]

        sandbox.client(0).originate(pssig_name, 0, "bootstrap1", pssig_contract, args)
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        entrypoint_cost = dict()
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["pssig"] = cust_bal_start - current_bal

        # Define initial storage and channel variables
        contract = contract_path + "zkchannel_main.tz"
        chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message
        sig_s1, sig_s2 = signature

        contract_name = "my_zkchannel"
        chan_id = chan_id_fr
        cust_bal = 21000 / 1000000
        merch_bal = 0
        cust_bal_mt = int(cust_bal * 1000000)
        merch_bal_mt = int(merch_bal * 1000000)
        # Balance in mutez as bytes
        cust_bal_b = cust_bal_fr 
        merch_bal_b = merch_bal_fr 
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        pssig_addr = sandbox.client(0).get_contract_address(pssig_name)

        # Originate zkchannel contract (without funding)
        initial_storage = form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal_mt, merch_bal_mt, rev_lock0, self_delay, pssig_addr)
        args = ["--init", initial_storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_name, 0, "bootstrap1", contract, args)
        
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        old_bal = current_bal
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
    (merch_pk, message, signature) = get_cust_close_token(cust_close_json)
    print("merch-pk: ", json.dumps(merch_pk, indent=4))
    print("message: ", message)
    print("signature: ", signature)

    scenario_cust_close(contract_path, merch_pk, message, signature)
    # scenario_mutual_close(contract_path, message)


