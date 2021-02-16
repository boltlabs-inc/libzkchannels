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
        pssig_contract = contract_path +"zkchannel_pssig_v2.tz"
        pssig_name = "pssig_contract"
        args = ["--init", "Unit", "--burn-cap", burncap]

        sandbox.client(0).originate(pssig_name, 0, "bootstrap1", pssig_contract, args)
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        entrypoint_cost = dict()
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["pssig"] = cust_bal_start - current_bal

        # Define initial storage and channel variables
        contract = contract_path + "zkchannel_main_v2.tz"
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
        rev_lock_final = rev_lock_fr

        print("rev_lock_final: " + str(rev_lock_final))
        
        # sample signature, merch-pk and g2 
        s1 = sig_s1 
        s2 = sig_s2 
        g2 = pubkey.get("g2") 
        merchPk0 = pubkey.get("Y0") 
        merchPk1 = pubkey.get("Y1") 
        merchPk2 = pubkey.get("Y2") 
        merchPk3 = pubkey.get("Y3") 
        merchPk4 = pubkey.get("X") 

        # # self contained value
        # chan_id = add_hex_prefix(convert_to_little_endian("0x5dffcd6f357f20a862f927fb7919e28ff3214977ed0a38232e907c4ab73691f0"))
        # print("Chan ID: %s" % chan_id)
        # rev_lock_final = add_hex_prefix(convert_to_little_endian("0x5c2e79664c13a8fc34b93e8882b9abf583208c6bc8cd2ad11e68d1232e88e68f"))
        # print("Revlock: %s" % rev_lock_final)
        # new_cust_bal_mt = "19999800"
        # new_merch_bal_mt = "10000200"
        # # new_cust_bal_mt = "0x382c310100000000000000000000000000000000000000000000000000000000"
        # # new_merch_bal_mt = "0x4897980000000000000000000000000000000000000000000000000000000000"

        # s1 = "0x1713091665473295e5ef2f6994c2a20aef21b38685558a4f938ed2cbdda411edf584bcfab31a3d55634ee08dfd5376bc19abad5e5e2e8e64d21b13ecb810601b49ae708fc383609068bee51e69db56af9030693a645fc0ef7df2024a4cde456d"
        # s2 = "0x0ef3081cbce139afe9f14da76b5e337b5a097c20bb62226f97086d851dc66bf72e85258eee96297fb9f6f955c74d65b00f9587346e58af360f8c7bb6e7d729c0fc99a8976d7ccd96c0c662ec974e05e44fc6be7ca3ef540998839b8ffdad2128"
        # g2 = "0x0990a9b13921c01f387c2725ee5c4c47a56825136dc85f9b55f5244dfe45be8aa610a7358905fc6a9ab848c850fb45ac097fc1f3b2aa09b660b8a7069d2db75f21fd9a924d15a855d93f8f4540f7626a4df560e9c12e215db86fdebb9b6bf8b5086129163c9e6071207ff43743012d37893e2b52fb75ff63dc35fefb7266af9883f4566ae2762862ae7084c4fd39381d185946e1c1280d87d3256673b9bb680cefe926e3e5ae194d732f762c62725ad13d3cecaefa1a75a724b58af3f1c9bd18"
        # merchPk0 = "0x083930b7626dbe92878de408eea223a6f7a183a6d18c6442ab801d558639322d7f37bd27073532e551d5e31a5b48a7fb055ac29b37c1d1f9092a57a476758e0be023cb43dd368d6dc30223a648324ce93d051469ffbcfe20a038bced8dbff606174e12e8a91c6a2e511c7b9aaae76a66191bb960b2571def75e231d3f6211aa98004cbb4e70ad9668fd8d386957479cb040bfc6519d793a8db488a0c604471deed80bb942c5730b8a94f54e898cbfc33ccfac15268b808c806b84111a5af921e"
        # merchPk1 = "0x11773bb86f7d8a50c5ef88ef515ed4ef3313278c67ce800196ee13d790a3f88a0ea094f9a67422fee73ecc5199ac109a1839d74d054d0cfe8467e773a6e0f2c81848c562035d4132b5f1e1fec343a77c1490c113316b92c2a7314ca33aa4932608df39e38326c3069c53c9fe877794f01e279621599123cbad1025fe87aedf763455ea457226d2f9a8d53d307d65e14510d1ad7031dae45c1e51b971c4964b549572b44edf97493b231a3d83c9474da416f53a8f036b07110a5577830987b76a"
        # merchPk2 = "0x1622c35b21afdd2223db3baa7ae35a6b6981951c711cf851dc1935e59a49f581cf7e33b8a5af1743bfe1e5c029cc12780021ab98bbb27eaf0031e3c7aebb8e496c7b4f0d6b210e8523b63b64be9105eeda7caf8ab34100c63e124fc647acd5c311feaeecc7fab921cb38b81d382398976e37b9a883d1b79c9c100849b5df3576af38870629269bb9342ea1d02cab3f5b018057f5c59e8f7a391348f34f31e7c3b1c375d6a03e065f29cd7ac3db28808ddf0f4367c3614dc995104f9103317f70"
        # merchPk3 = "0x18be8b41978a2aa56e77a46246438c20edb5145dcc53c8430ebe809899a0ab1db74c29038d10fb72707d6630b00d00bd048c0508011220765f4be805fc4d600562ce28b9aa6174880fd83d1bec0848df8b92d16906341d374156dbf0bf3b0111049e562db0222d419a2e3e11430b1acad3466506499a1f2f4872a03f7dfb97b92466d9723b411309b2cf5bbab043ae840d1f67d445ddfb776db6c524c14467faddd7fa7adfabbbb5edbb60631c5c52d7283802e9073d9b345e12fdde2517796e"
        # merchPk4 = "0x08f55c27b65bfe1cb0fc182a73c799f4955e13f3d48387422bffb81d7baf811098b19685558caa0c8f2834ef32d1a3910a55bfb3362d4545b8e8bf5e155af782930f120e295d95aaa9c144f4a37bb32363f7738d43c6c6aceef1e210187813c3164e73cc036b738436b7621e414bcebab60c3e6f6700be7fda35303c8b9e4ccc168db7f65e66739f37109760eb848fdf0a71d5bacacf1518e17948d266effe04b97a7b21336e33a68d0eba07a51c5360231df2dc1efba4f8a5a33296b3e723c7"

        # stack_args = "(Pair (Pair (Pair {chan_id} (Pair {custBal} {g2})) (Pair {merchBal} (Pair {merchPk0} {merchPk1}))) (Pair (Pair {merchPk2} (Pair {merchPk3} {merchPk4})) (Pair {rev_lock_final} (Pair {s1} {s2}))))".format(chan_id=chan_id, s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, rev_lock_final=rev_lock_final, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt)
        # result = sandbox.client(0).run_script(pssig_contract, 'Unit', stack_args, trace_stack=True)
        # sys.exit(0)

        # This storage format is for pssig_v3.tz
        storage = '(Pair (Pair (Pair {custBal} {g2}) (Pair {merchBal} (Pair {merchPk0} {merchPk1}))) (Pair (Pair {merchPk2} (Pair {merchPk3} {merchPk4})) (Pair {rev_lock_final} (Pair {s1} {s2}))))'.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, rev_lock_final=rev_lock_final, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt)

        # This storage format is for pssig_v2.tz
        # storage = '(Pair (Pair (Pair {custBal} (Pair {custBalB} {g2})) (Pair (Pair {merchBal} {merchBalB}) (Pair {merchPk0} {merchPk1}))) (Pair (Pair {merchPk2} (Pair {merchPk3} {merchPk4})) (Pair (Pair {rev_lock_final} {rev_lock_final_b}) (Pair {s1} {s2}))))'.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, rev_lock_final=rev_lock_final, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt, custBalB=cust_bal_b, merchBalB=merch_bal_b, rev_lock_final_b=rev_lock_final_b)

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
        pssig_contract = contract_path + "pssig_v3.tz"
        pssig_name = "pssig_contract"
        args = ["--init", "Unit", "--burn-cap", burncap]

        sandbox.client(0).originate(pssig_name, 0, "bootstrap1", pssig_contract, args)
        sandbox.client(0).bake('bootstrap5', BAKE_ARGS)

        entrypoint_cost = dict()
        current_bal = sandbox.client(0).get_balance(cust_addr)
        entrypoint_cost["pssig"] = cust_bal_start - current_bal

        # Define initial storage and channel variables
        contract = contract_path + "zkchannel_main_v3.tz"
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


