# Example usage:
# python3 zkchannel_edo2net_broadcaster.py --cust=tz1S6eSPZVQzHyPF2bRKhSKZhDZZSikB3e51.json --merch=tz1VcYZwxQoyxfjhpNiRkdCUe5rzs53LMev6.json --close=sample_cust_close.json 

import argparse
from pytezos import pytezos
from pytezos import Contract
from pytezos import ContractInterface
import json

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
    message = [ 
        add_hex_prefix(m["channel_id"]), 
        add_hex_prefix(m["rev_lock"]),
        add_hex_prefix(int(m["cust_bal"]).to_bytes(32, 'little').hex()),
        add_hex_prefix(int(m["merch_bal"]).to_bytes(32, 'little').hex()),
    ]
    sig = data.get("signature")
    s1 = add_hex_prefix(sig.get("s1"))
    s2 = add_hex_prefix(sig.get("s2"))
    signature = [s1, s2]
    # print("Merch PK: %s" % pubkey)
    # print("Message: %s" % message)
    # print("Signature: %s" % signature)
    return (pubkey, message, signature)

def convert_mt_to_tez(balance):
    return str(int(balance) /1000000)

if __name__ == "__main__":
        
    parser = argparse.ArgumentParser()
    parser.add_argument("--shell", "-n", help="the address to connect to edo2net", default = "https://rpc.tzkt.io/edo2net/")
    parser.add_argument("--cust", "-c", help="customer's testnet json file")
    parser.add_argument("--merch", "-m", help="merchant's testnet json file")
    parser.add_argument("--close", "-cc", help="Enter the filename (with path) to the cust_close.json file created by zkchannels-cli")
    args = parser.parse_args()

    if args.shell:
        pytezos = pytezos.using(shell=args.shell)
    print("Connecting to edo2net via: " + args.shell)
    cust_json = args.cust
    merch_json = args.merch

    # Set customer and merch pytezos interfaces
    cust_py = pytezos.using(key=cust_json)
    cust_addr = read_json_file(cust_json)['pkh']
    merch_py = pytezos.using(key=merch_json)
    merch_addr = read_json_file(merch_json)['pkh']

    # load cust_close json from libzkchannels
    cust_close_json = read_json_file('sample_cust_close.json')
    # load zchannel contracts
    pssig_code = ContractInterface.from_file('zkchannel_pssig.tz')
    main_code = ContractInterface.from_file('zkchannel_main.tz')

    # Activate cust and merch testnet accounts
    try:
        print("Activating cust account")
        cust_py.activate_account().fill().sign().inject()
    except:
        print("Cust account already activated")

    try:
        print("Revealing cust pubkey")
        out = cust_py.reveal().autofill().sign().inject()
    except:
        pass
    cust_pubkey = cust_py.key.public_key()

    try:
        print("Activating merch account")
        merch_py.activate_account().fill().sign().inject()
    except: 
        print("Merch account already activated")

    try:
        print("Revealing merch pubkey")
        out = merch_py.reveal().autofill().sign().inject()
    except:
        pass
    merch_pubkey = merch_py.key.public_key()

    # Originate the pssig contract
    pssig_ci = pssig_code.using(key=cust_json)
    print("Originate pssig contract")
    out = cust_py.origination(script=pssig_ci.script()).autofill().sign().inject(_async=False)
    print("Originate pssig contract ophash: ", out['hash'])
    # Get the address of the pssig contract so we can reference it in the 
    # main zkchannel contract
    opg = pytezos.shell.blocks[-20:].find_operation(out['hash'])
    pssig_id = opg['contents'][0]['metadata']['operation_result']['originated_contracts'][0]
    print("pssig contract address: ", pssig_id)

    # Create initial storage for main zkchannel contract
    (pubkey, message, signature) = get_cust_close_token(cust_close_json)
    chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message

    main_storage = {'chanID': chan_id_fr, 
    'custAddr': cust_addr, 
    'custBal':0, 
    'custFunding': 20000000, 
    'custPk': cust_pubkey, 
    'delayExpiry': '1970-01-01T00:00:00Z', 
    'merchAddr': merch_addr, 
    'merchBal': 0, 
    'merchFunding': 10000000, 
    'merchPk': merch_pubkey, 
    'pssigContract': pssig_id, 
    'revLock': '0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49', 
    'selfDelay': 3, 
    'status': 0}

    # Originate main zkchannel contract
    print("Originate main zkChannel contract")
    out = cust_py.origination(script=main_code.script(initial_storage=main_storage)).autofill().sign().inject(_async=False)
    print("Originate zkChannel ophash: ", out['hash'])
    # Get address of main zkchannel contract
    opg = pytezos.shell.blocks[-20:].find_operation(out['hash'])
    main_id = opg['contents'][0]['metadata']['operation_result']['originated_contracts'][0]
    print("zkChannel contract address: ", main_id)

    # Set contract interfaces for cust and merch
    cust_ci = cust_py.contract(main_id)
    merch_ci = merch_py.contract(main_id)

    print("Adding customer funding")
    out = cust_ci.addFunding().with_amount(20000000).inject(_async=False)
    print("Cust Add Funding ophash: ", out['hash'])

    print("Adding merchant funding")
    out = merch_ci.addFunding().with_amount(10000000).inject(_async=False)
    print("Merch Add Funding ophash: ", out['hash'])

    print("Broadcasting Merch Close")
    out = merch_ci.merchClose().inject(_async=False)
    print("Merch Close ophash: ", out['hash'])

    # Form cust close storage
    (pubkey, message, signature) = get_cust_close_token(cust_close_json)
    chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message
    sig_s1, sig_s2 = signature
    new_cust_bal_mt = cust_close_json["message"]["cust_bal"]
    new_merch_bal_mt = cust_close_json["message"]["merch_bal"]
    new_cust_bal = convert_mt_to_tez(new_cust_bal_mt)
    new_merch_bal = convert_mt_to_tez(new_merch_bal_mt)

    s1 = sig_s1 
    s2 = sig_s2 
    g2 = pubkey.get("g2") 
    merchPk0 = pubkey.get("Y0") 
    merchPk1 = pubkey.get("Y1") 
    merchPk2 = pubkey.get("Y2") 
    merchPk3 = pubkey.get("Y3") 
    merchPk4 = pubkey.get("X") 

    # storage = '\'(Pair (Pair (Pair {custBal} {g2}) (Pair {merchBal} (Pair {merchPk0} {merchPk1}))) (Pair (Pair {merchPk2} (Pair {merchPk3} {merchPk4})) (Pair {rev_lock_fr} (Pair {s1} {s2}))))\''.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, rev_lock_fr=rev_lock_fr, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt)

    close_storage = {
        "custBal": new_cust_bal,
        "g2": g2,
        "merchBal": new_merch_bal,
        "merchPk0": merchPk0,
        "merchPk1": merchPk1,
        "merchPk2": merchPk2,
        "merchPk3": merchPk3,
        "merchPk4": merchPk4,
        "revLock": rev_lock_fr,
        "s1": s1,
        "s2": s2
    }

    print("Broadcasting Cust Close")
    # print(cust_ci.custClose(close_storage).cmdline())
    out = cust_ci.custClose(close_storage).inject(_async=False)
    print("Cust Close ophash: ", out['hash'])

    import pdb; pdb.set_trace();

    print("Broadcasting Cust Claim")
    out = cust_ci.custClaim().inject()
    print("Cust Claim ophash: ", out['hash'])

    # # Alternatively, to close the channel with merchDispute, run:
    # print("Dry run of Cust Claim")
    # out = cust_ci.custClaim().run_operation()
    # print("Cust Claim valid: ", out.operations[0]['internal'])
    # print("Broadcasting Merch Dispute")
    # rev_secret = "enter secret here"
    # merch_ci.merchDispute(rev_secret).inject()

    print("Tests finished!")
