from pytezos import pytezos
from pytezos import Contract
from pytezos import ContractInterface
import json
import pprint

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


# pytezos = pytezos.using(shell='http://ec2-54-234-50-176.compute-1.amazonaws.com:18732')

cust_key = "tz1Q8qQ2FYRSJ8dKj8ukRMRXRcv41dssg1pN.json"
merch_key = "tz1axtoa27aKYaAj1TZVLXuBPMV6Z1XrhLoX.json"

# Set customer pytezos interface
cust_py = pytezos.using(key=cust_key)
cust_close_json = read_json_file(cust_key)
cust_addr = cust_close_json['pkh']
cust_py.activate_account().fill().sign().inject(_async=False)
cust_out = cust_py.reveal().autofill().sign().inject()
cust_pubkey = cust_out['contents'][0]['public_key']

# Set merchant pytezos interface
merch_py = pytezos.using(key=merch_key)
merch_close_json = read_json_file(merch_key)
merch_addr = merch_close_json['pkh']
merch_py.activate_account().fill().sign().inject(_async=False)
merch_out = merch_py.reveal().autofill().sign().inject()
merch_pubkey = merch_out['contents'][0]['public_key']

pssig_code = ContractInterface.from_file('zkchannel_pssig.tz')
pssig_ci = pssig_code.using(key=cust_key)

# Originate the pssig contract
out = cust_py.origination(script=pssig_ci.script()).autofill().sign().inject(_async=False)

# Get the address of the pssig contract so we can reference it in the 
# main zkchannel contract
opg = pytezos.shell.blocks[-20:].find_operation(out['hash'])
pssig_id = opg['contents'][0]['metadata']['operation_result']['originated_contracts'][0]

main_code = ContractInterface.from_file('zkchannel_main.tz')

cust_close_json = read_json_file('sample_cust_close.json')
(pubkey, message, signature) = get_cust_close_token(cust_close_json)
chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message
sig_s1, sig_s2 = signature

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
'revLock': '1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49', 
'selfDelay': 3, 
'status': 0}

out = cust_py.origination(script=main_code.script(initial_storage=main_storage)).autofill().sign().inject(_async=False)

opg = pytezos.shell.blocks[-20:].find_operation(out['hash'])
main_id = opg['contents'][0]['metadata']['operation_result']['originated_contracts'][0]

cust_ci = cust_py.contract(main_id)

merch_ci = merch_py.contract(main_id)

# watchtower_command = "python3 passive_zkchannel_watchtower.py --contract {cid} --network http://localhost:18731 --identity merchant".format(cid=main_id)

# print("Run the watchtower with \n" + watchtower_command)

out = cust_ci.addFunding().with_amount(20000000).inject(_async=False)

# input("Bake to add cust funding")

out = merch_ci.addFunding().with_amount(10000000).inject(_async=False)

# input("Bake to add merch funding")

# # print(merch_ci.merchClose("").cmdline())
out = merch_ci.merchClose().inject()

# input("Bake to confirm merchClose")



cust_close_json = read_json_file('sample_cust_close.json')
(pubkey, message, signature) = get_cust_close_token(cust_close_json)
chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message
sig_s1, sig_s2 = signature

new_merch_bal_mt = cust_close_json["message"]["merch_bal"]
new_cust_bal_mt = cust_close_json["message"]["cust_bal"]

# sample signature, merch-pk and g2 
s1 = sig_s1 
s2 = sig_s2 
g2 = pubkey.get("g2") 
merchPk0 = pubkey.get("Y0") 
merchPk1 = pubkey.get("Y1") 
merchPk2 = pubkey.get("Y2") 
merchPk3 = pubkey.get("Y3") 
merchPk4 = pubkey.get("X") 

storage = '\'(Pair (Pair (Pair {custBal} {g2}) (Pair {merchBal} (Pair {merchPk0} {merchPk1}))) (Pair (Pair {merchPk2} (Pair {merchPk3} {merchPk4})) (Pair {rev_lock_fr} (Pair {s1} {s2}))))\''.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, rev_lock_fr=rev_lock_fr, custBal=new_cust_bal_mt, merchBal=new_merch_bal_mt)


close_storage = {
    "custBal": new_cust_bal_mt,
    "g2": g2,
    "merchBal": new_merch_bal_mt,
    "merchPk0": merchPk0,
    "merchPk1": merchPk1,
    "merchPk2": merchPk2,
    "merchPk3": merchPk3,
    "merchPk4": merchPk4,
    "revLock": rev_lock_fr,
    "s1": s1,
    "s2": s2
}

import pdb; pdb.set_trace();
# # print(cust_ci.custClose(close_storage).cmdline())
out = cust_ci.custClose(close_storage).inject(_async=False)

# input("Bake to confirm custClose")

# cust_ci.custClaim("").inject()
# print("Bake to confirm custClaim and close the channel")

# # # Alternatively, to close the channel with merchDispute, run:
# # rev_secret = "123456789ccc"
# # merch_ci.dis(close_storage).inject()
# # print("Bake to confirm merchDispute and close the channel")

