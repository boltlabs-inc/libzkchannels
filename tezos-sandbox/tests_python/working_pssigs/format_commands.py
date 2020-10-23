
import argparse
import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox
import sys, json

def form_initial_storage(chan_id, cust_addr, cust_pk, merch_addr, merch_pk, cust_bal0, merch_bal0, rev_lock, self_delay, pssig_addr):

    return '(Pair (Pair (Pair {chan_id} (Pair \"{cust_addr}\" 0)) (Pair (Pair {cust_bal0} \"{cust_pk}\") (Pair "0" \"{merch_addr}\"))) (Pair (Pair 0 (Pair {merch_bal0} \"{merch_pk}\")) (Pair (Pair \"{pssig_addr}\"  {rev_lock}) (Pair {self_delay} "awaitingFunding"))))'.format(chan_id=chan_id, cust_addr=cust_addr, cust_pk=cust_pk, merch_addr=merch_addr, merch_pk=merch_pk, cust_bal0=cust_bal0, merch_bal0=merch_bal0, self_delay=self_delay, rev_lock=rev_lock, pssig_addr = pssig_addr)

def form_closing_state(chan_id, cust_addr, merch_addr, cust_bal_mt, merch_bal_mt, new_rev_lock):

    return '(Pair (Pair \"{chan_id}\" (Pair \"{cust_addr}\" \"{merch_addr}\")) (Pair {cust_bal_mt} (Pair {merch_bal_mt} {rev_lock})))'.format(chan_id=chan_id, cust_addr=cust_addr, merch_addr=merch_addr, cust_bal_mt=cust_bal_mt, merch_bal_mt=merch_bal_mt, rev_lock=new_rev_lock)

def form_mutual_state(chan_id, cust_addr, merch_addr, cust_bal_mt, merch_bal_mt):

    return '(Pair (Pair \"{chan_id}\" \"{cust_addr}\") (Pair \"{merch_addr}\" (Pair {cust_bal_mt} {merch_bal_mt} )))'.format(chan_id=chan_id, cust_addr=cust_addr, merch_addr=merch_addr, cust_bal_mt=cust_bal_mt, merch_bal_mt=merch_bal_mt)

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
    # print("Merch PK: %s" % pubkey)
    # print("Message: %s" % message)
    # print("Signature: %s" % signature)
    return (pubkey, message, signature)

def scenario_cust_close(pubkey, message, signature):
        burncap = "9"

        cust_addr = "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx"
        cust_pk = "edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav"
        merch_addr = "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN"
        merch_pk = "edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9"
        contract_path = ""

        # Originate pssigs contract
        contract = "pssig.tz"
        pssig_name = "pssig_contract"
        initial_storage = '\"Unit\"'
        args = '--burn-cap {burncap}'.format(burncap=burncap)

        sender = "bootstrap1"

        cmd = 'tezos-client originate contract {contract_name} transferring 0 from {sender} running {contract} --init {initial_storage} {args}&'.format(contract_name=pssig_name, sender=sender, contract=contract, initial_storage=initial_storage, args=args)

        print("\npssig contract origination command:\n{cmd}\n\n".format(cmd=cmd))

        pssig_addr = "KT1F5tmpJTdL1qE5nneb1qkHePzfQP8ynSJQ"

        # Originate main zkChannel contract
        contract = contract_path + "zkchannel_main.tz"
        chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message
        sig_s1, sig_s2 = signature

        zkchannel_name = "my_zkchannel"
        chan_id = chan_id_fr
        cust_bal = 20
        merch_bal = 10
        cust_bal_mt = cust_bal * 1000000
        merch_bal_mt = merch_bal * 1000000
        # Balance in mutez as bytes
        rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
        # self_delay = 86400    # seconds in 1 day (60*60*24)
        self_delay = 3

        # Originate zkchannel contract (without funding)
        initial_storage = '\'(Pair (Pair (Pair {chan_id} (Pair \"{cust_addr}\" 0)) (Pair (Pair {cust_bal_mt} \"{cust_pk}\") (Pair "0" \"{merch_addr}\"))) (Pair (Pair 0 (Pair {merch_bal_mt} \"{merch_pk}\")) (Pair (Pair \"{pssig_addr}\"  {rev_lock0}) (Pair {self_delay} "awaitingFunding"))))\''.format(chan_id=chan_id, cust_addr=cust_addr, cust_pk=cust_pk, merch_addr=merch_addr, merch_pk=merch_pk, cust_bal_mt=cust_bal_mt, merch_bal_mt=merch_bal_mt, self_delay=self_delay, rev_lock0=rev_lock0, pssig_addr = pssig_addr)

        args = '--burn-cap {burncap}'.format(burncap=burncap)
 
        cmd = 'tezos-client originate contract {contract_name} transferring 0 from {sender} running {contract} --init {initial_storage} {args}&'.format(contract_name=zkchannel_name, sender=sender, contract=contract, initial_storage=initial_storage, args=args)

        print("main zkchannel origination command:\n" + cmd + "\n")

        # Add funding 
        cmd = 'tezos-client transfer 20 from bootstrap1 to {contract_name} --burn-cap {burncap} --entrypoint addFunding&'.format(contract_name=zkchannel_name, burncap=burncap)
        print("add funding cust:\n" + cmd + "\n")
        cmd = 'tezos-client transfer 10 from bootstrap2 to {contract_name} --burn-cap {burncap} --entrypoint addFunding&'.format(contract_name=zkchannel_name, burncap=burncap)
        print("add funding merch:\n" + cmd + "\n")


        # Cust close entrypoint
        new_cust_bal_mt = 1 * 1000000
        new_merch_bal_mt = 29 * 1000000

        rev_lock = "0x90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729"

        # sample signature, merch-pk and g2 
        s1 = sig_s1 
        s2 = sig_s2 
        g2 = pubkey.get("g2") 
        merchPk0 = pubkey.get("Y0") 
        merchPk1 = pubkey.get("Y1") 
        merchPk2 = pubkey.get("Y2") 
        merchPk3 = pubkey.get("Y3") 
        merchPk4 = pubkey.get("X") 

        storage = '\'(Pair (Pair (Pair {new_cust_bal_mt} (Pair {cust_bal_fr} {g2})) (Pair (Pair {new_merch_bal_mt} {merch_bal_fr}) (Pair {merchPk0} {merchPk1}))) (Pair (Pair {merchPk2} (Pair {merchPk3} {merchPk4})) (Pair (Pair {rev_lock} {rev_lock_fr}) (Pair {s1} {s2}))))\''.format(s1=s1, s2=s2, g2=g2, merchPk0=merchPk0, merchPk1=merchPk1, merchPk2=merchPk2, merchPk3=merchPk3, merchPk4=merchPk4, rev_lock=rev_lock, new_cust_bal_mt=new_cust_bal_mt, new_merch_bal_mt=new_merch_bal_mt, cust_bal_fr=cust_bal_fr, merch_bal_fr=merch_bal_fr, rev_lock_fr=rev_lock_fr)

        cmd = 'tezos-client transfer 0 from {sender} to {contract_name} --entrypoint custClose --burn-cap {burncap} --arg {storage}&'.format(contract_name=zkchannel_name, sender=sender, contract=contract, burncap=burncap, storage=storage)

        print("custClose call command:\n" + cmd)


if __name__ == "__main__":
    cust_close_token = sys.argv[1]
    # print("Close token json: ", cust_close_token)
    cust_close_json = read_json_file(cust_close_token)
    (merch_pk, message, signature) = get_cust_close_token(cust_close_json)
    # print("merch-pk: ", json.dumps(merch_pk, indent=4))
    # print("message: ", message)
    # print("signature: ", signature)

    scenario_cust_close(merch_pk, message, signature)
