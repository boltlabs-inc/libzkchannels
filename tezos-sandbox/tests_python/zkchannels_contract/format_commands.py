import argparse
import sys, json

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
    # TODO: Dont flip endianness after zkchannels-cli fix
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

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--pssig_addr", "-ps", help="Enter the on-chain address of the pssig contract")
    parser.add_argument("--chan_id", "-id", help="Enter the value of 'Close Token' from zkchannels-cli after running the 'init' command")
    parser.add_argument("--cust_close", "-cc", help="Enter the filename (with path) to the cust_close.json file created by zkchannels-cli")
    input_args = parser.parse_args()

    burncap = "9"

    # Bootstrap1
    cust_addr = "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx"
    cust_pk = "edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav"
    # Bootstrap2
    merch_addr = "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN"
    merch_pk = "edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9"
    
    # Originate pssigs contract
    contract = "pssig.tz"
    pssig_name = "pssig_contract"
    initial_storage = '\"Unit\"'
    args = '--burn-cap {burncap}'.format(burncap=burncap)

    sender = "bootstrap1"

    cmd = 'tezos-client originate contract {contract_name} transferring 0 from {sender} running {contract} --init {initial_storage} {args}&'.format(contract_name=pssig_name, sender=sender, contract=contract, initial_storage=initial_storage, args=args)

    print("\npssig contract origination command:\n{cmd}\n".format(cmd=cmd))

    # Originate main zkChannel contract
    if not (input_args.pssig_addr and input_args.chan_id):
        sys.exit("To create the origination command for the main zkchannel contract, enter the address of the on-chain pssig contract '--pssig_addr', and the channel id '--chan_id'.")

    pssig_addr = input_args.pssig_addr

    chan_id_file = input_args.chan_id
    chan_id_json = read_json_file(chan_id_file)
    
    chan_id = add_hex_prefix(chan_id_json["channel_id"])

    contract = "zkchannel_main.tz"
    
    zkchannel_name = "my_zkchannel"
    cust_bal = 20
    merch_bal = 10
    cust_bal_mt = cust_bal * 1000000
    merch_bal_mt = merch_bal * 1000000
    # Balance in mutez as bytes
    rev_lock0 = "0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49"
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

    # Parse cust_close.json and create cust_close command
    if not input_args.cust_close:
        sys.exit("To create the cust close command, provide the cust_close.json using '--cust_close' followed by the filename.")
    cust_close_token = input_args.cust_close
    cust_close_json = read_json_file(cust_close_token)
    (pubkey, message, signature) = get_cust_close_token(cust_close_json)
    
    chan_id_fr, rev_lock_fr, cust_bal_fr, merch_bal_fr = message
    sig_s1, sig_s2 = signature

    if chan_id != chan_id_fr:
        sys.exit("Error: Chan id of close token does not match the chan id used in contract origination.")

    # Cust close entrypoint

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

    cmd = 'tezos-client transfer 0 from {sender} to {contract_name} --entrypoint custClose --burn-cap {burncap} --arg {storage}&'.format(contract_name=zkchannel_name, sender=sender, contract=contract, burncap=burncap, storage=storage)

    print("custClose call command:\n" + cmd)


