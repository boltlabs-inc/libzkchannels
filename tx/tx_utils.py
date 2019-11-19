import riemann
import requests, json
from riemann import tx
from riemann.tx import tx_builder as tb
from riemann import networks, simple, utils
from riemann.script import examples, serialization
from riemann.encoding import addresses
import base58
import hashlib
import sys
from binascii import hexlify

from fastecdsa import keys, curve
from fastecdsa.point import Point
from fastecdsa.encoding.sec1 import SEC1Encoder

debug = True
#NETWORK = 'zcash_sapling_test'
BITCOIN = "bitcoin"
ZCASH = "zcash"
CURRENCIES = [BITCOIN, ZCASH]

NETWORK = "bitcoin_main"
ln_redeem_script = (
    'OP_IF '
        'OP_2 {rev_pubkey} {merch_pubkey} OP_2 '   # noqa: E131
    'OP_ELSE '
        '{timeout} OP_CHECKSEQUENCEVERIFY OP_CHECKLOCKTIMEVERIFY OP_DROP '
        '{cust_pubkey} '
    'OP_ENDIF '
    'OP_CHECKSIGVERIFY')

def uint32_to_bytes(number):
    num_bytes = number.to_bytes(4, 'big')
    hex_bytes = ["{0:02x}".format(n) for n in num_bytes]
    return "".join(hex_bytes)

def createMultiSigAddress(pubkey0, pubkey1, verbose=None):
    msig_script = examples.msig_two_two
    msig_scriptpubkey = msig_script.format(pk0=pubkey0, pk1=pubkey1)

    if verbose: print("Multi sig script: ", msig_scriptpubkey)

    riemann.select_network(NETWORK)
    if ZCASH in NETWORK:
        msig_address = addresses.make_p2sh_address(msig_scriptpubkey)
    elif BITCOIN in NETWORK:
        msig_address = addresses.make_p2wsh_address(msig_scriptpubkey)
    else:
        sys.exit("%s not supported" % NETWORK)
    # TODO: add BOLT opcode here for channel opening?
    redeem_script = msig_scriptpubkey
    script = serialization.serialize(redeem_script)

    return msig_address, script.hex()

def createChangeAddress(pubkey):
    riemann.select_network(NETWORK)
    if ZCASH in NETWORK:
        pk_address = addresses.make_p2pkh_address(pubkey.encode('utf8'))
    elif BITCOIN in NETWORK:
        pk_address = addresses.make_p2wpkh_address(pubkey.encode('utf8'))
    else:
        sys.exit("%s not supported" % NETWORK)
    return pk_address

def compute_pk_hash(pubkey_hex):
    return utils.hash160(bytes.fromhex(pubkey_hex)).hex()

def createSingleFundingTransaction(network, funder_outpoint, funder_amount, funder_pubkey, fundee_pubkey):
    """network -> bitcoin or zcash
       script -> { stack_script :
                 , redeem_script : if spending a P2SH, then this should be set }
       funder_outpoint -> specific tx output consisting of (txid, output-index)
       funder_amount -> amount from unspent tx
       funder_pubkey -> pub key for the funder
       fundee_pubkey -> pub key of the fundee (or counterparty)
    """
    # create the multi-signature address
    # fee = 10000

    msig_addr, funding_redeem_script = createMultiSigAddress(funder_pubkey, fundee_pubkey)
    print("Output address: ", msig_addr)
    print("Redeem script: ", funding_redeem_script) # for closing
    # create tx input
    _redeem_script = bytes.fromhex("48304502210090587b6201e166ad6af0227d3036a9454223d49a1f11839c1a362184340ef0240220577f7cd5cca78719405cbf1de7414ac027f0239ef6e214c90fcaab0454d84b3b012103535b32d5eb0a6ed0982a0479bbadc9868d9836f6ba94dd5a63be16d875069184")
    #tx_ins = [simple.unsigned_input(outpoint=funder_outpoint, redeem_script=_redeem_script)]
    tx_ins = [tb.make_legacy_input(outpoint=funder_outpoint, stack_script=b"", redeem_script=_redeem_script, sequence=0xFFFFFFFF)]
    print("Input: ", tx_ins)
    tx_outs = [simple.output(address=msig_addr, value=funder_amount)]
    print("Output: ", tx_outs)

    if network == "bitcoin":
        unsigned_tx = simple.unsigned_legacy_tx(tx_ins, tx_outs)
    elif network == "zcash":
        unsigned_tx = simple.unsigned_legacy_tx(tx_ins, tx_outs)

    script_code1 = b'\x19' + addresses.to_output_script(msig_addr)

    # TODO: computing sighash_all => verify that this is done correctly
    sighash = unsigned_tx.sighash_all(index=0, script=script_code1, prevout_value=utils.i2le_padded(funder_amount, 8))
    # TODO: add signing of the sighash
    print("sighash hex: ", sighash.hex())

    # NOTE: for dual-funded channel, funder_bal = funder_amount + fundee_amount
    funding_tx = {'funding_tx_id': unsigned_tx.tx_id.hex(), 'funding_bal': funder_amount, 'funding_addr': str(msig_addr)}

    return funding_tx, unsigned_tx.hex(), funding_redeem_script


def parseTransaction(network, tx_hex):
    if network == BITCOIN:
        pass
    elif network == ZCASH:
        pass

def createCommitmentTransaction(funding_tx, cust_pubkey, rev_pubkey, merch_pubkey, cust_amount, merch_amount):
    funding_tx_id = funding_tx.get("funding_tx_id")
    funding_bal = funding_tx.get("funding_bal")
    funding_addr = funding_tx.get('funding_address')
    print("<= Create Commitment Transaction =>")
    # compute the funding tx outpoint
    funding_tx_outpoint = simple.outpoint(funding_tx_id, 0)
    # get the funding tx outpoint as the transaction input
    tx_ins = [simple.unsigned_input(funding_tx_outpoint)]
    # the commitment tx has two outputs: (1) customer and (2) merchant
    cust_redeem_script = ln_redeem_script.format(rev_pubkey=rev_pubkey,
                                                 merch_pubkey=merch_pubkey,
                                                 cust_pubkey=cust_pubkey,
                                                 timeout=uint32_to_bytes(1440)) # 1 day - timeout

    if debug: print("Cust redeem script: ", cust_redeem_script)

    cust_address = addresses.make_p2sh_address(cust_redeem_script)
    tx_out_1 = simple.output(cust_amount, cust_address)  # customer

    encoded_merch_pubkey = bytes.fromhex(merch_pubkey)
    merch_address = addresses.make_p2pkh_address(encoded_merch_pubkey)
    tx_out_2 = simple.output(merch_amount, merch_address)  # merchant

    unsigned_tx = simple.unsigned_legacy_tx(tx_ins, [tx_out_1, tx_out_2])

    # script code of prevout being spent (from funding tx)
    prevout_script_code = b'\x19' + addresses.to_output_script(funding_addr)
    sighash = unsigned_tx.sighash_all(index=0, script_code=prevout_script_code, prevout_value=utils.i2le_padded(funding_bal, 8))
    print("sighash hex: ", sighash.hex())

    return unsigned_tx.hex()

def convert_to_int(point):
    _point = SEC1Encoder.encode_public_key(point)
    return int.from_bytes(_point, byteorder='big')

def convert_to_bytes(point):
    return SEC1Encoder.encode_public_key(point)


class BoltTxBuilder(object):
    def __init__(self, network, verbose=False):
        self.network = network
        self.verbose = verbose
        self.input_utxo_specified = False
        self.network_fee_specified = False

    def setNetworkFees(self, fee, change_pubkey):
        self.network_fee = fee
        self.change_address = createChangeAddress(change_pubkey)
        self.network_fee_specified = True
        if self.verbose: print("Change Address set: ", self.change_address)

    def setUTXOs(self, txid, index, utxo_amount, scriptsig):
        if self.input_utxo_specified:
            return
        # assume these are specified correctly for now
        self.outpoint = simple.outpoint(txid, index)
        self.utxo_amount = utxo_amount
        self.scriptsig = bytes.fromhex(scriptsig)
        self.input_utxo_specified = True

    def createFundingTx(self, funder_amount, funder_pubkey, fundee_pubkey, change_address=None):
        if not self.input_utxo_specified:
            sys.exit("Did not specify source of funds.")
        msig_addr, funding_redeem_script = createMultiSigAddress(funder_pubkey, fundee_pubkey, verbose=self.verbose)
        # create tx input
        tx_ins = [tb.make_legacy_input(outpoint=self.outpoint, stack_script=b"", redeem_script=self.scriptsig,
                                       sequence=0xFFFFFFFF)]
        if self.verbose: print("Input: ", tx_ins)
        tx_outs = [simple.output(address=msig_addr, value=funder_amount)]
        if self.verbose: print("Output: ", tx_outs)

        need_change_output = True if self.utxo_amount > funder_amount else False
        if need_change_output:
            change_output_amount = self.utxo_amount - funder_amount - self.network_fee
            tx_outs += [simple.output(address=self.change_address, value=change_output_amount)]

        if BITCOIN in self.network:
            unsigned_tx = simple.unsigned_legacy_tx(tx_ins, tx_outs)
        elif ZCASH in self.network:
            unsigned_tx = simple.unsigned_legacy_tx(tx_ins, tx_outs)

        script_code1 = b'\x19' + addresses.to_output_script(msig_addr)

        # TODO: computing sighash_all => verify that this is done correctly
        sighash = unsigned_tx.sighash_all(index=0, script=script_code1,
                                          prevout_value=utils.i2le_padded(funder_amount, 8))
        # NOTE: for dual-funded channel, funder_bal = funder_amount + fundee_amount
        funding_tx = {'funding_tx_id': unsigned_tx.tx_id.hex(), 'funding_bal': funder_amount,
                      'funding_address': str(msig_addr), 'funding_witness_script': funding_redeem_script}

        return funding_tx, unsigned_tx.hex()

    # helper routines for creating commitment transactions
    def derive_pubkey(self, secret):
        P = keys.get_public_key(secret, curve.secp256k1)
        pub_key = SEC1Encoder.encode_public_key(P)
        #print("Pub key: ", pub_key)
        #print("pubkey : ", hexlify(pub_key))
        # return hex encoding in bytes AND int encoding
        return hexlify(pub_key), P

    def derive_localkeys(self, per_commitment_point, base_point, base_secret):
        hash = hashlib.sha256()
        hash.update(convert_to_bytes(per_commitment_point))
        hash.update(convert_to_bytes(base_point))

        initial_digest = hash.digest()
        digest = int.from_bytes(initial_digest, byteorder='big')
        #print("initial digest: 0x%s" % initial_digest.hex())

        # convert base_point to an actual Point
        #print("SHA: ", digest)
        P = keys.get_public_key(digest, curve.secp256k1)

        local_pubkey = base_point + P
        if self.verbose: print("local pubkey: 0x%s" % convert_to_bytes(local_pubkey).hex())
        local_pubkey_hex = convert_to_bytes(local_pubkey).hex()

        local_privkey = (base_secret + digest) % curve.secp256k1.q
        if self.verbose: print("local privkey: 0x%s" % hex(local_privkey))
        local_privkey_hex = hex(local_privkey).lstrip("0x")

        if self.verbose:
            print("local pubkey int: ", convert_to_int(local_pubkey))
            print("local privkey int:", local_privkey)
        #return convert_to_int(local_pubkey), local_privkey
        return local_pubkey_hex, local_privkey_hex


    def derive_revoke_keys(self, per_commitment_point, per_commitment_secret, revocation_basepoint, revocation_basepoint_secret):
        # revocationpubkey = revocation_basepoint * SHA256(revocation_basepoint || per_commitment_point) +
        #                     per_commitment_point * SHA256(per_commitment_point || revocation_basepoint)
        hash1 = hashlib.sha256()
        hash1.update(convert_to_bytes(revocation_basepoint))
        hash1.update(convert_to_bytes(per_commitment_point))

        rev_digest1 = hash1.digest()
        int_rev_digest1 = int.from_bytes(rev_digest1, byteorder='big')

        #print("rev_digest1 => ", rev_digest1.hex())
        #print("int_rev_digest1 => ", int_rev_digest1)

        # revocation_basepoint * rev_digest1
        R1 = revocation_basepoint * int_rev_digest1

        if self.verbose: print("R1 => ", SEC1Encoder.encode_public_key(R1).hex())

        hash2 = hashlib.sha256()
        hash2.update(convert_to_bytes(per_commitment_point))
        hash2.update(convert_to_bytes(revocation_basepoint))

        rev_digest2 = hash2.digest()
        int_rev_digest2 = int.from_bytes(rev_digest2, byteorder='big')

        # per_commitment_point * rev_digest2
        R2 = per_commitment_point * int_rev_digest2

        if self.verbose: print("R2 => ", SEC1Encoder.encode_public_key(R2).hex())

        rev_pubkey = R1 + R2
        if self.verbose: print("revocation_pubkey: 0x%s" % convert_to_bytes(rev_pubkey).hex())
        rev_pubkey_hex = convert_to_bytes(rev_pubkey).hex()

        # revocationprivkey = revocation_basepoint_secret * SHA256(revocation_basepoint || per_commitment_point) +
        #                      per_commitment_secret * SHA256(per_commitment_point || revocation_basepoint)

        R3 = (revocation_basepoint_secret * int_rev_digest1) % curve.secp256k1.q
        if self.verbose: print("R3 => ", hex(R3))

        R4 = (per_commitment_secret * int_rev_digest2) % curve.secp256k1.q
        if self.verbose: print("R4 => ", hex(R4))

        rev_privkey = (R3 + R4) % curve.secp256k1.q
        if self.verbose: print("revocation_privkey: %s" % hex(rev_privkey))
        rev_privkey_hex = hex(rev_privkey).lstrip("0x")

        return rev_pubkey_hex, rev_privkey_hex


    def derive_keys(self, base_secret, per_commit_secret, base_point, per_commit_point):

        # localpubkey => SHA256(per_commitment_point || base_point) + base_point
        # localprivkey => SHA256(per_commitment_point || base_point) + base_secret
        (pubkey, privkey) = self.derive_localkeys(per_commit_point, base_point, base_secret)
        print("local pubkey: ", pubkey)
        print("local privkey: ", privkey)

        (rev_pubkey, rev_privkey) = self.derive_revoke_keys(per_commit_point, per_commit_secret, base_point, base_secret)
        print("rev pubkey: ", rev_pubkey)
        print("rev privkey: ", rev_privkey)

        return {'local_pubkey': pubkey, 'local_privkey': privkey,
                'rev_pubkey': rev_pubkey, 'rev_privkey': rev_privkey}

    def createCommitmentTx(self, funding_tx, cust_pubkey, rev_pubkey, merch_pubkey, cust_amount, merch_amount):
        funding_tx_id = funding_tx.get("funding_tx_id")
        funding_bal = funding_tx.get("funding_bal")
        funding_addr = funding_tx.get('funding_address')
        print("\n\n<= Create Commitment Transaction =>")
        # compute the funding tx outpoint
        funding_tx_outpoint = simple.outpoint(funding_tx_id, 0)
        # get the funding tx outpoint as the transaction input

        if BITCOIN in self.network:
            tx_ins = [simple.unsigned_input(funding_tx_outpoint)]
            # the commitment tx has two outputs: (1) customer and (2) merchant
            cust_redeem_script = ln_redeem_script.format(rev_pubkey=rev_pubkey,
                                                         merch_pubkey=merch_pubkey,
                                                         cust_pubkey=cust_pubkey,
                                                         timeout=uint32_to_bytes(1440)) # 1 day - timeout
        else:
            sys.exit("%s not supported right now" % self.network)

        if self.verbose: print("Cust redeem script: ", cust_redeem_script)

        if BITCOIN in self.network:
            encoded_merch_pubkey = bytes.fromhex(merch_pubkey)
            merch_address = addresses.make_p2wpkh_address(encoded_merch_pubkey)
            tx_out_1 = simple.output( merch_amount, merch_address)  # merchant

            cust_address = addresses.make_p2wsh_address(cust_redeem_script)
            tx_out_2 = simple.output( cust_amount, cust_address)  # customer

            unsigned_tx = simple.unsigned_legacy_tx(tx_ins, [tx_out_1, tx_out_2])
        else:
            sys.exit("%s not supported right now" % self.network)

        # script code of prevout being spent (from funding tx)
        prevout_script_code = b'\x19' + addresses.to_output_script(funding_addr)
        sighash = unsigned_tx.sighash_all(index=0, script=prevout_script_code, prevout_value=utils.i2le_padded(funding_bal, 8))
        print("sighash hex: ", sighash.hex())

        return unsigned_tx.hex()


if __name__ == "__main__":
    # test code for creating funding tx and commitment tx
    cust_pubkey  = "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"
    merch_pubkey = "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1"
    change_pubkey= "03535b32d5eb0a6ed0982a0479bbadc9868d9836f6ba94dd5a63be16d875069184"

    init_cust_balance = 10000000

    # funding tx - utxo from LN spec
    txid = "fd2105607605d2302994ffea703b09f66b6351816ee737a93e42a841ea20bbad"
    index = 0
    utxo_amount = 5000000000
    scriptsig = "48304502210090587b6201e166ad6af0227d3036a9454223d49a1f11839c1a362184340ef0240220577f7cd5cca78719405cbf1de7414ac027f0239ef6e214c90fcaab0454d84b3b012103535b32d5eb0a6ed0982a0479bbadc9868d9836f6ba94dd5a63be16d875069184"

    #spec_pk_addr = "bcrt1q8j3nctjygm62xp0j8jqdlzk34lw0v5hejct6md"
    #pk = createChangeAddress(change_pubkey)

    tx_builder = BoltTxBuilder("bitcoin")
    tx_builder.setUTXOs(txid, index, utxo_amount, scriptsig)
    tx_builder.setNetworkFees(13920, change_pubkey)
    funding_tx, raw_tx = tx_builder.createFundingTx(init_cust_balance, cust_pubkey, merch_pubkey)

    print("Funding tx: ", funding_tx)
    print("Raw Tx: ", raw_tx)

    base_secret = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    base_point_hex, base_point = tx_builder.derive_pubkey(base_secret)

    per_commitment_secret = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
    per_commitment_point_hex, per_commitment_point = tx_builder.derive_pubkey(per_commitment_secret)

    spec_base_point = 0x036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2
    spec_per_commitment_point = 0x025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486

    assert(convert_to_int(base_point) == spec_base_point)
    assert(convert_to_int(per_commitment_point) == spec_per_commitment_point)

    keys = tx_builder.derive_keys(base_secret, per_commitment_secret, base_point, per_commitment_point)

    # TODO: generate commit tx and compare to original impl
    rev_pubkey = keys["rev_pubkey"]
    #cust_amount = init_cust_balance - 10000
    #merch_amount = 10000
    cust_amount = 7000000000
    merch_amount = 3000000000
    commit_tx = tx_builder.createCommitmentTx(funding_tx, cust_pubkey, rev_pubkey, merch_pubkey, cust_amount, merch_amount)

    print("CT Tx: ", commit_tx)
