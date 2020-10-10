from launchers.sandbox import Sandbox
from tools import constants, paths, utils
import json, sys, argparse

CONTRACTS = {}

# prefix a type name with 'bls12_381_'
def bls(tname):
    return f'bls12_381_{tname}'

def mk_contract(name, param, storage, code):
    CONTRACTS[name] = \
       (f"parameter ({param});\n"
        f"storage (option ({storage}));\n"
        "code {"
        "  CAR;"
        f"  {code};"
        "  SOME; NIL operation; PAIR"
        "}")

def write_contract(contract, filename):
    f = open(filename, 'w')
    f.write(contract)
    f.close()
    return

# def check_contract(client, contract, arg, expected_storage):
#     contract_file = "./pairing_neg.tz"
#     write_contract(contract, contract_file)
#     client.typecheck(contract_file)
#     result = client.run_script(contract_file, 'None', arg)
#     assert result.storage == f'(Some {expected_storage})'

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

    signature = [s1, s2]
    print("Merch PK: %s" % pubkey)
    print("Message: %s" % message)
    print("Signature: %s" % signature)
    return (pubkey, message, signature)

def run_psigs_contract(client, storage, pubkey, message, signature, debug=False):
    # pylint: disable=line-too-long

    # The public key, signature, and inputs are generated from libzkchannels.
    X = add_hex_prefix(pubkey.get('X'))
    Y0 = add_hex_prefix(pubkey.get('Y0'))
    Y1 = add_hex_prefix(pubkey.get('Y1'))
    Y2 = add_hex_prefix(pubkey.get('Y2'))
    Y3 = add_hex_prefix(pubkey.get('Y3'))
    g2 = add_hex_prefix(pubkey.get('g2'))
    m0, m1, m2, m3 = message
    sig_s1, sig_s2 = add_hex_prefix(signature.get("s1")), add_hex_prefix(signature.get("s2"))
    contract = \
            f'''
            # The contract returns if the signature verifies, and fails otherwise.
            storage {storage};

            # The parameter is a pair consisting of:
            # * A message of Fr element inputs, m0,m1,m2 and m3
            # * A signature, consisting of
            #   * G1 points `s1` and `s2`
            # * A mpk, consisting of
            #   * G2 point `g2`
            parameter (pair (pair (pair (pair bls12_381_fr bls12_381_fr) bls12_381_fr) bls12_381_fr) 
                            (pair (pair bls12_381_g1 bls12_381_g1)
                                  bls12_381_g2));

            code
              {{
                # Discard storage and unpair. Result stack should be
                # message{{m0:m1:m2:m3}} : signature{{s1:s2}} : mpk{{g2}}.
                CAR; UNPPAIPPAIIR; UNPAIR; UNPAIR;

                # Push the public key. Result stack should be
                # message{{m0:m1:m2:m3}} 
                # : signature{{s1:s2}}
                # : mpk{{g2}}
                # : pk_{{X:Y0:Y1:Y2:Y3}}
                DIP 7
                    {{
                      PUSH bls12_381_g2 {Y3};
                      PUSH bls12_381_g2 {Y2};
                      PUSH bls12_381_g2 {Y1};
                      PUSH bls12_381_g2 {Y0};
                      PUSH bls12_381_g2 {X}
                    }};

                # Compute prod1_x as 
                # (Y0 * m0) + (Y1 * m1) + (Y2 * m2) + (Y3 * m3) + X
                # Result stack should be
                # prod1_x
                # : message{{m0:m1:m2:m3}}
                # : signature{{s1:s2}}
                # : mpk{{g2}}
                # : pk_{{X:Y0:Y1:Y2:Y3}}
                DUP; DUP 10; MUL;        # Y0 * m0
                DUP 3; DUP 12; MUL;      # Y1 * m1
                DUP 5; DUP 14; MUL;      # Y2 * m2
                DUP 7; DUP 16; MUL;      # Y3 * m3

                ADD; ADD; ADD;
                DUP 9; ADD;  # prod1_x = L + X

                # Push the list for the pairing check. The list should be
                # [ (s1, prod1_x);
                #   (s2, g2 ^ -1) ]
                NIL (pair bls12_381_g1 bls12_381_g2);
                DUP 2; DUP 8; PAIR; CONS;
                DUP 9; NEG; 
                DUP 9; PAIR; CONS;

                # Compute the pairing check and fail if it doesn't succeed
                PAIRING_CHECK;
                ASSERT;

                # Drop the stack
                DROP 13;

                # return no operations
                UNIT; 
                NIL operation; 
                PAIR
              }}'''

    # Typecheck the contract
    filename = f'./pssig_verify.tz'
    with open(filename, 'w') as file:
        file.write(contract)
        CONTRACTS['ps_sig'] = filename
    client.typecheck(CONTRACTS['ps_sig'])

    # prepare arguments for the stack
    message = f"Pair (Pair (Pair {m0} {m1}) {m2}) {m3}"
    signature_and_mpk = f"Pair (Pair {sig_s1} {sig_s2}) {g2}"
    stack_args = f"Pair ({message}) ({signature_and_mpk})"

    result = client.run_script(CONTRACTS['ps_sig'], 'Unit', stack_args, trace_stack=debug)
    return result


def run_sig_verify(pubkey, message, signature, verbose):
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        # Launch a second node on the same private tezos network
        sandbox.add_node(1, params=constants.NODE_PARAMS)
        # Test PS sigs verification contract
        run_psigs_contract(sandbox.client(0), 'unit', pubkey, message, signature, debug=verbose)
        return 


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cust_close_token", "-c", help="close token which consists of message, pubkey and signature in json")
    parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")
    args = parser.parse_args()

################################
verbose = args.verbose
# cust_close_json = read_json_file(args.cust_close_token)
# (merch_pk, message, signature) = get_cust_close_token(cust_close_json)
# if verbose:
#     print("pk: ", json.dumps(merch_pk, indent=4))
#     print("msg: ", message)
#     print("sig: ", signature)

m0 = "0x67a6833570f081f32b47b8f56e95f5b627f7ea78d08d49f5a1e1c16e6eadcd37" 
m1 = "0xc498a81ec499243e5cee4befdcbc26d44a2295f27580cbff5df093853d210e29"
m2 = "0xa1c2c937b7c9b1840e66c177c19a3d14668df0252719cddccc9230c44fd48d58"
m3 = "0x5b81b9f14659c653d0a13844839989f5558a3c8f9fd8b7081fd79504a6cb775c"
#m3 = "0x231f6649b82d9f059b142df6ecec9085842692e19cca7636cb138500c5330527"
#m3 = "0xc1e6caf46394f1e438d766d2170bac14ef3e0e4aadb3b87f11de6403a484ba47"

message = [m0, m1, m2, m3]
#signature = {"s1":"166574b7d6e32eb60016df487172a3fb8d56f08be74630caf8b619d369e6a631e440fa05f3c00e01ffa39289623ff3750244e780f468174130bfd5bb760a83d0c9748ccc64845dfb2af7dca55e6483e3519af00fdd0ef3059b67d25452793e0c","s2":"1470c3d6dd5511afafad40e7454deede3181ba063b495ca977c209dbd3d28bb135072eee8aac9233fbde7edb225503ef0bc25341d7e357e3490579df30e4c8e62290600460daafe98c32895679702036a3656782f490c74524590de2fd06ea2a"}
#merch_pk = {"Y4":"0e2925220ac84a6f50d327adff2cc42ffe34ef7fd23931178bd898fe7ffb8bca73d6cc9a79f00976f44f5fa12359d8070205e16d783084596bc4b6cc5bf09a5f01402210a77904d7e96e35582155b7aacd65839cd06d9a95b577d28b0a6cd72b104a1a5c4809f6fe3019f89e77cf257c7a8ea188dbe5966b2cf8c92c9811a7504cb937e948cf23c07f76fa280eca624702e18c50d697cf21f2428248866ae2fd5396adc032a32630a0c1ef6d59e5f4082ecb5a9dfff1192aaf6db27363808ed6","Y0":"14bc48335fb2c240909738c6ba97b9f114ac38885fc4c8f680bd949fad3155bb34dc14c6f9f1903f331e3733abde83e310435fc07d517b5da3c0ced536dbd9e822609c711e5b5a849c9e618b7796242153e83ec54ed8ca680773e6f462d4b5aa0bdda52cb19242c83bc7169d0dcbd7645a282398b43b77002db7ada3ce53e032e0e71c7cb72470794ad3257f80f9042814208a7724e1a3cd4520004faf3a8a4285ce1a8942c19e5c94a3534ea1d05ef46c0b678332ee6b7ed751ff40e652a78b","Y2":"0a6ca6e607695904f8d7ae72edb683a30f5aeecdf4fe59a398c31d101e1de82a47588915854a8bb20d74f04f035e48db0603ba448c69177ae2c174c28745a6fb358a14fb90a410e8d5ce112c267b9713c68ce8ac12af0c08475369c88e627f02098234f30d97ad897a54cc976dcb0011663aeaff54d3de8937d96d337db0f7c838e7b39dc7ea3fb2a209ab856a64efe01428405899293b2c7b10b663b4c0eeadf3d5a6c418ead604b8cd06f31bd4acf3dc5640b789acc5d42ab11a642eeeebe0","g2":"14fbddce30e1a72f7e8e6360386deb0281f7bde1f190af3158e3219007476d3d035adbfcb0396f85e211c882d08911e814a64fd55aee07b7cbd29e12c0a99389466031d96ac46c6117ad9faca9fdf3c481d422ee9dddd8c3dfa9edb9e4c487bb0675eba5a9396b97f1a7a3fea208df03a3f238d98d1c3dbb37b500c29ebf2a12cf54be35f3793dfb740cbaf45b9cbef819b3a4fe8f63c3f3bcdf981e9d23620b957fbeb4471f082fd7e0a804de11bf97594b7dc278d5d0bfcfb97f0d82915bfa","X":"0787339d3c4a6871a5d1ce22bc500fb76513c688d2a9ef87b903f59c2c8942d5836675da315a444829fb74e9b95f8afa18df13c5d73badef85a8e742b29bf055e4b73123c8ed4c5f4536f9fd4675b4a267604b5b5d44e77707d6865c51c3c4b515b31f55f5255a78f4f182f68d11c8d923ad57eb3c7cda93f308495df7e397a1abc1ac98e9a12e68e37fc5cb900bb52f126d1dbc0fd839a78d937c2c7662002442865d8fffba016f105c9a145a54212bb9d4f15836ba32b79013eb1354f628db","Y1":"0550c8512ce93251f150f81985c9b2c3be3c4b7617c6601c410b4cffd13aee90d191cbac85d20a13256a448cdf1bcac10b0e25ee79c90dc3799ac0f3445ccbb3c7539a5cdade982cc950b49904c08224ab8cf06fb1465b5406a97e2ba7262a5214400ca4eced14f40b1334abec9ef8748f609d7c666daf5862c5fd77a6a247dd1ac689caff84e10bdcfdb8c9085db1bf095a420c53cf0685e047934eba48d57f1f19f9353749be41b364ca3c363aa649b1b8f027d2ac682f105d6166c8b96bd1","Y3":"0726b43a27056142000f9e8851ac51972852cf6b34cff087a66ff6fc1b00d0639fa4b0732a36bce3f82e0f976403817802ecec5ffb38649706bb332a456113c7a84bdea3f5b82b421aae5e8fbce5e29bbf96f940474c38ef741b8084e6e2202506cb23fbf89c51e1ae0a9b5930cf04903bc8c12230bed6ec683fa8026598ea48e31f8e5ebc7a21e3e6a54725d45af0460603ed333407d65cb304940bff127c36e066a7839dce8a251488ac90f09c8a0fa8a58a57c555864f38cded716f1ff4a7"}
#signature = {"s1":"1347d5b688f8a89a3fee5066628c5e423bf149a8265b2482dc2e1e5f5ae72efe8215eee2772695988876f80fdd26078002dad9ca2cd126581752e6db16dff942737a564851f8b8c088f5c7d2cfb0b3b17e1edb1b13f687c8376ed50e04120640","s2":"05c4718fbc5c0494f25a624c6703095a7cca12d99c22e5bdbf9ac0f32d015e99a24d976b10d7146f22648929d7d7c42f11bbdd7e2b2c4507deba21e5efd1899dcb1ab4d211a375947dfe6b3f64dec2863d3494ce69d62e5563e0a9ac9cb9811e"}
#merch_pk = {"X":"0787339d3c4a6871a5d1ce22bc500fb76513c688d2a9ef87b903f59c2c8942d5836675da315a444829fb74e9b95f8afa18df13c5d73badef85a8e742b29bf055e4b73123c8ed4c5f4536f9fd4675b4a267604b5b5d44e77707d6865c51c3c4b515b31f55f5255a78f4f182f68d11c8d923ad57eb3c7cda93f308495df7e397a1abc1ac98e9a12e68e37fc5cb900bb52f126d1dbc0fd839a78d937c2c7662002442865d8fffba016f105c9a145a54212bb9d4f15836ba32b79013eb1354f628db","g2":"14fbddce30e1a72f7e8e6360386deb0281f7bde1f190af3158e3219007476d3d035adbfcb0396f85e211c882d08911e814a64fd55aee07b7cbd29e12c0a99389466031d96ac46c6117ad9faca9fdf3c481d422ee9dddd8c3dfa9edb9e4c487bb0675eba5a9396b97f1a7a3fea208df03a3f238d98d1c3dbb37b500c29ebf2a12cf54be35f3793dfb740cbaf45b9cbef819b3a4fe8f63c3f3bcdf981e9d23620b957fbeb4471f082fd7e0a804de11bf97594b7dc278d5d0bfcfb97f0d82915bfa","Y1":"0550c8512ce93251f150f81985c9b2c3be3c4b7617c6601c410b4cffd13aee90d191cbac85d20a13256a448cdf1bcac10b0e25ee79c90dc3799ac0f3445ccbb3c7539a5cdade982cc950b49904c08224ab8cf06fb1465b5406a97e2ba7262a5214400ca4eced14f40b1334abec9ef8748f609d7c666daf5862c5fd77a6a247dd1ac689caff84e10bdcfdb8c9085db1bf095a420c53cf0685e047934eba48d57f1f19f9353749be41b364ca3c363aa649b1b8f027d2ac682f105d6166c8b96bd1","Y0":"14bc48335fb2c240909738c6ba97b9f114ac38885fc4c8f680bd949fad3155bb34dc14c6f9f1903f331e3733abde83e310435fc07d517b5da3c0ced536dbd9e822609c711e5b5a849c9e618b7796242153e83ec54ed8ca680773e6f462d4b5aa0bdda52cb19242c83bc7169d0dcbd7645a282398b43b77002db7ada3ce53e032e0e71c7cb72470794ad3257f80f9042814208a7724e1a3cd4520004faf3a8a4285ce1a8942c19e5c94a3534ea1d05ef46c0b678332ee6b7ed751ff40e652a78b","Y3":"0726b43a27056142000f9e8851ac51972852cf6b34cff087a66ff6fc1b00d0639fa4b0732a36bce3f82e0f976403817802ecec5ffb38649706bb332a456113c7a84bdea3f5b82b421aae5e8fbce5e29bbf96f940474c38ef741b8084e6e2202506cb23fbf89c51e1ae0a9b5930cf04903bc8c12230bed6ec683fa8026598ea48e31f8e5ebc7a21e3e6a54725d45af0460603ed333407d65cb304940bff127c36e066a7839dce8a251488ac90f09c8a0fa8a58a57c555864f38cded716f1ff4a7","Y2":"0a6ca6e607695904f8d7ae72edb683a30f5aeecdf4fe59a398c31d101e1de82a47588915854a8bb20d74f04f035e48db0603ba448c69177ae2c174c28745a6fb358a14fb90a410e8d5ce112c267b9713c68ce8ac12af0c08475369c88e627f02098234f30d97ad897a54cc976dcb0011663aeaff54d3de8937d96d337db0f7c838e7b39dc7ea3fb2a209ab856a64efe01428405899293b2c7b10b663b4c0eeadf3d5a6c418ead604b8cd06f31bd4acf3dc5640b789acc5d42ab11a642eeeebe0","Y4":"0e2925220ac84a6f50d327adff2cc42ffe34ef7fd23931178bd898fe7ffb8bca73d6cc9a79f00976f44f5fa12359d8070205e16d783084596bc4b6cc5bf09a5f01402210a77904d7e96e35582155b7aacd65839cd06d9a95b577d28b0a6cd72b104a1a5c4809f6fe3019f89e77cf257c7a8ea188dbe5966b2cf8c92c9811a7504cb937e948cf23c07f76fa280eca624702e18c50d697cf21f2428248866ae2fd5396adc032a32630a0c1ef6d59e5f4082ecb5a9dfff1192aaf6db27363808ed6"}

signature = {"s1":"09992a607f59d7bbaa4f330ba4c04b88398efa7b2c0ed53fb4e251affa1961b19a08af4e47631a88f92e58b6493e74ec0d5d0f95bacd38499785cc13a7115f0a23039d622aeb267bffb482d87e19a0ecddad2184041c4dbb0ec7a0c6b20f9c76","s2":"187b86422d9d0b6265be8da52f620f2b1c1bc07d33afe19a8fd13ed497c543aaeae9e551608d20f44bbbd5f6470af82b0d4198761aa2e6a481ecd2e37a30f566ddf9dd6a3c4c0d1c29c24c49db0bb88c2ea6df31c5deee65e21f07e2fd4c9014"}
merch_pk = {"Y2":"0a6ca6e607695904f8d7ae72edb683a30f5aeecdf4fe59a398c31d101e1de82a47588915854a8bb20d74f04f035e48db0603ba448c69177ae2c174c28745a6fb358a14fb90a410e8d5ce112c267b9713c68ce8ac12af0c08475369c88e627f02098234f30d97ad897a54cc976dcb0011663aeaff54d3de8937d96d337db0f7c838e7b39dc7ea3fb2a209ab856a64efe01428405899293b2c7b10b663b4c0eeadf3d5a6c418ead604b8cd06f31bd4acf3dc5640b789acc5d42ab11a642eeeebe0","Y1":"0550c8512ce93251f150f81985c9b2c3be3c4b7617c6601c410b4cffd13aee90d191cbac85d20a13256a448cdf1bcac10b0e25ee79c90dc3799ac0f3445ccbb3c7539a5cdade982cc950b49904c08224ab8cf06fb1465b5406a97e2ba7262a5214400ca4eced14f40b1334abec9ef8748f609d7c666daf5862c5fd77a6a247dd1ac689caff84e10bdcfdb8c9085db1bf095a420c53cf0685e047934eba48d57f1f19f9353749be41b364ca3c363aa649b1b8f027d2ac682f105d6166c8b96bd1","g2":"14fbddce30e1a72f7e8e6360386deb0281f7bde1f190af3158e3219007476d3d035adbfcb0396f85e211c882d08911e814a64fd55aee07b7cbd29e12c0a99389466031d96ac46c6117ad9faca9fdf3c481d422ee9dddd8c3dfa9edb9e4c487bb0675eba5a9396b97f1a7a3fea208df03a3f238d98d1c3dbb37b500c29ebf2a12cf54be35f3793dfb740cbaf45b9cbef819b3a4fe8f63c3f3bcdf981e9d23620b957fbeb4471f082fd7e0a804de11bf97594b7dc278d5d0bfcfb97f0d82915bfa","Y0":"14bc48335fb2c240909738c6ba97b9f114ac38885fc4c8f680bd949fad3155bb34dc14c6f9f1903f331e3733abde83e310435fc07d517b5da3c0ced536dbd9e822609c711e5b5a849c9e618b7796242153e83ec54ed8ca680773e6f462d4b5aa0bdda52cb19242c83bc7169d0dcbd7645a282398b43b77002db7ada3ce53e032e0e71c7cb72470794ad3257f80f9042814208a7724e1a3cd4520004faf3a8a4285ce1a8942c19e5c94a3534ea1d05ef46c0b678332ee6b7ed751ff40e652a78b","Y4":"0e2925220ac84a6f50d327adff2cc42ffe34ef7fd23931178bd898fe7ffb8bca73d6cc9a79f00976f44f5fa12359d8070205e16d783084596bc4b6cc5bf09a5f01402210a77904d7e96e35582155b7aacd65839cd06d9a95b577d28b0a6cd72b104a1a5c4809f6fe3019f89e77cf257c7a8ea188dbe5966b2cf8c92c9811a7504cb937e948cf23c07f76fa280eca624702e18c50d697cf21f2428248866ae2fd5396adc032a32630a0c1ef6d59e5f4082ecb5a9dfff1192aaf6db27363808ed6","X":"0787339d3c4a6871a5d1ce22bc500fb76513c688d2a9ef87b903f59c2c8942d5836675da315a444829fb74e9b95f8afa18df13c5d73badef85a8e742b29bf055e4b73123c8ed4c5f4536f9fd4675b4a267604b5b5d44e77707d6865c51c3c4b515b31f55f5255a78f4f182f68d11c8d923ad57eb3c7cda93f308495df7e397a1abc1ac98e9a12e68e37fc5cb900bb52f126d1dbc0fd839a78d937c2c7662002442865d8fffba016f105c9a145a54212bb9d4f15836ba32b79013eb1354f628db","Y3":"0726b43a27056142000f9e8851ac51972852cf6b34cff087a66ff6fc1b00d0639fa4b0732a36bce3f82e0f976403817802ecec5ffb38649706bb332a456113c7a84bdea3f5b82b421aae5e8fbce5e29bbf96f940474c38ef741b8084e6e2202506cb23fbf89c51e1ae0a9b5930cf04903bc8c12230bed6ec683fa8026598ea48e31f8e5ebc7a21e3e6a54725d45af0460603ed333407d65cb304940bff127c36e066a7839dce8a251488ac90f09c8a0fa8a58a57c555864f38cded716f1ff4a7"}

run_sig_verify(merch_pk, message, signature, True)
