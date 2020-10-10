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

def run_psigs_contract(client, storage, pubkey, message, signature, debug=False):
    # pylint: disable=line-too-long

    # The public key, signature, and inputs are generated from libzkchannels.
    X = pubkey.get('X')
    Y0 = pubkey.get('Y0')
    Y1 = pubkey.get('Y1')
    Y2 = pubkey.get('Y2')
    Y3 = pubkey.get('Y3')
    g2 = pubkey.get('g2')
    m0, m1, m2, m3 = message
    sig_s1, sig_s2 = signature
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
                DUP 9; ADD;  # prod1_x = (Y0 * m0) + (Y1 * m1) + (Y2 * m2) + (Y3 * m3) + X

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
    parser.add_argument("--cust_close_token", "-c", help="close token which consists of message, pubkey and signature in json", required=True)
    parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")
    args = parser.parse_args()

################################
verbose = args.verbose
cust_close_json = read_json_file(args.cust_close_token)
(merch_pk, message, signature) = get_cust_close_token(cust_close_json)
if verbose:
    print("pk: ", json.dumps(merch_pk, indent=4))
    print("msg: ", message)
    print("sig: ", signature)

run_sig_verify(merch_pk, message, signature, True)
