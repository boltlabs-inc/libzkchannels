from tools.bls12_381 import G1, G2, Fr, pairing_check
from tools import constants, paths, utils
from launchers.sandbox import Sandbox

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

def check_contract(client, contract, arg, expected_storage):
    contract_file = "./pairing_neg.tz"
    write_contract(contract, contract_file)
    client.typecheck(contract_file)
    result = client.run_script(contract_file, 'None', arg)
    assert result.storage == f'(Some {expected_storage})'

def run_pairing_negation_contract(client):
    g1 = G1.random()
    g2 = G2.random()
    # e(g1, g2) * e(g1, g2^-1) = 1
    args = [(g1, g2), (g1, G2.neg(g2))]
    # check if equality holds
    result = pairing_check(args)
    assert result

    stack_args = [(G1.to_hex(g1), G2.to_hex(g2)) for g1, g2 in args]
    stack_args = [f'Pair {g1} {g2}' for g1, g2 in stack_args]
    stack_args = f'{{ {"; ".join(stack_args)} }}'
    print("CONTRACT: ", CONTRACTS['pairing_check'])
    print("STACK ARGS: ", stack_args)
    check_contract(client, CONTRACTS['pairing_check'], stack_args, result)

def run_psigs_contract(client, storage, pubkey, debug=False):
    # pylint: disable=line-too-long

    # The public key, signature, and inputs are generated from libzkchannels.
    X = pubkey['X']
    Y0 = pubkey['Y0']
    Y1 = pubkey['Y1']
    contract = \
            f'''
            # The contract returns if the proof verifies, and fails otherwise.
            storage {storage};

            # The parameter is a pair consisting of:
            # * A pair of Fr element inputs, m0 and m1
            # * A signature, consisting of
            #   * G1 points `h1` and `h2`
            # * A mpk, consisting of
            #   * G2 point `g2`
            parameter (pair (pair bls12_381_fr bls12_381_fr)
                            (pair (pair bls12_381_g1_compressed bls12_381_g1_compressed)
                                  bls12_381_g2_compressed));

            code
              {{
                # Discard storage and unpair. Result stack should be
                # message{{m0:m1}} : signature{{s1:s2}} : mpk{{g2}}.
                CAR; UNPPAIPPAIIR;

                # Push the public key. Result stack should be
                # message{{m0:m1}} 
                # : signature{{h1:h2}}
                # : mpk{{g2}}
                # : pk_{{X:Y0:Y1}} # should be Y1, Y0, X (all in G2)
                DIP 5
                    {{
                      PUSH bls12_381_g2_compressed {Y1};
                      PUSH bls12_381_g2_compressed {Y0};
                      PUSH bls12_381_g2_compressed {X}
                    }};

                # Compute prod_1 as            
                # (Y0 * m0) + (Y1 * m1) + X
                # Result stack should be
                # prod1_x
                # : message{{m0:m1}}
                # : signature{{s1:s2}}
                # : mpk{{g2}}
                # : pk_{{X:Y0:Y1}}
                # : PROD1
                DUP; DUP 8; DECOMPRESS; MUL;
                DUP 3; DUP 10; DECOMPRESS; MUL;
                ADD; DUP 7; DECOMPRESS; ADD;

                # Push the list for the pairing check. The list should be
                # [ (s1, prod1_x);
                #   (s2, g2 ^ -1) ]
                NIL (pair bls12_381_g1 bls12_381_g2);
                DUP 2; DUP 6; DECOMPRESS; PAIR; CONS;
                DUP 7; DECOMPRESS; NEG; DUP 7; DECOMPRESS; PAIR; CONS;

                # Compute the pairing check and fail if it doesn't succeed
                PAIRING_CHECK;
                ASSERT;

                # Drop the stack
                DROP 9;

                # return no operations
                UNIT; 
                NIL operation; 
                PAIR
              }}'''

    # Typecheck the contract
    filename = f'./ps_sig_m2.tz'
    with open(filename, 'w') as file:
        file.write(contract)
        CONTRACTS['ps_sig'] = filename
    client.typecheck(CONTRACTS['ps_sig'])

    # ell = 2
    m_0 = "515e204c0b24891dfd3927deb27dcd8fba8b95e88ea55361f7046700322e1bbd"
    m_1 = "144484904ac59c1fa7c2273b2f301824b846fc0e848e803239c8f7b54795670f"
    m0 = (bytes.fromhex(m_0))[::-1]
    m1 = (bytes.fromhex(m_1))[::-1]
    m0 = "0x" + m0.hex()
    m1 = "0x" + m1.hex()

    # sig (\sigma_1, \sigma_2) <- G1
    # compressed form
    sig_s1 = "0x884af98175315b2d371343036bec675eca3f718924684f5be6e382cf7f104ef48ff4fcc512c6f74009b899d07e1a5eb8"  # noqa
    sig_s2 = "0x813776610b0a694deac364d0a3f39c421c0850f224df4ab358cb6c2842a9825bcc7c4aaa2eb9872075225c6ee6c6fa56"  # noqa
    # mpk <- G2
    # compressed form
    g2 = "0x94fbddce30e1a72f7e8e6360386deb0281f7bde1f190af3158e3219007476d3d035adbfcb0396f85e211c882d08911e814a64fd55aee07b7cbd29e12c0a99389466031d96ac46c6117ad9faca9fdf3c481d422ee9dddd8c3dfa9edb9e4c487bb"

    message = f"Pair {m0} {m1}"
    signature_and_mpk = f"Pair (Pair {sig_s1} {sig_s2}) {g2}"
    stack_args = f"Pair ({message}) ({signature_and_mpk})"

    result = client.run_script(CONTRACTS['ps_sig'], 'Unit', stack_args, trace_stack=debug)
    print(result.storage)


def run_pairing_test(pubkey):
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))
        # Launch a second node on the same private tezos network
        sandbox.add_node(1, params=constants.NODE_PARAMS)
        # Test the pairing contracts
        run_pairing_negation_contract(sandbox.client(0))
        # Test PS sigs verification contract
        run_psigs_contract(sandbox.client(0), 'unit', pubkey)
        return 


if __name__ == "__main__":
    mk_contract('pairing_check',
                f'list (pair ({bls("g1")}) ({bls("g2")}))',
                'bool',
                'PAIRING_CHECK')

    # pub key (X, Y0, Y1)
    X = "0x8a6ca6e607695904f8d7ae72edb683a30f5aeecdf4fe59a398c31d101e1de82a47588915854a8bb20d74f04f035e48db0603ba448c69177ae2c174c28745a6fb358a14fb90a410e8d5ce112c267b9713c68ce8ac12af0c08475369c88e627f02"
    Y0 = "0x94bc48335fb2c240909738c6ba97b9f114ac38885fc4c8f680bd949fad3155bb34dc14c6f9f1903f331e3733abde83e310435fc07d517b5da3c0ced536dbd9e822609c711e5b5a849c9e618b7796242153e83ec54ed8ca680773e6f462d4b5aa"
    Y1 = "0xa550c8512ce93251f150f81985c9b2c3be3c4b7617c6601c410b4cffd13aee90d191cbac85d20a13256a448cdf1bcac10b0e25ee79c90dc3799ac0f3445ccbb3c7539a5cdade982cc950b49904c08224ab8cf06fb1465b5406a97e2ba7262a52"
    pubkey = {'X': X, 'Y0': Y0, 'Y1': Y1, }
    run_pairing_test(pubkey)
