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
    contract_file = "./pairing_basic.tz"
    write_contract(contract, contract_file)
    client.typecheck(contract_file)
    result = client.run_script(contract_file, 'None', arg)
    assert result.storage == f'(Some {expected_storage})'

def run_pairing_property_contract(client):
    g1 = G1.random()
    g2 = G2.random()
    a = Fr.random()
    b = Fr.random()
    ab = a * b
    # e(g1^a, g2^b) * e(g1, g2^-ab) = 1
    args = [(G1.mul(g1, a), G2.mul(g2, b)), (g1, G2.neg(G2.mul(g2, ab)))]

    # check if equality holds
    result = pairing_check(args)
    assert result

    stack_args = [(G1.to_hex(g1), G2.to_hex(g2)) for g1, g2 in args]
    stack_args = [f'Pair {g1} {g2}' for g1, g2 in stack_args]
    stack_args = f'{{ {"; ".join(stack_args)} }}'
    print("CONTRACT: ", CONTRACTS['pairing_check'])
    print("STACK ARGS: ", stack_args)
    check_contract(client, CONTRACTS['pairing_check'], stack_args, result)

def run_groth16(client):
    # pylint: disable=line-too-long

    # The verifying key, proof, and inputs are generated from ZoKrates.
    # The circuit proves knowledge of a square root of 113569.

    vk_a = "0x1040577c7d349e332735fc947c868c24a665f812f5dc1e7f60e65e2df80be2267a4b7341ed2287285fccd517acd96d910abba947235c364553aa6445f2f2b3a1a728225a330286ba5197ab87f0edc560d89fc7b623812f7d0d633341726e597a"  # noqa
    vk_b = "0x0e9383f98df2c6e8b5b45f3876c3384596a0cdbc41349f83c4380bf463a050cdbd1d5057aa483a642e66486d1ed7362a1869e423c3877095e215c17282b11108601166f928043254bbce603bf86f4cec9f2e97e9660e98e4f5bce9b2b3bbacb40946b702ccfcc9a31e0bfc1543a2128edcc95807740a2310ae25eb47b935648e392c58dfae5b5e899d3b970d64e4e9e209741ea8bfedcfcc16b3fd890ff02c788ec0943feaaf01bbb354317acb85fcfd611133e4e563d53ca4e0f50e21cf2e7e"  # noqa
    vk_gamma = "0x16dcbd28bff336c2649c7dd1d8391ac7ce6f7ef0124a9db7a4a485a124199eded7ce963c1c18aee1eca9994fe06f192c00e0fb653e1fc737d8d0e2f2f91424ca01f6e6e7c5c04f1c43db03a2900cf6b942aaed6ae77daea6200e094b78c38d770028d531a9d1a118ec23d5a39be7aa6dc28f778da1988856d2235c4a35e81fa48380f050d4baf7ebd7b5e058bf294da916afc34562f097c02a8fcbcf62a00de44f8ae6cfa7acb8ad254e3aeea8b2af12f65b7ee0f54855cb9bd432f3436f238f"  # noqa
    vk_delta = "0x10c6d5cdca84fc3c7f33061add256f48e0ab03a697832b338901898b650419eb6f334b28153fb73ad2ecd1cd2ac67053161e9f46cfbdaf7b1132a4654a55162850249650f9b873ac3113fa8c02ef1cd1df481480a4457f351d28f4da89d19fa405c3d77f686dc9a24d2681c9184bf2b091f62e6b24df651a3da8bd7067e14e7908fb02f8955b84af5081614cb5bc49b416d9edf914fc608c441b3f2eb8b6043736ddb9d4e4d62334a23b5625c14ef3e1a7e99258386310221b22d83a5eac035c"  # noqa
    vk_gamma_a = "0x03535a322edd23c55b0ca025e54d450d95df49cc9ee873dcd500e8219f4771264bf159b3b105954d85c7bea8ffe1ea0400c767fe58989366c2837fba76f1b4f46644f19be8ad01e22d894b649e427e0d7e04677ee3919d982f0f96bb0a2f0c34"  # noqa
    vk_gamma_b = "0x11f5b5db1da7f1f26217edcce2219d016003af6e5b4d1ca3ad0ff477e354717e658bf16beddc4f4fb76ce39d3327811e0601709dc7ed98c70463cfa1ba33f99851b52b51d1a042d7425bec6277287441c399973632445ce61e7fdd63a70f0f60"  # noqa
    vk_gamma_c = "0x063bd6e11e2fcaac1dd8cf68c6b1925a73c3c583e298ed37c41c3715115cf96358a42dbe85a0228cbfd8a6c8a8c54cd015b5ae2860d1cc47f84698d951f14d9448d03f04df2ca0ffe609a2067d6f1a892163a5e05e541279134cae52b1f23c6b"  # noqa

    contract = \
            f'''
            # The contract returns if the proof verifies, and fails otherwise.
            storage unit;

            # The parameter is a pair consisting of:
            # * A pair of Fr element inputs, x and y
            # * A proof, consisting of
            #   * G1 points `a` and `c`
            #   * G2 point `b`
            parameter (pair (pair bls12_381_fr bls12_381_fr)
                            (pair (pair bls12_381_g1 bls12_381_g2)
                                  bls12_381_g1));

            code
              {{
                # Discard storage and unpair. Result stack should be
                # input{{x:y}} : proof{{a:b:c}}.
                CAR; UNPPAIPPAIIR;

                # Push the verifying key. Result stack should be
                # input{{x:y}}
                # : proof{{a:b:c}}
                # : vk_{{a:b:gamma:delta:gamma_{{a:b:c}}}}
                DIP 5
                    {{
                      PUSH bls12_381_g1 {vk_gamma_c};
                      PUSH bls12_381_g1 {vk_gamma_b};
                      PUSH bls12_381_g1 {vk_gamma_a};
                      PUSH bls12_381_g2 {vk_delta};
                      PUSH bls12_381_g2 {vk_gamma};
                      PUSH bls12_381_g2 {vk_b};
                      PUSH bls12_381_g1 {vk_a}
                    }};

                # Compute vk_x as
                # (vk_gamma_b * input_x) + (vk_gamma_c * input_y) + vk_gamma_a
                # Result stack should be
                # vk_x
                # : input{{x:y}}
                # : proof{{a:b:c}}
                # : vk_{{a:b:gamma:delta:gamma_{{a:b:c}}}}
                DUP; DUP 12; MUL;
                DUP 3; DUP 14; MUL;
                ADD; DUP 11; ADD;

                # Push the list for the pairing check. The list should be
                # [ (proof_a, proof_b);
                #   (-vk_x, vk_gamma);
                #   (-proof_c, vk_delta);
                #   (-vk_a, vk_b) ]
                NIL (pair bls12_381_g1 bls12_381_g2);
                DUP  9; DUP 9; NEG; PAIR; CONS;
                DUP 11; DUP 8; NEG; PAIR; CONS;
                DUP 10; DUP 3; NEG; PAIR; CONS;
                DUP  6; DUP 6;      PAIR; CONS;

                # Compute the pairing check and fail if it doesn't succeed
                PAIRING_CHECK; ASSERT;

                # Drop the stack
                DROP 13;

                # return no operations
                UNIT; NIL operation; PAIR


              }}'''

    # Typecheck the contract
    filename = f'./groth16.tz'
    with open(filename, 'w') as file:
        file.write(contract)
        CONTRACTS['groth16'] = filename
    client.typecheck(CONTRACTS['groth16'])

    # Check that the contract succeeds with valid input
    input_x = "0xa1bb010000000000000000000000000000000000000000000000000000000000"  # noqa
    input_y = "0x0100000000000000000000000000000000000000000000000000000000000000"  # noqa
    proof_a = "0x0a2841423326ab08f5f406409775e43fa0f9a0b97631fa85d2dd9242507d25059e9cf48b8b98f99a0008671423a148ec106d70637056972ef49fb6f62de2e89ba3682b9972292b6bb4e6f53799a75d2f8001ccfde280d8ac05fc209352236cbd"  # noqa
    proof_b = "0x0fced939fb1ad733f99669f50a383ef632f6d41dfbde434a6715afd5c7dfbb7bc5835e058ad8b590c7b38dd137d0bd0f0e1540f1b45d8aa626c360e2ea484a116243f7c802034de915db6b18d5303946f676e423cbd6046d37a82208d500625a11c7250ccb953a7ee49d704ad14de4b727733cff7cf06875d8b6444f3c0a8cbf0bd980e539c74bd5b37bb15fe816f23407d269193105fda71adf35fae9309d9d46729fcd4685699097a86f0460a2bc8b16293940cabfdcfe0f27e4107e74e90c"  # noqa
    proof_c = "0x0a1fb5a144ca3bdfe4ad0f183cf71dd7fdd28cbef4fcd47b5b419f65186703f62ecaaa1255fa21a6ebdd917ab1f9bd9707de7066865e2ff3875e22088619125a0d4088a622ab42224425ef89a5a149ce2db9c8292b62c7e7aaa7e87f3535304b"  # noqa

    inputs = f"Pair {input_x} {input_y}"
    proof = f"Pair (Pair {proof_a} {proof_b}) {proof_c}"
    stack_args = f"Pair ({inputs}) ({proof})"

    client.run_script(CONTRACTS['groth16'], 'Unit', stack_args)


def run_pairing_tests():
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME,
                constants.IDENTITIES) as sandbox:
        # Launch node running protocol Alpha
        sandbox.add_node(0)
        utils.activate_alpha(sandbox.client(0))
        # Launch a second node on the same private tezos network
        sandbox.add_node(1)
        # Launch a baker associated to node 0, baking on behalf of delegate
        # bootstrap5
        sandbox.add_baker(0, 'bootstrap5', proto=constants.ALPHA_DAEMON)
        # first client tells node 0 to transfer money for an account to another
        # receipt is an object representing the client answer
        receipt = sandbox.client(0).transfer(500, 'bootstrap1', 'bootstrap3')
        transfer_hash = receipt.operation_hash
        print("transfer hash for bootstrap1 -> bootstrap3: ", transfer_hash)
        # Run the pairing contract
        run_pairing_property_contract(sandbox.client(0))
        run_groth16(sandbox.client(0))
        return 


if __name__ == "__main__":
    mk_contract('pairing_check',
                f'list (pair ({bls("g1")}) ({bls("g2")}))',
                'bool',
                'PAIRING_CHECK')

    run_pairing_tests()
