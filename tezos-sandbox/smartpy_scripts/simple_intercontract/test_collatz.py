import time
from tools import constants, paths, utils
from launchers.sandbox import Sandbox

BAKE_ARGS = ['--minimal-timestamp']

def scenario_basic_call():
    """ a private tezos network, initialized with network parameters
        and some accounts. """
    with Sandbox(paths.TEZOS_HOME, constants.IDENTITIES) as sandbox:
        # Launch node running protocol alpha
        sandbox.add_node(0, params=constants.NODE_PARAMS)
        utils.activate_alpha(sandbox.client(0))

        # Launch a baker associated to node 0, baking on behalf of delegate
        # baker5
        sandbox.add_baker(0, 'baker5', proto=constants.ALPHA_DAEMON)
        # Wait for second node to update its protocol to alpha, if not
        # it may not know yet the `wait_for_inclusion` operation which is
        # protocol specific

        # (Originally this sleep was 15 seconds)
        time.sleep(5)

        even = "collatz_even.tz"
        even_name = "even_contract"
        burncap = "9"
        args = ["--init", "Unit", "--burn-cap", burncap]
        sandbox.client(0).originate(even_name, 0, "bootstrap1", even, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)


        odd = "collatz_odd.tz"
        odd_name = "odd_contract"
        burncap = "9"
        args = ["--init", "Unit", "--burn-cap", burncap]
        sandbox.client(0).originate(odd_name, 0, "bootstrap1", odd, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        even_addr = sandbox.client(0).get_contract_address(even_name)
        odd_addr = sandbox.client(0).get_contract_address(odd_name)

        main = "collatz_main.tz"
        main_name = "main_contract"
        burncap = "9"
        storage = '(Pair 0 (Pair "{c1}" "{c2}"))'.format(c1=even_addr, c2=odd_addr)
        args = ["--init", storage, "--burn-cap", burncap]
        sandbox.client(0).originate(main_name, 0, "bootstrap1", main, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        amt = 0
        sandbox.client(0).transfer(amt, 'bootstrap1', main_name,
                                   ['--entrypoint', 'run',
                                    '--burn-cap', burncap, 
                                    '--arg', '42'])

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        
if __name__ == "__main__":
    scenario_basic_call() 
