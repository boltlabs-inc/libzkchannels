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
        sandbox.add_baker(0, 'baker5', proto=constants.ALPHA_DAEMON)
        time.sleep(5)

        # Originate external contract
        # This is a dummy contract for the one that will check the signature.
        # For now, it returns True input is greate than 9, else False.
        contract_external = "simple_inter_contract/external_contract.tz"
        contract_external_name = "external_contract"
        burncap = "9"
        args = ["--init", "Unit", "--burn-cap", burncap]
        sandbox.client(0).originate(contract_external_name, 0, "bootstrap1", contract_external, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        external_contract_addr = sandbox.client(0).get_contract_address(contract_external_name)

        # Originate the main contract
        contract_main = "simple_inter_contract/main_contract.tz"
        contract_main_name = "main_contract"
        burncap = "9"
        storage = '(Pair \"{addr}\" False)'.format(addr=external_contract_addr)
        args = ["--init", storage, "--burn-cap", burncap]
        sandbox.client(0).originate(contract_main_name, 0, "bootstrap1", contract_main, args)

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Test running the main contract with 9 as an input. 
        # The storage field 'valid' should be set to False.
        amt = 0
        storage = "9"
        sandbox.client(0).transfer(amt, 'bootstrap1', contract_main_name,
                                   ['--entrypoint', 'run',
                                    '--burn-cap', burncap, 
                                    '--arg', storage])

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        # Test running the main contract with 10 as an input. 
        # The storage field 'valid' should be set to True.
        amt = 0
        storage = "10"
        sandbox.client(0).transfer(amt, 'bootstrap1', contract_main_name,
                                   ['--entrypoint', 'run',
                                    '--burn-cap', burncap, 
                                    '--arg', storage])

        sandbox.client(0).bake('baker5', BAKE_ARGS)

        
if __name__ == "__main__":
    scenario_basic_call() 
