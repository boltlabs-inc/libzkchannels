# Simple example of an inter-contract call to check if a number is CheckOdd
# Here, the external contract address is passed in as an argument when originating
# the main contract.

import smartpy as sp


# in this dummy example, an odd number is a valid signature
class CheckOdd(sp.Contract):
    @sp.entry_point
    def run(self, params):
        sp.if params.x % 2 == 1:
            sp.transfer(True, sp.mutez(0), params.k)
        sp.else:
            sp.transfer(False, sp.mutez(0), params.k)


class Collatz(sp.Contract):
    def __init__(self, checkOdd):
        self.init(checkOdd  = checkOdd,
                  result = False)

    @sp.entry_point
    def run(self, x):
        tk = sp.TRecord(k = sp.TContract(sp.TNat), x = sp.TNat)

        checkOdd = sp.contract(tk, self.data.checkOdd, entry_point = "run").open_some()
        kself = sp.contract(sp.TNat,
                            sp.to_address(sp.self),
                            entry_point = "receiveResult").open_some()
        param = sp.record(x = x, k = kself)

        sp.transfer(param, sp.mutez(0), checkOdd)

    @sp.entry_point
    def receiveResult(self, x):
        self.data.result = x


@sp.add_test(name = "Collatz")
def test():
    scenario = sp.test_scenario()
    scenario.h1("Inter-Contract Calls")
    scenario.h3("deploy external 'checkOdd' contract on chain")
    checkOdd = CheckOdd()
    scenario += checkOdd
    scenario.h3("define zkchannel contract on chain, referencing the checkOdd contract")
    collatz = Collatz(checkOdd = checkOdd.address)
    scenario += collatz
    scenario.h3("test contract with '23'")
    scenario += collatz.run(23)
