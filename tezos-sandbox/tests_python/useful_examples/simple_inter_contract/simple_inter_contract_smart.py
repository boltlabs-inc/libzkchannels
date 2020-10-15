import smartpy as sp

# CheckSig represents the external contract that will check the signature of the
# state. Right now this is just checking that the input is greater than 9.
class CheckSig(sp.Contract):
    @sp.entry_point
    def run(self, params):
        sp.set_type(params.x, sp.TNat)
        sp.if params.x > 9:
            sp.transfer(True, sp.mutez(0), params.k)
        sp.else:
            sp.transfer(False, sp.mutez(0), params.k)

class MainContract(sp.Contract):
    def __init__(self, checkSig):
        self.init(checkSig  = checkSig,
                  valid = False)

    @sp.entry_point
    def run(self, x):
        tk = sp.TRecord(k = sp.TContract(sp.TBool), x = sp.TNat)
        params = sp.record(k = sp.self_entry_point("receiveResult"), x = x)
        sp.transfer(params, sp.mutez(0), sp.contract(tk, self.data.checkSig).open_some())

    @sp.entry_point
    def receiveResult(self, result):
        self.data.valid = result

@sp.add_test(name = "VerifySig")
def test():
    scenario = sp.test_scenario()
    scenario.h1("VerifySig - Inter-Contract Calls")
    check_sig = CheckSig()
    scenario += check_sig
    mainContract = MainContract(checkSig = check_sig.address)
    scenario += mainContract
    scenario += mainContract.run(9)
    scenario.verify(mainContract.data.valid == False)
    scenario += mainContract.run(10)
    scenario.verify(mainContract.data.valid == True)