# This smart contract implements the zkchannel flow
import smartpy as sp

class PSSigContract(sp.Contract):
    @sp.entry_point
    def run(self, params):
        def checksig(params):
            sp.set_type(params.chanID, sp.TString)
            sp.set_type(params.revLock, sp.TBytes)
            sp.set_type(params.custBal, sp.TMutez)
            sp.set_type(params.merchBal, sp.TMutez)
            
            sp.set_type(params.s1, sp.TString)
            sp.set_type(params.s2, sp.TString)
            sp.set_type(params.g2, sp.TString)
            
            sp.set_type(params.merchPk0, sp.TString)
            sp.set_type(params.merchPk1, sp.TString)
            sp.set_type(params.merchPk2, sp.TString)
            sp.set_type(params.merchPk3, sp.TString)
            sp.set_type(params.merchPk4, sp.TString)
        
        
            dummy = sp.local('dummy', params.s1 + params.s2)
            out = sp.local('out', False)
            sp.if sp.len(dummy.value) > 5:
                out.value = True
            sp.else:
                out.value = False
           
            return out.value
                    
        # # For now, this is a dummy signature check
        sp.if checksig(params):
            data = sp.record(
                valid = True,
                newCustBal = params.custBal,
                newMerchBal = params.merchBal,
                newRevLock = params.revLock)
            sp.transfer(data, sp.mutez(0), params.k)
        sp.else:
            data = sp.record(
                valid = False,
                newCustBal = params.custBal,
                newMerchBal = params.merchBal,
                newRevLock = params.revLock)
            sp.transfer(data, sp.mutez(0), params.k)
            
class ZkChannel(sp.Contract):
    def __init__(self, revLock):
        self.init(
                  custBal           = sp.tez(0),
                  merchBal          = sp.tez(0),
                  revLock           = revLock)
                  
    @sp.entry_point
    def receiveCall(self, params):
        sp.verify(params.valid == True)
        self.data.custBal = params.newCustBal
        self.data.merchBal = params.newMerchBal
        self.data.revLock = params.newRevLock

    @sp.entry_point
    def dummyEntryPoint(self, params):
        sp.verify(params.valid == True)
        self.data.custBal = params.newCustBal
        self.data.merchBal = params.newMerchBal
        self.data.revLock = params.newRevLock


@sp.add_test(name = "basic")
def test():

    scenario = sp.test_scenario()
    scenario.table_of_contents()

    revLock = sp.blake2b(sp.bytes("0x12345678aabb"))

    scenario.h2("Scenario 1: escrow -> merchClose -> merchClaim")
    scenario.h3("escrow")
    c1 = ZkChannel(revLock)
    scenario += c1

    scenario.table_of_contents()