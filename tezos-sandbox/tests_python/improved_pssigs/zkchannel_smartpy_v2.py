# This smart contract implements the zkchannel flow
import smartpy as sp

class PSSigContract(sp.Contract):
    @sp.global_lambda
    def convert_to_bytes(bal):
        sp.set_type(bal, sp.TMutez)
        s = sp.local('s', bal)
        sp.if s.value > sp.mutez(0):
            t = sp.local('t', sp.bytes("0x78aacc123456"))
            sp.result(t.value)
        sp.else:
            t = sp.local('t', sp.bytes("0x12345678aacc"))
            sp.result(t.value)

    @sp.entry_point
    def run(self, params):
        def checksig(params):
            sp.set_type(params.chanID, sp.TBytes)
            sp.set_type(params.revLock, sp.TBytes)
            sp.set_type(params.revLockB, sp.TBytes)
            sp.set_type(params.custBalB, sp.TBytes)
            sp.set_type(params.merchBalB, sp.TBytes)
            sp.set_type(params.custBal, sp.TMutez)
            sp.set_type(params.merchBal, sp.TMutez)
            
            sp.set_type(params.s1, sp.TBytes)
            sp.set_type(params.s2, sp.TBytes)
            sp.set_type(params.g2, sp.TBytes)
            
            sp.set_type(params.merchPk0, sp.TBytes)
            sp.set_type(params.merchPk1, sp.TBytes)
            sp.set_type(params.merchPk2, sp.TBytes)
            sp.set_type(params.merchPk3, sp.TBytes)
            sp.set_type(params.merchPk4, sp.TBytes)
            
            # work in progress (converting mutez -> Fr bytes)
            cust_bal_b = sp.local("cust_bal_b", self.convert_to_bytes(params.custBal))
            merch_bal_b = sp.local("merch_bal_b", self.convert_to_bytes(params.merchBal))

            val1 = sp.local("val1", params.merchPk0 + params.chanID)
            val2 = sp.local("val2", params.merchPk1 + params.revLockB)
            val3 = sp.local("val3", params.merchPk2 + cust_bal_b.value)
            val4 = sp.local("val4", params.merchPk3 + merch_bal_b.value)
            
            prod1 = sp.local("prod1", val1.value + val2.value + val3.value + val4.value + params.merchPk4)
            pair_list = sp.local("pair_list", [sp.pair(params.s1, prod1.value), sp.pair(params.s2, params.g2)])
            out = sp.local('out', False)
            sp.if sp.len(pair_list.value) > 1:
                out.value = True
            sp.else:
                out.value = False
        
            return out.value
                    
        sp.verify(checksig(params))
        
# chanID is a unique identifier for the channel.
# Addresses are used both for interacting with contract, and receiving payouts.
# Public keys are used for verifying signatures required for certain state transitions.
# revLock is the revocation lock used to punish a customer who broadcasts a revoked custState.
# selfDelay defines the delay (in seconds) during which the other party can counter specific state transitions.
# delayExpiry is the unix timestamp corresponding to when the delay expires.
class ZkChannel(sp.Contract):
    def __init__(self, chanID, custAddr, merchAddr, custPk, merchPk, custFunding, merchFunding, selfDelay, revLock, pssigContract):
        self.init(
                  chanID            = chanID,
                  custAddr          = custAddr,
                  merchAddr         = merchAddr,
                  custPk            = custPk,
                  merchPk           = merchPk,
                  custBal           = sp.tez(0),
                  merchBal          = sp.tez(0),
                  custFunding       = custFunding,
                  merchFunding      = merchFunding,
                  status            = sp.string('awaitingFunding'),
                  revLock           = revLock,
                  selfDelay         = selfDelay,
                  delayExpiry       = sp.timestamp(0),
                  pssigContract     = pssigContract)
                  

    # addFunding is called by the customer or the merchant to fund their
    # portion of the channel (according to the amounts specified in custFunding
    # and merchFunding).
    @sp.entry_point
    def addFunding(self, params):
        sp.verify(self.data.status == "awaitingFunding")
        sp.if self.data.custAddr == sp.sender:
            sp.verify(sp.amount == self.data.custFunding)
            self.data.custBal = self.data.custFunding
        sp.if self.data.merchAddr == sp.sender:
            sp.verify(sp.amount == self.data.merchFunding)
            self.data.merchBal = self.data.merchFunding
        # If cust and merch Balances have been funded, mark the channel as open.
        sp.if ((self.data.custBal == self.data.custFunding) & (self.data.merchBal == self.data.merchFunding)):
            self.data.status = "open"
            

    # reclaimFunding allows the customer or merchant to withdraw funds
    # if the other party has not funded their side of the channel yet.
    @sp.entry_point
    def reclaimFunding(self, params):
        sp.verify(self.data.status == "awaitingFunding")
        sp.if self.data.custAddr == sp.sender:
            sp.verify(self.data.custBal == self.data.custFunding)
            sp.send(self.data.custAddr, self.data.custBal)
            self.data.custBal = sp.tez(0)
        sp.if self.data.merchAddr == sp.sender:
            sp.verify(self.data.merchBal == self.data.merchFunding)
            sp.send(self.data.merchAddr, self.data.merchBal)
            self.data.merchBal = sp.tez(0)

    # merchClose can be called by the merchant to initiate channel closure.
    # The customer should call custClose using the latest state. Otherwise,
    # after the delay expires, the merchant will be able to claim all the
    # funds in the channel using merchClaim.
    @sp.entry_point
    def merchClose(self, params):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == 'open')
        self.data.delayExpiry = sp.now.add_seconds(self.data.selfDelay)
        self.data.status = 'merchClose'

    # merchClaim can be called by the merchant if the customer has not called
    # custClose before the delay period has expired.
    @sp.entry_point
    def merchClaim(self, params):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == 'merchClose')
        sp.verify(self.data.delayExpiry < sp.now)
        sp.send(self.data.merchAddr, self.data.custBal + self.data.merchBal)
        self.data.custBal = sp.tez(0)
        self.data.merchBal = sp.tez(0)
        self.data.status = 'closed'

        
    @sp.entry_point
    def custClose(self, params):
        sp.verify(self.data.custAddr == sp.sender)
        sp.verify((self.data.status == 'open') | (self.data.status == 'merchClose'))
        self.data.custBal = params.custBal
        self.data.merchBal = params.merchBal
        self.data.revLock = params.revLock
        
        # Check merchant signature using contract call
        tk = sp.TRecord(
            chanID = sp.TBytes, 
            custBal = sp.TMutez, 
            merchBal = sp.TMutez, 
            custBalB = sp.TBytes, 
            merchBalB = sp.TBytes, 
            revLock = sp.TBytes,
            revLockB = sp.TBytes,
            s1 = sp.TBytes,
            s2 = sp.TBytes,
            g2 = sp.TBytes,
            merchPk0 = sp.TBytes,
            merchPk1 = sp.TBytes,
            merchPk2 = sp.TBytes,
            merchPk3 = sp.TBytes,
            merchPk4 = sp.TBytes,
            )
            
        params = sp.record(
            chanID = self.data.chanID,
            custBal = params.custBal,
            merchBal = params.merchBal,
            custBalB = params.custBalB,
            merchBalB = params.merchBalB,
            revLock = params.revLock,
            revLockB = params.revLockB,
            s1 = params.s1,
            s2 = params.s2,
            g2 = params.g2,
            merchPk0 = params.merchPk0,
            merchPk1 = params.merchPk1,
            merchPk2 = params.merchPk2,
            merchPk3 = params.merchPk3,
            merchPk4 = params.merchPk4,
            )
        
        sp.transfer(params, sp.mutez(0), sp.contract(tk, self.data.pssigContract).open_some())
        
        self.data.delayExpiry = sp.now.add_seconds(self.data.selfDelay)
        sp.send(self.data.merchAddr, self.data.merchBal)
        self.data.merchBal = sp.tez(0)
        self.data.status = 'custClose'
             

    # merchDispute can be called if the merchant has the secret corresponding
    # to the latest custClose state. If the secret is valid, the merchant will
    # receive the customer's balance too.
    @sp.entry_point
    def merchDispute(self, params):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify((self.data.status == 'custClose') | (self.data.status == 'checkingSig'))
        sp.verify(self.data.revLock == sp.sha256(params.secret))
        sp.send(self.data.merchAddr, self.data.custBal)
        self.data.custBal = sp.tez(0)
        self.data.status = 'closed'

    # custClaim can be called by the customer to claim their balance, but only
    # after the delay period from custClose has expired.
    @sp.entry_point
    def custClaim(self, params):
        sp.verify(self.data.custAddr == sp.sender)
        sp.verify(self.data.status == 'custClose')
        sp.verify(self.data.delayExpiry < sp.now)
        sp.send(self.data.custAddr, self.data.custBal)
        self.data.custBal = sp.tez(0)
        self.data.status = 'closed'

    # mutualClose can be called by either the customer or the merchant and
    # allows for an instant withdrawal of the funds. mutualClose requires
    # a signature from the merchant and the customer on the final state.
    @sp.entry_point
    def mutualClose(self, params):
        sp.verify(self.data.status == 'open')
        # Check customer signature
        sp.verify(sp.check_signature(self.data.custPk,
                                     params.custSig,
                                     sp.pack(sp.record(
                                             chanID = self.data.chanID,
                                             custAddr = self.data.custAddr,
                                             merchAddr = self.data.merchAddr,
                                             custBal = params.custBal,
                                             merchBal = params.merchBal)
                                            )
                                    ))
        # Check merchant signature
        sp.verify(sp.check_signature(self.data.merchPk,
                                     params.merchSig,
                                     sp.pack(sp.record(
                                             chanID = self.data.chanID,
                                             custAddr = self.data.custAddr,
                                             merchAddr = self.data.merchAddr,
                                             custBal = params.custBal,
                                             merchBal = params.merchBal)
                                            )
                                    ))
        self.data.custBal = params.custBal
        self.data.merchBal = params.merchBal
        sp.send(self.data.custAddr, self.data.custBal)
        sp.send(self.data.merchAddr, self.data.merchBal)
        self.data.custBal = sp.tez(0)
        self.data.merchBal = sp.tez(0)
        self.data.status = 'closed'


@sp.add_test(name = "basic")
def test():

    scenario = sp.test_scenario()
    scenario.table_of_contents()

    scenario.h1("zkChannels")
    alice = sp.test_account("Alice")
    bob = sp.test_account("Bob")

    scenario.h2("Parties")
    scenario.p("We start with two accounts Alice (customer) and Bob (merchant):")
    scenario.show([alice, bob])

    # Set zkChannel parameters
    chanID = sp.bytes("0x12345678aacc")
    custAddr = alice.address
    merchAddr = bob.address
    revLock = sp.sha256(sp.bytes("0x12345678aabb"))
    selfDelay = 60*60*24 # seconds in one day - 86,400
    scenario.h2("On-chain installment")
    custFunding = sp.tez(20)
    merchFunding = sp.tez(10)
    
    
    scenario.h2("Originate pssigContract on chain")
    pssigContract = PSSigContract()
    scenario += pssigContract
    
    
    scenario.h2("Scenario 1: escrow -> merchClose -> merchClaim")
    scenario.h3("escrow")
    c1 = ZkChannel(chanID, alice.address, bob.address, alice.public_key, bob.public_key, custFunding, merchFunding, selfDelay, revLock, pssigContract.address)
    scenario += c1
    scenario.h3("Funding the channel")
    scenario += c1.addFunding().run(sender = alice, amount = custFunding)
    scenario += c1.addFunding().run(sender = bob, amount = merchFunding)
    scenario.h3("merchClose")
    scenario += c1.merchClose().run(sender = bob)
    scenario.h3("unsuccessful merchClaim before delay period")
    scenario += c1.merchClaim().run(sender = bob, now = sp.timestamp(10), valid = False)
    scenario.h3("successful merchClaim after delay period")
    scenario += c1.merchClaim().run(sender = bob, now = sp.timestamp(100000))

    scenario.h2("Scenario 2: escrow -> custClose -> custClaim")
    scenario.h3("escrow")
    c2 = ZkChannel(chanID, alice.address, bob.address, alice.public_key, bob.public_key, custFunding, merchFunding, selfDelay, revLock, pssigContract.address)
    scenario += c2
    scenario.h3("Funding the channel")
    scenario += c2.addFunding().run(sender = alice, amount = custFunding)
    scenario += c2.addFunding().run(sender = bob, amount = merchFunding)
    scenario.p("Now the customer and merchant make a payment off chain.")
    scenario.p("For the payment to be considered complete, the customer should have received a signature from the merchant reflecting the final balances, and the merchant should have received the secret corresponding to the previous state's revLock.")
    custBal = sp.tez(25)
    custBalB = sp.bytes("0x017D7840")
    merchBal = sp.tez(5)
    merchBalB = sp.bytes("0x004C4B40")
    
    revLock2 = sp.sha256(sp.bytes("0x12345678aacf"))

    scenario.h3("custClose")
    scenario += c2.custClose(
        revLock = revLock, 
        custBal = custBal, 
        merchBal = merchBal, 
        revLockB = revLock2, 
        custBalB = custBalB, 
        merchBalB = merchBalB, 
        s1 = sp.bytes("0x12345678fff1"), 
        s2 = sp.bytes("0x12345678fff2"),
        g2 = sp.bytes("0x12345678fff3"),
        merchPk0 = sp.bytes("0x12345678fff4"),
        merchPk1 = sp.bytes("0x12345678fff5"),
        merchPk2 = sp.bytes("0x12345678fff6"),
        merchPk3 = sp.bytes("0x12345678fff7"),
        merchPk4 = sp.bytes("0x12345678fff8")
        ).run(sender = alice)
    scenario.h3("unsuccessful custClaim attempt before delay period")
    scenario += c2.custClaim().run(sender = alice, now = sp.timestamp(10), valid = False)
    scenario.h3("successful custClaim after delay period")
    scenario += c2.custClaim().run(sender = alice, now = sp.timestamp(100000))

    scenario.h2("Scenario 3: escrow -> custClose -> merchDispute")
    scenario.h3("escrow")
    c3 = ZkChannel(chanID, alice.address, bob.address, alice.public_key, bob.public_key, custFunding, merchFunding, selfDelay, revLock, pssigContract.address)
    scenario += c3
    scenario.h3("Funding the channel")
    scenario += c3.addFunding().run(sender = alice, amount = custFunding)
    scenario += c3.addFunding().run(sender = bob, amount = merchFunding)
    scenario.h3("custClose")
    revLock2 = sp.sha256(sp.bytes("0x12345678aacc"))
    scenario += c3.custClose(
        revLock = revLock2, 
        custBal = custBal, 
        merchBal = merchBal, 
        revLockB = revLock2, 
        custBalB = custBalB, 
        merchBalB = merchBalB, 
        s1 = sp.bytes("0x12345678aacc"), 
        s2 = sp.bytes("0x12345678aacc"),
        g2 = sp.bytes("0x12345678aacc"),
        merchPk0 = sp.bytes("0x12345678aacc"),
        merchPk1 = sp.bytes("0x12345678aacc"),
        merchPk2 = sp.bytes("0x12345678aacc"),
        merchPk3 = sp.bytes("0x12345678aacc"),
        merchPk4 = sp.bytes("0x12345678aacc")
        ).run(sender = alice)
    scenario.h3("merchDispute called with correct secret")
    scenario += c3.merchDispute(secret = sp.bytes("0x12345678aacc")).run(sender = bob, now = sp.timestamp(10))

    scenario.h2("Scenario 4: escrow -> merchClose -> custClose")
    scenario.h3("escrow")
    c4 = ZkChannel(chanID, alice.address, bob.address, alice.public_key, bob.public_key, custFunding, merchFunding, selfDelay, revLock, pssigContract.address)
    scenario += c4
    scenario.h3("Funding the channel")
    scenario += c4.addFunding().run(sender = alice, amount = custFunding)
    scenario += c4.addFunding().run(sender = bob, amount = merchFunding)
    scenario.h3("merchClose")
    scenario += c4.merchClose().run(sender = bob)
    scenario.h3("custClose")
    revLock3 = sp.sha256(sp.bytes("0x12345678aacc"))
    scenario += c4.custClose(
        revLock = revLock2, 
        custBal = custBal, 
        merchBal = merchBal, 
        revLockB = revLock2, 
        custBalB = custBalB, 
        merchBalB = merchBalB, 
        s1 = sp.bytes("0x12345678aacc"), 
        s2 = sp.bytes("0x12345678aacc"),
        g2 = sp.bytes("0x12345678aacc"),
        merchPk0 = sp.bytes("0x12345678aacc"),
        merchPk1 = sp.bytes("0x12345678aacc"),
        merchPk2 = sp.bytes("0x12345678aacc"),
        merchPk3 = sp.bytes("0x12345678aacc"),
        merchPk4 = sp.bytes("0x12345678aacc")
        ).run(sender = alice)

    scenario.h2("Scenario 5: escrow -> mutualClose")
    scenario.h3("escrow")
    c5 = ZkChannel(chanID, alice.address, bob.address, alice.public_key, bob.public_key, custFunding, merchFunding, selfDelay, revLock, pssigContract.address)
    scenario += c5
    scenario.h3("Funding the channel")
    scenario += c5.addFunding().run(sender = alice, amount = custFunding)
    scenario += c5.addFunding().run(sender = bob, amount = merchFunding)
    # Customer's signature on the latest state
    custSig = sp.make_signature(alice.secret_key, sp.pack(sp.record(chanID = chanID,
                                                                  custAddr = custAddr,
                                                                  merchAddr = merchAddr,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))

    # Merchant's signature on the latest state
    merchSig = sp.make_signature(bob.secret_key, sp.pack(sp.record(chanID = chanID,
                                                                  custAddr = custAddr,
                                                                  merchAddr = merchAddr,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
    scenario.h3("mutualClose")
    scenario += c5.mutualClose(custBal = custBal, merchBal = merchBal, custSig = custSig,  merchSig = merchSig).run(sender = alice)

    scenario.h2("Scenario 6: escrow -> addCustFunding -> reclaimCustFunding")
    scenario.h3("escrow")
    c6 = ZkChannel(chanID, alice.address, bob.address, alice.public_key, bob.public_key, custFunding, merchFunding, selfDelay, revLock, pssigContract.address)
    scenario += c6
    scenario.h3("Customer Funding their side of the channel")
    scenario += c6.addFunding().run(sender = alice, amount = custFunding)
    scenario.h3("Customer pulling out their side of the channel (before merchant funds their side)")
    scenario += c6.reclaimFunding().run(sender = alice)

    # # Make sure that the channel doesnt transition to 'custClose' on a 
    # # bad signature. Note that this test when run will fail. Using the usual
    # # 'valid = False' flag won't work since it's an inter-contract call.
    # # SmartPy doesn't have this functionality yet.
    # scenario.h2("Scenario 7: escrow -> custClose (with a bad signature)")
    # scenario.h3("escrow")
    # c3 = ZkChannel(chanID, alice.address, bob.address, alice.public_key, bob.public_key, custFunding, merchFunding, selfDelay, revLock, pssigContract.address)
    # scenario += c3
    # scenario.h3("Funding the channel")
    # scenario += c3.addFunding().run(sender = alice, amount = custFunding)
    # scenario += c3.addFunding().run(sender = bob, amount = merchFunding)
    # scenario.h3("custClose")
    # revLock2 = sp.sha256(sp.bytes("0x12345678aacc"))
    # scenario += c3.custClose(
    #     revLock = revLock2, 
    #     custBal = custBal, 
    #     merchBal = merchBal,
    #     s1 = "InvalidSig", 
    #     s2 = "InvalidSig",
    #     g2 = "dummy_g2",
    #     merchPk0 = "dummy_merchPk0",
    #     merchPk1 = "dummy_merchPk1",
    #     merchPk2 = "dummy_merchPk2",
    #     merchPk3 = "dummy_merchPk3",
    #     merchPk4 = "dummy_merchPk4"
    #     ).run(sender = alice)

    scenario.table_of_contents()
