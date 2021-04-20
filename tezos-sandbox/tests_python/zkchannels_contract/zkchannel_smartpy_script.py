# This smart contract implements the zkchannel flow
import smartpy as sp
import smartpy_michelson as mi
 
# sample inputs for scenario tests
CHAN_ID_FR = "0x90988a2421c40eaba101137fecccce44177b040c671fbce4ead7b129a3d1e26f"
REV_LOCK_FR = "0x16eee90f1221a6a8c0ee8a1907f030def6e2fcc3d6ba9517410f722b1c373852"
SIG_S1_G1 = "0x0a6c72a6cbe82240fb3e26892bb8baea20951af3843f13620a401239436fa6bc77106faa0d89228ccce1514962008eda14ff80b3b23e3de09b478281cfcb32a5064633830a32da6dd9e1f8da0c4a540eb873d396197e5264c4918022c61d9841"
SIG_S2_G1 = "0x19bc007de29752594f8c006b21fc1a4806fd2a1aa48db7f2d0c0dc694bea195f52c0c0159df4776fd89afbc1d7c2e0bf0b229543fba3cbcb2d4cf1559ee2f6327e2fecdf9fc7d52bb7a13b3699844f88f7f5dc1d1077b2d7fd9a1fc13e381159"
PUB_GEN_G2 = "0x0a6cca158299d9f2110d74aeaf0659713ff93851970e49919904abb1845a2a1e121dd1dea360f3556bdfe8f455c4dd07048c12b7a689a096b86e6c8d5b3c9be2d17d09531124d19538621c9bed7445552f14938dfdcceb52e079e0ceccf579e100b0bf57d7b73e7f9a6089e2f7de6b1044acc55c8254f30bf7417b9c765b4dafd53aaaa2226dbc7dff7b34e6f1cd7e48081979a3e7cee24ea7bf10163d237a5c8a84d2b9a4ede0e65b24446f3cdc861092960d7576cffbf1eab486d7ac067a47"
MERCH_PK0_G2 = "0x08f035b8a5be927d572523547626a4fab8e7eb70835e76ef384bebd24c00ff6a85b0276c9dc57c6193a2b7cb3c498aa10193b7a7c3acdd3de0d15da408ba6cd8f6076dfb7e65be8afa9844384230152062ad3a3a17c3cb3d4b9c059920821aba0d878c1f1e14dc4a7f1b4a35660b1a12348da93db333bb9fec00985d863e3c2c05af9b28e308a40bf8936af3ac50da0906e8fa7ee56e0e8d279e3897c19627ab5d2c72a1ae0bad6db53fa414d647077c206b751e70a14e45ce2baad8f0cc9a55"
MERCH_PK1_G2 = "0x01559bc5f6d3bc8e4b910d8c8faacdd3409ee1d532d16c24ab7b06a568aa26d9e449fb3515773d3d1cdf9a655cb50d4a19f851596b8a81f6d78a5b6735a1aa67e468f132a1de6ef4a6d0b34b5a70d32fd617391b37c051e237e7442389ec92560818a7d200a9b375e17b3cb0d5fbd3428674fb8dbbb85e34b94daae0bde343c4a3f665100d35b15c1d03a94b7e6ecb5405fcb52346116077b8d5a8c4c79de042e74496934ac7881e676c6dc55565530f3cb00a319209f36562554572f655d9de"
MERCH_PK2_G2 = "0x126f2dffe649539b2a9515b9dffafd037e33ff51571aaf5fa51a705943fc13c1c2cabff54788438ca660d19cc8bb0a920840798969f9b16fbf4e79dab7a1c90d762bb1dad3d86d840372449386bf19cc71f9a60e46cc322ef8e14ed2fa0e832310195756143ebd28a282f6865949caf7424b51338b694ba1eb2dce1b5993d829e27efe6d39f933efa8cf9a77847a2cc21900054d21e82c56b0cf2a27f78be1aaccf246c8c05371ed82149a0fa8665249afc73878777fae27e1570c549d673421"
MERCH_PK3_G2 = "0x14750e60de640a5be80ff79850a54b747ee07a958cfc9245d686afc79b086063ba639f59a15ece280d46272f66533e0e193ed0536ce7ecd0b8a893bb35d7d28e2eb0ce67d5623f52ba0250606c5ed5c8b32bb78deb4ceab2ace4f4a0afbeb5110c8889ff6917f5b9f5beca4156d0f72a62b35f8ea9bcb33f8d8fc4b4dfe112a345cb00b6a31f0c2d92536bd8a122f1b11594a77a9b331565eaa9f5aa2ec10bdb5e04c47d36a25786b02283b2a9a6057a6aa25707119e04db445115df1555ae74"
MERCH_PK4_G2 = "0x0b054195dc8d3458a311c57092a0cc683e4f095808ef023affafef03733003580cd53cc7f67a24ff6b7078303f86f6f3062c32845f0c74be2fd4a5e60c04da8e3a17460870ebfda4e882896c1991ffdb0be634c8b0a543bdfeb7c33dced313560ef3f6748fc3be638c0ca75e669a496e34084b3bb6657cc31c56a77709ed69df44133088aa304508c6a64f0f7100e9a105525d0156f3f3016388e7cbb5a5322daab0f302c3729d666f7df4b12b2b0ae15c78720ee85f9605f81d4ed08a094caa"
 
AWAITING_FUNDING = 0
OPEN = 1
MERCH_CLOSE = 2
CUST_CLOSE = 3
CLOSED = 4
 
ZERO_IN_G1 = "0x400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
 
        
# chanID is a unique identifier for the channel.
# Addresses are used both for interacting with contract, and receiving payouts.
# Public keys are used for verifying signatures required for certain state transitions.
# revLock is the revocation lock used to punish a customer who broadcasts a revoked custState.
# selfDelay defines the delay (in seconds) during which the other party can counter specific state transitions.
# delayExpiry is the unix timestamp corresponding to when the delay expires.
class ZkChannel(sp.Contract):

    @sp.global_lambda
    def is_g1_zero(val):
        packed_s1 = sp.pack(val)
        packed_zero = sp.reduce(sp.pack(sp.bls12_381_g1(ZERO_IN_G1)))
        sp.result(packed_s1 != packed_zero)
    
    def __init__(self, chanID, custAddr, merchAddr, custPk, merchPk, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4):
        self.init(
                  chanID            = chanID,
                  custAddr          = custAddr,
                  merchAddr         = merchAddr,
                  custPk            = custPk,
                  merchPk           = merchPk,
                  custBal           = sp.mutez(0),
                  merchBal          = sp.mutez(0),
                  custFunding       = custFunding,
                  merchFunding      = merchFunding,
                  status            = sp.nat(AWAITING_FUNDING),
                  revLock           = revLock,
                  selfDelay         = selfDelay,
                  delayExpiry       = sp.timestamp(0),
                  g2                = g2,
                  merchPk0          = merchPk0,
                  merchPk1          = merchPk1,
                  merchPk2          = merchPk2,
                  merchPk3          = merchPk3,
                  merchPk4          = merchPk4)
 
    # addFunding is called by the customer or the merchant to fund their
    # portion of the channel (according to the amounts specified in custFunding
    # and merchFunding).
    @sp.entry_point
    def addFunding(self, params):
        sp.verify(self.data.status == AWAITING_FUNDING)
        sp.if self.data.custAddr == sp.sender:
            sp.verify(sp.amount == self.data.custFunding)
            self.data.custBal = self.data.custFunding
        sp.if self.data.merchAddr == sp.sender:
            sp.verify(sp.amount == self.data.merchFunding)
            self.data.merchBal = self.data.merchFunding
        # If cust and merch Balances have been funded, mark the channel as open.
        sp.if ((self.data.custBal == self.data.custFunding) & (self.data.merchBal == self.data.merchFunding)):
            self.data.status = OPEN
            
 
    # reclaimFunding allows the customer or merchant to withdraw funds
    # if the other party has not funded their side of the channel yet.
    @sp.entry_point
    def reclaimFunding(self, params):
        sp.verify(self.data.status == AWAITING_FUNDING)
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
        sp.verify(self.data.status == OPEN)
        self.data.delayExpiry = sp.now.add_seconds(self.data.selfDelay)
        self.data.status = MERCH_CLOSE
 
    # merchClaim can be called by the merchant if the customer has not called
    # custClose before the delay period has expired.
    @sp.entry_point
    def merchClaim(self, params):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == MERCH_CLOSE)
        sp.verify(self.data.delayExpiry < sp.now)
        sp.send(self.data.merchAddr, self.data.custBal + self.data.merchBal)
        self.data.custBal = sp.tez(0)
        self.data.merchBal = sp.tez(0)
        self.data.status = CLOSED
 
        
    @sp.entry_point
    def custClose(self, params):
        sp.verify(self.data.custAddr == sp.sender)
        sp.verify((self.data.status == OPEN) | (self.data.status == MERCH_CLOSE))

        # custClose inputs
        custBal = params.custBal
        merchBal = params.merchBal
        revLock = params.revLock
        s1 = params.s1
        s2 = params.s2
        
        # Fail if G1 is set to 0
        sp.verify(self.is_g1_zero(s1))
        
        # Prepare pairing check inputs
        g2 = self.data.g2
        merchPk0 = self.data.merchPk0
        merchPk1 = self.data.merchPk1
        merchPk2 = self.data.merchPk2
        merchPk3 = self.data.merchPk3
        merchPk4 = self.data.merchPk4
        chanID = self.data.chanID
        cust_b = sp.local('cust_b', sp.fst(sp.ediv(custBal, sp.mutez(1)).open_some()))
        one = sp.local('one', sp.bls12_381_fr("0x01"))
        cust_bal_b = sp.local("cust_bal_b", sp.mul(cust_b.value, one.value))
        merch_b = sp.local('merch_b', sp.fst(sp.ediv(merchBal, sp.mutez(1)).open_some()))
        merch_bal_b = sp.local("merch_bal_b", sp.mul(merch_b.value, one.value))
        revLockConcat = sp.local('revLockConcat', sp.concat([sp.bytes("0x050a00000020"), revLock]))
        rev_lock_b = sp.local('rev_lock_b', sp.unpack(revLockConcat.value, t = sp.TBls12_381_fr).open_some())
        
        # Verify signature
        val1 = sp.local("val1", sp.mul(merchPk0, chanID))
        val2 = sp.local("val2", sp.mul(merchPk1, rev_lock_b.value))
        val3 = sp.local("val3", sp.mul(merchPk2, cust_bal_b.value))
        val4 = sp.local("val4", sp.mul(merchPk3, merch_bal_b.value))
        prod1 = sp.local("prod1", val1.value + val2.value + val3.value + val4.value + merchPk4)
        g2_negated = - g2
        pair_list = sp.local("pair_list", [sp.pair(s1, prod1.value), sp.pair(s2, g2_negated)])
        out = sp.local('out', False)
        sp.verify(sp.pairing_check(pair_list.value))
        
        # Update on-chain state and transfer merchant's balance   
        self.data.custBal = custBal
        self.data.revLock = revLock
        self.data.delayExpiry = sp.now.add_seconds(self.data.selfDelay)
        sp.send(self.data.merchAddr, merchBal)
        self.data.merchBal = sp.tez(0)
        self.data.status = CUST_CLOSE
             
 
    # merchDispute can be called if the merchant has the secret corresponding
    # to the latest custClose state. If the secret is valid, the merchant will
    # receive the customer's balance too.
    @sp.entry_point
    def merchDispute(self, params):
        sp.verify(self.data.merchAddr == sp.sender)
        sp.verify(self.data.status == CUST_CLOSE)
        sp.verify(self.data.revLock == sp.sha256(params.secret))
        sp.send(self.data.merchAddr, self.data.custBal)
        self.data.custBal = sp.tez(0)
        self.data.status = CLOSED
 
    # custClaim can be called by the customer to claim their balance, but only
    # after the delay period from custClose has expired.
    @sp.entry_point
    def custClaim(self, params):
        sp.verify(self.data.custAddr == sp.sender)
        sp.verify(self.data.status == CUST_CLOSE)
        sp.verify(self.data.delayExpiry < sp.now)
        sp.send(self.data.custAddr, self.data.custBal)
        self.data.custBal = sp.tez(0)
        self.data.status = CLOSED
 
    # mutualClose can be called by either the customer or the merchant and
    # allows for an instant withdrawal of the funds. mutualClose requires
    # a signature from the merchant and the customer on the final state.
    @sp.entry_point
    def mutualClose(self, params):
        sp.verify(self.data.status == OPEN)
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
        self.data.status = CLOSED
 
 
@sp.add_test(name = "basic")
def test():
 
    scenario = sp.test_scenario()
    scenario.table_of_contents()
 
    scenario.h1("zkChannels")
    aliceCust = sp.test_account("Alice")
    bobMerch = sp.test_account("Bob")
 
    scenario.h2("Parties")
    scenario.p("We start with two accounts Alice (customer) and Bob (merchant):")
    scenario.show([aliceCust, bobMerch])
 
    # Set zkChannel parameters
    chanID = sp.bls12_381_fr(CHAN_ID_FR)
    custAddr = aliceCust.address
    merchAddr = bobMerch.address
    revLock = sp.sha256(sp.bytes("0x12345678aabb"))
    # selfDelay = 60*60*24 # seconds in one day - 86,400
    selfDelay = 3 # seconds in one day - 86,400
    scenario.h2("On-chain installment")
    custFunding = sp.tez(20)
    merchFunding = sp.tez(10)
    g2 = sp.bls12_381_g2(PUB_GEN_G2)
    merchPk0 = sp.bls12_381_g2(MERCH_PK0_G2)
    merchPk1 = sp.bls12_381_g2(MERCH_PK1_G2)
    merchPk2 = sp.bls12_381_g2(MERCH_PK2_G2)
    merchPk3 = sp.bls12_381_g2(MERCH_PK3_G2)
    merchPk4 = sp.bls12_381_g2(MERCH_PK4_G2)
    
    scenario.h2("Scenario 1: escrow -> merchClose -> merchClaim")
    scenario.h3("escrow")
    c1 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4)
    scenario += c1
    scenario.h3("Funding the channel")
    scenario += c1.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c1.addFunding().run(sender = bobMerch, amount = merchFunding)
    scenario.h3("merchClose")
    scenario += c1.merchClose().run(sender = bobMerch)
    scenario.h3("unsuccessful merchClaim before delay period")
    scenario += c1.merchClaim().run(sender = bobMerch, now = sp.timestamp(1), valid = False)
    scenario.h3("successful merchClaim after delay period")
    scenario += c1.merchClaim().run(sender = bobMerch, now = sp.timestamp(100000))
 
    scenario.h2("Scenario 2: escrow -> custClose -> custClaim")
    scenario.h3("escrow")
    c2 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4)
    scenario += c2
    scenario.h3("Funding the channel")
    scenario += c2.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c2.addFunding().run(sender = bobMerch, amount = merchFunding)
    scenario.p("Now the customer and merchant make a payment off chain.")
    scenario.p("For the payment to be considered complete, the customer should have received a signature from the merchant reflecting the final balances, and the merchant should have received the secret corresponding to the previous state's revLock.")
    scenario.h3("custClose")
    custBal = sp.tez(18)
    merchBal = sp.tez(12)
    revLock2 = sp.bytes(REV_LOCK_FR)
    scenario += c2.custClose(
        revLock = revLock2, 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = sp.bls12_381_g2(PUB_GEN_G2)
        ).run(sender = aliceCust)
    scenario.h3("unsuccessful custClaim attempt before delay period")
    scenario += c2.custClaim().run(sender = aliceCust, now = sp.timestamp(1), valid = False)
    scenario.h3("successful custClaim after delay period")
    scenario += c2.custClaim().run(sender = aliceCust, now = sp.timestamp(100000))
 
    scenario.h2("Scenario 3: escrow -> custClose -> merchDispute")
    scenario.h3("escrow")
    c3 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4)
    scenario += c3
    scenario.h3("Funding the channel")
    scenario += c3.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c3.addFunding().run(sender = bobMerch, amount = merchFunding)
    scenario.h3("custClose")
    revLock2 = sp.bytes(REV_LOCK_FR) # sp.sha256(sp.bytes("0x12345678aacc"))
    scenario += c3.custClose(
        revLock = revLock2, 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = sp.bls12_381_g2(PUB_GEN_G2),
        merchPk0 = sp.bls12_381_g2(MERCH_PK0_G2),
        merchPk1 = sp.bls12_381_g2(MERCH_PK1_G2),
        merchPk2 = sp.bls12_381_g2(MERCH_PK2_G2),
        merchPk3 = sp.bls12_381_g2(MERCH_PK3_G2),
        merchPk4 = sp.bls12_381_g2(MERCH_PK4_G2)
        ).run(sender = aliceCust)
    scenario.h3("merchDispute called with correct secret")
    # scenario += c3.merchDispute(secret = sp.bytes("0x12345678aacc")).run(sender = bobMerch, now = sp.timestamp(10))
 
    scenario.h2("Scenario 4: escrow -> merchClose -> custClose")
    scenario.h3("escrow")
    c4 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4)
    scenario += c4
    scenario.h3("Funding the channel")
    scenario += c4.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c4.addFunding().run(sender = bobMerch, amount = merchFunding)
    scenario.h3("merchClose")
    scenario += c4.merchClose().run(sender = bobMerch)
    scenario.h3("custClose")
    revLock3 = sp.sha256(sp.bytes("0x12345678aacc"))
    scenario += c4.custClose(
        revLock = revLock2, 
        custBal = custBal, 
        merchBal = merchBal, 
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = sp.bls12_381_g2(PUB_GEN_G2),
        merchPk0 = sp.bls12_381_g2(MERCH_PK0_G2),
        merchPk1 = sp.bls12_381_g2(MERCH_PK1_G2),
        merchPk2 = sp.bls12_381_g2(MERCH_PK2_G2),
        merchPk3 = sp.bls12_381_g2(MERCH_PK3_G2),
        merchPk4 = sp.bls12_381_g2(MERCH_PK4_G2)
        ).run(sender = aliceCust)
 
    scenario.h2("Scenario 5: escrow -> mutualClose")
    scenario.h3("escrow")
    c5 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4)
    scenario += c5
    scenario.h3("Funding the channel")
    scenario += c5.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario += c5.addFunding().run(sender = bobMerch, amount = merchFunding)
    # Customer's signature on the latest state
    custSig = sp.make_signature(aliceCust.secret_key, sp.pack(sp.record(chanID = chanID,
                                                                  custAddr = custAddr,
                                                                  merchAddr = merchAddr,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
 
    # Merchant's signature on the latest state
    merchSig = sp.make_signature(bobMerch.secret_key, sp.pack(sp.record(chanID = chanID,
                                                                  custAddr = custAddr,
                                                                  merchAddr = merchAddr,
                                                                  custBal = custBal,
                                                                  merchBal = merchBal)))
    scenario.h3("mutualClose")
    scenario += c5.mutualClose(custBal = custBal, merchBal = merchBal, custSig = custSig,  merchSig = merchSig).run(sender = aliceCust)
 
    scenario.h2("Scenario 6: escrow -> addCustFunding -> reclaimCustFunding")
    scenario.h3("escrow")
    c6 = ZkChannel(chanID, aliceCust.address, bobMerch.address, aliceCust.public_key, bobMerch.public_key, custFunding, merchFunding, selfDelay, revLock, g2, merchPk0, merchPk1, merchPk2, merchPk3, merchPk4)
    scenario += c6
    scenario.h3("Customer Funding their side of the channel")
    scenario += c6.addFunding().run(sender = aliceCust, amount = custFunding)
    scenario.h3("Customer pulling out their side of the channel (before merchant funds their side)")
    scenario += c6.reclaimFunding().run(sender = aliceCust)
 
    scenario.table_of_contents()