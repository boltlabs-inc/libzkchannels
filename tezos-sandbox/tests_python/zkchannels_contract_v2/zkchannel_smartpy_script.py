# This smart contract implements the zkchannel flow
import smartpy as sp
import smartpy_michelson as mi

# sample inputs for scenario tests
CHAN_ID_FR = "0x71f0fcd58b7d488e6bf571facc72baf5ce2ef2bb79e2fd97d2e82fdb9c351f1c"
REV_LOCK_FR = "0x850b61642560bb2728502330588c20ff099a446cf8c30e07937837bcb1722625"
SIG_S1_G1 = "0x061fc259a0b1ab1becd92add0be69a20e8656751f15abf10957a98dfe6d64bd78d32095ae0142a27b386ef3abb7937d00b4b6a8ddafb737588f36666b3d26e5152080e698dabdee97f5c25c126e8a1e3a5617ac2bb47910eadb855480fcf29c4"
SIG_S2_G1 = "0x0ec9702805ba3529b00635329baf19db048cd5bf0ebae9b95567e1070513cb596cd5f9277eca4e31cff95c682dc17cd10fa25e3fc17ce1e2c65f06c076382dd5a6029ffd40df9dae443b2bef0f64d763f86e7877bf2d367286d869d60c4ecea6"
PUB_GEN_G2 = "0x06e9fa5d7564b8d10174afd5bb751aad0fa65bea80e17ebb9ae0e8117200e31b2a8b0ef076f50bba7ed332f74942915a083f3421618ef389a376b6d977514b748434df7d63589b66b04a1ac80b6c546eb18294d27c41de7c780d2e9ed3906cfb00982f8573b7028629a6ee7765572769d852d4ab1255e7e7d367ce8967e218a0a9900c81b12264fb2e5d33ea207b5e56089fc42740e3c1e74e47ba8c5fa3c21a110966a706d1833b3819598bbab6fbd665ca846b36a6d4766fbc5895a0933702"
MERCH_PK0_G2 = "0x186e27de64030cc09467bbd0b57d02f21b8709ad751a075444e2fb371222dcfdee2f541f94d59499f0296fd4010ac72c11f5c8914cf9c29f3e7230574f8da9b784b0ec2b71a40b4fe0675f2cf85536ab996b5cbc27ffdca6d31361fbc3a013860b61b19ff6e375b3cef8b59c5ffe442b0d46646b48b4a65eeec5ef59c0109f1b0521a0af7e275313591ed94fb5a217aa0aa9eb9b01e8ec6f5665412fba2fd046c35b9c1f5d5459a3b289db675dbf206f2a441b2a1f2f8ffe61c20337e1f08ecf"
MERCH_PK1_G2 = "0x0c071cb236c7777905e4f78eacf6ce2631b3b57b57ba00887da77a515675a2462e2762afa3f50dd481008df4692918c40c735a02e5b61ec0f4eebf572c68c512250c41d9b6f59072aabc05efc1671b41a80ff2929e61561f3d848e3406fdb2630e80b934ace1c9b2c87b5dfd5d2e10ba05e9483ff2c4a59758297a62ebacd9db1aff95f5cd24f00dd20752805b4260871600d26aef82dff073749b3aca5fd15191f32e3a719950e01dc9d6ca6e71f847f04ef8bd5e8ad98ed035190826cf774d"
MERCH_PK2_G2 = "0x058693ea4800a1167ed1ff1c4f1f29f0f082a4d7fb73841ee3dc579556329d8ab9686c9af3c7ef23f1a1deb47f42114d142ef6b5d114712f9c15cdb6f46918acfbc008979fe6912793a36cc662f35225c77afcfc602482de872cad0de47be4db027433daef5024a78c12ab714ebf24ed2d59b08d6e598e5c1e61dffefd7691797da1df6a45ae375bf563c78b3dfaa249031e0bf4f776919e314ef9762d25e0c8ccaa6c92c29eb7b1162989082fffb6cd85c0435552f4d8ada8a19821c1db1d23"
MERCH_PK3_G2 = "0x014b185fefcd1831976ad28254586b4687879a5179bfa0ac900fcc1d492678701cbaac605f6511905cd29e98eef0edea18c17510a2d1f66dc2cf2c150198e0cb0873478d0016a43cbcddc69acb842cfe74593cbc41d48d0dc9b97e2af101debb02886e9573937095b3f6c9c400635b4776de403fe65d4ee10e678d5686cae05acd595451c3bb53bbc584764700ac1d22126a4b950cad3b94aeb29435af9b6869477c5757ac63dc7cb6b5840e8c6cb3e40caccd690ca95dc8da084fd6f9ddae28"
MERCH_PK4_G2 = "0x0299ade68875ade0e4f01b2b648f7c00695fffec98f71402947e53dc10f0bc8361099357e26a1992770dc84698a8fd0817004a219baa2b20d9b57b6dc81588a2a626adbf34d4533d0118e12af5a2ebad25c6fa519b5e69645be5a98e7e205d60014bb16af8d117795130650bec2b6b8a21934481ce1c0fd1f7f60ed11dd38036e9535d4ec870b2433d1c712e3ffc24a501e951dfad03111098bdf92caffb6b27a5ba7910029ce59f4ed6fc428eb6c544a993019a4c24e2d2040a089ed3a61161"

class PSSigContract(sp.Contract):
    @sp.entry_point
    def run(self, params):
        def checksig(params):
            sp.set_type(params.chanID, sp.TBls12_381_fr)
            sp.set_type(params.revLock, sp.TBytes)
            sp.set_type(params.custBal, sp.TMutez)
            sp.set_type(params.merchBal, sp.TMutez)
            
            sp.set_type(params.s1, sp.TBls12_381_g1)
            sp.set_type(params.s2, sp.TBls12_381_g1)
            sp.set_type(params.g2, sp.TBls12_381_g2)
            
            sp.set_type(params.merchPk0, sp.TBls12_381_g2)
            sp.set_type(params.merchPk1, sp.TBls12_381_g2)
            sp.set_type(params.merchPk2, sp.TBls12_381_g2)
            sp.set_type(params.merchPk3, sp.TBls12_381_g2)
            sp.set_type(params.merchPk4, sp.TBls12_381_g2)
            
            cust_b = sp.local('cust_b', sp.fst(sp.ediv(params.custBal, sp.mutez(1)).open_some()))
            one = sp.local('one', sp.bls12_381_fr("0x01"))
            cust_bal_b = sp.local("cust_bal_b", sp.mul(cust_b.value, one.value))

            merch_b = sp.local('merch_b', sp.fst(sp.ediv(params.merchBal, sp.mutez(1)).open_some()))
            merch_bal_b = sp.local("merch_bal_b", sp.mul(merch_b.value, one.value))

            revLockConcat = sp.local('revLockConcat', sp.concat([sp.bytes("0x050a00000020"), params.revLock]))
            rev_lock_b = sp.local('rev_lock_b', sp.unpack(revLockConcat.value, t = sp.TBls12_381_fr).open_some())

            val1 = sp.local("val1", sp.mul(params.merchPk0, params.chanID))
            val2 = sp.local("val2", sp.mul(params.merchPk1, rev_lock_b.value))
            val3 = sp.local("val3", sp.mul(params.merchPk2, cust_bal_b.value))
            val4 = sp.local("val4", sp.mul(params.merchPk3, merch_bal_b.value))
            
            prod1 = sp.local("prod1", val1.value + val2.value + val3.value + val4.value + params.merchPk4)
            g2_negated = - params.g2
            pair_list = sp.local("pair_list", [sp.pair(params.s1, prod1.value), sp.pair(params.s2, g2_negated)])
            out = sp.local('out', False)
            sp.if sp.pairing_check(pair_list.value):
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
            chanID = sp.TBls12_381_fr, 
            custBal = sp.TMutez, 
            merchBal = sp.TMutez, 
            revLock = sp.TBytes,
            s1 = sp.TBls12_381_g1,
            s2 = sp.TBls12_381_g1,
            g2 = sp.TBls12_381_g2,
            merchPk0 = sp.TBls12_381_g2,
            merchPk1 = sp.TBls12_381_g2,
            merchPk2 = sp.TBls12_381_g2,
            merchPk3 = sp.TBls12_381_g2,
            merchPk4 = sp.TBls12_381_g2,
            )
            
        params = sp.record(
            chanID = self.data.chanID,
            custBal = params.custBal,
            merchBal = params.merchBal,
            revLock = params.revLock,
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
    chanID = sp.bls12_381_fr(CHAN_ID_FR)
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
    merchBal = sp.tez(5)
    
    revLock2 = sp.sha256(sp.bytes("0x12345678aacf"))

    scenario.h3("custClose")
    scenario += c2.custClose(
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
        s1 = sp.bls12_381_g1(SIG_S1_G1), 
        s2 = sp.bls12_381_g1(SIG_S2_G1),
        g2 = sp.bls12_381_g2(PUB_GEN_G2),
        merchPk0 = sp.bls12_381_g2(MERCH_PK0_G2),
        merchPk1 = sp.bls12_381_g2(MERCH_PK1_G2),
        merchPk2 = sp.bls12_381_g2(MERCH_PK2_G2),
        merchPk3 = sp.bls12_381_g2(MERCH_PK3_G2),
        merchPk4 = sp.bls12_381_g2(MERCH_PK4_G2)
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
