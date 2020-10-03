# Escrow - Example for illustrative purposes only.

import smartpy as sp

class Escrow(sp.Contract):
    def __init__(self, owner, fromOwner, counterparty, fromCounterparty, epoch, hashedSecret):
        self.init(fromOwner           = fromOwner,
                  fromCounterparty    = fromCounterparty,
                  balanceOwner        = sp.tez(0),
                  balanceCounterparty = sp.tez(0),
                  hashedSecret        = hashedSecret,
                  epoch               = epoch,
                  owner               = owner,
                  counterparty        = counterparty)

    # addBalanceOwner ensures Alice's balance is funded with the right amount
    @sp.entry_point
    def addBalanceOwner(self, params):
        sp.verify(self.data.balanceOwner == sp.tez(0))
        sp.verify(sp.amount == self.data.fromOwner)
        self.data.balanceOwner = self.data.fromOwner

    # addBalanceOwner ensures Bob's balance is funded with the right amount
    @sp.entry_point
    def addBalanceCounterparty(self, params):
        sp.verify(self.data.balanceCounterparty == sp.tez(0))
        sp.verify(sp.amount == self.data.fromCounterparty)
        self.data.balanceCounterparty = self.data.fromCounterparty

    def claim(self, identity):
        sp.verify(sp.sender == identity)
        sp.send(identity, self.data.balanceOwner + self.data.balanceCounterparty)
        self.data.balanceOwner = sp.tez(0)
        self.data.balanceCounterparty = sp.tez(0)

    # If Bob is able to prove that he has the hash secret, and the time period (epoch) has not expired, he can claim the whole balance of the escrow.
    @sp.entry_point
    def claimCounterparty(self, params):
        sp.verify(sp.now < self.data.epoch)
        sp.verify(self.data.hashedSecret == sp.blake2b(params.secret))
        self.claim(self.data.counterparty)

    # On the other hand, if the time period (epoch) has expired, Alice will be able to claim the total funds(assuming Bob did not claim them already).
    @sp.entry_point
    def claimOwner(self, params):
        sp.verify(self.data.epoch < sp.now)
        self.claim(self.data.owner)

@sp.add_test(name = "Escrow")
def test():
    scenario = sp.test_scenario()
    scenario.h1("Escrow")
    hashSecret = sp.blake2b(sp.bytes("0x01223344"))
    alice = sp.test_account("Alice")
    bob = sp.test_account("Bob")
    c1 = Escrow(alice.address, sp.tez(50), bob.address, sp.tez(4), sp.timestamp(123), hashSecret)
    scenario += c1
    # Alice (owner) is adding some tez to the contract.
    scenario += c1.addBalanceOwner().run(sender = alice, amount = sp.tez(50))
    # Bob (counterparty) is adding some tez to the contract.
    scenario += c1.addBalanceCounterparty().run(sender = bob, amount = sp.tez(4))
    scenario.h3("Erronous secret")
    # Bob tries to claim the funds with an incorrect secret and fails.
    scenario += c1.claimCounterparty(secret = sp.bytes("0x01223343"))    .run(sender = bob, valid = False)
    scenario.h3("Correct secret")
    # This time Bob claims the funds with a correct secret and claims the total funds.
    scenario += c1.claimCounterparty(secret = sp.bytes("0x01223344")).run(sender = bob)
