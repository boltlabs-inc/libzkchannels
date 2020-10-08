# On chain payment channel as a basic example.
# This script is not meant to be used as a useful
# payment channel, but it has some of the core
# features:
# - A customer and merchant balance.
# - The ability to fund the customer or merchant's balance,
# the ability to withdraw funds at any point.
# - The ability for the customer to pay the merchant.

import smartpy as sp

class UpdatableBalance(sp.Contract):
    def __init__(self, custAddr, custBal, merchAddr, merchBal):
        self.init(custAddr      = custAddr,
                  merchAddr     = merchAddr,
                  custBal       = custBal,
                  merchBal      = merchBal)

    @sp.entry_point
    def fundCust(self, params):
        sp.verify(self.data.custBal == sp.tez(0))
        sp.verify(sp.sender == self.data.custAddr)
        self.data.custBal += sp.amount

    @sp.entry_point
    def fundMerch(self, params):
        sp.verify(self.data.merchBal == sp.tez(0))
        sp.verify(sp.sender == self.data.merchAddr)
        self.data.merchBal += sp.amount

    @sp.entry_point
    def custClaim(self):
        sp.verify(sp.sender == self.data.custAddr)
        sp.send(self.data.custAddr, self.data.custBal)
        self.data.custBal = sp.tez(0)

    @sp.entry_point
    def merchClaim(self):
        sp.verify(sp.sender == self.data.merchAddr)
        sp.send(self.data.merchAddr, self.data.merchBal)
        self.data.merchBal = sp.tez(0)

    @sp.entry_point
    def pay(self, params):
        sp.verify(sp.sender == self.data.custAddr)
        sp.verify(sp.tez(0) < sp.amount)
        sp.verify(sp.amount <= self.data.custBal)
        self.data.custBal -= sp.amount
        self.data.merchBal += sp.amount

@sp.add_test(name = "basic")
def test():

    scenario = sp.test_scenario()
    alice = sp.test_account("Alice")
    bob = sp.test_account("Bob")

    c1 = UpdatableBalance(alice.address, sp.tez(0), bob.address, sp.tez(0))
    scenario += c1

    scenario.h2("Fund the customer")
    scenario += c1.fundCust().run(sender = alice, amount = sp.tez(100))
    scenario.h2("Fund the merchant")
    scenario += c1.fundMerch().run(sender = bob, amount = sp.tez(20))
    scenario.h2("Pay merchant")
    scenario += c1.pay().run(sender = alice, amount = sp.tez(10))
    scenario.h2("A failed attempt for merchant to claim customer's balance")
    scenario += c1.custClaim().run(sender = bob, valid=False)
    scenario.h1("A customer's valid claim on their balance")
    scenario += c1.custClaim().run(sender = alice)
