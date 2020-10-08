# Atomic Swaps - Example for illustrative purposes only.

import smartpy as sp

class AtomicSwap(sp.Contract):
    def __init__(self, notional, epoch, hashedSecret, owner, counterparty):
        self.init(notional     = notional,
                  hashedSecret = hashedSecret,
                  epoch        = epoch,
                  owner        = owner,
                  counterparty = counterparty)

    def checkAlive(self, identity):
        sp.verify(self.data.notional != sp.mutez(0))
        sp.verify(identity == sp.sender)

    def finish(self):
        self.data.notional = sp.mutez(0)

    # If the owner is satisfied with the conditions of the swap,
    # they may call allSigned in order to send the notional tez
    # to the counterparty.
    @sp.entry_point
    def allSigned(self, params):
        self.checkAlive(self.data.owner)
        sp.send(self.data.counterparty, self.data.notional)
        self.finish()

    # If the time period has expired, the owner may cancel
    # the swap and reclaim their notional amount.
    @sp.entry_point
    def cancelSwap(self, params):
        self.checkAlive(self.data.owner)
        sp.verify(self.data.epoch < sp.now)
        sp.send(self.data.owner, self.data.notional)
        self.finish()

    # If the counterparty has the hash secret, and the time period
    # has not expired, they may claim the tez.
    @sp.entry_point
    def knownSecret(self, params):
        self.checkAlive(self.data.counterparty)
        sp.verify(self.data.hashedSecret == sp.blake2b(params.secret))
        sp.send(self.data.counterparty, self.data.notional)
        self.finish()

@sp.add_test(name = "AtomicSwap1")
def test():
    hashSecret = sp.blake2b(sp.bytes("0x12345678aabb"))
    alice = sp.test_account("Alice")
    bob   = sp.test_account("Robert")
    c1 = AtomicSwap(sp.mutez(12), sp.timestamp(50), hashSecret,
                    alice.address,
                    bob.address)
    scenario  = sp.test_scenario()
    scenario.h1("Atomic Swap")
    scenario += c1

@sp.add_test(name = "AtomicSwap2")
def test():
    alice = sp.test_account("Alice")
    bob   = sp.test_account("Robert")
    scenario = sp.test_scenario()
    scenario.h1("Atomic Swap")

    # Here, two AtomicSwap contracts are created. One with Alice as the owner
    # and Bob as the counterparty, and the second with the identities reversed.
    # They are both secured with the same hash secret, so if the secret gets
    # revealed, then both swaps can happen.
    hashSecret = sp.blake2b(sp.bytes("0x12345678aabb"))
    c1 = AtomicSwap(sp.mutez(12), sp.timestamp(50), hashSecret,
                    alice.address,
                    bob.address)
    c2 = AtomicSwap(sp.mutez(20), sp.timestamp(50), hashSecret,
                    bob.address,
                    alice.address)
    scenario.h1("c1")
    scenario += c1
    scenario += c1.knownSecret(secret = sp.bytes("0x12345678aa")).run(sender = bob, valid = False)
    scenario += c1.knownSecret(secret = sp.bytes("0x12345678aabb")).run(sender = bob)
    scenario.h1("c2")
    scenario += c2
    scenario.h2("C2.export()")
    scenario.p(c2.export())
