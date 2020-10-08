import smartpy as sp

class TestCheckSignature(sp.Contract):
    def __init__(self, boss_pk):
        self.init(currentValue = 'Hello World', counter = 0, bossPublicKey = boss_pk)

    @sp.entry_point
    def setCurrentValue(self, params):
        # We will also need Michelson SELF and CHAIN_ID to avoid all replay attacks:
        thingToSign = sp.pack(sp.record(o = self.data.currentValue, n = params.newValue, c = self.data.counter))
        sp.verify(sp.check_signature(self.data.bossPublicKey, params.userSignature, thingToSign))
        self.data.currentValue = params.newValue
        self.data.counter = self.data.counter + 1

# Tests
@sp.add_test(name = "CheckSignature")
def test():
    scenario = sp.test_scenario()
    rightful_owner = sp.test_account("Alice")
    attacker = sp.test_account("Robert")
    c1 = TestCheckSignature(rightful_owner.public_key)

    scenario += c1
    # Let's build a successful call:
    #
    scenario.h2("Successful Call")
    first_message_packed = sp.pack(sp.record(o = "Hello World", n = "should work", c = 0))
    sig_from_alice = sp.make_signature(secret_key = rightful_owner.secret_key,
                                       message = first_message_packed,
                                       message_format = "Raw")
    scenario += c1.setCurrentValue(newValue = "should work",
                                   userSignature = sig_from_alice
                                   ).run(valid = True)
    #
    scenario.h2("Replay Attack")
    scenario.p("Trying to reuse the same signature is blocked by the value of the counter.")
    scenario += c1.setCurrentValue(newValue = "should work",
                                   userSignature = sig_from_alice
                                   ).run(valid = False)
    #
    #
    scenario.h2("Signature From Wrong Secret Key")
    scenario.p("Signing the right thing from a different secret-key.")
    #
    #
    # Gives:
    second_message_packed = sp.pack(sp.record(o = "should work", n = "Hello again World", c = 1))
    sig_from_bob = sp.make_signature(secret_key = attacker.secret_key,
                                     message = second_message_packed,
                                     message_format = "Raw")
    scenario += c1.setCurrentValue(newValue = "Hello again World",
                                   userSignature = sig_from_bob
                                   ).run(valid = False)
    #
    scenario.h2("Second Successful Call")
    scenario.p("Showing that the previous call failed <b>because</b> of the secret-key (signing same bytes).")
    sig_from_alice = sp.make_signature(secret_key = rightful_owner.secret_key,
                                       message = second_message_packed,
                                       message_format = "Raw")
    scenario += c1.setCurrentValue(newValue = "Hello again World",
                                   userSignature = sig_from_alice
                                   ).run(valid = True)
