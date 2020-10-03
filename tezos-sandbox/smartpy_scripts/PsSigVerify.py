import smartpy as sp

Fr = sp.TInt # sp.TSimple("bls12_381_fr") 
G1 = sp.TInt # sp.TSimple("bls12_381_g1")
G2 = sp.TInt # sp.TSimple("bls12_381_g2")

class PsSigContract(sp.Contract):
    def __init__(self, pubkey):        
        sp.set_type(pubkey.g2, G2)
        sp.set_type(pubkey.X, G2)
        sp.set_type(pubkey.Y0, G2)
        sp.set_type(pubkey.Y1, G2)
        sp.set_type(pubkey.Y2, G2)
        sp.set_type(pubkey.Y3, G2)
        sp.set_type(pubkey.Y4, G2)
        self.init(close_sig = False, 
                  pubkey = sp.record(g2 = pubkey.g2, 
                                     X = pubkey.X, 
                                     Y0 = pubkey.Y0, 
                                     Y1 = pubkey.Y1, 
                                     Y2 = pubkey.Y2, 
                                     Y3 = pubkey.Y3, 
                                     Y4 = pubkey.Y4), 
                  s = '')

    def pairing_check(self, args):
        return True

    @sp.entry_point
    def ps_sig_verify(self, params):
        sp.set_type(params.wallet.m0, Fr)
        sp.set_type(params.wallet.m1, Fr)
        sp.set_type(params.wallet.m2, Fr)
        sp.set_type(params.wallet.m3, Fr)
        sp.set_type(params.wallet.m4, Fr)
        sp.set_type(params.signature.s1, G1)
        sp.set_type(params.signature.s2, G2)

        # (Y0 * m0) + (Y1 * m1) + (Y2 * m2) + (Y3 * m3) + (Y4 * m4) + X
        prod1 = (self.data.pubkey.Y0 * params.wallet.m0) + (self.data.pubkey.Y1 * params.wallet.m1) + \
                (self.data.pubkey.Y2 * params.wallet.m2) + (self.data.pubkey.Y3 * params.wallet.m3) + \
                (self.data.pubkey.Y4 * params.wallet.m4) + self.data.pubkey.X
        # [ (s1, prod1_x);
        #   (s2, g2 ^ -1) ]
        pairing_check_inputs = [sp.pair(params.signature.s1, prod1), sp.pair(params.signature.s2, -self.data.pubkey.g2)]
        # execute the pairing check and return the result
        self.data.close_sig = self.pairing_check(pairing_check_inputs)

@sp.add_test(name = "Pointcheval Sanders signatures")
def test():
    scenario = sp.test_scenario()
    scenario.h1("PS sig verification")
    pubkey = sp.record(g2 = 1, X = 2, Y0 = 3, Y1 = 4, Y2 = 5, Y3 = 6, Y4 = 7)
    c1 = PsSigContract(pubkey)
    wallet = sp.record(m0 = 8, m1 = 9, m2 = 10, m3 = 11, m4 = 12)
    signature = sp.record(s1 = 13, s2 = 14)
    scenario += c1
    scenario += c1.ps_sig_verify(wallet = wallet, signature = signature).run()
    scenario.table_of_contents()