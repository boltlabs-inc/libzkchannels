import smartpy as sp


class Bls12_381(sp.Contract):
    def __init__(self, **params):
        self.init(**params)

    """
    ADD: Add two curve points or field elements.

    :: bls12_381_g1 : bls12_381_g1 : 'S -> bls12_381_g1 : 'S
    :: bls12_381_g2 : bls12_381_g2 : 'S -> bls12_381_g2 : 'S
    :: bls12_381_fr : bls12_381_fr : 'S -> bls12_381_fr : 'S
    """
    @sp.entry_point
    def add(self, g1, g2, fr):
        self.data.g1 += g1;
        self.data.g2 += g2;
        self.data.fr += fr;

    """
    NEG: Negate a curve point or field element.

    :: bls12_381_g1 : 'S -> bls12_381_g1 : 'S
    :: bls12_381_g2 : 'S -> bls12_381_g2 : 'S
    :: bls12_381_fr : 'S -> bls12_381_fr : 'S
    """
    @sp.entry_point
    def negate(self):
        self.data.g1 = - self.data.g1

    """
    INT: Convert a field element to type int. The returned value is always between 0 (inclusive) and the order of Fr (exclusive).

    :: bls12_381_fr : 'S -> int : 'S
    """
    @sp.entry_point
    def toInt(self):
        sp.verify(sp.to_int(self.data.fr) ==  35115637951021136697019058358166656987035571271296265805438287419849817743725, message = "Failed to cast field element Fr to Int");

    """
    MUL: Multiply a curve point or field element by a scalar field element. Fr
    elements can be built from naturals by multiplying by the unit of Fr using PUSH bls12_381_fr 1; MUL. Note
    that the multiplication will be computed using the natural modulo the order
    of Fr.

    :: bls12_381_g1 : bls12_381_fr : 'S -> bls12_381_g1 : 'S
    :: bls12_381_g2 : bls12_381_fr : 'S -> bls12_381_g2 : 'S
    :: bls12_381_fr : bls12_381_fr : 'S -> bls12_381_fr : 'S
    :: nat : bls12_381_fr : 'S -> bls12_381_fr : 'S
    :: int : bls12_381_fr : 'S -> bls12_381_fr : 'S
    :: bls12_381_fr : nat : 'S -> bls12_381_fr : 'S
    :: bls12_381_fr : int : 'S -> bls12_381_fr : 'S
    """
    @sp.entry_point
    def mul(self, pair):
        self.data.mulResult = sp.some(sp.fst(pair) * sp.snd(pair));

    """
    PAIRING_CHECK:
    Verify that the product of pairings of the given list of points is equal to 1 in Fq12. Returns true if the list is empty.
    Can be used to verify if two pairings P1 and P2 are equal by verifying P1 * P2^(-1) = 1.

    :: list (pair bls12_381_g1 bls12_381_g2) : 'S -> bool : 'S
    """
    @sp.entry_point
    def pairing_check(self, listOfPairs):
        self.data.checkResult = sp.some(sp.pairing_check(listOfPairs));

@sp.add_test(name = "BLS12-381")
def test():
    c1 = Bls12_381(
        g1 = sp.bls12_381_g1("0x8ce3b57b791798433fd323753489cac9bca43b98deaafaed91f4cb010730ae1e38b186ccd37a09b8aed62ce23b699c48"),
        g2 = sp.bls12_381_g2("0x8647aa9680cd0cdf065b94e818ff2bb948cc97838bcee987b9bc1b76d0a0a6e0d85db4e9d75aaedfc79d4ea2733a21ae0579014de7636dd2943d45b87c82b1c66a289006b0b9767921bb8edd3f6c5c5dec0d54cd65f61513113c50cc977849e5"),
        fr = sp.bls12_381_fr("0x60c8333ef28e1b3b7fc487952b1e21372bd43056e8cb993625735b645e8030b7"),
        mulResult = sp.none,
        checkResult = sp.none
    );

    scenario = sp.test_scenario()
    scenario += c1

    scenario += c1.add(
        g1 = sp.bls12_381_g1("0x8ce3b57b791798433fd323753489cac9bca43b98deaafaed91f4cb010730ae1e38b186ccd37a09b8aed62ce23b699c48"),
        g2 = sp.bls12_381_g2("0x8647aa9680cd0cdf065b94e818ff2bb948cc97838bcee987b9bc1b76d0a0a6e0d85db4e9d75aaedfc79d4ea2733a21ae0579014de7636dd2943d45b87c82b1c66a289006b0b9767921bb8edd3f6c5c5dec0d54cd65f61513113c50cc977849e5"),
        fr = sp.bls12_381_fr("0x60c8333ef28e1b3b7fc487952b1e21372bd43056e8cb993625735b645e8030b7")
    );

    scenario += c1.negate();
    scenario += c1.toInt();

    scenario += c1.mul(
        sp.pair(
            sp.bls12_381_fr("0x8ce3b57b791798433fd323753489cac9bca43b98deaafaed91f4cb010730ae1e38b186ccd37a09b8aed62ce23b699c48"),
            sp.bls12_381_fr("0x8ce3b57b791798433fd323753489cac9bca43b98deaafaed91f4cb010730ae1e38b186ccd37a09b8aed62ce23b699c")
        )
    );

    scenario += c1.pairing_check(
        sp.list([
           sp.pair(
                sp.bls12_381_g1("0x8ce3b57b791798433fd323753489cac9bca43b98deaafaed91f4cb010730ae1e38b186ccd37a09b8aed62ce23b699c48"),
                sp.bls12_381_g2("0x8647aa9680cd0cdf065b94e818ff2bb948cc97838bcee987b9bc1b76d0a0a6e0d85db4e9d75aaedfc79d4ea2733a21ae0579014de7636dd2943d45b87c82b1c66a289006b0b9767921bb8edd3f6c5c5dec0d54cd65f61513113c50cc977849e5")
            ),
            sp.pair(
                sp.bls12_381_g1("0x8ce3b57b791798433fd323753489cac9bca43b98deaafaed91f4cb010730ae1e38b186ccd37a09b8aed62ce23b699c48"),
                sp.bls12_381_g2("0x8647aa9680cd0cdf065b94e818ff2bb948cc97838bcee987b9bc1b76d0a0a6e0d85db4e9d75aaedfc79d4ea2733a21ae0579014de7636dd2943d45b87c82b1c66a289006b0b9767921bb8edd3f6c5c5dec0d54cd65f61513113c50cc977849e5")
            )
        ])
    );