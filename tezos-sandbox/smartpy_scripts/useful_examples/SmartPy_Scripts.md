# SmartPy Scripts

### Overview of example scripts and mechanisms used

#### Escrow
Alice and Bob can set up a contract where both parties fund it with prespecified amounts.

If Bob is able to provide a hash secret before a timeout, he will be able to claim all the funds held by the escrow. Otherwise, when the timeout expires, only Alice will be able to claim the funds (without needing to provide the hash secret).

Mechnisms used: hash secrets ```(sp.blake2b)```, timeout ```(sp.now < self.data.epoch)```

#### AtomicSwap
Here, two AtomicSwap contracts are created. One with Alice as the owner and Bob as the counterparty, and the second with the identities reversed. They are both secured with the same hash secret, so that if the secret gets revealed, the counterparties on each contract can claim their balance. If the transfer doesn't happen before the timeout, the owners can cancel the swap.

Mechnisms used: hash secrets ```(sp.blake2b)```, timeout ```(sp.now < self.data.epoch)```

#### Signature Reference Example
Simple example and test cases for creating and verifying signatures.

Mechnisms used: ```sp.make_signature```, ```sp.check_signature```
