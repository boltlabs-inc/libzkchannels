# Tezos Sandbox zkchannel Tutorial

### Introduction

This tutorial is designed to walk you through how to set up a zero-knowledge channel (zkchannel) on tezos sandbox mode. 

Here, we will learn how to set up a local payment channel between a customer, `Alice`, and a merchant, `Bob`. 

The schema will be the following.

    Customer                    Merchant
    + ----- +                   + --- +
    | Alice | <-- zkchannel --> | Bob |
    + ----- +                   + --- +
        |                          |
        |                          |
        + - - - -  - - - - - - - - +
                      |
             + --------------- +
             |  Tezos Sandbox  |
             + --------------- +


### Installing Tezos

zkChannels uses a form of signature verification which can only be computed on the dalpha-release branch of tezos. To install  it, follow the instructions in this link. (It is not necessary to install SmartPy for this tutorial.)

https://github.com/boltlabs-inc/libzkchannels/tree/master/tezos-sandbox

### Setting up a node

(Instructions from https://tezos.gitlab.io/user/sandbox.html)

In a terminal in your tezos directory, the following command will initialize a node listening for peers on port 19731 and listening for RPC on port 18731:
```
./src/bin_node/tezos-sandboxed-node.sh 1 --connections 1
```

Once your node is running, open a new terminal and initialize the “sandboxed” client data in a temporary directory:

```
eval `./src/bin_client/tezos-init-sandboxed-client.sh 1`
```

It will also define in the current shell session an alias tezos-client preconfigured for communicating with the same-numbered node.

When you bootstrap a new network, the network is initialized with a dummy economic protocol, called genesis. If you want to run the whole implemented protocol, init-sandboxed-client also defines an alias tezos-activate-alpha, that you need to execute once for activating the whole network. For instance:

```
$ tezos-client rpc get /chains/main/blocks/head/metadata
  "next_protocol": "Ps9mPmXaRzmzk35gbAYNCAw6UXdE2qoABTHbN2oEEc1qM7CwT9P"
$ tezos-activate-alpha
  Injected BMV9KnSPE1yw
$ tezos-client rpc get /chains/main/blocks/head/metadata
  "protocol": "Ps9mPmXaRzmzk35gbAYNCAw6UXdE2qoABTHbN2oEEc1qM7CwT9P"
```

We now have the possibility to send transactions to the sandboxed network. As the genesis block used to initialize the sandboxed network differs from the one used in test networks, it is not possible to activate accounts obtained from the faucet. However, we can use the preconfigured accounts which can be listed with:

```
$ tezos-client list known addresses

  activator: tz1TGu6TN5GSez2ndXXeDX6LgUDvLzPLqgYV (unencrypted sk known)
  bootstrap5: tz1ddb9NMYHZi5UzPdzTZMYQQZoMub195zgv (unencrypted sk known)
  bootstrap4: tz1b7tUupMgCNw2cCLpKTkSD1NZzB5TkP2sv (unencrypted sk known)
  bootstrap3: tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU (unencrypted sk known)
  bootstrap2: tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN (unencrypted sk known)
  bootstrap1: tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx (unencrypted sk known)
```

We can run the following command to transfer some Tez from one account to another:


```
$ tezos-client transfer 42 from bootstrap1 to bootstrap2 &
...
Waiting for the operation to be included...
```

You will notice that this command doesn’t terminate (hence the &), as usual it is waiting for the network to include the transaction in a block. Given that we are in a sandbox we need to bake a block ourselves and we can do so with the following command:

```
$ tezos-client bake for bootstrap1
```
### zkChannels

Now that we have the tezos-sandbox node up and running and are familiar with performing a basic transfer operation, we will start setting up a zkChannel between a customer and a merchant.

#### The contracts

Our current version of zkChannels on Tezos uses two smart contracts. The first is ```zkchannels_mock_pssig.tz```, which defines the rules governing the channel, such as when the channel is considered open, closed, or in dispute. The second contract is ```mock_pssig.tz```, which performs the Pointcheval-Sanders (PS) Signature verification.

PS signatures are used in zkChannels for the merchant to provide a blind signature on the channel's state, so that the customer can update the state without revealing its contents to the merchant.

The separation of the ```zkchannels_mock_pssig.tz``` and ```mock_pssig.tz``` is because ```mock_pssig.tz``` uses logic which is only available on the ```bls12-381``` branch of tezos, and such there are no tools currently available to combine them easily. When these tools have been developed, we will likely combine them into one contract.

#### Originating the contracts

As part of originating the contracts, we will need to define our initial storage parameters that go with them. Since the ```zkchannels_mock_pssig.tz``` contract will need to reference the on-chain address of the ```mock_pssig.tz``` contract, we will need to originate the ```mock_pssig.tz``` contract first so that we know its address. Below is the command that will originate the contract with the arguments included.

```
$ tezos-client originate contract pssig_contract transferring 0 from bootstrap1 running mock_pssig.tz --init Unit --burn-cap 9
```

Breaking down the components:
- ```transferring 0``` : Since we are only originating a contract and not sending funds, we transfer 0 tez.
- ```mock_pssig.tz``` : Our smart contract. (Make sure it is in the current directory.)
- ```--init Unit```: The contract does not take in any storage arguments, so the default value is ```Unit```
- ```--burn-cap 9```: Specifies the maximum amount of tez we are willing to consume as gas costs. ```9``` is a large enough value that we will not hit the limit. 

Next, we want to bake a block so that the origination is confirmed on chain:

```
$ tezos-client bake for bootstrap1 --minimal-timestamp
```

Next we would like to originate our zkChannel contract, but in order to do so we need to define some parameters which will go into the channel's initial storage. 

First, we'll need the customer's address and public key. For the purpose of this tutorial, we will use the ```bootstrap1``` account for our customer. We can find out the address of this account by running.

```
$ tezos-client show known contract bootstrap1
```
And to get the public key run

*TODO Darius: not sure if this is the command*
```
$ tezos-client show address bootstrap1
```

Now, we'll do the same for the merchant. For the merchant we'll use the account ```bootstrap2```.

```
$ tezos-client show known contract bootstrap2
$ tezos-client show address bootstrap2
```

Next, we'll need to set a revocation secret and revocation lock for the initial channel state. This is what allows a merchant to dispute the channel balance if the customer broadcasts an old state. Note that these would be automatically generated by the zkChannel node implementation, but for now we will define them manually. The revocation lock is a blake2b hash of the revocation secret. For our example we will use:

```
# secret_final = 0x123456789ccc
# rev_lock_final = "0x5d33df275854dc7aea1323eab177a195935d0af0cb7fa727c5b491d41244d42c"
```

Finally, we will need to specify the initial balances. The initial balances correspond to how much each party will fund the channel. In this example the customer will start off with 20 tez and the merchant with 10 tez. It is possible 

```
$ tezos-client originate contract my_zkchannel transferring 0 from bootstrap1 running zkchannel_mock_ps.tz --init (Pair (Pair (Pair "randomchanid" (Pair "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx" 0)) (Pair (Pair 20000000 "edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav") (Pair "0" "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN"))) (Pair (Pair 0 (Pair 10000000 "edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9")) (Pair (Pair "KT1Jbw6ZUf1nbKedLndHMQBzkwk8Yk91QAuG"  0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49) (Pair 3 "awaitingFunding")))) --burn-cap 9
```

Breaking down the components:
- ```zkchannel_mock_ps.tz``` : Our smart contract. (Make sure it is in the current directory.)

