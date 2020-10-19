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


# Installing Tezos

zkChannels uses a form of signature verification which can only be computed on the dalpha-release branch of tezos. To install  it, follow the instructions in this link. (It is not necessary to install SmartPy for this tutorial.)

https://github.com/boltlabs-inc/libzkchannels/tree/master/tezos-sandbox

# Setting up a node

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

## Basic commands
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

TODO Darius: command below might need to be: ```
$ tezos-client bake for baker5``` instead
```
$ tezos-client bake for bootstrap1
```
# zkChannels Tutorial

Now that we have the tezos-sandbox node up and running and are familiar with performing a basic transfer operation, we will start setting up a zkChannel between a customer and a merchant.

#### The contracts

Our current version of zkChannels on Tezos uses two smart contracts. The first is ```zkchannels_mock_pssig.tz```, which defines the rules governing the channel, such as when the channel is considered open, closed, or in dispute. The second contract is ```mock_pssig.tz```, which performs the Pointcheval-Sanders (PS) Signature verification.

PS signatures are used in zkChannels for the merchant to provide a blind signature on the channel's state, so that the customer can update the state without revealing its contents to the merchant.

The separation of the ```zkchannels_mock_pssig.tz``` and ```mock_pssig.tz``` is because ```mock_pssig.tz``` uses logic which is only available on the ```bls12-381``` branch of tezos, and such there are no tools currently available to combine them easily. When these tools have been developed, we will likely combine them into one contract.

# Origination

As part of originating the contracts, we will need to define our initial storage parameters that go with them. Since the ```zkchannels_mock_pssig.tz``` contract will need to reference the on-chain address of the ```mock_pssig.tz``` contract, we will need to originate the ```mock_pssig.tz``` contract first so that we know its address. Below is the command that will originate the contract with the arguments included.

```
$ tezos-client originate contract pssig_contract transferring 0 from bootstrap1 running mock_pssig.tz --init Unit --burn-cap 9
```

Breaking down the components:
- ```pssig_contract``` : The alias we will use to refer to our contract locally.
- ```transferring 0``` : Since we are only originating a contract and not sending funds, we transfer 0 tez.
- ```mock_pssig.tz``` : Our smart contract. (Make sure it is in the current directory.)
- ```--init Unit```: The contract does not take in any storage arguments, so the default value is ```Unit```
- ```--burn-cap 9```: Specifies the maximum amount of tez we are willing to consume as gas costs. ```9``` is a large enough value that we will not hit the limit. 

Next, we want to bake a block so that the origination is confirmed on chain:

TODO Darius: check bake command
```
$ tezos-client bake for bootstrap1 --minimal-timestamp
```

If the contract was successfully originated, then the address of the contract will be displayed to you. You will need this when originating the main zkChannel contract. You can also find the address of the contract later by running:

```
$ tezos-client show address pssig_contract
```

Next we would like to originate our zkChannel contract, but in order to do so we need to define some parameters which will go into the channel's initial storage. 

First, we'll need the customer's address and public key. For the purpose of this tutorial, we will use the ```bootstrap1``` account for our customer. We can find out the address of this account by running.

```
$ tezos-client show known contract bootstrap1
```
And to get the public key run:

*TODO Darius: not sure if this is the command*
```
$ tezos-client show address bootstrap1
```

Now, we'll do the same for the merchant. For the merchant we'll use the account ```bootstrap2```.

```
$ tezos-client show known contract bootstrap2
$ tezos-client show address bootstrap2
```

Next, we'll need to set a revocation secret and revocation lock for the initial channel state. This is what allows a merchant to dispute the channel balance if the customer broadcasts an old state. Note that these would be automatically generated by the zkChannel node implementation, but for now we will define them manually. The revocation lock is a sha256 hash of the revocation secret. For our example we will use:

```
# secret_final = 0x123456789ccc
# rev_lock_final = "0x90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729"
```

Another value which must be defined during establishment is the ```self_delay```. This defines the delay period (in seconds) between when a customer can post the closing transaction to when they can claim their balance. This delay ensures that the merchant has enough time to broadcast their dispute transaction, in order to punish the customer, if they attempted to close on a revoked state. The merchant defines this value, as it should be fixed across all of the merchant's channels. For our tutorial we will choose a very short delay period of 3 seconds. In practise this would be on the order of hours or days.

Finally, we will need to specify the initial balances. The initial balances correspond to how much each party will fund the channel. In this example the customer will start off with 20 tez and the merchant with 10 tez. It is possible to fund the channel unilaterally, in which case the value for the other party will just be 0 tez.

```
$ tezos-client originate contract my_zkchannel transferring 0 from bootstrap1 running zkchannel_mock_ps.tz --init (Pair (Pair (Pair "randomchanid" (Pair "<cust_address>" 0)) (Pair (Pair <cust_balance> "<cust_pubkey") (Pair "0" "<merch_address>"))) (Pair (Pair 0 (Pair <merch_balance> "<merch_pubkey>")) (Pair (Pair "<pssig_contract_address>"  <revocation_lock>) (Pair <self_delay> "awaitingFunding")))) --burn-cap 9
```

Breaking down the components:
- ```my_zkchannel``` : The alias we will use to refer to our contract locally.
- ```zkchannel_mock_ps.tz``` : Our smart contract. (Make sure it is in the current directory.)
- ```--init (Pair (Pair ...``` : These are the initial storage parameters being entered. Michelson storage is formatted in pairs, and the specific structure of the pairing will be fixed for given contract.
- ```"randomchanid"``` : The channel ID. In practise this will be a randomly generated string.
- ```"awaitingFunding"```: The initial state that the channel will be in when established.

Filling all the fields in, we should get something that looks like:

```
$ tezos-client originate contract my_zkchannel transferring 0 from bootstrap1 running zkchannel_mock_ps.tz --init (Pair (Pair (Pair "randomchanid" (Pair "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx" 0)) (Pair (Pair 20000000 "edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav") (Pair "0" "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN"))) (Pair (Pair 0 (Pair 10000000 "edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9")) (Pair (Pair "KT1Jbw6ZUf1nbKedLndHMQBzkwk8Yk91QAuG"  0x90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729) (Pair 3 "awaitingFunding")))) --burn-cap 9
```

# Establishment
 
Two more steps are needed before channel can be considered established. First, we will need to prepare the off-chain state of the channel between the customer and the merchant using the rust cli. Second, we will need to fund the channel.


## Rust cli

TODO Darius: Installation instructions for rust cli
TODO Darius: Funding channel should happen before unlink?

## Open

## Init

## Activate

## Unlink

## Funding the channel on chain

To fund the customer's side of the channel we will transfer the exact amount specified during origination to the contract from the customer's account (```bootstrap1```). We will also specify the _entrypoint_ of the on-chain contract we are interacting with:
```
tezos-client transfer 20 from bootstrap1 to zkcontract --burn-cap 9 --entrypoint addFunding
```
- ```20``` : The amount of tez  being transfered to the contract must equal the amount specified during contract origination.
- ```zkcontract``` : We reference our on-chain zkChannel contract using the alias defined during origination.
- ```addFunding``` : The entrypoint used when funding.

Now we will do the same for  the merchant:
```
tezos-client transfer 10 from bootstrap2 to zkcontract --burn-cap 9 --entrypoint addFunding
```
Bake a block so that these transfers will be confirmed:

TODO Darius: check bake command
```
tezos-client bake for bootstrap1
```
Now, we should be able to check that the status of the zkChannel contract has changed from ```"awaitingFunding"``` to ```open``` by viewing its storage:
```
tezos-client get contract storage for zkcontract
```
And we can check its balance using:
```
tezos-client get balance for zkcontract
```

# Pay


# Mutual Close
In the case of a mutual close, both the customer and merchant need to sign off on the final state.
TODO Darius: Check if there is a libzkchannel protocol for initating a mutual close.

The final state that gets signed needs to be serialized in a specific way according to how it'll be checked in the on-chain contract. The command to create the serialized data to be signed, and the format of the storage is as follows:

```
hash data (Pair (Pair "<channel_id> <cust_address>) (Pair "<merch_address>" (Pair <cust_balance> <merch_balance> ))) of type pair (pair string address) (pair address (pair mutez mutez))
```
Breaking down the components:
- ```hash data``` : The command that will give us our serialized data to be signed.
- ```of type pair (pair...``` : This lets the tezos node know what structure and types to expect.

Filling in the fields, it should look something like:

```
hash data (Pair (Pair "randomchanid" "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx") (Pair "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN" (Pair 1000000 29000000 ))) of type pair (pair string address) (pair address (pair mutez mutez))
```

The terminal should return a result with a field ```Raw packed data```. Now we want to sign this data with the customer and merchant's account. First, with the customer's account (```bootstrap1```):

```
sign bytes 0x0507070707010000000c72616e646f6d6368616e69640a00000016000002298c03ed7d454a101eb7022bc95f7e5f41ac7807070a000000160000e7670f32038107a59a2b9cfefae36ea21f5aa63c07070080897a008085d41b for bootstrap1
```
and with the merchant's account (```bootstrap2```):

```
sign bytes 0x0507070707010000000c72616e646f6d6368616e69640a00000016000002298c03ed7d454a101eb7022bc95f7e5f41ac7807070a000000160000e7670f32038107a59a2b9cfefae36ea21f5aa63c07070080897a008085d41b for bootstrap2
```

Now that we have both signatures on the final state of the channel, we can initiate the mutual close!

```
transfer 0 from bootstrap1 to my_zkchannel --entrypoint mutualClose --burn-cap 9 --arg (Pair (Pair "<cust_signature" "<merch_signature>") (Pair 1000000 29000000))
```

Filling in the signatures:

```
transfer 0 from bootstrap1 to my_zkchannel --entrypoint mutualClose --burn-cap 9 --arg (Pair (Pair "edsigtYVTS2pJoXt8eARKnZGtFa8g9i8buUe7AVDtcfv7nbFykAhwZTr9dHSi9jxUbsU66K4aetdtA8tJyVrjzwapx9FB3eoKtR" "edsigtfpHDYiu56zvvXJujdMP3HjidSFd17L8Wgw3VvrghkJTCUKe81YtscWV9PJnTK7g4uGV8s4dqRy2dMayvUGyuXqznSjMgr") (Pair 1000000 29000000))
```

# Unilateral Close

## Customer close
If the customer wishes to close the channel, and the merchant was not cooperative, the customer can initiate channel closure via the ```custClose``` entrypoint. In order for the close to be valid, the storage parameters must include the final state and the merchant's signatures on them:
```
transfer 0 from bootstrap1 to my_zkchannel --entrypoint custClose --burn-cap 9 --arg (Pair (Pair (Pair "<g2>" "<merchPk0>") (Pair "<merchPk0>" (Pair "<merchPk0>" "<merchPk0>"))) (Pair (Pair "<merchPk0>" (Pair <cust_balance> <merch_balance>)) (Pair <revocation_lock> (Pair "<s1>" "<s2>"))))
```
With the parameters filled it in should look something like this:
```
transfer 0 from bootstrap1 to my_zkchannel --entrypoint custClose --burn-cap 9 --arg (Pair (Pair (Pair "dummy_g2" "dummy_merchPk0") (Pair "dummy_merchPk1" (Pair "dummy_merchPk2" "dummy_merchPk3"))) (Pair (Pair "dummy_merchPk4" (Pair 1000000 29000000)) (Pair 0x90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729 (Pair "dummy_s1" "dummy_s2"))))
```

## Expiry

```
tezos-client transfer 0 from bootstrap2 to zkcontract --burn-cap 9 --entrypoint merchClose&
```

## Claiming payouts
If the channel was closed unilaterally, after the ```self_delay``` period has expired, the customer or merchant who is waiting to receive their funds can do so via the ```custClaim``` or ```merchClaim``` entrypoints respectively. Note that in order for time to progress in our sandbox mode, blocks would need to be baked using the standard ```bake``` command. The command for the customer would be:
```
transfer 0 from bootstrap1 to my_zkchannel --entrypoint custClaim --burn-cap 9
```
and for the merchant:
```
transfer 0 from bootstrap2 to my_zkchannel --entrypoint merchClaim --burn-cap 9
```

## Disputes
If the customer posts an old (previously revoked) state, the merchant should dispute it via the ```merchDispute``` entrypoint. To prove that the state was revoked, the merchant must provide the revocation secret:

```
transfer 0 from bootstrap2 to my_zkchannel --entrypoint merchDispute --burn-cap 9 --arg <revocation_secret>
```
Filling in the revocation secret using our example:

```
transfer 0 from bootstrap2 to my_zkchannel --entrypoint merchDispute --burn-cap 9 --arg 0x123456789ccc
```
