# zkChannels Tutorial

In [part 1](tutorial_pt1_setup.md), we went over how to set up a Tezos node running in sandbox mode. If you do not have a Tezos sandbox node running, please refer to part 1. Here, we will learn how to set up a local payment channel between a customer and a merchant. 

The schema will be the following.
                        
    + -------- +                   + -------- +
    | Customer | <-- zkchannel --> | Merchant |
    + -------- +                   + ---------+
         |                               |
         |                               |
         + - - - - - - - - - - - - - - - +
                         |
                 + --------------- +
                 |  Tezos Sandbox  |
                 + --------------- +

## The contracts

Our current version of zkChannels on Tezos uses two smart contracts located in the ```libzkchannels/tezos-sandbox/tests_python/zkchannels_contract/``` subdirectory. The first is ```zkchannels_pssig.tz```, which defines the rules governing the channel, such as when the channel is considered open, closed, or in dispute. The second contract is ```pssig.tz```, which performs the Pointcheval-Sanders (PS) Signature verification. PS signatures are used in zkChannels for the merchant to provide a blind signature on the channel's state, so that the customer can update the state without revealing its contents to the merchant.

Make sure the two contract files,  ```zkchannels_pssig.tz``` and ```pssig.tz``` are in the current directory. Alternatively, you can use the full file path when referencing them during contract origination.

For some parts of the tutorial, we will need to format the storage going into the on-chain commands for originating and interacting with the contract. For formatting the storage, we will use the help of a python script `format_storage.py` in the same directory. Alternatively, if you are familiar with using jupyter notebook, it may be easier to follow the [ipynb version](https://github.com/boltlabs-inc/libzkchannels/blob/master/tezos-sandbox/tutorial_pt2_zkchannels.ipynb) of the tutorial in which the formatting code is embedded in the tutorial.


## Channel Establishment

Before originating our contracts on chain, the customer and merchant need to communicate with each other off-chain to agree upon the parameters that will be used in the smart contract. This is done to ensure that both parties are able to close the channel unilaterally after it has been funded, in case the other party goes offline.

Our off-chain protocol will be simulated using the zkChannels-cli utility. For installation instructions, refer to part 1 of the tutorial.

### zkChannels-cli

Open two terminals in the `libzkchannels` directory, one for the customer and one for the merchant. Make sure the environment has been set up by running `. ./env`. In both terminals we'll begin by setting the minimum balance for each party:

```
$ zkchannels-cli setfees --bal-min-cust 0 --bal-min-merch 0
```

### Open
To open a zkChannel, from the customer's terminal (denoted by `cust$`), run the open command with the initial balances for the channel:

```
cust$ zkchannels-cli open --party CUST --other-port 12347 --own-port 12346 --cust-bal 20000000 --merch-bal 10000000 --channel-name "channel1"

******************************************
Waiting for merchant's channel_state and channel_token...
```

The customer's node will keep attempting to communicate with the merchant's node until it responds. To respond from the merchant's terminal (denoted by `merch$`), execute following command to accept the channel request:

```
merch$ zkchannels-cli open --party MERCH --own-port 12347 --other-port 12346

******************************************
******************************************
```

Once the merchant accepts the request, the two terminals will exchange the appropriate messages and the customer's terminal will display:

```
Saving the initial customer state...
******************************************
```

### Init
The next step is to initialize the channel. From the customer's terminal, run:

``` 
cust$ zkchannels-cli init --party CUST --other-port 12347 --own-port 12346 --input-amount 0 --output-amount 30000000 --channel-name "channel1" 

******************************************
Channel token: Fr(0x50d2ebb431fe4b8a5ebcfe128b6cc9b2f31b777ee3cc9db2e137bb0432c010c6)
Verified the closing token...
Failed to connect, try: 1, error: Connection refused (os error 111)
```

We must make a note of the `Channel token` as we'll need to reference it when originating our contract.

Then to accept from the merchant's side:

```
merch$ zkchannels-cli init --party MERCH --own-port 12347 --other-port 12346

******************************************
Initial state for customer is correct, init close token: Signature : 
(h = G1(x=Fq(0x05a1247077037ce81218f248de1b068bf5d5d17fc9d3cab0522efc1463462ea7812c149673e23258d5a4de4c051bb534), y=Fq(0x0e2997734925b9914f795f087eaea28576284af7b561d315b324a4e433d77cc020f4e93b564abdc94b1af45697a9d71f)),
H = G1(x=Fq(0x0629a7f85822d06e2e1fd72929815ff789ac33651f17a6db99d369eee1871c60dbd23f0d5753795ea9f83cda1fa2857c), y=Fq(0x08ff4bb674f698a23ad0f95effbde8d0a9925a7f4ee00609750690a796bd6936566df28441bb5bd70cbd95ee52ae4632)))
```

At this point, we are ready to originate and fund the contract.

### Contract Origination

As part of originating the contracts, we will need to define our initial storage parameters that go with them. Since the ```zkchannel_main.tz``` contract will need to reference the on-chain address of the ```pssig.tz``` contract, we will need to originate the ```pssig.tz``` contract first so that we know its address. Below is the command that will originate the contract with the arguments included.

Copy the contracts into the current directory. 

```
cp ../libzkchannels/tezos-sandbox/tests_python/zkchannels_contract/* .
```

After running the following command, hit enter twice.

```
$ tezos-client originate contract pssig_contract transferring 0 from bootstrap1 running pssig.tz --init Unit --burn-cap 9&
 
Node is bootstrapped.
Estimated gas: 26616000 units (will add 100000 for safety)
Estimated storage: 887 bytes added (will add 20 for safety)
Operation successfully injected in the node.
Operation hash is 'op7NikzVhgWneyhTU3s1AvHNctojFZoZQQqvD2nWBXRKiTQvw2r'
Waiting for the operation to be included...
```

Breaking down the components:
- ```pssig_contract``` : The alias we will use to refer to our contract locally.
- ```transferring 0``` : Since we are only originating a contract and not sending funds, we transfer 0 tez.
- ```pssig.tz``` : Our smart contract. (Make sure it is in the current directory.)
- ```--init Unit```: The contract does not take in any storage arguments, so the default value is ```Unit```
- ```--burn-cap 9```: Specifies the maximum amount of tez we are willing to consume as gas costs. ```9``` is a large enough value that we will not hit the limit. 

Next, we want to bake a block so that the origination is confirmed on chain:

```
$ tezos-client bake for bootstrap5 --minimal-timestamp

Oct 22 16:08:51.179 - alpha.baking.forge: found 1 valid operations (0 refused) for timestamp 2020-10-22T14:16:24-00:00 (fitness 01::0000000000000001)
Injected block BLtQWt6L479T
Operation found in block: BLtQWt6L479TWH7DEjzdpa4ZHG4zA1rK1CzNP4PdzhnWJDFYFZz (pass: 3, offset: 0)
This sequence of operations was run:
  Manager signed operations:
    From: tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx
    Fee to the baker: ꜩ0.003531
    Expected counter: 1
    Gas limit: 26716000
    Storage limit: 907 bytes
    Balance updates:
      tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx ........... -ꜩ0.003531
      fees(SG1jfZeHRzeWAM1T4zrwunEyUpwWc82D4tbv,0) ... +ꜩ0.003531
    Origination:
      From: tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx
      Credit: ꜩ0
      Script:
...
<Contract details>
...
        Initial storage: Unit
        No delegate for this contract
        This origination was successfully applied
        Originated contracts:
          KT1AQVd9GnJbHBZnbbuuyS9tzqxadJ2ajaY5
        Storage size: 630 bytes
        Paid storage size diff: 630 bytes
        Consumed gas: 26616000
        Balance updates:
          tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx ... -ꜩ0.63
          tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx ... -ꜩ0.257

New contract KT1AQVd9GnJbHBZnbbuuyS9tzqxadJ2ajaY5 originated.
The operation has only been included 0 blocks ago.
We recommend to wait more.
Use command
  tezos-client wait for op7NikzVhgWneyhTU3s1AvHNctojFZoZQQqvD2nWBXRKiTQvw2r to be included --confirmations 30 --branch BLCxBSmsByb4jFipcayGQcPLhHKYFXbh5NLtXL5J57RUKi3TNVT
and/or an external block explorer.
Contract memorized as pssig_contract.
```

If the contract was successfully originated, then the address of the contract will be displayed to you e.g. `Originated contracts: KT1AQVd9GnJbHBZnbbuuyS9tzqxadJ2ajaY5`. You will need this when originating the main zkChannel contract. You can also find the address of the contract later by running:

```
$ tezos-client show known contract pssig_contract

KT1AQVd9GnJbHBZnbbuuyS9tzqxadJ2ajaY5
```

Next, we would like to originate our zkChannel contract, but in order to do so we need to gather some parameters which will go into the channel's initial storage. 

First, we'll need the customer's address and public key. For the purpose of this tutorial, we will use the ```bootstrap1``` account for our customer. We can find these by running:

```
$ tezos-client show address bootstrap1

Hash: tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx
Public Key: edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav
```

Now, we'll do the same for the merchant. For the merchant we'll use the account ```bootstrap2```.

```
$ tezos-client show address bootstrap2

Hash: tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN
Public Key: edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9
```

Next, we'll need to set a revocation secret and revocation lock for the initial channel state. This is what allows a merchant to dispute the channel balance if the customer broadcasts an old state. Note that these would be automatically generated by the zkChannel node implementation, but for now we will define them manually. The revocation lock is a sha256 hash of the revocation secret. 

For our example we will use the following values (this is not a command):

```
# secret = 0x123456789ccc
# rev_lock = "0x90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729"
```

Another value we need during establishment is the ```self_delay```. This defines the delay period (in seconds) between when a customer can post the closing transaction to when they can claim their balance. This delay ensures that the merchant has enough time to broadcast their dispute transaction, if the customer attempted to close on a revoked state. This value should be defined by the merchant, and should be fixed across all of the merchant's channels. For our tutorial we will choose a very short delay period of 3 seconds. In practise this would be on the order of hours or days.

```
# self_delay = 3
```

Finally, we will need to specify the initial balances. The initial balances correspond to how much each party will fund the channel. In this example the customer will start off with 20 tez and the merchant with 10 tez. It is possible to fund the channel unilaterally, in which case the value for the other party will just be 0 tez.

Here is the complete template of the command used to originate the main zkChannel contract (this is not a command):

```
originate contract my_zkchannel transferring 0 from bootstrap1 running ./zkchannel_main.tz --init (Pair (Pair (Pair <channel_token> (Pair <cust_addr> 0)) (Pair (Pair <cust_balance> "<cust_public_key>") (Pair "0" "<merch_balance>))) (Pair (Pair 0 (Pair <merch_balance "<merch_public_key>")) (Pair (Pair "<pssig_addr>"  <rev_lock>) (Pair <self_delay> "awaitingFunding"))))
```

Breaking down the components:
- ```my_zkchannel``` : The alias we will use to refer to our contract locally.
- ```zkchannel_ps.tz``` : Our smart contract. (Make sure it is in the current directory.)
- ```--init (Pair (Pair ...``` : These are the initial storage parameters being entered. Michelson storage is formatted in pairs, and the specific structure of the pairing will be fixed for given contract.
- ```"awaitingFunding"```: The initial state that the channel will be in when established.

Run the `format_commands.py` helper script with the pssig contract address and channel id (channel token) as input arguments to create our tezos origination command:
```
$ python3 format_commands.py --pssig_addr=KT1AQVd9GnJbHBZnbbuuyS9tzqxadJ2ajaY5 --chan_id=0x71f0fcd58b7d488e6bf571facc72baf5ce2ef2bb79e2fd97d2e82fdb9c351f1c 
```

Now when we run the command in the tezos client we should get something like:

```
$ tezos-client originate contract my_zkchannel transferring 0 from bootstrap1 running ./zkchannel_main.tz --init (Pair (Pair (Pair 0x71f0fcd58b7d488e6bf571facc72baf5ce2ef2bb79e2fd97d2e82fdb9c351f1c (Pair "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx" 0)) (Pair (Pair 20000000 "edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav") (Pair "0" "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN"))) (Pair (Pair 0 (Pair 10000000 "edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9")) (Pair (Pair "KT1AWZfj8xGxFjyK5A1K6uF2yFF933s1vcm5"  0x1f98c84caf714d00ede5d23142bc166d84f8cd42adc18be22c3d47453853ea49) (Pair 3 "awaitingFunding")))) --burn-cap 9&

Estimated gas: 26616000 units (will add 100000 for safety)
Estimated storage: 887 bytes added (will add 20 for safety)
Operation successfully injected in the node.
Operation hash is 'ooTqZgvg5RsCqFDqpgUM6s32ZSKvuUqL4p7ohNArMkgwk6UnRQP'
Waiting for the operation to be included...
```

Hit enter, then bake a block:

```
$ tezos-client bake for bootstrap5

Injected block BLzsNAUGuw65
Operation found in block: BLzsNAUGuw655zHfexVkcYDY2sXTQBTfAkCeBTnezk8GmSmfceX (pass: 3, offset: 0)
This sequence of operations was run:
...
<Output has been abbreviated for the tutorial>
...
        This origination was successfully applied
        Originated contracts:
          KT1S8V3Ncvgxi495SWBUSwVZJaDgpnxCjrNM
        Storage size: 7428 bytes
        Paid storage size diff: 7428 bytes
        Consumed gas: 200259000
        Balance updates:
          tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx ... -ꜩ7.428
          tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx ... -ꜩ0.257
          
New contract KT1Hx4uh6nnBErT2tioQyJoYZQ2AcHfDkNug originated.
The operation has only been included 0 blocks ago.
We recommend to wait more.
Use command
  tezos-client wait for ooTqZgvg5RsCqFDqpgUM6s32ZSKvuUqL4p7ohNArMkgwk6UnRQP to be included --confirmations 30 --branch BLtQWt6L479TWH7DEjzdpa4ZHG4zA1rK1CzNP4PdzhnWJDFYFZz
and/or an external block explorer.

Contract memorized as my_zkchannel.
```

Now, the main zkchannel contract has been originated (as well as the pssig verification contract), but it does not yet hold any funds. 

### Funding the on-chain contract

To fund the customer's side of the channel we will transfer the exact amount specified during origination to the contract from the customer's account (```bootstrap1```). We will also specify the _entrypoint_ of the on-chain contract we are interacting with:

```
$ tezos-client transfer 20 from bootstrap1 to my_zkchannel --burn-cap 9 --entrypoint addFunding&

Estimated gas: 180344958 units (will add 100000 for safety)
Estimated storage: no bytes added
Operation successfully injected in the node.
Operation hash is 'ooSdDpGico2P4r5VZJQzTVndmVRUatBdWCxyJBsYMuJfKun1w7o'
Waiting for the operation to be included...
```

- ```20``` : The amount of tez  being transfered to the contract must equal the amount specified during contract origination.
- ```my_zkchannel``` : We reference our on-chain zkChannel contract using the alias defined during origination.
- ```addFunding``` : The entrypoint used when funding.

Hit enter, then bake a block:

```
$ tezos-client bake for bootstrap5
```

Now we will do the same for the merchant:

```
$ tezos-client transfer 10 from bootstrap2 to my_zkchannel --burn-cap 9 --entrypoint addFunding&

Estimated gas: 180434332 units (will add 100000 for safety)
Estimated storage: 3 bytes added (will add 20 for safety)
Operation successfully injected in the node.
Operation hash is 'ooKEZL6arjeibqHeKnsUsHJpmtvZSVPTrJRsm8kbB5fRS7B52Jd'
Waiting for the operation to be included...
```

Hit enter, then bake a block:

```
$ tezos-client bake for bootstrap5
```

Now, we should be able to check that the status of the zkChannel contract has changed from ```"awaitingFunding"``` to ```open``` by viewing its storage:

```
$ tezos-client get contract storage for my_zkchannel

Pair (Pair (Pair "0x71f0fcd58b7d488e6bf571facc72baf5ce2ef2bb79e2fd97d2e82fdb9c351f1c" (Pair "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx" 20000000))
           (Pair (Pair 20000000 "edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav")
                 (Pair "1970-01-01T00:00:00Z" "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN")))
     (Pair (Pair 10000000
                 (Pair 10000000 "edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9"))
           (Pair (Pair "KT1Jbw6ZUf1nbKedLndHMQBzkwk8Yk91QAuG"
                       0x90d774c7ce82fbe85a7bd34bf9cbb00689e1352e7bf6b54591ccd0d3fde9d729)
                 (Pair 3 "open")))
```
And we can check that its balance is 30 tez using:
```
$ tezos-client get balance for my_zkchannel

30 ꜩ
```

Now that our channel has been funded, we are ready for the customer to receive their first _pay token_ via the off-chain _Activate_ step.

### Activate

From the customer's zkchannels-cli terminal, run:

```
cust$ zkchannels-cli activate --party CUST --other-port 12347 --own-port 12346 --channel-name "channel1"

******************************************
Sending channel token and state (s0)
Failed to connect, try: 1, error: Connection refused (os error 111)
```

And to accept from the merchant's side:

```
merch$ zkchannels-cli activate --party MERCH --own-port 12347 --other-port 12346

******************************************
```

The customer should then automatically receive their first pay token:

```
cust$
Obtained pay token (p0): Signature : 
(h = G1(x=Fq(0x01660f4f49e54779b7fcd93eedec5a3b46a30448eb6533bf8a738d9a076c76dc3922d694883cd5b5e38e56b6eaa29389), y=Fq(0x145c703270663cc091d137d955921ff3f07ae8cf58aa7130107ff3393955822e1ff4d6ae09115772e1799d4908187ebd)),
H = G1(x=Fq(0x051feeb3eb6940faafa49fbb53d8fa1ad3654476d422af38a992fc9f430ab93ddfab356fa06fee9562f5906c8c20a30f), y=Fq(0x00d522235ea2aa141b9b1f597577fc56db2ca003e698ef9c64318dc9732caebee1bdec9c1c8e68eca06fe8c493d4466e)))
```

If the customer were to make a payment on their zkChannel using this initial pay token, their payment activity would not be anonymous. The final step in opening the channel will be to unlink the customer's payment tag from the channel via the _Unlink_ step.

### Unlink
From the customer's terminal we run:

```
cust$ zkchannels-cli unlink --party CUST --other-port 12347 --own-port 12346 --channel-name "channel1" -v

******************************************
Failed to connect, try: 1, error: Connection refused (os error 111)
```

And from the merchant's side:

```
merch$ zkchannels-cli unlink --party MERCH --own-port 12347 --other-port 12346

******************************************
Merchant running unlink...

Sent new close token and getting revoked state back: ["{\"rev_lock\":\"86803b5a0e73d2176226735645ad0548dfa71e85b64d9b05ba0bb36ca0e0f2ce\",\"rev_secret\":\"3cf23fda9d9e027ffe3c110076b47c168e9393f9092e4adb71d38d2f8440be7f\"}"]
Failed to connect, try: 1, error: Connection refused (os error 111)
Sending new pay token: ["true"]
```

The customer's terminal should then return a success message with a new pay token:

```
cust$ 
Sent session id, unlink payment and waiting for new close token: ["{\"h\":\"8041f4ee752eadbfcac83138a081cc94d78636ed238655a87c7104ff9dd8dd6e8f5578ef094d492267ee910bc318aad0\",\"H\":\"8883a6ea5a780e5ab09c6a4ac386693f59b593cbf983b4d67cd2b9de127aa2d2d48da34cecebb59a8707b6763f6361c7\"}"]
Sent revoked state and waiting for new pay token: ["{\"h\":\"93c814d9bf99f0301b63e695540973b861fd3c3935fc92209773789fab873b09077f30b7835663e8edbf75e1b8a06dad\",\"H\":\"b8952db3681cbff9d09068a2592932aa4be7511197e7f501037cfab7409b3bac2b8fe4afca41a57a58297fbd7b189798\"}"]
Unlink phase successful!
```

Now we are ready to make anonymous payments on our zkchannel!

## Pay
In zkChannels, making a payment can be thought of as the customer obtaining a new closing signature (or _closing token_) from the merchant with an updated balance, with the difference in the new balance being equal to the payment amount. The merchant will only learn that one of its open channels made a payment of a particular amount, without knowing specifically which channel it came from.

To perform a payment, from the customer's terminal run the following command with the payment amount (in mutez) following the `--amount` flag:

```
cust$ zkchannels-cli pay --party CUST --other-port 12347 --own-port 12346 --channel-name "channel1" --amount=200

******************************************
Failed to connect, try: 1, error: Connection refused (os error 111)
```

To accept the payment from the merchant's terminal:

```
merch$ zkchannels-cli pay --party MERCH --own-port 12347 --other-port 12346 &

******************************************

Sent new close token and getting revoked state back: ["{\"rev_lock\":\"2c645ef419b40d865c7108e6f35cee5f5424157620d3c9a889cebfded9cff962\",\"rev_secret\":\"f650328c237cbaf91d6a038a062c69b342946bf9a7294401efc84d712325fc58\"}"]
Failed to connect, try: 1, error: Connection refused (os error 111)
Sending new pay token: ["true"]
[!] valid pay tokend delivered: true
```

And the customer's node should receive a new close token and pay token:

```
Reveal nonce and confirm payment request: ["true"]
Sent session id & payment and waiting for new close token: ["{\"h\":\"a8ad9c3a6f029a6fe607bdcbca515b87cb047a7770ad948018d4e9ec060f3684955785b24738fa9f3147bbcbcf72546f\",\"H\":\"87c69dd2aa60a7bd54a7bfeb0f7504aca3fb0ba5a327f09ce3d70940b237e8f184de436d2ac5a09a5848cc84e748c66f\"}"]
Sent revoked state and waiting for new pay token: ["{\"h\":\"90a7dd3479186a0db4fc91c88a5e9e3ebc8e8cfc729803542ab0c0dc87aacc3952ef28a9b65527dc799d3d78eecb4bf8\",\"H\":\"af04ad250ca449525a9c5222f699404657f8fcf2cb9a9a5767a54f9bcef320c790f984d6ea66ac9f65e1d58b7ffe5cca\"}"]
******************************************
```

## Unilateral Close

### Customer close
If the customer wishes to close the channel, the customer can initiate channel closure via the ```custClose``` entrypoint. In order for the close to be valid, the storage parameters must include the final state and the merchant's signature for it:

To retrieve the necessary variables including merchant's signature, in the customer's zkchannels-cli terminal run:

```
cust$ zkchannels-cli close --party CUST --channel-id "channel1" --file cust_close.json --decompress-cust-close
```

This will create a json file `cust_close.json` containing the closing state as well as the merchant's closing signature and pubkey. The merchant's signature has 2 parts, `s1` and `s2`, and the pubkey has 6 parts, `g2`, `Y0`, `Y1`, `Y2`, `Y3` and `X`. In order to convert these outputs into a form ready to be entered into the zkchannel contract, we'll use the python helper script `format_commands.py`. This time we will include the cust_close.json file produced by zkchannels-cli.

```
$ python3 format_commands.py --pssig_addr=KT1AQVd9GnJbHBZnbbuuyS9tzqxadJ2ajaY5 --chan_id=0x71f0fcd58b7d488e6bf571facc72baf5ce2ef2bb79e2fd97d2e82fdb9c351f1c --cust_close=cust_close.json

custClose call command:
tezos-client transfer 0 from bootstrap1 to my_zkchannel --entrypoint custClose --burn-cap 9 --arg '(Pair (Pair (Pair 1000000 (Pair ...
...
<Abbreviated output>
```

The output will be the formatted storage needed to call the `custClose` entrypoint. Execute the command in the tezos node:

```
$ tezos-client transfer 0 from bootstrap1 to my_zkchannel --entrypoint custClose --burn-cap 9 --arg '(Pair (Pair (Pair 1000000 (Pair ...

Estimated gas: 180434332 units (will add 100000 for safety)
Estimated storage: 3 bytes added (will add 20 for safety)
Operation successfully injected in the node.
Operation hash is 'ooKEZL6arjeibqHeKnsUsHJpmtvZSVPTrJRsm8kbB5fRS7B52Jd'
Waiting for the operation to be included...
```

Hit enter, then bake a block:

```
$ tezos-client bake for bootstrap5
```

Then in the output under `Transaction: Updated storage:` the channel state should have changed to `"custClose`. 

At this point, the merchant should verify that the closing state is indeed the latest state and not an old (revoked) one by checking the revocation lock (see 'Disputes' below). 

### Expiry
At any point while the channel is open, the merchant may initiate a channel closure by calling on the `merchClose` entrypoint. This transitions the channel into a `"merchClose"` state and forces the customer to broadcast their latest closing state to the channel before the timeout specified in `self_delay`. If the delay period elapses before the customer has broadcast their latest state, the merchant may claim the entire channel balance using the `merchClaim` command (see below).
```
$ tezos-client transfer 0 from bootstrap2 to my_zkchannel --burn-cap 9 --entrypoint merchClose&
```

### Claiming payouts
If the channel was closed unilaterally, after the `self_delay` period has expired, the customer or merchant who is waiting to receive their funds can do so via the `custClaim` or `merchClaim` entrypoints respectively. Note that in order for time to progress in our sandbox mode, blocks would need to be baked using the standard `bake` command. The command for the customer would be:
```
$ tezos-client transfer 0 from bootstrap1 to my_zkchannel --entrypoint custClaim --burn-cap 9&
```
and for the merchant:
```
$ tezos-client transfer 0 from bootstrap2 to my_zkchannel --entrypoint merchClaim --burn-cap 9&
```

### Disputes
Once the customer calls the `custClose` entrypoint, the merchant should check whether the state was final or not by checking if the secret to the revocation lock had been previously revealed. To check this, the merchant should run this zkchannels-cli command with the revocation lock as an input argument:

```
merch$ zkchannels-cli close --party MERCH -- revlock <revocation lock>
```

If the customer closes the channel on an old (revoked) state, the corresponding revocation secret will be revealed. If this is the case, then the merchant will be able to call the `merchDispute` entrypoint and claim the entire balance of the channel. To prove that the state was revoked, the merchant must provide the revocation secret:

```
tezos-client transfer 0 from bootstrap2 to my_zkchannel --entrypoint merchDispute --burn-cap 9 --arg <revocation_secret>&
```
Filling in the revocation secret using our example:

```
$ tezos-client transfer 0 from bootstrap2 to my_zkchannel --entrypoint merchDispute --burn-cap 9 --arg 0x123456789ccc&
```


## Navigation
- [Back to part 1 - Setup Instructions](tutorial_pt1_setup.md)
- [Gas cost benchmarks](gas_cost_benchmarks.md)
