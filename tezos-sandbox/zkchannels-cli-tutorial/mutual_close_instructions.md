
## Mutual Close
In the case of a mutual close, both the customer and merchant need to sign off on the final state. The final state that gets signed needs to be serialized in a specific way according to how it'll be checked in the on-chain contract. The command to create the serialized data to be signed, and the format of the storage is as follows:

```
tezos-client hash data '(Pair (Pair "<channel_id> <cust_address>) (Pair "<merch_address>" (Pair <cust_balance> <merch_balance> )))' of type 'pair (pair string address) (pair address (pair mutez mutez))'
```
Breaking down the components:
- ```hash data``` : The command that will give us our serialized data to be signed.
- ```of type pair (pair...``` : This lets the tezos node know what structure and types to expect.

Filling in the fields, we get:

```
$ tezos-client hash data '(Pair (Pair "randomchanid" "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx") (Pair "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN" (Pair 1000000 29000000 )))' of type 'pair (pair string address) (pair address (pair mutez mutez))'
```

The terminal should return a result with a field ```Raw packed data```. This is what we'll sign the customer and merchant's account. First, with the customer's account (```bootstrap1```):

```
$ tezos-client sign bytes 0x0507070707010000000c72616e646f6d6368616e69640a00000016000002298c03ed7d454a101eb7022bc95f7e5f41ac7807070a000000160000e7670f32038107a59a2b9cfefae36ea21f5aa63c07070080897a008085d41b for bootstrap1
```
and with the merchant's account (```bootstrap2```):
```
$ tezos-client sign bytes 0x0507070707010000000c72616e646f6d6368616e69640a00000016000002298c03ed7d454a101eb7022bc95f7e5f41ac7807070a000000160000e7670f32038107a59a2b9cfefae36ea21f5aa63c07070080897a008085d41b for bootstrap2
```

Now that we have both signatures on the final state of the channel, we can initiate the mutual close!

```
tezos-client transfer 0 from bootstrap1 to my_zkchannel --entrypoint mutualClose --burn-cap 9 --arg '(Pair (Pair "<cust_signature" "<merch_signature>") (Pair 1000000 29000000))'&
```

Filling in the signatures:

```
$ tezos-client transfer 0 from bootstrap1 to my_zkchannel --entrypoint mutualClose --burn-cap 9 --arg '(Pair (Pair "edsigtYVTS2pJoXt8eARKnZGtFa8g9i8buUe7AVDtcfv7nbFykAhwZTr9dHSi9jxUbsU66K4aetdtA8tJyVrjzwapx9FB3eoKtR" "edsigtfpHDYiu56zvvXJujdMP3HjidSFd17L8Wgw3VvrghkJTCUKe81YtscWV9PJnTK7g4uGV8s4dqRy2dMayvUGyuXqznSjMgr") (Pair 1000000 29000000))'&
```
This should result in the zkChannel transitioning to the ```closed``` state, and with the customer and merchant receiving their final balance payouts.