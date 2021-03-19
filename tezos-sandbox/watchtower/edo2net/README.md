# Tezos Watchtower Setup Instructions

# Introduction

This tutorial is designed to walk you through how to set up a notification watchtower and test it with a node connected to the edo2net testnet.

# Setting up the watchtower

First, we'll need to download [pytezos](https://github.com/baking-bad/pytezos) to interact with the tezos node. 

```
sudo apt-get install libsodium-dev libsecp256k1-dev libgmp-dev
pip3 install pytezos
```

Copy the following files into the current directory: `passive_zkchannel_watchtower.py`, `zkchannel_edo2net_broadcaster.py`, `zkchannel_pssig.tz`, `zkchannel_mock.tz`, `sample_cust_close.json`.

```
cp path/to/tezos-sandbox/watchtower/edo2net_test* .
```

We are going to need two terminals, one for broadcasting the zkchannel contract operations, and another for running the watchtower. In the first terminal, start up `zkchannel_edo2net_broadcaster.py`. The `cust` and `merch` arguments contain the testnet account files which have already been funded and activated. If you prefer, you may replace them with new testnet accounts. The script will automatically activate the accounts for you. 

```
$ python3 zkchannel_edo2net_broadcaster.py --cust=tz1S6eSPZVQzHyPF2bRKhSKZhDZZSikB3e51.json --merch=tz1VcYZwxQoyxfjhpNiRkdCUe5rzs53LMev6.json --close=sample_cust_close.json 
```

It will create and inject all the operations needed to go through the full flow of the zkchannel contract, from origination to funding to closing. However, once it originates the main zkchannel contract, it'll pause so that you can run the watchtower in a separate terminal. The command would look like:

```
$ python3 passive_zkchannel_watchtower.py --contract <contract_id> --network https://rpc.tzkt.io/edo2net/ --identity merchant
```

Where the \<contract id> would be the contract id of the zkchannel contract (e.g. KT1VsXV19JKxQmtiCyyR9H5eVDZ89gLazcgH).

Once you have entered the command and the watchtower is running, hit enter on the terminal running `zkchannel_edo2net_broadcaster.py`. The broadcaster script will go through the whole channel flow of the zkchannel from funding to settling. Each time an entrypoint is called on the main zkchannel contract, the watchtower will return a corresponding notification of the entrypoint called and the blockheight.