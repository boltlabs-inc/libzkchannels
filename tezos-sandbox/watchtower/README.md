# Tezos Watchtower Setup Instructions

# Introduction

This tutorial is designed to walk you through how to set up a notification watchtower and test it with a zkchannel in sandbox mode.

# Installing Tezos (Delphi branch)


(1a) Build dependencies on Ubuntu 20.04:
	
    sudo add-apt-repository ppa:avsm/ppa
    sudo apt update
    sudo apt-get install -y rsync git m4 build-essential patch unzip wget pkg-config libgmp-dev libev-dev libhidapi-dev libffi-dev opam jq
    sudo apt-get install -y virtualenv python3-pip 
    
(1b) Build deps on Mac OS:

    brew install opam libffi gmp libev pkg-config hidapi python3
    pip3 install virtualenv

(2) Install poetry:
	
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3
    source $HOME/.poetry/env

(3) Install rust 1.42
	
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    rustup toolchain install 1.42.0
    rustup default 1.42.0

To switch back to latest stable version of rust do the following:

    rustup default stable
	
(4) Clone Tezos here. Make sure you have git 2.18+ installed:
    
    git clone https://gitlab.com/metastatedev/tezos.git
    cd tezos
    git checkout delphi
    opam init --bare
    make build-deps
    eval $(opam env)
    make
    export PATH=~/tezos:$PATH
    source ./src/bin_client/bash-completion.sh
    export TEZOS_CLIENT_UNSAFE_DISABLE_DISCLAIMER=Y

# Setting up a sandbox node

(Instructions from https://tezos.gitlab.io/user/sandbox.html)

In a terminal in your tezos directory, the following command will initialize a node listening for peers on port 19731 and listening for RPC on port 18731:
```
./src/bin_node/tezos-sandboxed-node.sh 1 --connections 1
```

Once your node is running, open a new terminal in the same tezos directory and initialize the “sandboxed” client data:

```
export TEZOS_CLIENT_UNSAFE_DISABLE_DISCLAIMER=Y
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

Bake one block so that the network is activated.

```
$ tezos-client bake for bootstrap5
```

# Setting up the watchtower

First, we'll need to download [pytezos](https://github.com/baking-bad/pytezos) to interact with the tezos node. 

```
sudo apt-get install libsodium-dev libsecp256k1-dev libgmp-dev
pip3 install pytezos
```

Copy the following files into the current directory: `passive_zkchannel_watchtower.py`, `zkchannel_broadcaster.py`, `mock_pssig3.tz`, `zkchannel_mock_ps3.tz`.

```
cp path/to/tezos-sandbox/watchtower/* .
```

We are going to need to terminals, one for broadcasting the zkchannel contract operations, and another for running the watchtower. In the first terminal, start up `zkchannel_broadcaster.py`.

```
$ python3 zkchannel_broadcaster.py
```

It will create and inject all the operations needed to go through the full flow of the zkchannel contract, from origination to funding to closing. After each operation however, it'll wait for you to bake a block, then hit enter. 

To bake a block, in the terminal with the tezos-client active, run:

```
$ tezos-client bake for bootstrap5
```

Once the main zkchannel contract has been originated. It'll find the contract id and return the command you can use to run the watchtower on the second terminal. The command would look like:

```
$ python3 passive_zkchannel_watchtower.py --contract <contract_id> --network http://localhost:18731 --identity merchant
```

Where the \<contract id> would be the contract id of the zkchannel contract.

Now, when you continue injecting the operations from `zkchannel_broadcaster.py`, you'll see the corresponding notifications from `passive_zkchannel_watchtower.py`.
