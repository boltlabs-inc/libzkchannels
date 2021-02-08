# Tezos Sandbox Setup Instructions

# Introduction

This tutorial is designed to walk you through how to set up a zero-knowledge channel (zkchannel) on tezos sandbox mode. In part 1 we will go over the installation and setup for the Tezos sandbox node. In [part 2](tutorial_pt2_zkchannels.md) we will establish and use a zkChannel.

# Installing Tezos (Edo branch)

zkChannels uses a form of signature verification which can only be computed on the dalpha-release branch of tezos. To install this branch of Tezos, complete the following steps:

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

(3) Install rust 1.39
	
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    rustup toolchain install 1.39.0
    rustup default 1.39.0

To switch back to latest stable version of rust do the following:

    rustup default stable
	
(4) Clone Tezos here. Make sure you have git 2.18+ installed:
    
    git clone https://gitlab.com/metastatedev/tezos.git
    cd tezos
    git checkout edo
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

```
$ tezos-client bake for bootstrap5
```

# Setting up zkChannels-cli 
Now that we have got the Tezos sandbox node up and running, we are ready to set up the zkChannels rust cli used for the off-chain part of the protocol. For the tutorial, we will simulate communication between the customer and merchant by running two terminals communicating with each other. You can install the zkChannels-cli utility by running the following steps:
```
git clone https://github.com/boltlabs-inc/libzkchannels.git
cd libzkchannels
```

You should already have rustc installed from the previous step, however, for building libzkchannels you'll need to use version 1.49 or greater. You can update to 1.49 as follows:

```
rustup toolchain install 1.49
rustup default 1.49
```

Can also update to the latest version instead:

```
rustup update
```

To be able to build libzkchannels, we require that you install the EMP-toolkit and other dependencies as follows:

```
. ./env
make deps
```

In addition, you'll need to start the Redis database service as follows:

```
./setup_redis.sh
```

To build libzkchannels and execute all unit tests, run: 

```
make
```

Build the release:
```
cargo build --release
```

You can run `zkchannels-cli` from the directory `../target/release/`, or install in `CARGO_INSTALL_ROOT`:
```
cargo install 
```

## Navigation
- [Proceed to part 2 - zkChannels on Tezos](tutorial_pt2_zkchannels.md)
- [Gas cost benchmarks](gas_cost_benchmarks.md)
