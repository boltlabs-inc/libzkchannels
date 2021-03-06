# tezos-sandbox dir
/cli - the zkchannels-cli used for executing the off-chain side of the protocol.<br>
/docs - docs, tutorials, diagrams, and benchmarks.<br>
/smartpy_scripts - useful smartpy script examples.<br>
/tests_python/zkchannels_contract - zkchannels smartpy and michelson contract with tezos-client pytest script.<br>
/watchtower - notification watchtower implementation in pytezos.<br>
/zkchannel_sandbox - tezos-client pytests for ps sig verification logic.<br>


# Testing with Tezos using BLS12-381
## Building on sandbox

(1a) Build dependencies on Ubuntu 20.04:
	
    sudo add-apt-repository ppa:avsm/ppa
    sudo apt update
    sudo apt-get install -y rsync git m4 build-essential patch unzip wget pkg-config libgmp-dev libev-dev libhidapi-dev libffi-dev opam jq virtualenv python3-pip 
    
(1b) Build deps on Mac OS:

    brew install opam libffi gmp libev pkg-config hidapi python3
    pip3 install virtualenv

(2) Install poetry:
	
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3
    source $HOME/.poetry/env

(3) Install rust 1.44
	
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    rustup toolchain install 1.44.0
    rustup default 1.44.0

To switch back to latest stable version of rust do the following:

    rustup default stable
	
(4) Clone Tezos here (Edo branch). Make sure you have git 2.18+ installed:
    
    git clone https://gitlab.com/tezos/tezos.git
    cd tezos
    git checkout v9.0
    opam init --bare -y
    opam switch create for_tezos 4.09.1   (if Linux)
    make build-deps
    eval $(opam env)
    make
    export PATH=~/tezos:$PATH
    source ./src/bin_client/bash-completion.sh
    export TEZOS_CLIENT_UNSAFE_DISABLE_DISCLAIMER=Y

(5) Clone libzkchannels repo

    cd ..
    git clone https://github.com/boltlabs-inc/libzkchannels.git
    cd tezos

(6) Can run pytests (need Python 3.8+)
    
    virtualenv --python=python3 venv
    source ./venv/bin/activate
    
(7) Setup poetry environment (using `pyproject.toml` from the tezos-sandbox dir)

    cp ../libzkchannels/tezos-sandbox/pyproject.toml .
    poetry install 

(8) Install some dependencies

    pip install base58check ed25519 pyblake2

(8) Run the test sandbox script for the zkChannels contract

    cp -r ../libzkchannels/tezos-sandbox/tests_python/zkchannels_contract tests_python/
    cd tests_python/
    ./zkchannels_contract/run_test.sh zkchannels_contract/test_zkchannel.py zkchannels_contract/sample_cust_close.json 
## Installing SmartPy

SmartPy is only needed to run the SmartPy scripts. It is not needed for testing the tezos smart contracts with the Tezos sandbox node. Alternatively, you can also use the [SmartPy online IDE](https://smartpy.io/) to run the SmartPy scripts.

(1) Clone the source repo

    git clone --recurse-submodules https://gitlab.com/SmartPy/SmartPy

(2) Install the dependencies

    env/naked/init

(3) Build the compiler

    ./envsh
    ./with_env make
    ./with_env make test

(4) In the case of a naked environment, this should also work:

    smartpy-cli/SmartPy.sh --help

(5) Run unit tests for zkChannels contract as follows:

    mkdir tmp/
    smartpy-cli/SmartPy.sh test ../smartpy_scripts/zkchannels.py tmp/
