# tezos-sandbox
Testing with Tezos using BLS12-381

## Building on sandbox

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
    git checkout master
    opam init --bare
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
    
(8) Run the test sandbox script for PS signature verification

    cp ../libzkchannels/tezos-sandbox/pssigs_verify_optimized.py tests_python/
    cp ../libzkchannels/tezos-sandbox/dec_cust_close.json tests_python/
    cd tests_python
    poetry run python3 pssigs_verify_optimized.py -c dec_cust_close.json

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
