# zkchannels-mpc command-line utility

We have developed a `zkchannels-mpc` tool for testing the zkChannels protocol end-to-end. It was designed to not interact with a bitcoin full node to broadcast transactions or watch the blockchain. Such features are out of scope for the utility and refer to the [zkLND](https://github.com/boltlabs-inc/lnd).

# Install

    # build the release
    cargo build --release

    # path to the utility from cli/ dir
    ../target/release/zkchannels-mpc

# Usage Guide

The `zkchannels-mpc` shows the following subcommands which reflects each phase of zkChannels protocol:

    zkchannels-mpc 0.4.0

    USAGE:
        zkchannels-mpc <SUBCOMMAND>

    FLAGS:
        -h, --help       Prints help information
        -V, --version    Prints version information

    SUBCOMMANDS:
        activate    
        close       
        help        Prints this message or the help of the given subcommand(s)
        init        
        open        
        pay         
        unlink    

# Open

To open a zkChannel, the customer runs the `open` command with the initial balances for the channel:

    zkchannels-mpc open --party CUST --other-port 12347 --own-port 12346 --cust-bal 10000 --merch-bal 0 --channel-name "alice1"

Similarly, the merchant executes following command to accept the channel request:

    zkchannels-mpc open --party MERCH --own-port 12347 --other-port 12346 --dust-limit 100

# Init

The customer initializes the channel by specifying the UTXO to fund the channel and exchange signatures:

    zkchannels-mpc init --party CUST --other-port 12347 --own-port 12346 --index 0 --input-sats 20000 --output-sats 10000 --channel-name "alice1" --txid f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1

Merchant runs the following to form the initial transactions and exchange signatures:

    zkchannels-mpc init --party MERCH --own-port 12347 --other-port 12346

# Activate

To activate the channel, the customer runs the following command:

    zkchannels-mpc activate --party CUST --other-port 12347 --own-port 12346 --channel-name "alice1"

Similarly, the merchant does the same:

    zkchannels-mpc activate --party MERCH --own-port 12347 --other-port 12346

# Unlink

TBD

# Pay

TBD

# Close

TBD
