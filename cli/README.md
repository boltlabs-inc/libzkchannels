# zkchannels-mpc command-line utility

We have developed a `zkchannels-mpc` tool for testing the zkChannels protocol end-to-end. It was designed to not interact with a bitcoin full node to broadcast transactions or watch the blockchain. Such features are out of scope for the utility and refer to the [zkLND](https://github.com/boltlabs-inc/lnd).

# Install

    # build the release
    cargo build --release

    # path to the utility from cli/ dir
    ../target/release/zkchannels-mpc

    # or install in CARGO_INSTALL_ROOT
    cargo install 

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
	setfees
        unlink    

# Set transaction fees info

Use the default values:

    zkchannels-mpc setfees

Can set individual fees as follows:

    zkchannels-mpc setfees --bal-min-cust 500 --bal-min-merch 500 --val-cpfp 1000 --fee-cc 1000 --fee-mc 1000 --min-fee 0 --max-fee 10000

# Open

To open a zkChannel, the customer runs the `open` command with the initial balances for the channel:

    zkchannels-mpc open --party CUST --other-port 12347 --own-port 12346 --cust-bal 10000 --merch-bal 0 --channel-name "alice1"

Similarly, the merchant executes following command to accept the channel request:

    zkchannels-mpc open --party MERCH --own-port 12347 --other-port 12346 --min-threshold 546

# Init

The customer initializes the channel by specifying the UTXO to fund the channel and exchange signatures:

    zkchannels-mpc init --party CUST --other-port 12347 --own-port 12346 --index 0 --input-sats 20000 --output-sats 10000 --channel-name "alice1" --txid f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1

Merchant runs the following to form the initial transactions and exchange signatures:

    zkchannels-mpc init --party MERCH --own-port 12347 --other-port 12346

# Activate

The customer can `activate` the channel as follows:

    zkchannels-mpc activate --party CUST --other-port 12347 --own-port 12346 --channel-name "alice1"

Similarly, the merchant does the same:

    zkchannels-mpc activate --party MERCH --own-port 12347 --other-port 12346

At this point, the escrow transaction should have been broadcast to the payment network (which is generated/signed during this phase). The merchant obtains the customer's signature on the `<merch-close-tx>`. Similarly, the customer obtains the merchant's signatures on the initial pair of closing transactions `<cust-close-tx>` (from `<escrow-tx>` and `<merch-close-tx>`). Finally, the customer has obtained a payment token from the merchant on the initial state of the channel as well.

# Unlink

After the channel is established, the customer can then `unlink` her payment token from the channel. That is, the customer and merchant 
execute a payment session with the MPC with a 0-value amount. In a real deployment, the network connection would be established over Tor.

Customer runs the following command:

    zkchannels-mpc unlink --party CUST --other-port 12347 --own-port 12346 --channel-name "alice1" -v

Merchant does the same:

    zkchannels-mpc unlink --party MERCH --own-port 12347 --other-port 12346

If this is successful, the customer now has an unlinkable payment token from the merchant on the initial state of the channel.

# Pay

To update the channel state, the customer does the following:

    zkchannels-mpc pay --party CUST --other-port 12347 --own-port 12346 --channel-name "alice1" --amount=200

At this point, the merchant can the `pay` command in the background:

    zkchannels-mpc pay --party MERCH --own-port 12347 --other-port 12346 &

The customer runs an MPC protocol to obtain the merchant's signature on updated closing transactions, then revokes its previous state and obtains a new unlinkable payment token for a future payment. The MPC execution guarantees that each party learns nothing about the other’s private inputs: the merchant does not learn the identity of the customer or channel balance information, and the customer does not learn the merchant’s private keys.

# Unilateral Close

To close down the channel, the customer simply does the following:

    zkchannels-mpc close --party CUST --channel-id "alice1" --file cust_close_escrow.txt

The merchant would need to provide the channel ID to close. You can list the channel IDs as follows:

    zkchannels-mpc close --party MERCH --file signed_merch_close.txt

Once you have the channel ID, the merchant can initiate closure as follows:

    zkchannels-mpc close --party MERCH --channel-id "e03081c3a28c5ef8b22aa1d0bf6bfbe41cc5d26c01669355e09972f3bb910730" --file signed_merch_close.txt

If the merchant initiates, then the customer can close from `<merch-close-tx>` as follows:

    zkchannels-mpc close --party CUST --channel-id "alice" --file cust_close_merch.txt --from-merch
