# zkchannels-mpc command-line utility

We have developed a complementary tool `zkchannels-mpc` for testing the zkChannels protocol end-to-end. It was designed to not interact with a bitcoin full node to broadcast transactions or watch the blockchain. Such features are out of scope for the utility and refer to the [zkLND](https://github.com/boltlabs-inc/lnd).

# Install

    # build the release
    cargo build --release

    # path to the utility from cli/ dir
    ../target/release/zkchannels-mpc

# Usage Guide

The `zkchannels-mpc` shows the following subcommands which reflects a phase of zkChannels protocol:

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

TBD

# Init

TBD

# Activate

TBD

# Unlink

TBD

# Pay

TBD

# Close

TBD
