# libzkchannels

A pure-Rust library implementation of libzkchannels (formerly BOLT: Blind Off-chain Lightweight Transactions).

BOLT is a system for conducting **privacy-preserving off-chain payments** between pairs of individual parties. BOLT is designed to provide a Layer 2 payment protocol for privacy-preserving cryptocurrencies such as Zcash, by allowing individuals to establish and use payment channels for instantaneous payments that do not require an on-chain transaction.

# WARNING

The libzkchannels library is a proof of concept implementation that relies on experimental libraries and dependencies at the moment. It is not suitable for production software yet.

# Major Dependencies

* secp256k1
* ff
* pairing
* serde
* sha2, ripemd160, hmac, hex
* wagyu-bitcoin, wagyu-model

Note that the above rust dependencies will be compiled and installed as a result of running the `make` command.

# Rust Nightly Setup

Please keep in mind we are currently working with nightly Rust for now which gives access to the nightly compiler and experimental features.

	rustup install nightly
	
To run a quick test of the nightly toolchain, run the following command:

	rustup run nightly rustc --version

Optionally, to make this the default globally, run the following command:

	rustup default nightly

We will switch to the stable release channel once libzkchannels (and dependencies) are ready for production use.

# Build & Install

First, install the dependencies by

	. ./env
	make deps
	./test_emp.sh

To build the library and execute basic examples, run `make` 


# Tests

To run libzkchannels unit tests, run `make test`

# Benchmarks

To run libzkchannels benchmarks, run `make bench`

# Usage

To use the libzkchannels library, add the `libzkchannels` crate to your dependency file in `Cargo.toml` as follows:

```toml
[dependencies]
zkchannels = "0.4.0"
```

Then add an extern declaration at the root of your crate as follows:
```rust
extern crate zkchannels;
```

# API

The libzkchannels library provides APIs for two types of payment channels:

* bidirectional payment channels
* third-party payments

## Payment Channels using ZK Proof techniques

An anonymous payment channel enables two parties to exchange arbitrary positive and negative amounts. 

### Channel Setup and Key Generation

The first part of setting up bi-directional payment channels involve generating initial setup parameters using curve BLS12-381 with channel state.
	
	use zkchannels::zkproofs;
		
	// generate the initial channel state 
	// second argument represents third-party mode
    let mut channel_state = zkproofs::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
    let mut rng = &mut rand::thread_rng();
    
    // generate fresh public parameters
    channel_state.setup(&mut rng); 

### Initialization

To initialize state/keys for both parties, call the ``zkproofs::init_merchant()`` and ``zkproofs::init_customer()``:
	
	let b0_merch = 10;
	let b0_cust = 100;

	// initialize the merchant state and initialize with balance
    let (mut channel_token, mut merch_state, mut channel_state) = zkproofs::init_merchant(rng, &mut channel_state, "Bob");
				    
    // generate the customer state using the channel token from the merchant
	let mut cust_state = zkproofs::init_customer(rng, // rng
	                                              &mut channel_token, // channel token
	                                              b0_cust, // init customer balance
	                                              b0_merch, // init merchant balance
	                                              "Alice")); // channel name/purpose


### Establish Protocol

When opening a payment channel, execute the establishment protocol API to escrow funds privately as follows:

    // establish the channel by generating initial state commitment proof
    let (com, com_proof) = zkproofs::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_state);
    
    // obtain close token for closing out channel
    let close_token = zkproofs::establish_merchant_issue_close_token(rng, &channel_state, &com, &com_proof, &merch_state);
    
    // customer verifies that close-token
    assert!(cust_state.verify_close_token(&channel_state, &close_token));
    
    // form funding tx and wait for network confirmation
    
    // obtain payment token after confirming funding tx
    let pay_token = zkproofs::establish_merchant_issue_pay_token(rng, &channel_state, &com, &merch_state);
        
    // customer 
    assert!(zkproofs::establish_final(&mut channel_state, &mut cust_state, &pay_token));   
    		
	// confirm that the channel state is now established
	assert!(channel_state.channel_established);
	
### Pay protocol		

To spend on the channel, execute the pay protocol API (can be executed as many times as necessary):

	// phase 1 - payment proof and new cust state
    let (payment, new_cust_state) = zkproofs::generate_payment_proof(rng, &channel_state, &cust_state, 10);

	// phase 1 - merchant verifies the payment proof and returns a close-token   
    let new_close_token = zkproofs::verify_payment_proof(rng, &channel_state, &payment, &mut merch_state);
 
    // phase 2 - verify the close-token, update cust state and generate a revoke token for previous cust state state
    let revoke_token = zkproofs::generate_revoke_token(&channel_state, &mut cust_state, new_cust_state, &new_close_token);
    
    // phase 2 - merchant verifies the revoke token and sends back the pay-token in response
    let new_pay_token = zkproofs::verify_revoke_token(&revoke_token, &mut merch_state);
    
    // final - customer verifies the pay token and updates internal state
    assert!(cust_state.verify_pay_token(&channel_state, &new_pay_token));


### Channel Closure

To close a channel, the customer must execute the `zkproofs::customer_refund()` routine as follows:

	let cust_close_msg = zkproofs::customer_close(&channel_state, &cust_state);
	
If the customer broadcasts an outdated version of his state, then the merchant can dispute this claim by executing the `zkproofs::merchant_retute()` routine as follows:

	let merch_close = zkproofs::merchant_close(&channel_state, &channel_token, &cust_close_msg, &merch_state);
	                                                         
## Third-party Payments

The bidirectional payment channels can be used to construct third-party payments in which a party **A** pays a second party **B** through an untrusted intermediary (**I**) to which both **A** and **B** have already established a channel. With BOLT, the intermediary learns nothing about the payment from **A** to **B** and cannot link transactions to individual users. 

To enable third-party payment support, initialize each payment channel as follows:
			
	// create the channel state for each channel and indicate third-party support 
	let mut channel_state = zkproofs::ChannelState::<Bls12>::new(String::from("Third-party Channels"), true);
	
Moreover, the intermediary can set a channel fee as follows:
	
	channel_state.set_channel_fee(5);

The channel establishment still works as described before and the pay protocol includes an additional step to verify that the payments on both channels cancel out or include a channel fee (if specified).

	
	...
	
	let payment_amount = 20;
	// get payment proof on first channel with party A and H
	let (sender_payment, new_cust_stateA) = zkproofs::generate_payment_proof(rng, &channel_state,
                                                                        &cust_stateA,
	                                                                    payment_amount); // bal inc
	// get payment proof on second channel with party B and H
	let (receiver_payment, new_cust_stateB) = zkproofs::generate_payment_proof(rng, &channel_state,
                                                                        &cust_stateB,                                                
                                                                        -payment_amount); // bal dec
                                                               	
    // intermediary executes the following on the two payment proofs
	// verifies that the payment proof is valid & cancels out and results in hub's fee    
    let close_token_result = zkproofs::verify_multiple_payment_proofs(rng, &channel_state, 
                                                                           &sender_payment, 
                                                                           &receiver_payment, 
                                                                           &mut merch_state);
                                                                           
    // alice gets a close token and bob gets a conditional token which requires alice's revoke token to be valid                                                                           
    let (alice_close_token, bob_cond_close_token) = handle_bolt_result!(close_token_result).unwrap();
	
    // both alice and bob generate a revoke token
    let revoke_token_alice = zkproofs::generate_revoke_token(&channel_state, 
                                                                  &mut cust_stateA, 
                                                                  new_cust_stateA, 
                                                                  &alice_close_token);
    let revoke_token_bob = zkproofs::generate_revoke_token(&channel_state,
                                                                  &mut cust_stateB, 
                                                                  new_cust_stateB, 
                                                                  &bob_cond_close_token);
	
    // send both revoke tokens to intermediary and receive pay-tokens (one for sender and another for receiver)
    let new_pay_tokens: BoltResult<(cl::Signature<Bls12>,cl::Signature<Bls12>)> = \
                        zkproofs::verify_multiple_revoke_tokens(&revoke_token_sender, 
                                                                     &revoke_token_receiver, 
                                                                     &mut merch_state);
                                                                     	
	...

See the `intermediary_payment_basics_works()` unit test in `src/lib.rs` for more details.

## Payment Channels using MPC techniques

### Channel Setup

	// create initial channel mpc state
	let mut channel = mpc::ChannelMPCState::new(String::from("Channel A -> B"), false);

### Initialization

	let cust_bal = 100;
	let merch_bal = 100;
	
	// merchant initializes state for all channels it will open with customers
	let mut merch_state = mpc::init_merchant(&mut rng, &mut channel, "Bob");
	
	// form all the transactions: escrow-tx and merch-close-tx 
	// extract the txids, prevout hashes from both transactions
	let funding_tx_info = getFundingTxDetails(...)
	
	// customer initializes state for channel with initial balances
	let (channel_token, mut cust_state) = mpc::init_customer(&mut rng, &merch_state.pk_m, &funding_tx_info, cust_bal, merch_bal, "Alice");

### Activate & Unlink

	// prepare to active the channel by generating initial rev lock commitment and initial randomness
	// returns the initial state of channel
	let s0 = mpc::activate_customer(&mut rng, &mut cust_state);
	
	// merchant stores the initial state and returns an initial pay token for channel
	let pay_token = mpc::activate_merchant(channel_token, &s0, &mut merch_state);
	
	// customer stores the initial pay token
	mpc::activate_customer_finalize(pay_token, &mut cust_state);

	// customer unlinks initial pay-token by running the following pay protocol with a 0-payment

### Pay Protocol

Prepare phase
	
	// customer prepares payment by generating a new state, new revocation lock and secret, and 
	let (new_state, rev_lock_com, rev_lock, rev_secret) = mpc::pay_prepare_customer(&mut rng, &mut channel, 10, &mut cust_state);

	// merchant generates a pay token mask and return a commitment to it 
	let pay_mask_com = mpc::pay_prepare_merchant(&mut rng, new_state.nonce, &mut merch_state);

Execute MPC phase
	
	// customer executes mpc protocol with old/new state, pay mask commitment, rev lock commitment and payment amount
	let ok_cust = mpc::pay_customer(&mut channel, &channel_token, s0, new_state, pay_mask_com, rev_lock_com, 10, &mut cust_state);
	
	// merchant executes mpc protocol with customer nonce, pay mask commitment, rev lock commitment and payment amount
	let ok_merch = mpc::pay_merchant(&mut rng, &mut channel, s0.nonce, pay_mask_com, rev_lock_com, 10, &mut merch_state);
	
	// customer sends success/error back to merchant if the customer obtains 3 masked outputs for both closing transactions and pay token

Unmask/Revoke phase

	// unmask the closing transactions received from the MPC to close the channel and 
	// customer forms and sends the revoked state message
	let is_ok = mpc::pay_unmask_tx_customer(masks, &mut cust_state);
	let revoked_state = RevokedState { nonce: s0.nonce, rev_lock_com, rev_lock, rev_secret, t }

	// customer revokes the previous state if the unmasking was successful
	let result = mpc::pay_validate_rev_lock_merchant(revoked_state, &mut merch_state);
	
	// customer unmasks the pay token and checks validity of pay-token mask commitment opening 
	let is_ok = mpc::pay_unmask_pay_token_customer(pt_mask, &mut cust_state);


# Documentation 

Build the api documentation by simply running `make doc`. Documentation will be generated in your local `target/doc` directory.

For the libzkchannels (or BOLT) design documentation, see the `docs/bolt.pdf` document.

# Contributions

To contribute code improvements, please checkout the repository, make your changes and submit a pull request.

	git clone https://github.com/boltlabs-inc/libzkchannels.git

# TODOs

Here are some TODOs (not in any particular order):

* Add more unit tests for other dispute resolution scenarios and third-party test cases
	
# License

Licensed under MIT (LICENSE-MIT or http://opensource.org/licenses/MIT)
