![](blog-header-light-14.png)

# libzkchannels

<a href="https://travis-ci.com/github/boltlabs-inc/libzkchannels"><img src="https://travis-ci.com/boltlabs-inc/libzkchannels.svg?branch=master"></a>

A Rust library implementation of libzkchannels (formerly BOLT: Blind Off-chain Lightweight Transactions).

zkChannels is a chain-agnostic approach for conducting **privacy-preserving off-chain payments** between pairs of individual parties. The protocol is designed to enable privacy-preserving cryptocurrencies on top of Bitcoin (via MPC) and Zcash/Tezos (via ZK proofs), by allowing individuals to establish and use payment channels for instantaneous payments that do not require an on-chain transaction.

## <a name='TableofContents'></a>Table of Contents

* [Install Rust](#installing-rust)
* [Build & Install](#build--install)
    * [1. Install dependencies](#1-install-dependencies)
    * [2. Build libzkchannels](#2-build-libzkchannels)
* [Run Tests](#tests)
* [zkChannels API](#zkchannels-api)
    * [1. Using MPC techniques](#1-using-mpc-techniques)
      * [1.1 Overview of Architecture](#11-overview-of-architecture) 
      * [1.2 Protocol API](#12-protocol-api)
      * [1.3 Build MPC with Malicious Security](#13-build-mpc-with-malicious-security)
      * [1.4 Performance](#14-performance)	
    * [2. Using ZK Proof techniques](#2-using-zk-proof-techniques)
      * [2.1 Protocol API](#21-protocol-api)
* [zkChannels-mpc CLI](https://github.com/boltlabs-inc/libzkchannels/tree/master/cli)
* [Documentation](#documentation)
* [Contributions](#contributions)
* [License](#license)

# WARNING

The libzkchannels library is a proof of concept implementation that relies on experimental libraries and dependencies at the moment. It is not suitable for production software yet.

# Major Dependencies

* secp256k1
* ff
* pairing
* serde, serde_json
* sha2, ripemd160, hmac, hex
* redis
* [zkchan-tx](https://github.com/boltlabs-inc/zkchan-tx)

Note that the above rust dependencies will be compiled and installed as a result of running the `make` command.

# Installing Rust

 To install Rust, we recommend using [rustup](https://www.rustup.rs/). You can install `rustup` on macOS or Linux as follows:

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

Make sure the version of `rustc` is `1.40.0` or greater. If you have an older version, you can update to `1.40` as follows:

   ```bash
	rustup toolchain install 1.40.0
	rustup default 1.40.0
   ```

Can also update to the latest version instead: 

   ```bash
   rustup update
   ```

# Build & Install

## 1. Install dependencies

To be able to build libzkchannels, we require that you install the EMP-toolkit and other dependencies as follows:

	. ./env
	make deps
	./test_emp.sh

In addition, you'll need to start the Redis database service as follows:

	./setup_redis.sh

## 2. Build libzkchannels

To build libzkchannels and execute all unit tests, run `make`

# Tests

To run just the libzkchannels unit tests, run `make test` and for MPC-only tests, run `make mpctest`

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

# zkChannels API

The libzkchannels library provides APIs for anonymous bidirectional payment channels for cryptocurrencies based on two classes of cryptographic techniques:

* Secure multi-party computation (or 2PC)
* Non-interactive Zero-knowledge proofs of knowledge

zkChannels allow a customer and a merchant to exchange arbitrary positive and negative amounts.

## 1. Using MPC techniques

We now describe the APIs around our support for non-anonymous currencies like Bitcoin.

<img src="libzkchannels-mpc-arch.png" width=300 align=center>

### 1.1. Overview of Architecture

To implement our MPC protocol, we used an existing software framework that runs MPC on an arbitrary function: the **Efficient Multi-Party (EMP) computation [toolkit](https://github.com/emp-toolkit/)**. 

This framework has several advantages that make it well-suited for our application: in particular, it supports multiple protocols in both the semi-honest and malicious security models, and all of these protocols are in the garbled circuit paradigm. 

In our implementation, the *merchant* plays the role of the garbler and the *customer* serves as the evaluator. This was a natural choice as only the customer is supposed to receive an output from the computation. 

**EMP toolkit** implements a C library used to describe secure functionalities. The library either executes a semi-honest protocol or compiles the function into a boolean circuit. This circuit can be passed to one of several additional MPC protocol implementations (including several that are secure against a malicious adversary).

Our application (**libtoken-utils** above) breaks down into several main functionalities, including lots of SHA256 hashes, lots of input validation, and ECDSA signatures. With the exception of the signatures, all of these functions are basically boolean operations: bit shifts, equality checks, and XOR masks. EMP-toolkit represents data as encrypted (garbled) bits and functions as boolean circuits. 

### 1.2 Protocol API

We now describe the high-level protocol API implemented in module `zkchannels::mpc`. The protocol implementation consists of 5 subprotocols: setup, initialize/establish, activate/unlink, pay and close.

#### 1.2.1 Channel Setup

	use zkchannels::mpc;

	// create initial channel mpc state
	let mut channel_state = mpc::ChannelMPCState::new(String::from("Channel A -> B"), false);

#### 1.2.2 Initialize & Establish

	let cust_bal = 10000;
	let merch_bal = 3000;

	// set the network transaction fees
	let tx_fee_info = mpc::TransactionFeeInfo { ... };

	// merchant initializes state for all channels it will open with customers
	let mut merch_state = mpc::init_merchant(&mut rng, &mut channel_state, "Bob");

	// customer initializes state for channel with initial balances
	let (channel_token, mut cust_state) = mpc::init_customer(&mut rng, &merch_state.pk_m, cust_bal, merch_bal, &tx_fee_info, "Alice");

	// form all the transactions using tx builder: <escrow-tx> and <merch-close-tx>
	// obtain closing signatures on <cust-close-txs> (from escrow-tx and merch-close-tx)
	
	// customer gets the initial state of the channel and
	let (init_cust_state, init_hash) = mpc::get_initial_state(&cust_state).unwrap();

	// merchant validates the initial state
	let res = mpc::validate_channel_params(&channel_token, &init_cust_state, init_hash, &mut merch_state);

	// at this point, both parties proceed with exchanging signatures on their respective closing transactions
	// customer gets two signed closing transactions from merchant that issues a refund back to customer
	// merchant gets a signed <merch-close-tx> that locks up the channel balance to another timelocked multi-sig

	// customer signs & broadcasts <escrow-tx> to the blockchain
	// both parties wait for the network to confirm the txs

	// customer mark the channel open after a suitable number of confirmations of the funding transactions
	let res = mpc::customer_mark_open_channel(&mut cust_state);

	// merchant marks the channel open after a suitable number of confirmations of the funding transactions
	let escrow_txid = &channel_token.escrow_txid.0.clone();
	let res = mpc::merchant_mark_open_channel(&escrow_txid, &mut merch_state);

#### 1.2.3 Activate & Unlink

	// prepare to active the channel by retrieving the initial state (rev lock commitment, etc)
	let init_state = mpc::activate_customer(&mut rng, &mut cust_state);

	// merchant returns an initial pay token for channel
	let pay_token = mpc::activate_merchant(&mut db, channel_token, &init_state, &mut merch_state);

	// customer stores the initial pay token
	mpc::activate_customer_finalize(pay_token, &mut cust_state);

	// customer unlinks initial pay-token by running the following pay protocol with a 0-value payment

#### 1.2.4 Unlinkable Payments

Prepare/Update State phase

	// customer prepares payment by generating a new state, new revocation lock and secret
	let (new_state, rev_state, rev_lock_com, session_id) = mpc::pay_prepare_customer(&mut rng, &mut channel_state, 10, &mut cust_state).unwrap();

	// merchant generates a pay token mask and return a commitment to the customer
	let pay_mask_com = mpc::pay_prepare_merchant(&mut rng, channel_state, session_id, old_state.get_nonce(), rev_lock_com, 10, &mut merch_state).unwrap();

Now proceed with executing the MPC if successful

	// customer executes mpc protocol with old/new state, pay mask commitment, rev lock commitment and payment amount
	let mpc_ok = mpc::pay_update_customer(&mut channel_state, &channel_token, old_state, new_state, pay_mask_com, rev_lock_com, 10, &mut cust_state);

	// merchant executes mpc protocol with customer nonce, pay mask commitment, rev lock commitment and payment amount
	mpc::pay_update_merchant(&mut rng, &mut channel_state, session_id, pay_mask_com, &mut merch_state);

	// customer sends success/error back to merchant if the customer obtains 3 masked outputs for both closing transactions and pay token
	let is_ok = mpc::pay_confirm_mpc_result(&mut rng, &mut db, mpc_ok, &merch_state)

Unmask/Revoke phase

	// unmask the closing signatures on the current state (from MPC output)
	// and if signatures are valid, the customer sends the revoked state message
	let is_ok = mpc::pay_unmask_sigs_customer(masks, &mut cust_state);

	// merchant verifies that revoked message on the previous state if unmasking was successful
	let (pt_mask, pt_mask_r) = mpc::pay_validate_rev_lock_merchant(session_id, revoked_state, &mut merch_state).unwrap();

	// customer unmasks the pay token and checks validity of pay-token mask commitment opening
	let is_ok = mpc::pay_unmask_pay_token_customer(pt_mask, pt_mask_r, &mut cust_state);

#### 1.2.5 Force Close

Merchant can initiate channel closing with a signed *merch-close-tx* that pays full channel balance to a timelocked multi-sig:

	// merchant signs the merch-close-tx for the channel and combines with customer signature
	let (merch_signed_tx, txidbe, txidle) = mpc::force_merchant_close(&escrow_txid, &mut merch_state).unwrap();

Customer can similarly initiate channel closing with a signed *cust-close-tx* of current balances spending from *escrow-tx* (or *merch-close-tx*):

	// customer signs the current state of channel and combines with escrow signature (if spending from <escrow-tx>)
	let from_escrow = true;
	let (cust_signed_tx, txidbe, txidle) = mpc::force_customer_close(&channel_state, &channel_token, from_escrow, &mut cust_state).unwrap();

### 1.3 Build MPC with Malicious Security 

As mentioned before, our MPC functionality can be instantiated in two possible models: **semi-honest** or **malicious**. For testing, we build with the semi-honest model by default. Our MPC functionality is also secure against adversaries that do not necessarily follow the protocol and may try any arbitrary attack strategy in order to deanonymize the users, link payments, or corrupt the MPC outputs. Security in the malicious model means that despite the attack strategy, users either get correct output from the MPC or no output (e.g., due to an abort). 

You can compile zkChannels with malicious security as follows:

First build the dependencies as described [earlier](#1-install-dependencies), next:

	export AG2PC=1
	cargo clean
	cargo build --release
	make mpctest

### 1.4 Performance

The strong guarantee of the malicious model is necessary for production deployment but also has significant performance drawbacks. For instance, the time to execute the MPC takes about **7–9 seconds on average** on a modern workstation (not including network latency). There are a number of optimizations we are investigating to speed up computation in this model.

## 2. Using ZK Proof techniques

We now describe the construction based on ZK proofs.

### 2.1 Protocol API

#### 2.1.0 Channel Setup and Key Generation

The first part of setting up bi-directional payment channels involve generating initial setup parameters using curve BLS12-381 with channel state.

	use zkchannels::zkproofs;

	// generate the initial channel state
	// second argument represents third-party mode
	let mut channel_state = zkproofs::ChannelState::<Bls12>::new(String::from("Direct channel A -> B"), false);
	let mut rng = &mut rand::thread_rng();

#### 2.1.1 Intialize

To initialize state/keys for both parties, call the ``zkproofs::merchant_init()`` and ``zkproofs::customer_init()``:

	let b0_merch = 100;
	let b0_cust = 100;

	// initialize the merchant state and initialize with balance
	let (mut channel_token, mut merch_state, mut channel_state) = zkproofs::merchant_init(rng, &mut channel_state, "Bob");

	// generate the customer state using the channel token from the merchant
	let mut cust_state = zkproofs::customer_init(rng, // rng
	                                              &mut channel_token, // channel token
	                                              b0_cust, // init customer balance
	                                              b0_merch, // init merchant balance
	                                              "Alice")); // channel name/purpose


#### 2.1.2 Establish protocol

When opening a payment channel, execute the establishment protocol API to escrow funds privately as follows:

	// customer gets the initial state of the channel
	let init_state = zkproofs::get_initial_state(&cust_state);	

	// merchant validates the initial state and returns close token 
	let init_close_token = zkproofs::validate_channel_params(rng, &init_state, &merch_state);

	// both parties proceed with funding the channel and wait for payment network 
	// to confirm the transactions

	// NEW - customer mark the channel open after a suitable number of confirmations of the funding transactions
	let res = zkproofs::customer_mark_open_channel(init_close_token, &mut channel_state, &mut cust_state);

	// NEW - merchant marks the channel open after a suitable number of confirmations of the funding transactions
	let res = zkproofs::merchant_mark_open_channel(&escrow_txid, &mut merch_state);

	// confirm that the channel state is now established
	assert!(channel_state.channel_established);

#### 2.1.3 Activate

	// prepare to active the channel by retrieving the initial state (rev lock, etc)
	let init_state = zkproofs::activate::customer_init(&cust_state);

	// merchant returns an initial pay token for channel
	let pay_token = zkproofs::activate::merchant_init(&mut db, channel_token, &init_state, &mut merch_state);

	// customer stores the initial pay token
	zkproofs::activate::customer_finalize(&mut channel_state, &mut cust_state, pay_token);

#### 2.1.4 Unlink protocol

The customer/merchant execute the unlink subprotocol to unlink the initial pay token from the now activated channel as follows:

	// customer generates the unlink payment proof (0-value payment)
    let (session_id, unlink_payment, unlinked_cust_state) = zkproofs::unlink::customer_update_state(rng, &channel_state, &cust_state);

	// merchant verifies the payment proof and returns a close token if valid
    let new_close_token = zkproofs::unlink::merchant_update_state(rng, &channel_state, &session_id, &unlink_payment, &mut merch_state);

	// customer revokes previous state
    let revoked_state = zkproofs::unlink::customer_unmask(&channel_state, &mut cust_state, unlinked_cust_state, &new_close_token);

    // send revoke token and get pay-token in response
    let new_pay_token = zkproofs::unlink::merchant_validate_rev_lock(&session_id, &revoked_state, &mut merch_state);

    // verify the pay token and update internal customer state
    let is_ok = zkproofs::unlink::customer_finalize(&mut channel_state, &mut cust_state, new_pay_token);

#### 2.1.5 Pay protocol

Prepare/Update State phase

	// customer prepares payment by revealing nonce and picking a session id for payment 
	// internally, it generates a new state (new revocation lock and secret, etc)
	let (nonce, session_id) = zkproofs::pay::customer_prepare(&mut rng, &mut channel_state, 10, &mut cust_state).unwrap();

	// merchant generates a pay token mask and return a commitment to the customer
	let pay_mask_com = zkproofs::pay::merchant_prepare(&session_id, nonce, 10, &mut merch_state).unwrap();

Now proceed with executing a payment

	// customer generates a payment proof for specified amount and generates a new customer state that reflects the payment
	let (payment, new_cust_state) = zkproofs::pay::customer_update_state(&mut channel_state, &channel_token, 10, &mut cust_state);

	// merchant checks payment proof and returns a new close token if valid
	let new_close_token = zkproofs::pay::merchant_update_state(&mut rng, &mut channel_state, &session_id, &payment, &mut merch_state);

Unmask/Revoke phase to get the next pay token

	// unmask the closing signatures on the current state
	// and if signatures are valid, the customer sends the revoked state message
	let revoked_state = zkproofs::pay::customer_unmask(&channel_state, &mut cust_state, &new_cust_state, new_close_token);

	// merchant verifies that revoked message on the previous state if unmasking was successful
	let pay_token = zkproofs::pay::merchant_validate_rev_lock(&session_id, revoked_state, &mut merch_state).unwrap();

	// customer unmasks the pay token and checks validity of pay-token mask commitment opening
	let is_ok = zkproofs::pay::customer_unmask_pay_token(pay_token, &channel_state, &mut cust_state);

#### 2.1.6 Channel Closure

To close a channel, the customer must execute the `zkproofs::force_customer_close()` routine as follows:

	let cust_close_msg = zkproofs::force_customer_close(&channel_state, &cust_state);

If the customer broadcasts an outdated version of his state, then the merchant can dispute this claim by executing the `zkproofs::force_merchant_close()` routine as follows:

	let merch_close = zkproofs::force_merchant_close(&channel_state, &channel_token, &cust_close_msg, &merch_state);

### 2.2 Third-party Payments

The bidirectional payment channels can be used to construct third-party payments in which a party **A** pays a second party **B** through an untrusted intermediary (**I**) to which both **A** and **B** have already established a channel. With zkChannels, the intermediary learns nothing about the payment from **A** to **B** and cannot link transactions to individual users.

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

# Documentation

Build the api documentation by simply running `make doc`. Documentation will be generated in your local `target/doc` directory.

# Contributions

To contribute code improvements, please checkout the repository, make your changes and submit a pull request.

	git clone https://github.com/boltlabs-inc/libzkchannels.git

# License

Licensed under MIT (LICENSE-MIT or http://opensource.org/licenses/MIT)
