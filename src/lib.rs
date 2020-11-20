//! This crate is an experimental implementation of zkChannels
//! - formerly Blind Off-chain lightweight transactions (BOLT).
//!
//! zkChannels extends academic work by Matthew Green and Ian Miers -
//! https://eprint.iacr.org/2016/701.
//!
//! Libzkchannels relies on the EMP-toolkit (['emp-ag2pc`](https://github.com/boltlabs-inc/emp-ag2pc) and
//! ['emp-sh2pc`](https://github.com/boltlabs-inc/emp-sh2pc)), BN-256 and BLS12-381 curves at 128-bit security,
//! as implemented in a fork of [`pairing module`](https://github.com/boltlabs-inc/pairing).
//!
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused_parens)]
#![allow(non_upper_case_globals)]
#![allow(unused_results)]
#![allow(missing_docs)]
#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))]
extern crate test;

extern crate ff_bl as ff;
extern crate pairing_bl as pairing;
extern crate rand;

extern crate secp256k1;
extern crate sha2;
extern crate time;

extern crate serde;
extern crate serde_with;

extern crate hex;
extern crate libc;

extern crate bit_array;
extern crate hmac;
extern crate num;
extern crate ripemd160;
extern crate serde_json;
extern crate typenum;

extern crate redis;
extern crate zkchan_tx;

#[macro_use]
extern crate enum_display_derive;

#[cfg(test)]
#[macro_use]
extern crate rusty_fork;
extern crate rand_xorshift;
extern crate serde_bytes;

pub mod bindings;
pub mod ccs08;
pub mod channels_mpc;
pub mod channels_util;
pub mod channels_zk;
pub mod cl;
pub mod database;
pub mod ecdsa_partial;
pub mod ffishim_bls12;
// pub mod ffishim_bn256;
pub mod ffishim_mpc;
pub mod mpc;
pub mod mpcwrapper;
pub mod nizk;
pub mod ped92;
pub mod tze_utils;
pub mod util;
pub mod wallet;
pub mod zkproofs;

#[cfg(test)]
pub mod test_e2e;

pub use channels_util::FundingTxInfo;
use ff::{Field, Rand};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str;
use zkchan_tx::fixed_size_array::FixedSizeArray32;
pub use zkproofs::BoltResult;
pub use zkproofs::Payment;

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use rand::{thread_rng, Rng};
    use test::Bencher;

    #[bench]
    pub fn bench_one(bh: &mut Bencher) {
        println!("Run benchmark tests here!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use sha2::{Digest, Sha256};

    use bindings::ConnType_NETIO;
    use channels_util::{ChannelStatus, PaymentStatus, ProtocolStatus};
    use database::{
        get_file_from_db, store_file_in_db, HashMapDatabase, MaskedTxMPCInputs, RedisDatabase,
        StateDatabase,
    };
    use std::process::Command;
    use std::{env, ptr};
    use zkchan_tx::fixed_size_array::FixedSizeArray32;
    use zkchan_tx::Testnet;

    fn setup_new_channel_helper(
        channel_state: &mut zkproofs::ChannelState<Bls12>,
        init_cust_bal: i64,
        init_merch_bal: i64,
    ) -> (
        zkproofs::ChannelToken<Bls12>,
        zkproofs::MerchantState<Bls12>,
        zkproofs::CustomerState<Bls12>,
        zkproofs::ChannelState<Bls12>,
    ) {
        let rng = &mut rand::thread_rng();
        let merch_name = "Bob";
        let cust_name = "Alice";

        let b0_cust = init_cust_bal;
        let b0_merch = init_merch_bal;

        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let (mut channel_token, merch_state, channel_state) =
            zkproofs::merchant_init(rng, channel_state, merch_name);

        // initialize on the customer side with balance: b0_cust
        let cust_state =
            zkproofs::customer_init(rng, &mut channel_token, b0_cust, b0_merch, cust_name);

        return (channel_token, merch_state, cust_state, channel_state);
    }

    fn execute_establish_protocol_helper(
        channel_state: &mut zkproofs::ChannelState<Bls12>,
        merch_state: &mut zkproofs::MerchantState<Bls12>,
        cust_state: &mut zkproofs::CustomerState<Bls12>,
    ) {
        let rng = &mut rand::thread_rng();

        // obtain close token for closing out channel
        let init_state = zkproofs::get_initial_state(&cust_state);
        let close_token = zkproofs::validate_channel_params(rng, &init_state, &merch_state);

        assert!(cust_state.verify_init_close_token(&channel_state, close_token));

        // wait for funding tx to be confirmed, etc

        // prepare channel for activation
        let init_state = zkproofs::activate::customer_init(&cust_state).unwrap();

        // obtain payment token for pay protocol
        let pay_token = zkproofs::activate::merchant_init(rng, &init_state, merch_state);

        assert!(zkproofs::activate::customer_finalize(
            channel_state,
            cust_state,
            pay_token
        ));
        execute_unlink_helper(channel_state, merch_state, cust_state);
        println!("Channel established!");
    }

    fn execute_unlink_helper(
        channel_state: &mut zkproofs::ChannelState<Bls12>,
        merch_state: &mut zkproofs::MerchantState<Bls12>,
        cust_state: &mut zkproofs::CustomerState<Bls12>,
    ) {
        let rng = &mut rand::thread_rng();
        let (session_id, unlink_info, unlinked_cust_state) =
            zkproofs::unlink::customer_update_state(rng, &channel_state, &cust_state);
        let new_close_token_result = zkproofs::unlink::merchant_update_state(
            rng,
            &channel_state,
            &session_id,
            &unlink_info,
            merch_state,
        );
        let new_close_token = handle_bolt_result!(new_close_token_result).unwrap();
        let rt_pair = zkproofs::unlink::customer_unmask(
            &channel_state,
            cust_state,
            unlinked_cust_state.clone(),
            &new_close_token,
        )
        .unwrap();

        // send revoke token and get pay-token in response
        let new_pay_token_result: BoltResult<cl::Signature<Bls12>> =
            zkproofs::unlink::merchant_validate_rev_lock(&session_id, &rt_pair, merch_state);
        let new_pay_token = handle_bolt_result!(new_pay_token_result);

        // verify the pay token and update internal state
        let is_ok =
            zkproofs::unlink::customer_finalize(channel_state, cust_state, new_pay_token.unwrap());
        assert!(is_ok);
    }

    fn execute_payment_protocol_helper(
        channel_state: &mut zkproofs::ChannelState<Bls12>,
        merch_state: &mut zkproofs::MerchantState<Bls12>,
        cust_state: &mut zkproofs::CustomerState<Bls12>,
        payment_increment: i64,
    ) {
        let rng = &mut rand::thread_rng();

        let (nonce, session_id) =
            zkproofs::pay::customer_prepare(rng, &channel_state, payment_increment, &cust_state)
                .unwrap();

        assert!(zkproofs::pay::merchant_prepare(
            &session_id,
            nonce,
            payment_increment,
            merch_state
        ));

        let (payment, new_cust_state) = zkproofs::pay::customer_update_state(
            rng,
            channel_state,
            &cust_state,
            payment_increment,
        );

        let new_close_token = zkproofs::pay::merchant_update_state(
            rng,
            &channel_state,
            &session_id,
            &payment,
            merch_state,
        );

        let rev_lock_pair = zkproofs::pay::customer_unmask(
            &channel_state,
            cust_state,
            new_cust_state,
            &new_close_token,
        )
        .unwrap();

        // send revoke token and get pay-token in response
        let new_pay_token_result: BoltResult<cl::Signature<Bls12>> =
            zkproofs::pay::merchant_validate_rev_lock(&session_id, &rev_lock_pair, merch_state);
        let new_pay_token = handle_bolt_result!(new_pay_token_result);

        // verify the pay token and update internal state
        assert!(zkproofs::pay::customer_unmask_pay_token(
            new_pay_token.unwrap(),
            channel_state,
            cust_state
        )
        .unwrap());
    }

    #[test]
    fn bidirectional_payment_basics_work() {
        // just bidirectional case (w/o third party)
        let mut channel_state =
            zkproofs::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
        let rng = &mut rand::thread_rng();

        let b0_customer = 90;
        let b0_merchant = 20;

        // initialize the channel
        let (mut channel_token, mut merch_state, mut channel_state) =
            zkproofs::merchant_init(rng, &mut channel_state, "Merchant Bob");

        let mut cust_state =
            zkproofs::customer_init(rng, &mut channel_token, b0_customer, b0_merchant, "Alice");

        println!("{}", cust_state);

        // obtain close token for closing out channel
        let init_state = zkproofs::get_initial_state(&cust_state);

        let close_token = zkproofs::validate_channel_params(rng, &init_state, &merch_state);

        // customer verifies that initial close token
        assert!(cust_state.verify_init_close_token(&channel_state, close_token));

        // proceed to funding tx and wait for it be confirmed on payment network
        let init_state = zkproofs::activate::customer_init(&cust_state).unwrap();

        // obtain payment token for pay protocol
        let pay_token = zkproofs::activate::merchant_init(rng, &init_state, &mut merch_state);
        //assert!(cust_state.verify_pay_token(&channel_state, &pay_token));

        // customer verifies pay token and completes the activate phase
        assert!(zkproofs::activate::customer_finalize(
            &mut channel_state,
            &mut cust_state,
            pay_token
        ));

        // move forward with unlink
        let (session_id, unlink_info, unlinked_cust_state) =
            zkproofs::unlink::customer_update_state(rng, &channel_state, &cust_state);
        let new_close_token_result = zkproofs::unlink::merchant_update_state(
            rng,
            &channel_state,
            &session_id,
            &unlink_info,
            &mut merch_state,
        );

        let new_close_token = handle_bolt_result!(new_close_token_result).unwrap();

        let rt_pair = zkproofs::unlink::customer_unmask(
            &channel_state,
            &mut cust_state,
            unlinked_cust_state,
            &new_close_token,
        )
        .unwrap();

        // send revoke token and get pay-token in response
        let new_pay_token_result: BoltResult<cl::Signature<Bls12>> =
            zkproofs::unlink::merchant_validate_rev_lock(&session_id, &rt_pair, &mut merch_state);
        let new_pay_token = handle_bolt_result!(new_pay_token_result);

        // verify the pay token and update internal state
        assert!(zkproofs::unlink::customer_finalize(
            &mut channel_state,
            &mut cust_state,
            new_pay_token.unwrap()
        ));

        println!("Channel unlinked and established!");

        // execute the pay protocol
        let (nonce, session_id) =
            zkproofs::pay::customer_prepare(rng, &channel_state, 10, &cust_state).unwrap();
        assert!(zkproofs::pay::merchant_prepare(
            &session_id,
            nonce,
            10,
            &mut merch_state
        ));

        let (payment, new_cust_state) =
            zkproofs::pay::customer_update_state(rng, &channel_state, &cust_state, 10);

        let new_close_token = zkproofs::pay::merchant_update_state(
            rng,
            &channel_state,
            &session_id,
            &payment,
            &mut merch_state,
        );

        let rt_pair = zkproofs::pay::customer_unmask(
            &channel_state,
            &mut cust_state,
            new_cust_state.clone(),
            &new_close_token,
        )
        .unwrap();

        // send revoke token and get pay-token in response
        let new_pay_token_result: BoltResult<cl::Signature<Bls12>> =
            zkproofs::pay::merchant_validate_rev_lock(&session_id, &rt_pair, &mut merch_state);
        let new_pay_token = handle_bolt_result!(new_pay_token_result);

        // verify the pay token and update internal state
        assert!(zkproofs::pay::customer_unmask_pay_token(
            new_pay_token.unwrap(),
            &channel_state,
            &mut cust_state
        )
        .unwrap());
        println!("Successful payment!");

        let cust_close = zkproofs::force_customer_close(&channel_state, &cust_state).unwrap();
        println!("Obtained the channel close message");
        println!("{}", cust_close.message);
        println!("close_token => {}", cust_close.merch_signature);
        println!("cust_sig => {}", cust_close.cust_signature);
    }

    #[test]
    fn bidirectional_multiple_payments_work() {
        let total_owed = 40;
        let b0_customer = 380;
        let b0_merchant = 20;
        let payment_increment = 20;

        let mut channel_state =
            zkproofs::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);

        // set fee for channel
        let fee = 5;
        channel_state.set_channel_fee(fee);

        let (_channel_token, mut merch_state, mut cust_state, mut channel_state) =
            setup_new_channel_helper(&mut channel_state, b0_customer, b0_merchant);

        // run establish protocol for customer and merchant channel
        execute_establish_protocol_helper(&mut channel_state, &mut merch_state, &mut cust_state);

        assert!(cust_state.protocol_status == ProtocolStatus::Established);

        {
            // make multiple payments in a loop
            let num_payments = total_owed / payment_increment;
            for _i in 0..num_payments {
                execute_payment_protocol_helper(
                    &mut channel_state,
                    &mut merch_state,
                    &mut cust_state,
                    payment_increment,
                );
            }

            {
                // scope localizes the immutable borrow here (for debug purposes only)
                println!("Customer balance: {:?}", &cust_state.cust_balance);
                println!("Merchant balance: {:?}", &cust_state.merch_balance);
                let total_owed_with_fees = (fee * num_payments) + total_owed;
                assert!(
                    cust_state.cust_balance == (b0_customer - total_owed_with_fees)
                        && cust_state.merch_balance == total_owed_with_fees + b0_merchant
                );
            }

            let cust_close_msg =
                zkproofs::force_customer_close(&channel_state, &cust_state).unwrap();
            println!("Obtained the channel close message");
            println!("{}", cust_close_msg.message);
            println!("{}", cust_close_msg.merch_signature);
        }
    }

    #[test]
    fn bidirectional_payment_negative_payment_works() {
        // just bidirectional case (w/o third party)
        let total_owed = -20;
        let b0_customer = 90;
        let b0_merchant = 30;
        let payment_increment = -20;

        let mut channel_state =
            zkproofs::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);

        let (_channel_token, mut merch_state, mut cust_state, mut channel_state) =
            setup_new_channel_helper(&mut channel_state, b0_customer, b0_merchant);

        // run establish protocol for customer and merchant channel
        execute_establish_protocol_helper(&mut channel_state, &mut merch_state, &mut cust_state);

        assert!(cust_state.protocol_status == ProtocolStatus::Established);

        {
            execute_payment_protocol_helper(
                &mut channel_state,
                &mut merch_state,
                &mut cust_state,
                payment_increment,
            );

            {
                // scope localizes the immutable borrow here (for debug purposes only)
                println!("Customer balance: {:?}", &cust_state.cust_balance);
                println!("Merchant balance: {:?}", &cust_state.merch_balance);
                assert!(
                    cust_state.cust_balance == (b0_customer - total_owed)
                        && cust_state.merch_balance == total_owed + b0_merchant
                );
            }
        }
    }

    #[test]
    fn bidirectional_merchant_close_detects_double_spends() {
        let rng = &mut rand::thread_rng();

        let b0_customer = rng.gen_range(100, 1000);
        let b0_merchant = 10;
        let pay_increment = 20;

        let mut channel_state =
            zkproofs::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);

        let (channel_token, mut merch_state, mut cust_state, mut channel_state) =
            setup_new_channel_helper(&mut channel_state, b0_customer, b0_merchant);

        // run establish protocol for customer and merchant channel
        execute_establish_protocol_helper(&mut channel_state, &mut merch_state, &mut cust_state);

        assert!(cust_state.protocol_status == ProtocolStatus::Established);

        // let's make a few payments then exit channel (will post an old channel state
        execute_payment_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut cust_state,
            pay_increment,
        );

        execute_payment_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut cust_state,
            pay_increment,
        );

        // let's close then move state forward
        let old_cust_close_msg =
            zkproofs::force_customer_close(&channel_state, &cust_state).unwrap();

        execute_payment_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut cust_state,
            pay_increment,
        );

        execute_payment_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut cust_state,
            pay_increment,
        );
        let _cur_cust_close_msg =
            zkproofs::force_customer_close(&channel_state, &cust_state).unwrap();

        let merch_close_result = zkproofs::force_merchant_close(
            &channel_state,
            &channel_token,
            &old_cust_close_msg,
            &merch_state,
        );

        let merch_close_msg = merch_close_result.unwrap();
        println!("Double spend attempt by customer! Evidence below...");
        println!(
            "Merchant close: rev_lock = {}",
            hex::encode(merch_close_msg.rev_lock.0)
        );
        println!(
            "Merchant close: rev_secret = {}",
            hex::encode(merch_close_msg.rev_secret.0)
        );
    }

    #[test]
    #[should_panic(expected = "Merchant close msg")]
    fn bidirectional_merchant_close_works() {
        let rng = &mut rand::thread_rng();

        let b0_customer = rng.gen_range(100, 1000);
        let b0_merchant = 10;
        let pay_increment = 20;

        let mut channel_state =
            zkproofs::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);

        let (channel_token, mut merch_state, mut cust_state, mut channel_state) =
            setup_new_channel_helper(&mut channel_state, b0_customer, b0_merchant);

        // run establish protocol for customer and merchant channel
        execute_establish_protocol_helper(&mut channel_state, &mut merch_state, &mut cust_state);

        assert!(cust_state.protocol_status == ProtocolStatus::Established);

        // let's make a few payments then exit channel (will post an old channel state
        execute_payment_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut cust_state,
            pay_increment,
        );

        execute_payment_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut cust_state,
            pay_increment,
        );

        execute_payment_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut cust_state,
            pay_increment,
        );

        execute_payment_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut cust_state,
            pay_increment,
        );

        let cust_close_msg = zkproofs::force_customer_close(&channel_state, &cust_state).unwrap();

        let merch_close_result = zkproofs::force_merchant_close(
            &channel_state,
            &channel_token,
            &cust_close_msg,
            &merch_state,
        );
        let _merch_close_msg = match merch_close_result {
            Ok(n) => n,
            Err(err) => panic!("Merchant close msg: {}", err),
        };
    }

    #[test]
    fn intermediary_payment_basics_works() {
        println!("Intermediary test...");
        let rng = &mut rand::thread_rng();

        let b0_alice = rng.gen_range(100, 1000);
        let b0_bob = rng.gen_range(100, 1000);
        let b0_merch_a = rng.gen_range(100, 1000);
        let b0_merch_b = rng.gen_range(100, 1000);
        let tx_fee = rng.gen_range(1, 5);
        let mut channel_state =
            zkproofs::ChannelState::<Bls12>::new(String::from("New Channel State"), true);
        channel_state.set_channel_fee(tx_fee);

        let merch_name = "Hub";
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let (mut channel_token, mut merch_state, mut channel_state) =
            zkproofs::merchant_init(rng, &mut channel_state, merch_name);

        // initialize on the customer side with balance: b0_cust
        let mut alice_cust_state =
            zkproofs::customer_init(rng, &mut channel_token, b0_alice, b0_merch_a, "Alice");

        let mut bob_cust_state =
            zkproofs::customer_init(rng, &mut channel_token, b0_bob, b0_merch_b, "Bob");

        // run establish protocol for customer and merchant channel
        //let mut channel_state_alice = channel_state.clone();
        //let mut channel_state_bob = channel_state.clone();

        execute_establish_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut alice_cust_state,
        );
        execute_establish_protocol_helper(
            &mut channel_state,
            &mut merch_state,
            &mut bob_cust_state,
        );

        assert!(alice_cust_state.protocol_status == ProtocolStatus::Established);
        assert!(bob_cust_state.protocol_status == ProtocolStatus::Established);

        // run pay protocol - flow for third-party

        let amount = rng.gen_range(5, 100);
        let (alice_nonce, alice_session_id) =
            zkproofs::pay::customer_prepare(rng, &channel_state, amount, &alice_cust_state)
                .unwrap();
        assert!(zkproofs::pay::merchant_prepare(
            &alice_session_id,
            alice_nonce,
            amount,
            &mut merch_state
        ));

        let (sender_payment, new_alice_cust_state) =
            zkproofs::pay::customer_update_state(rng, &channel_state, &alice_cust_state, amount);

        let (bob_nonce, bob_session_id) =
            zkproofs::pay::customer_prepare(rng, &channel_state, -amount, &bob_cust_state).unwrap();
        assert!(zkproofs::pay::merchant_prepare(
            &bob_session_id,
            bob_nonce,
            -amount,
            &mut merch_state
        ));

        let (receiver_payment, new_bob_cust_state) =
            zkproofs::pay::customer_update_state(rng, &channel_state, &bob_cust_state, -amount);

        // TODO: figure out how to attach conditions on payment recipients close token that they must (1) produce revocation token for sender's old wallet and (2) must have channel open

        // intermediary executes the following on the two payment proofs
        let close_token_result = zkproofs::pay::multi_customer_update_state(
            rng,
            &channel_state,
            &sender_payment,
            &receiver_payment,
            &mut merch_state,
        );
        let (alice_close_token, bob_cond_close_token) =
            handle_bolt_result!(close_token_result).unwrap();

        // both alice and bob generate a revoke token
        let revoke_token_alice = zkproofs::pay::customer_unmask(
            &channel_state,
            &mut alice_cust_state,
            new_alice_cust_state,
            &alice_close_token,
        )
        .unwrap();
        let revoke_token_bob = zkproofs::pay::customer_unmask(
            &channel_state,
            &mut bob_cust_state,
            new_bob_cust_state,
            &bob_cond_close_token,
        )
        .unwrap();

        // send both revoke tokens to intermediary and get pay-tokens in response
        let new_pay_token_result: BoltResult<(cl::Signature<Bls12>, cl::Signature<Bls12>)> =
            zkproofs::pay::multi_merchant_unmask(
                &revoke_token_alice,
                &revoke_token_bob,
                &mut merch_state,
            );
        let (new_pay_token_alice, new_pay_token_bob) =
            handle_bolt_result!(new_pay_token_result).unwrap();

        // verify the pay tokens and update internal state
        assert!(alice_cust_state.pay_unmask_customer(&channel_state, &new_pay_token_alice));
        assert!(bob_cust_state.pay_unmask_customer(&channel_state, &new_pay_token_bob));

        println!("Successful payment with intermediary!");
    }

    #[test]
    fn serialization_tests() {
        let mut channel_state =
            zkproofs::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
        let rng = &mut rand::thread_rng();

        let serialized = serde_json::to_string(&channel_state).unwrap();
        println!("new channel state len: {}", &serialized.len());

        let _chan_state: zkproofs::ChannelState<Bls12> = serde_json::from_str(&serialized).unwrap();

        let (mut channel_token, _merch_state, _channel_state) =
            zkproofs::merchant_init(rng, &mut channel_state, "Merchant A");

        let b0_cust = 100;
        let b0_merch = 10;
        let cust_state =
            zkproofs::customer_init(rng, &mut channel_token, b0_cust, b0_merch, "Customer A");

        let serialized_ct = serde_json::to_string(&channel_token).unwrap();

        println!("serialized ct: {:?}", &serialized_ct);

        let _des_ct: zkproofs::ChannelToken<Bls12> = serde_json::from_str(&serialized_ct).unwrap();

        //println!("des_ct: {}", &des_ct);

        let serialized_cw = serde_json::to_string(&cust_state).unwrap();

        println!("serialized cw: {:?}", &serialized_cw);

        let _des_cw: zkproofs::CustomerState<Bls12> = serde_json::from_str(&serialized_cw).unwrap();
    }

    #[test]
    fn test_reconstruct_channel_token() {
        let _ser_channel_token = "024c252c7e36d0c30ae7c67dabea2168f41b36b85c14d3e180b423fa1a5df0e7ac027df0457901953b9b776f4999d5a1e78\
        049c0afa4f741d0d3bb7d9711a0f8c0038f4c70072363fe07ffe1450d63205cbaeaafe600ca9001d8bbf8984ce54a9c5e041084779dace7a4cf582906ea4e\
        493a1368ec7f05e7f89635c555c26e5d0149186095856dc210bef4b8fec03415cd6d1253bdafd0934a20b57ee088fa7ee0bab0668b1aa84c30e856dd685ce\
        e2a95844cb68504e82fd9dd874cbf6f7ee58155245e97c52625b53f4ca969f48b33c59f0009adc70d1472a303a35ace0d96149c8cdb96f29b6f476b8f4a10\
        bd430c4658d4e0b5873fcb946a76aa861c6c4c601ab8fb0b9c88d2e8861de2f0dae2bb2a8492db2978ce8f2e509328efbf12384ae2db5c17021d222724a3b\
        c4b621bf4f32601d555ff2cfc2171adeb2f1bd42c484c1c0a1e5d7d2853c102080680cefc925808b6e3d71b29a93f7e8f5c2eeeeef944b3740feddb24ec2c\
        17e3db22ee6a7af77e32a9d186bdcc150dd59b0cd92b92b6656cb588dec9d1d07be5e2a319bf37f1120b7c656f78dc6c4064f8d63f590f70cdc0c1746fde6\
        035eeb9aa90b69ea666ad71b27078ab61573aec60bab80a4e6a8e4d8ce02204f5b7e0131bf24d5df1428e9e571891c6feb1c0a52ba789136b244f13f510c4\
        f1f0eb4b0a7e675f105f8102c672461da340ebcae1eddd49a009bcf3b199eb2006fab6cf0ccf102b5c6dd45722dc0c27d4b9697f627f1bcbe44f6d96842de\
        c92877ff23d374964970c3386972a8ae369367907001bcd8bba458b8f29842321a8231f3441054999cb19b2c40409da8216406298e1d41bcaf5ea8a225266\
        2848d3f810dd369aba5ff684360080aa6f5e9ba61be1331f6bdf8b00d1ec8453637c4b480f6d0c5e5467013aa0e8be1777c370a1988db21d8d3de3f6d79d8\
        cbe6412f88d39de0cd1bf9e8f9b57ff933f21bef89b5bd3f9a901936568db58cc8326a719bf56438bbcab659a20ea5c0342eb9f072f105303c90de3b3b865\
        66155899d05d00396cfae74ac0526f0dd30c33e0c6790f3f8119dac12fb6f870b9a317afa94cd624b88ede30d49d2373b58453637c4b480f6d0c5e5467013\
        aa0e8be1777c370a1988db21d8d3de3f6d79d8cbe6412f88d39de0cd1bf9e8f9b57ffa397625c859a63e2c6e42486c4f76f306d484cce151f8614f87506e9\
        9c871521dd244bfeb380481aed8df823a507c7a3ad367c1797fc6efa089f929729e7d48bfa9c60860fbb212918bb91d8c6aa523046bdf208c95fa5a0fb86a\
        1e46f92e0e5893e136b74d38e106fa990590598932a4e2458034cea22337c6f365bcb5cab59ceea03d7a9f7821ea432e262877ef0128cb73d8733c3961762\
        26acb6b3de132c803be39a4e803cbc5a4670cb6169583fa899146fab0227dc2ae167393f96f3b8b31e015af1c305de3a07f52408e9c52495c2458ea05c7a3\
        71dc14f3b1d6a646ed7cc0ca9417d8bde6efc1ac300d8e28f";
        let ser_channel_token = hex::decode(_ser_channel_token).unwrap();

        let option_ct = tze_utils::reconstruct_channel_token_bls12(&ser_channel_token);
        let channel_token = match option_ct {
            Ok(n) => n.unwrap(),
            Err(e) => panic!("Error reconstructing compact rep of channel token: {}", e),
        };

        let channelId = channel_token.compute_channel_id();

        let original_channelId =
            "[\"e4f4bb9c5c64440788682c5ea06f457f265bd24186689fa50ce24a3be00c6107\"]";
        let computed_channelId = serde_json::to_string(&channelId).unwrap();

        println!("channel ID: {}", channelId);
        println!("pkc: {:?}", channel_token.pk_c.unwrap());
        println!("pkm: {:?}", channel_token.pk_m);

        assert_eq!(original_channelId, computed_channelId);

        // reconstruct signature
        let _ser_signature = "93f26490b4576c38dfb8dceae547f4b49aeb945ecc9cccc528c39068c78177bda68aaf45743f09c48ad99b6007fe415b\
                              aee9eafd51cfdb0dc567a5d152bc37861727e85088b417cf3ff57c108d0156eee56aff810f1e5f9e76cd6a3590d6db5e";
        let ser_signature = hex::decode(_ser_signature).unwrap();

        let option_sig = tze_utils::reconstruct_signature_bls12(&ser_signature);

        let _sig = match option_sig {
            Ok(n) => n.unwrap(),
            Err(e) => panic!("Error reconstructing compact rep of signature: {}", e),
        };
    }

    #[test]
    fn test_reconstruct_secp_sig() {
        let _ser_sig = "3044022064650285b55624f1f64b2c75e76589fa4b1033dabaa7ff50ff026e1dc038279202204ca696e0a829687c87171e8e5dab17069be248ff2595fd9607f3346dadcb579f";
        let ser_sig = hex::decode(_ser_sig).unwrap();

        let signature = tze_utils::reconstruct_secp_signature(ser_sig.as_slice());
        assert_eq!(format!("{:?}", signature), _ser_sig);

        let sk = hex::decode("81361b9bc2f67524dcc59b980dc8b06aadb77db54f6968d2af76ecdb612e07e4")
            .unwrap();
        let msg = "hello world!";
        let mut sha256 = sha2::Sha256::new();
        sha256.input(msg);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&sha256.result());

        let mut seckey = [0u8; 32];
        seckey.copy_from_slice(sk.as_slice());
        let sig = tze_utils::tze_generate_secp_signature(&seckey, &hash);
        assert!(sig.len() > 0);
    }

    #[test]
    fn test_reconstruct_channel_close_m() {
        let mut address = [0u8; 33];
        let address_slice =
            hex::decode("0a1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        address.copy_from_slice(address_slice.as_slice());

        let channelClose = tze_utils::reconstruct_secp_channel_close_m(&address,
                                                                       &hex::decode("3044022041932b376fe2c5e9e9ad0a3804e2290c3bc40617ea4f7b913be858dbcc3760b50220429d6eb1aabbd4135db4e0776c0b768af844b0af44f2f8f9da5a65e8541b4e9f").unwrap(),
                                                                       &hex::decode("3045022100e76653c5f8cb4c2f39efc7c5450d4f68ef3d84d482305534f5dfc310095a3124022003c4651ce1305cffe5e483ab99925cc4c9c5df2b5449bb18a51d52b21d789716").unwrap());

        assert_eq!(
            channelClose.address,
            "0a1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(format!("{:?}", channelClose.revoke.unwrap()), "3044022041932b376fe2c5e9e9ad0a3804e2290c3bc40617ea4f7b913be858dbcc3760b50220429d6eb1aabbd4135db4e0776c0b768af844b0af44f2f8f9da5a65e8541b4e9f");
        assert_eq!(format!("{:?}", channelClose.signature), "3045022100e76653c5f8cb4c2f39efc7c5450d4f68ef3d84d482305534f5dfc310095a3124022003c4651ce1305cffe5e483ab99925cc4c9c5df2b5449bb18a51d52b21d789716");
    }

    #[test]
    fn test_establish_mpc_channel() {
        let mut rng = &mut rand::thread_rng();
        // let mut db = RedisDatabase::new("lib", "redis://127.0.0.1/").unwrap();
        let mut db = HashMapDatabase::new("", "".to_string()).unwrap();

        let min_threshold = 546;
        let val_cpfp = 1000;
        let mut channel_state = mpc::ChannelMPCState::new(
            String::from("Channel A -> B"),
            1487,
            min_threshold,
            min_threshold,
            val_cpfp,
            false,
        );
        // init merchant
        let mut merch_state = mpc::init_merchant(rng, "".to_string(), &mut channel_state, "Bob");

        let fee_cc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let fee_mc = 1000;
        let b0_cust = 10000;
        let b0_merch = 10000;

        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        // init customer
        let (mut channel_token, mut cust_state) = mpc::init_customer(
            rng,
            &merch_state.pk_m,
            b0_cust,
            b0_merch,
            &tx_fee_info,
            "Alice",
        );

        // form all of the escrow and merch-close-tx transactions
        let funding_tx_info = generate_funding_tx(&mut rng, b0_cust, b0_merch);

        // form and sign the cust-close-from-escrow-tx and from-merch-close-tx
        let pubkeys = cust_state.get_pubkeys(&channel_state, &channel_token);

        // merchant signs the customer's closing transactions and sends signatures back to customer
        let to_self_delay_be = channel_state.get_self_delay_be(); // [0x05, 0xcf]; // big-endian format
        let (escrow_sig, merch_sig) = merch_state
            .sign_initial_closing_transaction::<Testnet>(
                funding_tx_info.clone(),
                pubkeys.rev_lock.0,
                pubkeys.cust_pk,
                pubkeys.cust_close_pk,
                to_self_delay_be,
                fee_cc,
                fee_mc,
                channel_state.get_val_cpfp(),
            )
            .unwrap();

        let res1 =
            cust_state.set_initial_cust_state(&mut channel_token, &funding_tx_info, &tx_fee_info);
        assert!(res1.is_ok(), res1.err().unwrap());

        let got_close_tx = cust_state.sign_initial_closing_transaction::<Testnet>(
            &channel_state,
            &channel_token,
            &escrow_sig,
            &merch_sig,
        );
        assert!(got_close_tx.is_ok(), got_close_tx.err().unwrap());
        // customer can proceed to sign the escrow-tx and merch-close-tx and sends resulting signatures to merchant
        let (init_cust_state, init_hash) = mpc::get_initial_state(&cust_state).unwrap();

        // at this point, the escrow-tx can be broadcast and confirmed
        let res2 = mpc::validate_channel_params(
            &mut db as &mut dyn StateDatabase,
            &channel_token,
            &init_cust_state,
            init_hash,
            &mut merch_state,
        );
        assert!(res2.is_ok(), res2.err().unwrap());
        let _rc = mpc::customer_mark_open_channel(&mut cust_state).unwrap();
        let _rc =
            mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state)
                .unwrap();

        let s0 = mpc::activate_customer(rng, &mut cust_state).unwrap();

        let pay_token = mpc::activate_merchant(
            &mut db as &mut dyn StateDatabase,
            channel_token,
            &s0,
            &mut merch_state,
        );
        assert!(pay_token.is_ok(), pay_token.err().unwrap());

        mpc::activate_customer_finalize(pay_token.unwrap(), &mut cust_state).unwrap();

        //TODO: test unlinking with a 0-payment of pay protocol
    }

    fn generate_funding_tx<R: Rng>(csprng: &mut R, b0_cust: i64, b0_merch: i64) -> FundingTxInfo {
        let mut escrow_txid = [0u8; 32];
        let mut merch_txid = [0u8; 32];

        csprng.fill_bytes(&mut escrow_txid);
        csprng.fill_bytes(&mut merch_txid);

        let mut escrow_prevout = [0u8; 32];
        let mut merch_prevout = [0u8; 32];

        let mut prevout_preimage1: Vec<u8> = Vec::new();
        prevout_preimage1.extend(escrow_txid.iter()); // txid1
        prevout_preimage1.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result1 = Sha256::digest(&Sha256::digest(&prevout_preimage1));
        escrow_prevout.copy_from_slice(&result1);

        let mut prevout_preimage2: Vec<u8> = Vec::new();
        prevout_preimage2.extend(merch_txid.iter()); // txid2
        prevout_preimage2.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result2 = Sha256::digest(&Sha256::digest(&prevout_preimage2));
        merch_prevout.copy_from_slice(&result2);

        return FundingTxInfo {
            init_cust_bal: b0_cust,
            init_merch_bal: b0_merch,
            escrow_txid: FixedSizeArray32(escrow_txid),
            merch_txid: FixedSizeArray32(merch_txid),
            escrow_prevout: FixedSizeArray32(escrow_prevout),
            merch_prevout: FixedSizeArray32(merch_prevout),
        };
    }

    fn setup_new_zkchannel_helper<R: Rng>(
        rng: &mut R,
        cust_bal: i64,
        merch_bal: i64,
        tx_fee_info: &mpc::TransactionFeeInfo,
    ) -> (
        mpc::ChannelMPCState,
        mpc::ChannelMPCToken,
        mpc::CustomerMPCState,
        mpc::MerchantMPCState,
    ) {
        // init channel state
        let mut channel_state = mpc::ChannelMPCState::new(
            String::from("Channel A -> B"),
            1487,
            tx_fee_info.bal_min_cust,
            tx_fee_info.bal_min_merch,
            tx_fee_info.val_cpfp,
            false,
        );
        // init merchant
        let merch_state = mpc::init_merchant(rng, "".to_string(), &mut channel_state, "Bob");

        let b0_cust = cust_bal;
        let b0_merch = merch_bal;
        // init customer
        let (channel_token, cust_state) = mpc::init_customer(
            rng,
            &merch_state.pk_m,
            b0_cust,
            b0_merch,
            tx_fee_info,
            "Alice",
        );

        return (channel_state, channel_token, cust_state, merch_state);
    }

    #[test]
    #[ignore]
    fn test_payment_mpc_channel_merch() {
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d76);
        let mut db = RedisDatabase::new("merch.lib", "redis://127.0.0.1/".to_string()).unwrap();

        let min_threshold = 546;
        let val_cpfp = 1000;
        let mut channel_state = mpc::ChannelMPCState::new(
            String::from("Channel A -> B"),
            1487,
            min_threshold,
            min_threshold,
            val_cpfp,
            false,
        );

        let mut merch_state =
            mpc::init_merchant(&mut rng, "".to_string(), &mut channel_state, "Bob");

        let b0_cust = 100000;
        let b0_merch = 100000;
        let fee_cc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let fee_mc = 1000;
        let amount = 1000;
        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        let (mut channel_token, mut cust_state) = mpc::init_customer(
            &mut rng,
            &merch_state.pk_m,
            b0_cust,
            b0_merch,
            &tx_fee_info,
            "Alice",
        );

        let funding_tx_info = generate_funding_tx(&mut rng, b0_cust, b0_merch);

        cust_state
            .set_initial_cust_state(&mut channel_token, &funding_tx_info, &tx_fee_info)
            .unwrap();

        let (init_cust_state, init_hash) = mpc::get_initial_state(&cust_state).unwrap();

        let res2 = mpc::validate_channel_params(
            &mut db as &mut dyn StateDatabase,
            &channel_token,
            &init_cust_state,
            init_hash,
            &mut merch_state,
        );
        println!("mpc::validate_channel_params: {}", res2.is_ok());

        // TODO: add cust-close tx signing API
        // transition state manually
        cust_state.protocol_status = ProtocolStatus::Initialized;
        let mut escrow_txid_be = channel_token.escrow_txid.0.clone();
        escrow_txid_be.reverse();
        let rc = cust_state.change_channel_status(ChannelStatus::PendingOpen);
        assert!(rc.is_ok());
        let rc = merch_state.change_channel_status(escrow_txid_be, ChannelStatus::PendingOpen);
        assert!(rc.is_ok());

        let _rc = mpc::customer_mark_open_channel(&mut cust_state).unwrap();
        let _rc =
            mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state)
                .unwrap();

        let s0 = mpc::activate_customer(&mut rng, &mut cust_state).unwrap();

        let pay_token = mpc::activate_merchant(
            &mut db as &mut dyn StateDatabase,
            channel_token.clone(),
            &s0,
            &mut merch_state,
        )
        .unwrap();

        mpc::activate_customer_finalize(pay_token, &mut cust_state).unwrap();

        let (_new_state, revoked_state, rev_lock_com, session_id) =
            mpc::pay_prepare_customer(&mut rng, &channel_state, amount, &mut cust_state).unwrap();

        let pay_mask_com = mpc::pay_prepare_merchant(
            &mut rng,
            &mut db as &mut dyn StateDatabase,
            &channel_state,
            session_id,
            s0.get_nonce(),
            rev_lock_com.clone(),
            amount,
            None,
            &mut merch_state,
        )
        .unwrap();

        let res_merch = mpc::pay_update_merchant(
            &mut rng,
            &mut db as &mut dyn StateDatabase,
            &channel_state,
            session_id,
            pay_mask_com,
            &mut merch_state,
            ptr::null_mut(),
            None,
            None,
        );
        assert!(res_merch.is_ok(), res_merch.err().unwrap());

        let mpc_result = res_merch.unwrap();
        let masked_inputs = mpc::pay_confirm_mpc_result(
            &mut db as &mut dyn StateDatabase,
            session_id.clone(),
            mpc_result,
            &mut merch_state,
        );
        assert!(masked_inputs.is_ok(), masked_inputs.err().unwrap());
        // println!("Masked Tx Inputs: {:#?}", masked_inputs.unwrap());
        let mask_in = masked_inputs.unwrap();
        println!("escrow_mask: {}", hex::encode(mask_in.escrow_mask.0));
        println!("merch_mask: {}", hex::encode(mask_in.merch_mask.0));
        println!("r_escrow_sig: {}", hex::encode(mask_in.r_escrow_sig.0));
        println!("r_merch_sig: {}", hex::encode(mask_in.r_merch_sig.0));

        let (pay_token_mask, pay_token_mask_r) = match mpc::pay_validate_rev_lock_merchant(
            &mut db as &mut dyn StateDatabase,
            session_id,
            revoked_state,
            &mut merch_state,
        ) {
            Ok(n) => (n.0, n.1),
            Err(e) => panic!("Could not get pay token mask and randomness: {}", e),
        };
        println!("pt_mask_r => {}", hex::encode(&pay_token_mask_r));
        assert_eq!(
            hex::encode(pay_token_mask),
            "4a682bd5d46e3b5c7c6c353636086ed7a943895982cb43deba0a8843459500e4"
        );
        assert_eq!(
            hex::encode(pay_token_mask_r),
            "671687f7cecc583745cd86342ddcccd4"
        );
        // db.clear_state();
    }

    rusty_fork_test! {
        #[test]
        #[ignore]
        fn test_payment_mpc_channel_cust() {
            let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d76);
            let mut db = RedisDatabase::new("cust.lib", "redis://127.0.0.1/".to_string()).unwrap();

            let min_threshold = 546;
            let val_cpfp = 1000;
            let mut channel_state = mpc::ChannelMPCState::new(String::from("Channel A -> B"), 1487, min_threshold, min_threshold, val_cpfp, false);
            let mut merch_state = mpc::init_merchant(&mut rng, "".to_string(), &mut channel_state, "Bob");

            let b0_cust = 100000;
            let b0_merch = 100000;
            let fee_cc = 1000;
            let min_fee = 0;
            let max_fee = 10000;
            let fee_mc = 1000;
            let amount = 1000;
            let tx_fee_info = mpc::TransactionFeeInfo {
                bal_min_cust: min_threshold,
                bal_min_merch: min_threshold,
                val_cpfp: val_cpfp,
                fee_cc: fee_cc,
                fee_mc: fee_mc,
                min_fee: min_fee,
                max_fee: max_fee
            };

            let (mut channel_token, mut cust_state) = mpc::init_customer(&mut rng, &merch_state.pk_m, b0_cust, b0_merch, &tx_fee_info, "Alice");

            let funding_tx_info = generate_funding_tx(&mut rng, b0_cust, b0_merch);

            cust_state.set_initial_cust_state(&mut channel_token, &funding_tx_info, &tx_fee_info).unwrap();

            let (init_cust_state, init_hash) = match mpc::get_initial_state(&cust_state) {
                Ok(n) => (n.0, n.1),
                Err(e) => panic!(e)
            };

            let res2 = mpc::validate_channel_params(&mut db as &mut dyn StateDatabase, &channel_token, &init_cust_state, init_hash, &mut merch_state);
            println!("mpc::validate_channel_params: {}", res2.is_ok());

            // transition state manually
            cust_state.protocol_status = ProtocolStatus::Initialized;
            let mut escrow_txid_be = channel_token.escrow_txid.0.clone();
            escrow_txid_be.reverse();
            let rc = cust_state.change_channel_status(ChannelStatus::PendingOpen);
            assert!(rc.is_ok());
            let rc = merch_state.change_channel_status(escrow_txid_be, ChannelStatus::PendingOpen);
            assert!(rc.is_ok());

            let rc = mpc::customer_mark_open_channel(&mut cust_state);
            assert!(rc.is_ok());
            let rc = mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state);
            assert!(rc.is_ok());

            let s0 = mpc::activate_customer(&mut rng, &mut cust_state).unwrap();

            let pay_token = mpc::activate_merchant(&mut db as &mut dyn StateDatabase, channel_token.clone(), &s0, &mut merch_state).unwrap();

            mpc::activate_customer_finalize(pay_token, &mut cust_state).unwrap();

            let ser_tx_info = serde_json::to_string(&funding_tx_info).unwrap();
            println!("Ser Funding Tx Info: {}", ser_tx_info);
            let orig_funding_tx_info: FundingTxInfo = serde_json::from_str(&ser_tx_info).unwrap();
            assert_eq!(funding_tx_info, orig_funding_tx_info);

            let (state, _rev_state, rev_lock_com, session_id) = mpc::pay_prepare_customer(&mut rng, &mut channel_state, amount, &mut cust_state).unwrap();

            let pay_mask_com = mpc::pay_prepare_merchant(&mut rng, &mut db as &mut dyn StateDatabase, &channel_state, session_id, state.get_nonce(), rev_lock_com.clone(), amount, None, &mut merch_state).unwrap();

            let res_cust = mpc::pay_update_customer(&channel_state, &channel_token, s0, state, pay_mask_com, rev_lock_com, amount, &mut cust_state,
            ptr::null_mut(),
            None,
            None,);
            assert!(res_cust.is_ok() && res_cust.unwrap());

            let mut escrow_mask = [0u8; 32];
            escrow_mask.copy_from_slice(hex::decode("28a6c48749023149e45657f824b8d2d710b18575a3d667b4bd56c5f6d9c394b4").unwrap().as_slice());
            let mut merch_mask = [0u8; 32];
            merch_mask.copy_from_slice(hex::decode("fddc371be95df8ea164916e88dcd895a1522fcff163fc3d70182c78d91d33699").unwrap().as_slice());
            let mut r_escrow_sig = [0u8; 32];
            r_escrow_sig.copy_from_slice(hex::decode("e9b5a76742e28c1c5a2efb071abb5b37e62756ee0f02cc45ac79b3a5ed3bb824").unwrap().as_slice());
            let mut r_merch_sig = [0u8; 32];
            r_merch_sig.copy_from_slice(hex::decode("c1270ef7f78f7f8f208eb28da447d2e5820c9b7b9e37aee7f2f60af454d7ca31").unwrap().as_slice());

            let masks = MaskedTxMPCInputs::new(
                escrow_mask,
                merch_mask,
                r_escrow_sig,
                r_merch_sig
            );

            let is_ok = mpc::pay_unmask_sigs_customer(&channel_state, &channel_token, masks, &mut cust_state);
            assert!(is_ok.is_ok(), is_ok.err().unwrap());

            let mut pt_mask = [0u8; 32];
            pt_mask.copy_from_slice(hex::decode("4a682bd5d46e3b5c7c6c353636086ed7a943895982cb43deba0a8843459500e4").unwrap().as_slice());
            let mut pt_mask_r = [0u8; 16];
            pt_mask_r.copy_from_slice(hex::decode("671687f7cecc583745cd86342ddcccd4").unwrap().as_slice());

            let is_ok = mpc::pay_unmask_pay_token_customer(pt_mask, pt_mask_r, &mut cust_state).unwrap();
            assert!(is_ok);
        }
    }

    // establish the funding tx and sign initial closing tx
    fn establish_init_cust_close_tx_helper(
        funding_tx: &FundingTxInfo,
        tx_fee_info: &mpc::TransactionFeeInfo,
        channel_state: &mpc::ChannelMPCState,
        channel_token: &mut mpc::ChannelMPCToken,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
    ) {
        cust_state
            .set_initial_cust_state(channel_token, funding_tx, tx_fee_info)
            .unwrap();
        let pubkeys = cust_state.get_pubkeys(&channel_state, &channel_token);

        let to_self_delay_be = channel_state.get_self_delay_be();
        // merchant signs and returns initial close sigs to customer
        let (escrow_sig, merch_sig) = merch_state
            .sign_initial_closing_transaction::<Testnet>(
                funding_tx.clone(),
                pubkeys.rev_lock.0,
                pubkeys.cust_pk,
                pubkeys.cust_close_pk,
                to_self_delay_be.clone(),
                tx_fee_info.fee_cc,
                tx_fee_info.fee_mc,
                tx_fee_info.val_cpfp,
            )
            .unwrap();

        assert!(cust_state.protocol_status == ProtocolStatus::New);

        // customer verifies the close signatures
        let got_close_tx = cust_state.sign_initial_closing_transaction::<Testnet>(
            &channel_state,
            &channel_token,
            &escrow_sig,
            &merch_sig,
        );
        assert!(got_close_tx.is_ok(), got_close_tx.err().unwrap());

        // at this point, we should be pending open since we've got the initial close tx signed
        // just need to broadcast the escrow tx
        assert!(cust_state.get_channel_status() == ChannelStatus::PendingOpen);
    }

    // establish the init merch-close-tx
    fn establish_merch_close_tx_helper(
        funding_tx_info: &mut FundingTxInfo,
        channel_state: &mpc::ChannelMPCState,
        channel_token: &mpc::ChannelMPCToken,
        cust_bal: i64,
        merch_bal: i64,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
        fee_mc: i64,
    ) {
        let escrow_txid_be = funding_tx_info.escrow_txid.0.clone();
        let to_self_delay_be = channel_state.get_self_delay_be();
        let pubkeys = cust_state.get_pubkeys(&channel_state, &channel_token);
        let cust_sk = cust_state.get_close_secret_key();

        let (merch_tx_preimage, tx_params) =
            zkchan_tx::transactions::btc::merchant_form_close_transaction::<Testnet>(
                escrow_txid_be.to_vec(),
                pubkeys.cust_pk.clone(),
                pubkeys.merch_pk.clone(),
                pubkeys.merch_close_pk.clone(),
                pubkeys.merch_child_pk.clone(),
                cust_bal,
                merch_bal,
                fee_mc,
                channel_state.get_val_cpfp(),
                to_self_delay_be.clone(),
            )
            .unwrap();

        // set the funding_tx_info structure
        let (merch_txid_be, prevout) =
            zkchan_tx::txutil::merchant_generate_transaction_id(tx_params).unwrap();
        funding_tx_info.merch_txid = FixedSizeArray32(merch_txid_be);
        funding_tx_info.merch_prevout = FixedSizeArray32(prevout);

        // generate merch-close tx
        let cust_sig =
            zkchan_tx::txutil::customer_sign_merch_close_transaction(&cust_sk, &merch_tx_preimage)
                .unwrap();

        let _is_ok = zkchan_tx::txutil::merchant_verify_merch_close_transaction(
            &merch_tx_preimage,
            &cust_sig,
            &pubkeys.cust_pk,
        )
        .unwrap();

        // store the signature for merch-close-tx
        merch_state.store_merch_close_tx(
            &escrow_txid_be.to_vec(),
            &pubkeys.cust_pk,
            cust_bal,
            merch_bal,
            fee_mc,
            to_self_delay_be,
            &cust_sig,
        );
    }

    // validate the initial state of the channel
    fn validate_initial_channel_state_helper(
        db: &mut RedisDatabase,
        channel_token: &mpc::ChannelMPCToken,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
    ) {
        let (init_state, init_hash) = mpc::get_initial_state(&cust_state).unwrap();

        assert!(mpc::validate_channel_params(
            db as &mut dyn StateDatabase,
            &channel_token,
            &init_state,
            init_hash,
            merch_state
        )
        .unwrap());
    }

    // run activate sub protocol between customer/merchant
    fn activate_channel_helper<R: Rng>(
        rng: &mut R,
        db: &mut RedisDatabase,
        channel_token: &mpc::ChannelMPCToken,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
    ) {
        let s0_result = mpc::activate_customer(rng, cust_state);
        assert!(s0_result.is_ok());
        let s0 = s0_result.unwrap();

        let pay_token_result = mpc::activate_merchant(
            db as &mut dyn StateDatabase,
            channel_token.clone(),
            &s0,
            merch_state,
        );
        assert!(pay_token_result.is_ok());
        let pay_token = pay_token_result.unwrap();

        let res = mpc::activate_customer_finalize(pay_token, cust_state);
        assert!(res.is_ok());
    }

    // run pay prepare between customer and merchant
    fn pay_prepare_helper<R: Rng>(
        rng: &mut R,
        db: &mut RedisDatabase,
        channel_state: &mpc::ChannelMPCState,
        cust_state: &mut mpc::CustomerMPCState,
        amount: i64,
        merch_state: &mut mpc::MerchantMPCState,
    ) -> (
        [u8; 16],
        mpc::State,
        mpc::State,
        mpc::RevokedState,
        [u8; 32],
        [u8; 32],
    ) {
        // get the old state
        let cur_state = cust_state.get_current_state();
        // let's prepare a new payment
        let (new_state, rev_state, rev_lock_com, session_id) =
            mpc::pay_prepare_customer(rng, channel_state, amount, cust_state).unwrap();

        // println!("Old Nonce: {}", hex::encode(&cur_state.get_nonce()));
        let justification = match amount < 0 {
            true => Some(format!("empty-sig")),
            false => None,
        };
        let pay_mask_com = mpc::pay_prepare_merchant(
            rng,
            db as &mut dyn StateDatabase,
            channel_state,
            session_id,
            cur_state.get_nonce(),
            rev_lock_com.clone(),
            amount,
            justification,
            merch_state,
        )
        .unwrap();

        return (
            session_id,
            cur_state,
            new_state,
            rev_state,
            rev_lock_com,
            pay_mask_com,
        );
    }

    #[test]
    fn test_channel_activated_correctly() {
        let mut rng = XorShiftRng::seed_from_u64(0xc7175992415de87a);
        let mut db = RedisDatabase::new("mpclib", "redis://127.0.0.1/".to_string()).unwrap();
        db.clear_state();

        let b0_cust = 10000;
        let b0_merch = 10000;
        let fee_cc = 1000;
        let fee_mc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let min_threshold = 546; // dust limit
        let val_cpfp = 1000;

        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        let (channel_state, mut channel_token, mut cust_state, mut merch_state) =
            setup_new_zkchannel_helper(&mut rng, b0_cust, b0_merch, &tx_fee_info);

        // create funding txs
        let funding_tx_info = generate_funding_tx(&mut rng, b0_cust, b0_merch);

        // customer obtains signatures on initial closing tx
        establish_init_cust_close_tx_helper(
            &funding_tx_info,
            &tx_fee_info,
            &channel_state,
            &mut channel_token,
            &mut cust_state,
            &mut merch_state,
        );

        assert!(cust_state.protocol_status == ProtocolStatus::Initialized);

        // merchant validates the initial state
        validate_initial_channel_state_helper(
            &mut db,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );
        println!("initial channel state validated!");
        // println!("cust_state channel status: {}", cust_state.protocol_status);

        let rc = mpc::customer_mark_open_channel(&mut cust_state);
        assert!(rc.is_ok());
        let rc =
            mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state);
        assert!(rc.is_ok());

        activate_channel_helper(
            &mut rng,
            &mut db,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );
        assert!(cust_state.protocol_status == ProtocolStatus::Activated);
        println!("cust_state channel status: {}", cust_state.protocol_status);
    }

    fn zkchannel_full_establish_setup_helper<R: Rng>(
        rng: &mut R,
        db: &mut RedisDatabase,
        tx_fee_info: &mpc::TransactionFeeInfo,
    ) -> (
        mpc::ChannelMPCState,
        mpc::ChannelMPCToken,
        mpc::CustomerMPCState,
        mpc::MerchantMPCState,
    ) {
        let b0_cust = 10000;
        let b0_merch = 10000;

        let (channel_state, mut channel_token, mut cust_state, mut merch_state) =
            setup_new_zkchannel_helper(rng, b0_cust, b0_merch, &tx_fee_info);

        // generate random funding tx for testing
        let mut funding_tx_info = generate_funding_tx(rng, b0_cust, b0_merch);

        // customer and merchant jointly sign merch-close-tx
        establish_merch_close_tx_helper(
            &mut funding_tx_info,
            &channel_state,
            &channel_token,
            b0_cust,
            b0_merch,
            &mut cust_state,
            &mut merch_state,
            tx_fee_info.fee_mc,
        );

        // customer obtains signatures on initial closing tx
        establish_init_cust_close_tx_helper(
            &funding_tx_info,
            tx_fee_info,
            &channel_state,
            &mut channel_token,
            &mut cust_state,
            &mut merch_state,
        );
        assert!(cust_state.protocol_status == ProtocolStatus::Initialized);

        //println!("channel_token: {:?}", cust_state);

        // merchant validates the initial state
        validate_initial_channel_state_helper(
            db,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );

        // if escrow-tx confirmed on chain, can proceed to change status for both customer/merchant
        let rc = mpc::customer_mark_open_channel(&mut cust_state);
        assert!(rc.is_ok());
        let rc =
            mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state);
        assert!(rc.is_ok());

        // customer/merchant activate the channel
        activate_channel_helper(rng, db, &channel_token, &mut cust_state, &mut merch_state);
        assert!(cust_state.protocol_status == ProtocolStatus::Activated);
        println!("cust_state channel status: {}", cust_state.protocol_status);

        return (channel_state, channel_token, cust_state, merch_state);
    }

    fn complete_pay_helper(
        merch_db: &mut RedisDatabase,
        session_id: [u8; 16],
        rev_state: mpc::RevokedState,
        channel_state: &mpc::ChannelMPCState,
        channel_token: &mpc::ChannelMPCToken,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
    ) {
        let mask_bytes = mpc::pay_confirm_mpc_result(
            merch_db as &mut dyn StateDatabase,
            session_id.clone(),
            true,
            merch_state,
        )
        .unwrap();

        println!("complete_pay_helper - got the mask bytes: {:?}", mask_bytes);

        // unmask the closing tx
        let is_sigs_ok =
            mpc::pay_unmask_sigs_customer(&channel_state, &channel_token, mask_bytes, cust_state)
                .unwrap();
        assert!(is_sigs_ok);

        // merchant validates the old state
        let (pt_mask, pt_mask_r) = match mpc::pay_validate_rev_lock_merchant(
            merch_db as &mut dyn StateDatabase,
            session_id,
            rev_state,
            merch_state,
        ) {
            Ok(n) => (n.0, n.1),
            Err(e) => {
                println!("Could not get pay token mask and randomness: {}", e);
                return;
            }
        };

        println!(
            "complete_pay_helper - new pay token: {}",
            hex::encode(&pt_mask)
        );

        // unmask pay_token
        let is_ok = mpc::pay_unmask_pay_token_customer(pt_mask, pt_mask_r, cust_state).unwrap();
        assert!(is_ok);
    }

    fn load_merchant_state_info(
        db_conn: &mut redis::Connection,
        db_key: &String,
        merch_state_key: &String,
    ) -> Result<mpc::MerchantMPCState, String> {
        // load the merchant state from DB
        let ser_merch_state = get_file_from_db(db_conn, &db_key, &merch_state_key).unwrap();
        let merch_state: mpc::MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();
        Ok(merch_state)
    }

    fn save_merchant_state_info(
        db_conn: &mut redis::Connection,
        db_key: &String,
        channel_state_key: &String,
        channel_state: Option<&mpc::ChannelMPCState>,
        merch_state_key: &String,
        merch_state: &mpc::MerchantMPCState,
    ) -> Result<(), String> {
        // let key = String::from("cli:merch_db");
        match channel_state {
            Some(n) => {
                let channel_state_json_str = serde_json::to_string(n).unwrap();
                store_file_in_db(
                    db_conn,
                    &db_key,
                    &channel_state_key,
                    &channel_state_json_str,
                )?
            }
            None => false, // do nothing
        };

        let merch_state_json_str = serde_json::to_string(merch_state).unwrap();
        store_file_in_db(db_conn, &db_key, &merch_state_key, &merch_state_json_str)?;
        Ok(())
    }

    fn run_mpctest_as_merchant(
        db: &mut RedisDatabase,
        db_key: &String,
        session_id: [u8; 16],
        pay_mask_com: [u8; 32],
        channel_state: &mpc::ChannelMPCState,
        merch_state_key: &String,
        merch_state: &mpc::MerchantMPCState,
    ) -> std::process::Child {
        let cur_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let mut profile = "release";
        if cfg!(debug_assertions) {
            profile = "debug";
        }
        let mpc_test_bin = format!("{}/target/{}/mpctest", cur_dir, profile);
        println!("mpctest path: {}", mpc_test_bin);

        let session_id_arg = format!("{}", hex::encode(session_id));
        let pay_mask_com_arg = format!("{}", hex::encode(pay_mask_com));

        // let's start a thread but block until we get to pay_update_customer()
        let channel_state_key = "channel_state".to_string();
        save_merchant_state_info(
            &mut db.conn,
            db_key,
            &channel_state_key,
            Some(&channel_state),
            &merch_state_key,
            &merch_state,
        )
        .unwrap();

        let child = Command::new(mpc_test_bin)
            .arg("--db-key")
            .arg(db_key.clone())
            .arg("--pay-mask-com")
            .arg(pay_mask_com_arg)
            .arg("--session-id")
            .arg(session_id_arg)
            .spawn()
            .expect("failed to execute mpctest");

        return child;
    }

    #[test]
    fn test_unlink_and_pay_is_correct() {
        let mut rng = &mut rand::thread_rng();
        let mut db = RedisDatabase::new("mpctest", "redis://127.0.0.1/".to_string()).unwrap();
        db.clear_state();

        // full channel setup
        let fee_cc = 1000;
        let fee_mc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let min_threshold = 546; // dust limit
        let val_cpfp = 1000;

        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        let (channel_state, channel_token, mut cust_state, mut merch_state) =
            zkchannel_full_establish_setup_helper(&mut rng, &mut db, &tx_fee_info);

        // UNLINK PROTOCOL
        let (session_id, cur_state, new_state, rev_state, rev_lock_com, pay_mask_com) =
            pay_prepare_helper(
                &mut rng,
                &mut db,
                &channel_state,
                &mut cust_state,
                10,
                &mut merch_state,
            );

        let nc = channels_mpc::NetworkConfig {
            conn_type: ConnType_NETIO,
            path: String::from("tmpsock"),
            dest_ip: String::from("127.0.0.1"),
            dest_port: 5000,
        };
        cust_state.set_network_config(nc.clone());
        merch_state.set_network_config(nc.clone());

        let db_key = "mpctest:merch_db".to_string();
        let merch_state_key = "merch_state".to_string();
        let mut mpc_child = run_mpctest_as_merchant(
            &mut db,
            &db_key,
            session_id.clone(),
            pay_mask_com,
            &channel_state,
            &merch_state_key,
            &merch_state,
        );

        // pay update for customer
        let res_cust = mpc::pay_update_customer(
            &channel_state,
            &channel_token,
            cur_state,
            new_state,
            pay_mask_com,
            rev_lock_com,
            10,
            &mut cust_state,
            ptr::null_mut(),
            None,
            None,
        );
        assert!(res_cust.is_ok());
        let mpc_result_ok = res_cust.unwrap();
        assert!(mpc_result_ok);

        // wait for mpctest to complete execution
        let ecode = mpc_child.wait().expect("failed to wait on mpctest");
        assert!(ecode.success());

        // load the updated merchant state
        let mut merch_state =
            load_merchant_state_info(&mut db.conn, &db_key, &merch_state_key).unwrap();

        // complete the rest of unlink
        complete_pay_helper(
            &mut db,
            session_id,
            rev_state,
            &channel_state,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );

        println!("cust state: {:?}", cust_state.get_current_state());
        println!("customer's channel status: {}", cust_state.protocol_status);

        assert!(cust_state.protocol_status == ProtocolStatus::Established);

        // PAY PROTOCOL
        let (session_id1, cur_state1, new_state1, rev_state1, rev_lock_com1, pay_mask_com1) =
            pay_prepare_helper(
                &mut rng,
                &mut db,
                &channel_state,
                &mut cust_state,
                200,
                &mut merch_state,
            );

        let mut mpc_child = run_mpctest_as_merchant(
            &mut db,
            &db_key,
            session_id1.clone(),
            pay_mask_com1,
            &channel_state,
            &merch_state_key,
            &merch_state,
        );

        // pay update for customer
        let res_cust = mpc::pay_update_customer(
            &channel_state,
            &channel_token,
            cur_state1,
            new_state1,
            pay_mask_com1,
            rev_lock_com1,
            200,
            &mut cust_state,
            ptr::null_mut(),
            None,
            None,
        );
        assert!(res_cust.is_ok());
        let mpc_result_ok = res_cust.unwrap();
        assert!(mpc_result_ok);

        let ecode = mpc_child.wait().expect("failed to wait on mpctest");
        assert!(ecode.success());

        // load the updated merchant state
        let merch_state_key = "merch_state".to_string();
        let mut merch_state =
            load_merchant_state_info(&mut db.conn, &db_key, &merch_state_key).unwrap();

        // complete the rest of unlink
        complete_pay_helper(
            &mut db,
            session_id1,
            rev_state1,
            &channel_state,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );

        // channel status should be Open at this point. Open -> ConfirmedClose should fail
        let res = cust_state.change_channel_status(ChannelStatus::ConfirmedClose);
        assert!(res.is_err());

        // customer initiates close tx
        let (_cust_close_signed_tx, _close_txid_be, _close_txid_le) =
            mpc::force_customer_close(&channel_state, &channel_token, true, &mut cust_state)
                .unwrap();

        assert_eq!(
            cust_state.get_channel_status(),
            ChannelStatus::CustomerInitClose
        );

        let mut escrow_txid_be = channel_token.escrow_txid.0.clone(); // originally in LE
        escrow_txid_be.reverse();
        let (_merch_close_signed_tx, _merch_txid_be, _merch_txid_le) = mpc::force_merchant_close(
            &escrow_txid_be.to_vec(),
            channel_state.get_val_cpfp(),
            &mut merch_state,
        )
        .unwrap();
        assert!(
            merch_state.get_channel_status(escrow_txid_be).unwrap()
                == ChannelStatus::MerchantInitClose
        );

        // change close status after closing transaction is detected on-chain
        let res = cust_state.change_channel_status(ChannelStatus::PendingClose);
        assert!(res.is_ok());
        assert_eq!(cust_state.get_channel_status(), ChannelStatus::PendingClose);

        // assume that timelock has passed and there was no dispute
        let res = cust_state.change_channel_status(ChannelStatus::ConfirmedClose);
        assert!(res.is_ok());
        assert_eq!(
            cust_state.get_channel_status(),
            ChannelStatus::ConfirmedClose
        );
    }

    #[test]
    fn test_unlink_fail_as_expected() {
        let mut rng = &mut rand::thread_rng();
        let mut db = RedisDatabase::new("mpctest", "redis://127.0.0.1/".to_string()).unwrap();
        db.clear_state();

        // full channel setup
        let fee_cc = 1000;
        let fee_mc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let min_threshold = 546; // dust limit
        let val_cpfp = 1000;
        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        let (channel_state, channel_token, mut cust_state, mut merch_state) =
            zkchannel_full_establish_setup_helper(&mut rng, &mut db, &tx_fee_info);

        // UNLINK PROTOCOL
        let (session_id, cur_state, new_state, _rev_state, rev_lock_com, pay_mask_com) =
            pay_prepare_helper(
                &mut rng,
                &mut db,
                &channel_state,
                &mut cust_state,
                10,
                &mut merch_state,
            );

        let nc = channels_mpc::NetworkConfig {
            conn_type: ConnType_NETIO,
            path: String::from("tmpsock"),
            dest_ip: String::from("127.0.0.1"),
            dest_port: 5000,
        };
        cust_state.set_network_config(nc.clone());
        merch_state.set_network_config(nc.clone());

        let db_key = "mpctest:merch_db".to_string();
        let merch_state_key = "merch_state".to_string();
        let mut mpc_child = run_mpctest_as_merchant(
            &mut db,
            &db_key,
            session_id,
            pay_mask_com,
            &channel_state,
            &merch_state_key,
            &merch_state,
        );

        // pay update for customer
        let res_cust = mpc::pay_update_customer(
            &channel_state,
            &channel_token,
            cur_state,
            new_state,
            [11u8; 32], // bad pay-token-mask commitment
            rev_lock_com,
            10,
            &mut cust_state,
            ptr::null_mut(),
            None,
            None,
        );
        assert!(res_cust.is_err());

        // wait for mpctest to complete execution
        let ecode = mpc_child.wait().expect("failed to wait on mpctest");
        assert!(ecode.success());

        // load the updated merchant state
        let mut merch_state =
            load_merchant_state_info(&mut db.conn, &db_key, &merch_state_key).unwrap();
        let mask = mpc::pay_confirm_mpc_result(
            &mut db as &mut dyn StateDatabase,
            session_id.clone(),
            res_cust.is_ok(),
            &mut merch_state,
        );
        assert!(mask.is_err());

        let session_id_hex = hex::encode(session_id);
        let session_state = db.load_session_state(&session_id_hex).unwrap();
        print!("Session State: {:?}\n", session_state);
        //assert!(session_state.status == PaymentStatus::Error);
    }
}
