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
extern crate sha3;
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
pub mod test_mpc;

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
    use channels_util::ProtocolStatus;
    use pairing::bls12_381::Bls12;
    use rand::Rng;
    use sha2::Digest;

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
            "[\"40d8d5ce100f7d4c7d465e68b28a9d1412fd086a5f85794bdb15334966eac95a\"]";
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
}
