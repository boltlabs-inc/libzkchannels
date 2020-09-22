extern crate ff_bl as ff;
extern crate pairing_bl as pairing;
extern crate rand;
extern crate secp256k1;
extern crate time;
extern crate zkchannels;

use pairing::bls12_381::Bls12;
use std::time::Instant;
use zkchannels::{handle_bolt_result, BoltResult};
use zkchannels::zkproofs;
use zkchannels::cl::Signature;
use zkchannels::util::encode_short_bytes_to_fr;

macro_rules! measure_one_arg {
    ($x: expr) => {{
        let s = Instant::now();
        let res = $x;
        let e = s.elapsed();
        (res, e.as_millis())
    };};
}

macro_rules! measure_two_arg {
    ($x: expr) => {{
        let s = Instant::now();
        let (res1, res2) = $x;
        let e = s.elapsed();
        (res1, res2, e.as_millis())
    };};
}

fn main() {
    println!("******************************************");
    let mut channel_state =
        zkproofs::ChannelState::<Bls12>::new(String::from("Channel A -> B"), false);
    let rng = &mut rand::thread_rng();

    let b0_customer = 150;
    let b0_merchant = 10;
    let pay_inc = 20;
    let pay_inc2 = 10;

    let (mut channel_token, mut merch_state, mut channel_state) =
        zkproofs::init_merchant(rng, &mut channel_state, "Merchant Bob");

    let mut cust_state =
        zkproofs::init_customer(rng, &mut channel_token, b0_customer, b0_merchant, "Alice");

    println!("{}", cust_state);

    // obtain close token for closing out channel
    let close_token = zkproofs::init_merchant_issue_close_token(
        rng,
        &cust_state.get_wallet(),
        &merch_state,
    );

    assert!(cust_state.verify_init_close_token(&channel_state, close_token));

    // wait for funding tx to be confirmed, etc

    // obtain payment token for pay protocol
    let pay_token =
        zkproofs::activate_merchant_issue_pay_token(rng, &cust_state.get_wallet(), &mut merch_state);
    assert!(merch_state.unlink_nonces.contains(&encode_short_bytes_to_fr::<Bls12>(cust_state.nonce.0).to_string()));
    //assert!(cust_state.verify_pay_token(&channel_state, &pay_token));

    assert!(zkproofs::activate_customer_final(
        &mut channel_state,
        &mut cust_state,
        pay_token
    ));

    let (unlink_info, unlinked_cust_state) = zkproofs::unlink_channel_customer(rng, &channel_state, &cust_state);
    let new_close_token_result = zkproofs::unlink_channel_merchant(rng, &channel_state, &unlink_info, &mut merch_state);
    let new_close_token = handle_bolt_result!(new_close_token_result).unwrap();
    let rt_pair = zkproofs::get_revoke_lock_pair(
        &channel_state,
        &mut cust_state,
        unlinked_cust_state.clone(),
        &new_close_token,
    )
        .unwrap();

    // send revoke token and get pay-token in response
    let new_pay_token_result: BoltResult<Signature<Bls12>> =
        zkproofs::verify_revoke_message(&rt_pair, &mut merch_state);
    let new_pay_token = handle_bolt_result!(new_pay_token_result);

    // verify the pay token and update internal state
    assert!(cust_state.unlink_verify_pay_token(&mut channel_state, &new_pay_token.unwrap()));
    println!("Channel established!");

    let (payment, new_cust_state, pay_time) = measure_two_arg!(zkproofs::generate_payment_proof(
        rng,
        &channel_state,
        &cust_state,
        pay_inc
    ));
    println!(">> Time to generate payment proof: {} ms", pay_time);

    let (new_close_token, verify_time) = measure_one_arg!(zkproofs::verify_payment_proof(
        rng,
        &channel_state,
        &payment,
        &mut merch_state
    ));
    println!(">> Time to verify payment proof: {} ms", verify_time);

    let rt_pair1 = zkproofs::get_revoke_lock_pair(
        &channel_state,
        &mut cust_state,
        new_cust_state,
        &new_close_token,
    )
    .unwrap();

    // send revoke token and get pay-token in response
    let new_pay_token_result = zkproofs::verify_revoke_message(&rt_pair1, &mut merch_state);
    let new_pay_token = handle_bolt_result!(new_pay_token_result);

    // verify the pay token and update internal state
    assert!(cust_state.verify_pay_token(&channel_state, &new_pay_token.unwrap()));

    println!("******************************************");

    let (payment2, new_cust_state2, pay_time2) = measure_two_arg!(
        zkproofs::generate_payment_proof(rng, &channel_state, &cust_state, pay_inc2)
    );
    println!(">> Time to generate payment proof 2: {} ms", pay_time2);

    let (new_close_token2, verify_time2) = measure_one_arg!(zkproofs::verify_payment_proof(
        rng,
        &channel_state,
        &payment2,
        &mut merch_state
    ));
    println!(">> Time to verify payment proof 2: {} ms", verify_time2);

    let rt_pair2 = zkproofs::get_revoke_lock_pair(
        &channel_state,
        &mut cust_state,
        new_cust_state2,
        &new_close_token2,
    )
    .unwrap();

    // send revoke token and get pay-token in response
    let new_pay_token_result2 = zkproofs::verify_revoke_message(&rt_pair2, &mut merch_state);
    let new_pay_token2 = handle_bolt_result!(new_pay_token_result2);

    // verify the pay token and update internal state
    assert!(cust_state.verify_pay_token(&channel_state, &new_pay_token2.unwrap()));

    println!("Final Cust state: {}", cust_state);
}
