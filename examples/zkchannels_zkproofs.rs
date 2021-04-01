extern crate ff_bl as ff;
extern crate pairing_bl as pairing;
extern crate rand;
extern crate secp256k1;
extern crate time;
extern crate zkchannels;

use pairing::bls12_381::Bls12;
use std::time::Instant;
use zkchannels::crypto::pssig::Signature;
use zkchannels::util::encode_short_bytes_to_fr;
use zkchannels::zkproofs;
use zkchannels::zkproofs::{ChannelState, CustomerState, MerchantState};
use zkchannels::{handle_bolt_result, BoltResult};

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

fn execute_pay_protocol(
    channel_state: &mut ChannelState<Bls12>,
    cust_state: &mut CustomerState<Bls12>,
    merch_state: &mut MerchantState<Bls12>,
    amount: i64,
) {
    let rng = &mut rand::thread_rng();

    let (nonce, session_id) =
        zkproofs::pay::customer_prepare(rng, &channel_state, amount, cust_state).unwrap();

    assert!(zkproofs::pay::merchant_prepare(
        &session_id,
        nonce,
        amount,
        &String::from(""),
        merch_state
    ));

    let (payment, new_cust_state, pay_time) = measure_two_arg!(
        zkproofs::pay::customer_update_state(rng, &channel_state, &cust_state, amount)
    );
    println!(">> Time to generate payment proof: {} ms", pay_time);

    let (new_close_token, verify_time) = measure_one_arg!(zkproofs::pay::merchant_update_state(
        rng,
        &channel_state,
        &session_id,
        &payment,
        merch_state
    ));
    println!(">> Time to verify payment proof: {} ms", verify_time);

    let rt_pair1 = zkproofs::pay::customer_unmask(
        &channel_state,
        cust_state,
        new_cust_state,
        &new_close_token,
    )
    .unwrap();

    // send revoke token and get pay-token in response
    let new_pay_token_result =
        zkproofs::pay::merchant_validate_rev_lock(&session_id, &rt_pair1, merch_state);
    let new_pay_token = handle_bolt_result!(new_pay_token_result);

    // verify the pay token and update internal state
    assert!(zkproofs::pay::customer_unmask_pay_token(
        new_pay_token.unwrap().0,
        &channel_state,
        cust_state
    )
    .unwrap());
}

fn main() {
    println!("******************************************");
    let mut channel_state =
        zkproofs::ChannelState::<Bls12>::new(String::from("Direct channel A -> B"));
    let rng = &mut rand::thread_rng();

    let b0_customer = 150;
    let b0_merchant = 10;

    let (mut channel_token, mut merch_state) =
        zkproofs::merchant_init(rng, &mut channel_state, "Merchant Bob");

    let mut cust_state =
        zkproofs::customer_init(rng, &mut channel_token, b0_customer, b0_merchant, "Alice");

    println!("{}", cust_state);

    // obtain close token for closing out channel
    let init_state = zkproofs::get_initial_state(&cust_state);
    let close_token = zkproofs::validate_channel_params(rng, &init_state, &merch_state);

    assert!(
        zkproofs::customer_mark_open_channel(close_token, &mut channel_state, &mut cust_state)
            .unwrap()
    );
    // TODO: generate test escrow tx here then call merchant_mark_open_channel()

    // wait for funding tx to be confirmed, etc

    // obtain payment token for pay protocol
    let init_state = zkproofs::activate::customer_init(&cust_state).unwrap();
    let pay_token = zkproofs::activate::merchant_init(rng, &init_state, &mut merch_state);
    assert!(merch_state
        .unlink_nonces
        .contains(&encode_short_bytes_to_fr::<Bls12>(cust_state.nonce.0).to_string()));

    assert!(zkproofs::activate::customer_finalize(
        &mut channel_state,
        &mut cust_state,
        pay_token
    ));

    // start unlink phase
    let (session_id, unlink_payment, unlinked_cust_state) =
        zkproofs::unlink::customer_update_state(rng, &channel_state, &cust_state);
    let new_close_token_result = zkproofs::unlink::merchant_update_state(
        rng,
        &channel_state,
        &session_id,
        &unlink_payment,
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
    let new_pay_token_result: BoltResult<(Signature<Bls12>, String)> =
        zkproofs::unlink::merchant_validate_rev_lock(&session_id, &rt_pair, &mut merch_state);
    let new_pay_token = handle_bolt_result!(new_pay_token_result);

    // verify the pay token and update internal state
    let is_ok = zkproofs::unlink::customer_finalize(
        &mut channel_state,
        &mut cust_state,
        new_pay_token.unwrap().0,
    );
    assert!(is_ok);

    println!("Channel unlinked and established!");

    // execute pay protocol
    let pay_amount1 = 10;
    let pay_amount2 = 20;
    println!("Customer makes first payment: {}", pay_amount1);
    execute_pay_protocol(
        &mut channel_state,
        &mut cust_state,
        &mut merch_state,
        pay_amount1,
    );
    println!("******************************************");

    println!("Customer makes second payment: {}", pay_amount2);
    execute_pay_protocol(
        &mut channel_state,
        &mut cust_state,
        &mut merch_state,
        pay_amount2,
    );
    println!("******************************************");

    println!("Final Cust state: {}", cust_state);
}
