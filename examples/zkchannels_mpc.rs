extern crate rand;
extern crate zkchannels;
extern crate time;
extern crate secp256k1;

#[cfg(feature = "mpc-bitcoin")]
use zkchannels::mpc;
use std::time::Instant;
use zkchannels::handle_bolt_result;

macro_rules! measure_one_arg {
    ($x: expr) => {
        {
            let s = Instant::now();
            let res = $x;
            let e = s.elapsed();
            (res, e.as_millis())
        };
    }
}

macro_rules! measure_two_arg {
    ($x: expr) => {
        {
            let s = Instant::now();
            let (res1, res2) = $x;
            let e = s.elapsed();
            (res1, res2, e.as_millis())
        };
    }
}

fn main() {
    println!("******************************************");
    println!(" MPC example goes here!");
//    let mut channel_state = mpc::ChannelState::new(String::from("Channel A -> B"), false);
//    let rng = &mut rand::thread_rng();
//
//    let b0_customer = 150;
//    let b0_merchant = 10;
//    let pay_inc = 20;
//    let pay_inc2 = 10;
//
//    let (mut channel_token, mut merch_state, mut channel_state) = mpc::init_merchant(rng, &mut channel_state, "Merchant Bob");
//
//    let mut cust_state = mpc::init_customer(rng, &mut channel_token, b0_customer, b0_merchant, "Alice");
//
//    println!("{}", cust_state);

//    // lets establish the channel
//    let (com, com_proof, est_time) = measure_two_arg!(mpc::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_state));
//    println!(">> Time to generate proof for establish: {} ms", est_time);
//
//    // obtain close token for closing out channel
//    let channel_id = channel_token.compute_channel_id();
//    let option = mpc::establish_merchant_issue_close_token(rng, &channel_state, &com, &com_proof,
//                                                                                         &channel_id, b0_customer, b0_merchant, &merch_state);
//    let close_token = match option {
//        Ok(n) => n.unwrap(),
//        Err(e) => panic!("Failed - mpc::establish_merchant_issue_close_token(): {}", e)
//    };
//
//    assert!(cust_state.verify_close_token(&channel_state, &close_token));

    // wait for funding tx to be confirmed, etc
    println!("******************************************");
}
