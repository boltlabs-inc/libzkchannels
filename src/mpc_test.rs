extern crate bufstream;
extern crate rand;
extern crate redis;
extern crate secp256k1;
extern crate serde;
extern crate sha2;
extern crate structopt;
extern crate zkchan_tx;
extern crate zkchannels;

use rand::Rng;
use redis::Commands;
use serde::Deserialize;
use structopt::StructOpt;
use zkchannels::mpc;
use zkchannels::mpc::{ChannelMPCState, MerchantMPCState, NetworkConfig};
use zkchannels::database::{RedisDatabase, StateDatabase, get_file_from_db, store_file_in_db};
use zkchannels::bindings::ConnType_NETIO;

// #[derive(Clone, Debug, Deserialize)]
// enum Party {
//     MERCH,
//     CUST,
// }

// impl FromStr for Party {
//     type Err = serde_json::error::Error;
//     fn from_str(s: &str) -> Result<Party, serde_json::error::Error> {
//         Ok(serde_json::from_str(&format!("\"{}\"", s))?)
//     }
// }

macro_rules! handle_error_result {
    ($e:expr) => {
        match $e {
            Ok(val) => val,
            Err(err) => return Err(err.to_string()),
        }
    };
}

macro_rules! handle_error_with_string {
    ($e:expr, $str:tt) => {
        match $e {
            Ok(val) => val,
            Err(_err) => return Err(format!($str)),
        }
    };
}
static MERCH_STATE_KEY: &str = "merch_state";
static CHANNEL_STATE_KEY: &str = "channel_state";

fn load_merchant_state_info(
    db_conn: &mut redis::Connection,
    db_key: &String,
) -> Result<(ChannelMPCState, MerchantMPCState), String> {
    // let mut db = handle_error_result!(RedisDatabase::new("mpctest", db_url.clone()));
    // let key = String::from("cli:merch_db");

    // load the channel state from DB
    let ser_channel_state = handle_error_with_string!(
        get_file_from_db(db_conn, &db_key, &CHANNEL_STATE_KEY.to_string()),
        "Could not load the merchant channel state"
    );
    let channel_state: ChannelMPCState =
        handle_error_result!(serde_json::from_str(&ser_channel_state));

    // load the merchant state from DB
    let ser_merch_state = handle_error_with_string!(
        get_file_from_db(db_conn, &db_key, &MERCH_STATE_KEY.to_string()),
        "Could not load the merchant state DB"
    );
    let merch_state: MerchantMPCState =
        handle_error_result!(serde_json::from_str(&ser_merch_state));

    Ok((channel_state, merch_state))
}

fn save_merchant_state_info(
    db_conn: &mut redis::Connection,
    db_key: &String,
    channel_state: Option<&ChannelMPCState>,
    merch_state: &MerchantMPCState,
) -> Result<(), String> {
    // let key = String::from("cli:merch_db");
    match channel_state {
        Some(n) => {
            let channel_state_json_str = handle_error_result!(serde_json::to_string(n));
            store_file_in_db(
                db_conn,
                &db_key,
                &CHANNEL_STATE_KEY.to_string(),
                &channel_state_json_str,
            )?
        }
        None => false, // do nothing
    };

    let merch_state_json_str = handle_error_result!(serde_json::to_string(merch_state));
    store_file_in_db(
        db_conn,
        &db_key,
        &MERCH_STATE_KEY.to_string(),
        &merch_state_json_str,
    )?;
    Ok(())
}

#[derive(StructOpt, Debug)]
#[structopt(name = "mpctest")]
struct Cli {
    #[structopt(short = "k", long = "db-key")]
    db_key: String,
    #[structopt(short = "s", long = "session-id")]
    session_id: String,
    #[structopt(short = "p", long = "pay-mask-com")]
    pay_mask_com: String,
}

fn main() {

    let args = Cli::from_args();

    let db_url = "redis://127.0.0.1/".to_string(); // make constant
    let mut db = RedisDatabase::new("mpctest", db_url.clone()).unwrap();
    let db_key = args.db_key; // // String::from("mpclib3:merch_db");

    let session_id_buf = hex::decode(args.session_id).unwrap();
    let mut session_id = [0u8; 16];
    // TODO: return an error if len < 16
    session_id.copy_from_slice(session_id_buf.as_slice());
    println!("session id: {}", hex::encode(session_id));

    let pay_mask_com_buf = hex::decode(args.pay_mask_com).unwrap();
    let mut pay_mask_com = [0u8; 32];
    pay_mask_com.copy_from_slice(pay_mask_com_buf.as_slice());
    println!("pay_mask_com: {}", hex::encode(pay_mask_com));

    let (channel_state, mut merch_state) = load_merchant_state_info(&mut db.conn, &db_key).unwrap();

    println!("channel_state: {:?}", channel_state);
    // println!("merch_state: {:?}", merch_state);

    println!("executing the mpc for merchant...");
    let mut rng = &mut rand::thread_rng();

    let res_merch = mpc::pay_update_merchant(
        &mut rng,
        &mut db as &mut dyn StateDatabase,
        &channel_state,
        session_id,
        pay_mask_com,
        &mut merch_state,
    );
    assert!(res_merch.is_ok(), res_merch.err().unwrap());

    println!("MPC executed successfully");

    // save updated merch_state
    save_merchant_state_info(&mut db.conn, &db_key, None, &merch_state);
}