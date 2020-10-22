#![allow(unused_imports)] // TODO: clean up/remove
#![allow(unused_variables)]
#![allow(unused_must_use)]

extern crate bufstream;
extern crate confy;
extern crate ff_bl as ff;
extern crate libc;
extern crate pairing_bl as pairing;
extern crate rand;
extern crate redis;
extern crate secp256k1;
extern crate serde;
extern crate sha2;
extern crate structopt;
extern crate zkchan_tx;
extern crate zkchannels;

use bufstream::BufStream;
use ff::PrimeField;
use libc::{c_int, c_void};
use pairing::bls12_381::Bls12;
use pairing::CurveProjective;
use pairing::{
    bls12_381::{Fr, G1Uncompressed, G2Uncompressed, G1, G2},
    EncodedPoint,
};
use rand::Rng;
use redis::Commands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::str::FromStr;
use std::thread::sleep;
use std::time;
use structopt::StructOpt;
use zkchan_tx::fixed_size_array::FixedSizeArray16;
use zkchannels::cl;
use zkchannels::database::create_db_connection;
use zkchannels::database::{RedisDatabase, StateDatabase};
use zkchannels::zkproofs;
use zkchannels::zkproofs::TransactionFeeInfo;
use zkchannels::FundingTxInfo;

static TX_FEE_INFO_KEY: &str = "tx_fee_info";

macro_rules! handle_error_result {
    ($e:expr) => {
        match $e {
            Ok(val) => val,
            Err(err) => return Err(err.to_string()),
        }
    };
}

macro_rules! handle_option_result {
    ($e:expr) => {
        match $e {
            Ok(val) => val,
            Err(_) => None,
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

macro_rules! print_error_result {
    ($e:expr) => {
        match $e {
            Ok(val) => val,
            Err(err) => println!("{}", err.to_string()),
        }
    };
}

macro_rules! log {
    ($e:expr, $x:expr) => {
        match $x {
            true => println!($e),
            false => (),
        }
    };
}

macro_rules! create_connection {
    ($e: expr) => {
        &mut Conn::new($e.own_ip, $e.own_port, $e.other_ip, $e.other_port)
    };
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ZKChannelConfig {
    version: u8,
    db_url: String,
    // set_fees: bool,
}

impl Default for ZKChannelConfig {
    fn default() -> Self {
        ZKChannelConfig {
            version: 0,
            db_url: "redis://127.0.0.1/".to_string(),
            // set_fees: false,
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
enum Party {
    MERCH,
    CUST,
}

impl FromStr for Party {
    type Err = serde_json::error::Error;
    fn from_str(s: &str) -> Result<Party, serde_json::error::Error> {
        Ok(serde_json::from_str(&format!("\"{}\"", s))?)
    }
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct SetFees {
    #[structopt(short = "d", long = "bal-min-cust", default_value = "100")]
    bal_min_cust: i64,
    #[structopt(short = "e", long = "bal-min-merch", default_value = "100")]
    bal_min_merch: i64,
    #[structopt(short = "c", long = "fee-cc", default_value = "10")]
    fee_cc: i64,
    #[structopt(short = "m", long = "fee-mc", default_value = "10")]
    fee_mc: i64,
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct Open {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(short = "c", long = "cust-bal", default_value = "0")]
    cust_bal: i64,
    #[structopt(short = "m", long = "merch-bal", default_value = "0")]
    merch_bal: i64,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String,
    #[structopt(short = "n", long = "channel-name", default_value = "")]
    channel_name: String,
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct Init {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(short = "a", long = "input-amount")]
    input_amount: Option<i64>,
    #[structopt(short = "o", long = "output-amount")]
    output_amount: Option<i64>,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String,
    #[structopt(short = "n", long = "channel-name", default_value = "")]
    channel_name: String,
    // TODO: revisit
    #[structopt(long = "txid")]
    txid: Option<String>,
    #[structopt(long = "index")]
    index: Option<u32>,
    #[structopt(short = "f", long = "tx-fee", default_value = "10")]
    tx_fee: i64,
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct Activate {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String,
    #[structopt(short = "n", long = "channel-name", default_value = "")]
    channel_name: String,
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct Unlink {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String,
    #[structopt(short = "n", long = "channel-name", default_value = "")]
    channel_name: String,
    #[structopt(short)]
    verbose: bool,
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct Pay {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(short = "a", long = "amount", allow_hyphen_values = true)]
    amount: Option<i64>,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String,
    #[structopt(short = "n", long = "channel-name", default_value = "")]
    channel_name: String,
    #[structopt(short)]
    verbose: bool,
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct Close {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(short = "c", long = "cust-close")]
    cust_close: Option<PathBuf>,
    #[structopt(short = "f", long = "file")]
    file: PathBuf,
    #[structopt(short = "e", long = "from-merch")]
    from_merch_close: bool,
    #[structopt(short = "n", long = "channel-id", default_value = "")]
    channel_id: String,
    #[structopt(short = "d", long = "decompress-cust-close")]
    decompress: bool,
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub enum Command {
    #[structopt(name = "setfees")] // for setting transaction fees for zkchannels
    SETFEES(SetFees),
    #[structopt(name = "open")] // for initializing channel state and cust/merch state
    OPEN(Open),
    #[structopt(name = "init")] // for creating/signing txs between cust/merch
    INIT(Init),
    #[structopt(name = "activate")] // for activating channel
    ACTIVATE(Activate),
    #[structopt(name = "unlink")] // for unlinking channel
    UNLINK(Unlink),
    #[structopt(name = "pay")] // for making a payment on an existing channel
    PAY(Pay),
    #[structopt(name = "close")] // for generating closing txs
    CLOSE(Close),
}

impl FromStr for Command {
    type Err = serde_json::error::Error;
    fn from_str(s: &str) -> Result<Command, serde_json::error::Error> {
        Ok(serde_json::from_str(&format!("\"{}\"", s))?)
    }
}

pub fn get_merch_db_connection(db_url: String) -> Result<RedisDatabase, String> {
    return RedisDatabase::new("cli", db_url);
}

pub fn read_file(file_name: &'static str) -> Result<String, String> {
    let mut file = match File::open(file_name) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };
    let mut content = String::new();
    let content_len = match file.read_to_string(&mut content) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };
    assert!(content_len > 0);
    Ok(content)
}

pub fn read_pathfile(path_buf: PathBuf) -> Result<String, String> {
    let mut file = match File::open(path_buf) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };
    let mut content = String::new();
    let content_len = match file.read_to_string(&mut content) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };
    assert!(content_len > 0);
    Ok(content)
}

pub fn write_file(file_name: &'static str, content: String) -> Result<(), String> {
    let mut file = match File::create(file_name) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };
    match file.write_all(content.as_ref()) {
        Ok(n) => Ok(n),
        Err(e) => return Err(e.to_string()),
    }
}

pub fn write_pathfile(path_buf: PathBuf, content: String) -> Result<(), String> {
    let mut file = match File::create(path_buf) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };
    match file.write_all(content.as_ref()) {
        Ok(n) => Ok(n),
        Err(e) => return Err(e.to_string()),
    }
}

pub fn generate_keypair<R: Rng>(csprng: &mut R) -> (secp256k1::PublicKey, secp256k1::SecretKey) {
    let secp = secp256k1::Secp256k1::new();

    let mut seckey = [0u8; 32];
    csprng.fill_bytes(&mut seckey);

    // generate the signing keypair for the channel
    let sk = secp256k1::SecretKey::from_slice(&seckey).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    (pk, sk)
}

pub fn connect_db(url: String) -> Result<redis::Connection, String> {
    let conn = match create_db_connection(url) {
        Ok(c) => c,
        Err(e) => return Err(e.to_string()),
    };

    Ok(conn)
}

pub fn store_file_in_db(
    conn: &mut redis::Connection,
    key: &String,
    field_name: &String,
    json_blob: &String,
) -> Result<bool, String> {
    match conn.hset::<String, String, String, i32>(
        key.clone(),
        field_name.clone(),
        json_blob.clone(),
    ) {
        Ok(s) => Ok(s != 0),
        Err(e) => return Err(e.to_string()),
    }
}

pub fn get_file_from_db(
    conn: &mut redis::Connection,
    key: &String,
    field_name: &String,
) -> Result<String, String> {
    match conn.hget::<String, String, String>(key.clone(), field_name.clone()) {
        Ok(s) => Ok(s),
        Err(e) => return Err(e.to_string()),
    }
}

fn get_tx_fee_info() -> TransactionFeeInfo {
    let min_threshold = 100;
    let tx_fee_info = TransactionFeeInfo {
        bal_min_cust: min_threshold,
        bal_min_merch: min_threshold,
        fee_cc: 10,
        fee_mc: 10,
    };
    return tx_fee_info;
}

pub fn load_tx_fee_info(db_conn: &mut redis::Connection) -> Result<TransactionFeeInfo, String> {
    let key = String::from("cli:tx_fee");

    // load the channel state from DB
    let ser_tx_fee_info = handle_error_with_string!(
        get_file_from_db(db_conn, &key, &TX_FEE_INFO_KEY.to_string()),
        "could not load the tx fee info"
    );
    let tx_fee_info: TransactionFeeInfo = handle_error_with_string!(
        serde_json::from_str(&ser_tx_fee_info),
        "tx fee info json string is malformed"
    );

    return Ok(tx_fee_info);
}

pub fn store_tx_fee_info(db_url: String, tx_fee_info: &TransactionFeeInfo) -> Result<(), String> {
    let mut db = handle_error_result!(get_merch_db_connection(db_url));
    let key = String::from("cli:tx_fee");

    let tx_fee_info_str = handle_error_result!(serde_json::to_string(tx_fee_info));
    store_file_in_db(
        &mut db.conn,
        &key,
        &TX_FEE_INFO_KEY.to_string(),
        &tx_fee_info_str,
    )?;
    Ok(())
}

#[derive(StructOpt, Debug)]
#[structopt(name = "zkchannels-cli")]
struct Cli {
    #[structopt(
        subcommand,
        help = "Options: open, init, activate, unlink, pay, or close"
    )]
    command: Command,
}

pub struct Conn {
    pub in_addr: SocketAddr,
    pub out_addr: SocketAddr,
    pub own_port: i32,
    pub other_port: i32,
}

impl Conn {
    pub fn new(own_ip: String, own_port: String, other_ip: String, other_port: String) -> Conn {
        let in_addr = own_ip + ":" + own_port.as_ref();
        let in_addr_sock = SocketAddr::from_str(in_addr.as_ref()).unwrap();
        let own_p = own_port.parse().unwrap_or(0);

        let out_addr = other_ip + ":" + other_port.as_ref();
        let out_addr_sock = SocketAddr::from_str(out_addr.as_ref()).unwrap();
        let other_p = other_port.parse().unwrap_or(0);

        Conn {
            in_addr: in_addr_sock,
            out_addr: out_addr_sock,
            own_port: own_p,
            other_port: other_p,
        }
    }

    pub fn send(&mut self, msg: &[String]) {
        for i in 1..6 {
            match TcpStream::connect(self.out_addr) {
                Ok(stream) => {
                    let mut buf_stream = BufStream::new(stream);
                    for msg0 in msg {
                        buf_stream.write((msg0.to_owned() + "\n").as_ref()).unwrap();
                    }
                    buf_stream.write(b"end\n").unwrap();
                    buf_stream.flush().unwrap();
                    return;
                }
                Err(e) => {
                    println!("Failed to connect, try: {}, error: {}", i, e);
                    let duration = time::Duration::from_secs(5);
                    sleep(duration)
                }
            }
        }
    }

    pub fn send_and_wait(
        &mut self,
        msg: &[String],
        label: Option<String>,
        verbose: bool,
    ) -> Vec<String> {
        self.send(msg);
        self.wait_for(label, verbose)
    }

    pub fn wait_for(&mut self, label: Option<String>, verbose: bool) -> Vec<String> {
        let listener = TcpListener::bind(self.in_addr).unwrap();
        let mut out: Vec<String> = vec![];

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let mut buf_stream = BufStream::new(stream);
                    loop {
                        let mut reads = String::new();
                        buf_stream.read_line(&mut reads).unwrap();
                        if reads == "end\n" {
                            if verbose && label.is_some() {
                                println!("{}: {:?}", label.unwrap(), out);
                            }
                            return out;
                        }
                        if reads != "" {
                            reads.pop();
                            out.push(reads);
                        }
                    }
                }
                Err(err) => println!("Not good: {:?}", err),
            }
        }

        out
    }
}

fn main() -> Result<(), confy::ConfyError> {
    let args = Cli::from_args();
    let cfg: ZKChannelConfig = confy::load("zkchannel_cfg")?;
    // println!("Loaded config: {:#?}", cfg);
    let db_url = cfg.db_url.clone();

    println!("******************************************");

    match args.command {
        Command::SETFEES(setfees) => {
            let tx_fee_info = TransactionFeeInfo {
                bal_min_cust: setfees.bal_min_cust,
                bal_min_merch: setfees.bal_min_merch,
                fee_cc: setfees.fee_cc,
                fee_mc: setfees.fee_mc,
            };
            println!("{}", tx_fee_info);
            print_error_result!(store_tx_fee_info(db_url, &tx_fee_info));
            // TODO: integrate setting tx fees and other config items
            // confy::store("zkchannel_cfg", &cfg)?;
        }
        Command::OPEN(open) => match open.party {
            Party::MERCH => match merch::open(&cfg, create_connection!(open), &db_url) {
                Err(e) => println!("Channel opening phase failed with error: {}", e),
                _ => (),
            },
            Party::CUST => {
                match cust::open(
                    create_connection!(open),
                    &db_url,
                    open.cust_bal,
                    open.merch_bal,
                    open.channel_name,
                ) {
                    Err(e) => println!("Channel opening phase failed with error: {}", e),
                    _ => (),
                }
            }
        },
        Command::INIT(init) => match init.party {
            Party::MERCH => match merch::init(create_connection!(init), &db_url) {
                Err(e) => println!("Initialize phase failed with error: {}", e),
                _ => (),
            },
            Party::CUST => match cust::init(
                create_connection!(init),
                &db_url,
                init.txid,
                init.index,
                init.input_amount.unwrap(),
                init.output_amount.unwrap(),
                init.tx_fee,
                init.channel_name,
            ) {
                Err(e) => println!("Initialize phase failed with error: {}", e),
                _ => (),
            },
        },
        Command::ACTIVATE(activate) => match activate.party {
            Party::MERCH => merch::activate(create_connection!(activate), &db_url).unwrap(),
            Party::CUST => {
                cust::activate(create_connection!(activate), &db_url, activate.channel_name)
                    .unwrap()
            }
        },
        Command::UNLINK(unlink) => match unlink.party {
            Party::MERCH => {
                println!("Merchant running unlink...");
                let merch_state_info = merch::load_merchant_state_info(&db_url);
                let (mut channel_state, mut merch_state) = match merch_state_info {
                    Ok(n) => (n.0, n.2),
                    Err(e) => panic!("ERROR: {}", e.to_string()),
                };
                merch::unlink(
                    create_connection!(unlink),
                    &db_url,
                    &mut channel_state,
                    &mut merch_state,
                )
                .unwrap()
            }
            Party::CUST => cust::unlink(
                create_connection!(unlink),
                &db_url,
                unlink.channel_name,
                unlink.verbose,
            )
            .unwrap(),
        },
        Command::PAY(pay) => match pay.party {
            Party::MERCH => {
                let (mut channel_state, _, mut merch_state) =
                    merch::load_merchant_state_info(&db_url).unwrap();
                loop {
                    match merch::pay(
                        pay.amount.clone(),
                        create_connection!(pay.clone()),
                        &db_url,
                        &mut channel_state,
                        &mut merch_state,
                    ) {
                        Err(e) => println!("Pay phase failed with error: {}", e),
                        _ => (),
                    }
                }
            }
            Party::CUST => {
                match cust::pay(
                    pay.amount.unwrap(),
                    create_connection!(pay),
                    &db_url,
                    pay.channel_name,
                    pay.verbose,
                ) {
                    Err(e) => println!("Pay protocol failed with error: {}", e),
                    _ => (),
                }
            }
        },
        Command::CLOSE(close) => match close.party {
            Party::MERCH => print_error_result!(merch::close(
                &db_url,
                close.cust_close,
                close.file,
                close.channel_id
            )),
            Party::CUST => print_error_result!(cust::close(
                &db_url,
                close.file,
                close.from_merch_close,
                close.channel_id,
                close.decompress
            )),
        },
    }

    println!("******************************************");
    Ok(())
}

mod cust {
    use super::*;
    use pairing::bls12_381::Bls12;
    use zkchannels::channels_zk::{ChannelState, ChannelToken, CustomerState};

    pub fn open(
        conn: &mut Conn,
        db_url: &String,
        b0_cust: i64,
        b0_merch: i64,
        channel_name: String,
    ) -> Result<(), String> {
        if channel_name == "" {
            return Err(String::from("missing channel-name"));
        }

        // TODO: send the initial balances to merchant to check if it's acceptable
        let rng = &mut rand::thread_rng();
        let mut db_conn = handle_error_result!(create_db_connection(db_url.clone()));

        let tx_fee_info = handle_error_result!(load_tx_fee_info(&mut db_conn));

        println!("Waiting for merchant's channel_state and channel_token...");
        let msg0 = conn.wait_for(None, false);
        let channel_state: ChannelState<Bls12> =
            serde_json::from_str(&msg0.get(0).unwrap()).unwrap();
        let mut channel_token: ChannelToken<Bls12> =
            serde_json::from_str(&msg0.get(1).unwrap()).unwrap();

        // now we can initialize the customer state with the initial balances
        let cust_state = zkproofs::customer_init(
            rng,
            &mut channel_token,
            b0_cust,
            b0_merch,
            channel_name.as_str(),
        );

        println!("Saving the initial customer state...");
        cust_save_state_in_db(
            &mut db_conn,
            channel_name,
            Some(channel_state),
            Some(channel_token),
            cust_state,
        )
    }

    pub fn init(
        conn: &mut Conn,
        db_url: &String,
        _txid: Option<String>,
        _index: Option<u32>,
        input_amount: i64,
        output_amount: i64,
        tx_fee: i64,
        channel_name: String,
    ) -> Result<(), String> {
        if channel_name == "" {
            return Err(String::from("missing channel-name"));
        }

        let rng = &mut rand::thread_rng();
        let mut db_conn = handle_error_result!(create_db_connection(db_url.clone()));
        let key = format!("id:{}", channel_name);
        let tx_fee_info = get_tx_fee_info();

        // load the customer state from DB
        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let ser_cust_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &cust_state_key));
        let mut cust_state: CustomerState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        // load the channel state from DB
        let channel_state_key = format!("cust:{}:channel_state", channel_name);
        let ser_channel_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_state_key));
        let mut channel_state: ChannelState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the channel token from DB
        let channel_token_key = format!("cust:{}:channel_token", channel_name);
        let ser_channel_token =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_token_key));
        let channel_token: ChannelToken<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        println!("Channel token: {}", &channel_token.compute_channel_id());

        // now sign the customer's initial closing txs
        log!("Verified the closing token...", true);
        // get the initial customer state
        let init_state = zkproofs::get_initial_state(&cust_state);

        // prepare and send
        let msg2 = [handle_error_result!(serde_json::to_string(&init_state))];
        let msg3 = conn.send_and_wait(&msg2, None, false);

        let init_close_token: cl::Signature<Bls12> =
            handle_error_result!(serde_json::from_str(&msg3.get(0).unwrap()));
        let got_close_token = true; // handle the serde_json unwrapping

        if got_close_token {
            // if broadcast successful, then we can mark the channel as open
            handle_error_result!(zkproofs::customer_mark_open_channel(
                init_close_token,
                &mut channel_state,
                &mut cust_state
            ));

            cust_save_state_in_db(
                &mut db_conn,
                channel_name,
                Some(channel_state),
                Some(channel_token),
                cust_state,
            )?;
        }

        log!("Can now proceed with channel funding", true);
        Ok(())
    }

    pub fn activate(conn: &mut Conn, db_url: &String, channel_name: String) -> Result<(), String> {
        // let rng = &mut rand::thread_rng();
        let mut db_conn = handle_error_result!(create_db_connection(db_url.clone()));
        let key = format!("id:{}", channel_name);

        // load the channel state
        let channel_state_key = format!("cust:{}:channel_state", channel_name);
        let ser_channel_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_state_key));
        let mut channel_state: ChannelState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the customer state from DB
        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let ser_cust_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &cust_state_key));
        let mut cust_state: CustomerState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        // load the channel token from DB
        let channel_token_key = format!("cust:{}:channel_token", channel_name);
        let ser_channel_token =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_token_key));
        let channel_token: ChannelToken<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        // retrieve the initial state and check we are ready for activate phase
        let s0 = handle_error_result!(zkproofs::activate::customer_init(&cust_state));

        // send the channel token and initial state
        let msg1 = [
            handle_error_result!(serde_json::to_string(&channel_token)),
            handle_error_result!(serde_json::to_string(&s0)),
        ];
        println!("Sending channel token and state (s0)");
        let msg2 = conn.send_and_wait(&msg1, None, false);

        let pay_token: cl::Signature<Bls12> = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        println!("Obtained pay token (p0): {}", pay_token);
        let res =
            zkproofs::activate::customer_finalize(&mut channel_state, &mut cust_state, pay_token);
        if !res {
            return Err(String::from("Failed to verify pay token!"));
        }

        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let cust_state_json_str = handle_error_result!(serde_json::to_string(&cust_state));
        store_file_in_db(&mut db_conn, &key, &cust_state_key, &cust_state_json_str)?;

        Ok(())
    }

    pub fn unlink(
        conn: &mut Conn,
        db_url: &String,
        channel_name: String,
        verbose: bool,
    ) -> Result<(), String> {
        let rng = &mut rand::thread_rng();
        let mut db_conn = handle_error_result!(create_db_connection(db_url.clone()));
        let key = format!("id:{}", channel_name);

        // load the channel state from DB
        let channel_state_key = format!("cust:{}:channel_state", channel_name);
        let ser_channel_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_state_key));
        let mut channel_state: ChannelState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the customer state from DB
        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let ser_cust_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &cust_state_key));
        let mut cust_state: CustomerState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        let (session_id, unlink_payment, unlinked_cust_state) =
            zkproofs::unlink::customer_update_state(rng, &channel_state, &cust_state);

        // send to merchant
        let session_id_str = hex::encode(&session_id);
        let unlink_payment_str = handle_error_result!(serde_json::to_string(&unlink_payment));

        let msg = [session_id_str, unlink_payment_str];
        let msg1 = conn.send_and_wait(
            &msg,
            Some(String::from(
                "Sent session id, unlink payment and waiting for new close token",
            )),
            true,
        );
        let ser_close_token = msg1.get(0).unwrap();
        let new_close_token = handle_error_result!(serde_json::from_str(&ser_close_token));

        let revoked_state = handle_error_result!(zkproofs::unlink::customer_unmask(
            &channel_state,
            &mut cust_state,
            unlinked_cust_state,
            &new_close_token,
        ));
        let revoked_state_str = handle_error_result!(serde_json::to_string(&revoked_state));

        let msg2 = [revoked_state_str];
        let msg3 = conn.send_and_wait(
            &msg2,
            Some(String::from(
                "Sent revoked state and waiting for new pay token",
            )),
            true,
        );
        let ser_pay_token = msg3.get(0).unwrap();
        let new_pay_token = handle_error_result!(serde_json::from_str(&ser_pay_token));

        // verify the pay token and update internal state
        let is_ok =
            zkproofs::unlink::customer_finalize(&mut channel_state, &mut cust_state, new_pay_token);
        let msg4 = [handle_error_result!(serde_json::to_string(&is_ok))];
        conn.send(&msg4);

        if !is_ok {
            return Err(String::from("Unlink phase FAILED!"));
        }
        println!("Unlink phase successful!");
        cust_save_state_in_db(
            &mut db_conn,
            channel_name,
            Some(channel_state),
            None,
            cust_state,
        )
    }

    pub fn pay(
        amount: i64,
        conn: &mut Conn,
        db_url: &String,
        channel_name: String,
        verbose: bool,
    ) -> Result<(), String> {
        let rng = &mut rand::thread_rng();
        let mut db_conn = handle_error_result!(create_db_connection(db_url.clone()));
        let key = format!("id:{}", channel_name);

        // load the channel state from DB
        let channel_state_key = format!("cust:{}:channel_state", channel_name);
        let ser_channel_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_state_key));
        let channel_state: ChannelState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the customer state from DB
        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let ser_cust_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &cust_state_key));
        let mut cust_state: CustomerState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        // step 1 - customer prepare
        let (nonce, session_id) = handle_error_result!(zkproofs::pay::customer_prepare(
            rng,
            &channel_state,
            amount,
            &cust_state
        ));

        let session_id_str = hex::encode(&session_id);
        let nonce_str = hex::encode(&nonce);
        let amount_str = hex::encode(amount.to_be_bytes());
        let msg0 = [session_id_str, nonce_str, amount_str];
        let msg1 = conn.send_and_wait(
            &msg0,
            Some(String::from("Reveal nonce and confirm payment request")),
            true,
        );

        let is_ok: bool = serde_json::from_str(msg1.get(0).unwrap()).unwrap();

        if !is_ok {
            return Err(String::from("oops, payment request was rejected!"));
        }

        // step 2 - customer update state
        let (payment, new_cust_state) =
            zkproofs::pay::customer_update_state(rng, &channel_state, &cust_state, amount);

        // send to merchant
        let payment_str = handle_error_result!(serde_json::to_string(&payment));

        let msg2 = [payment_str];
        let msg3 = conn.send_and_wait(
            &msg2,
            Some(String::from(
                "Sent session id & payment and waiting for new close token",
            )),
            true,
        );
        let ser_close_token = msg3.get(0).unwrap();
        let new_close_token = handle_error_result!(serde_json::from_str(&ser_close_token));
        log!("[!] got an updated close token!", verbose);

        // step 3 - customer unmasks the previous state
        let revoked_state = handle_error_result!(zkproofs::pay::customer_unmask(
            &channel_state,
            &mut cust_state,
            new_cust_state,
            &new_close_token,
        ));
        let revoked_state_str = handle_error_result!(serde_json::to_string(&revoked_state));
        log!("[!] unmasking by sending revoked state!", verbose);

        let msg2 = [revoked_state_str];
        let msg3 = conn.send_and_wait(
            &msg2,
            Some(String::from(
                "Sent revoked state and waiting for new pay token",
            )),
            true,
        );
        let ser_pay_token = msg3.get(0).unwrap();
        let new_pay_token = handle_error_result!(serde_json::from_str(&ser_pay_token));
        log!("[!] now we have an updated pay token!", verbose);

        // step 4 - verify the pay token and update internal state
        let got_pay_token = handle_error_result!(zkproofs::pay::customer_unmask_pay_token(
            new_pay_token,
            &channel_state,
            &mut cust_state
        ));

        let msg4 = [handle_error_result!(serde_json::to_string(&got_pay_token))];
        conn.send(&msg4);
        log!(
            "[!] sent status result for if we have a valid pay token",
            verbose
        );

        if !got_pay_token {
            return Err(String::from(
                "Could not obtain a new pay token for future payments!",
            ));
        }
        cust_save_state_in_db(
            &mut db_conn,
            channel_name,
            Some(channel_state),
            None,
            cust_state,
        );

        log!("[!] pay run successful!", verbose);
        Ok(())
    }

    pub fn close(
        db_url: &String,
        out_file: PathBuf,
        from_merch_close: bool,
        channel_id: String,
        decompress_cust_close: bool,
    ) -> Result<(), String> {
        let mut db_conn = handle_error_result!(create_db_connection(db_url.clone()));
        let key = format!("id:{}", channel_id);

        // load the channel state from DB
        let channel_state_key = format!("cust:{}:channel_state", channel_id);
        let ser_channel_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_state_key));
        let channel_state: ChannelState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the customer state from DB
        let cust_state_key = format!("cust:{}:cust_state", channel_id);
        let ser_cust_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &cust_state_key));
        let cust_state: CustomerState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        // load the channel token from DB
        let channel_token_key = format!("cust:{}:channel_token", channel_id);
        let ser_channel_token =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_token_key));
        let channel_token: ChannelToken<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        let cust_close =
            handle_error_result!(zkproofs::force_customer_close(&channel_state, &cust_state));

        // if decompress enabled
        if decompress_cust_close {
            let cp = channel_state.cp.unwrap();
            let mut merch_pk_map = HashMap::new();
            let mut message_map = HashMap::new();
            let mut signature_map = HashMap::new();
            // let mut y_partial_prod_map = HashMap::new();
            // let mut l_partial_prod_map = HashMap::new();

            // encode the merch public key
            let g2 = G2Uncompressed::from_affine(cp.pub_params.mpk.g2.into_affine());
            let x2 = G2Uncompressed::from_affine(cp.pub_params.pk.X2.into_affine());

            // encode the signature
            let s1 = G1Uncompressed::from_affine(cust_close.merch_signature.h.into_affine());
            let s2 = G1Uncompressed::from_affine(cust_close.merch_signature.H.into_affine());

            merch_pk_map.insert("g2".to_string(), hex::encode(&g2));
            merch_pk_map.insert("X".to_string(), hex::encode(&x2));
            let l = cp.pub_params.pk.Y2.len();
            for i in 0..l {
                let key = format!("Y{}", i);
                let y = G2Uncompressed::from_affine(cp.pub_params.pk.Y2[i].into_affine());
                merch_pk_map.insert(key, hex::encode(&y));
            }

            signature_map.insert("s1".to_string(), hex::encode(&s1));
            signature_map.insert("s2".to_string(), hex::encode(&s2));

            message_map.insert(
                "channel_id",
                format!("{}", cust_close.message.channelId.into_repr()),
            );
            message_map.insert(
                "rev_lock",
                format!("{}", cust_close.message.rev_lock.into_repr()),
            );
            message_map.insert("cust_bal", cust_close.message.bc.to_string());
            message_map.insert("merch_bal", cust_close.message.bm.to_string());

            // for i in 0..cust_close.pp.Ys.len() {
            //     let key = format!("Ys{}", i);
            //     let y = G2Uncompressed::from_affine(cust_close.pp.Ys[i].into_affine());
            //     y_partial_prod_map.insert(key, hex::encode(&y));
            // }

            // for i in 0..cust_close.pp.Ls.len() {
            //     let key = format!("Ls{}", i);
            //     let y = G2Uncompressed::from_affine(cust_close.pp.Ls[i].into_affine());
            //     l_partial_prod_map.insert(key, hex::encode(&y));
            // }

            let json = [
                "{\"merch_pk\":",
                serde_json::to_string(&merch_pk_map).unwrap().as_str(),
                ", \"message\":",
                serde_json::to_string(&message_map).unwrap().as_str(),
                ", \"signature\":",
                serde_json::to_string(&signature_map).unwrap().as_str(),
                // ", \"y_partial_product\":",
                // serde_json::to_string(&y_partial_prod_map).unwrap().as_str(),
                // ", \"l_partial_product\":",
                // serde_json::to_string(&l_partial_prod_map).unwrap().as_str(),
                "}",
            ]
            .concat();
            let output_str = String::from(json);
            // println!("decompressed cust close json => \n{}\n", output_str);
            write_pathfile(out_file, output_str)?;
        } else {
            println!("Obtained the channel close message:");
            println!("current_state =>\n{}\n", cust_close.message);
            println!("close_token =>\n{}\n", cust_close.merch_signature);
            println!("cust_sig =>\n{}\n", cust_close.cust_signature);

            // write out to a file
            let cust_close_json_str = handle_error_result!(serde_json::to_string(&cust_close));
            write_pathfile(out_file, cust_close_json_str)?;
        }
        Ok(())
    }

    fn cust_save_state_in_db(
        db_conn: &mut redis::Connection,
        channel_name: String,
        channel_state_option: Option<ChannelState<Bls12>>,
        channel_token_option: Option<ChannelToken<Bls12>>,
        cust_state: CustomerState<Bls12>,
    ) -> Result<(), String> {
        let key = format!("id:{}", channel_name);

        match channel_state_option {
            Some(channel_state) => {
                let channel_state_key = format!("cust:{}:channel_state", channel_name);
                let channel_state_json_str =
                    handle_error_result!(serde_json::to_string(&channel_state));
                store_file_in_db(db_conn, &key, &channel_state_key, &channel_state_json_str)?;
            }
            None => (),
        };

        match channel_token_option {
            Some(channel_token) => {
                let channel_token_key = format!("cust:{}:channel_token", channel_name);
                let channel_token_json_str =
                    handle_error_result!(serde_json::to_string(&channel_token));
                store_file_in_db(db_conn, &key, &channel_token_key, &channel_token_json_str)?;
            }
            None => (),
        };
        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let cust_state_json_str = handle_error_result!(serde_json::to_string(&cust_state));
        store_file_in_db(db_conn, &key, &cust_state_key, &cust_state_json_str)?;
        Ok(())
    }
}

mod merch {
    use super::*;
    use pairing::bls12_381::Bls12;
    use std::ptr;
    use zkchannels::channels_zk::{ChannelState, ChannelToken, ChannelcloseM, MerchantState};
    use zkchannels::database::StateDatabase;
    use zkchannels::wallet::Wallet;
    use zkchannels::zkproofs::ChannelcloseC;

    static MERCH_STATE_KEY: &str = "merch_state";
    static CHANNEL_TOKEN_KEY: &str = "channel_token";
    static CHANNEL_STATE_KEY: &str = "channel_state";

    pub fn open(_cfg: &ZKChannelConfig, conn: &mut Conn, db_url: &String) -> Result<(), String> {
        let merch_state_info = load_merchant_state_info(&db_url);
        let tx_fee_info = get_tx_fee_info();
        let (channel_state, channel_token, merch_state) = match merch_state_info {
            Err(_) => {
                // create a new channel state and merchant state DB
                let rng = &mut rand::thread_rng();
                let mut channel_state = zkproofs::ChannelState::<Bls12>::new(
                    String::from("Direct channel A -> B"),
                    false,
                );

                if tx_fee_info.bal_min_cust == 0 || tx_fee_info.bal_min_merch == 0 {
                    let s = format!("Dust limit must be greater than 0!");
                    return Err(s);
                }

                let (channel_token, merch_state, channel_state) =
                    zkproofs::merchant_init(rng, &mut channel_state, "Merchant"); // db_url.clone(),

                let mut db = handle_error_result!(get_merch_db_connection(db_url.clone()));

                merch_save_state_in_db(
                    &mut db.conn,
                    Some(&channel_state),
                    Some(&channel_token),
                    &merch_state,
                )?;

                (channel_state, channel_token, merch_state)
            }
            Ok(n) => (n.0, n.1, n.2),
        };

        // send initial channel info
        let msg1 = [
            handle_error_result!(serde_json::to_string(&channel_state)),
            handle_error_result!(serde_json::to_string(&channel_token)),
        ];
        conn.send(&msg1);

        Ok(())
    }

    pub fn init(conn: &mut Conn, db_url: &String) -> Result<(), String> {
        // build tx and sign it
        let rng = &mut rand::thread_rng();

        let mut db = handle_error_result!(get_merch_db_connection(db_url.clone()));
        let key = String::from("cli:merch_db");
        let tx_fee_info = get_tx_fee_info();

        // load the channel state from DB
        let ser_channel_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &CHANNEL_STATE_KEY.to_string()),
            "Could not load the merchant channel state"
        );
        let channel_state: ChannelState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the merchant state from DB
        let ser_merch_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &MERCH_STATE_KEY.to_string()),
            "Could not load the merchant state DB"
        );
        let mut merch_state: MerchantState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_merch_state));

        let msg0 = conn.wait_for(None, false);

        let init_state: Wallet<Bls12> = serde_json::from_str(&msg0.get(0).unwrap()).unwrap();

        let init_close_token = zkproofs::validate_channel_params(
            // &mut db as &mut dyn StateDatabase,
            rng,
            &init_state,
            &mut merch_state,
        );
        println!(
            "Initial state for customer is correct, init close token: {}",
            init_close_token
        );

        let msg5 = [handle_error_result!(serde_json::to_string(
            &init_close_token
        ))];

        conn.send(&msg5);

        // if broadcast successful, then we can mark the channel as open
        let escrow_txid = [1u8; 32];
        handle_error_result!(zkproofs::merchant_mark_open_channel(
            escrow_txid.clone(),
            &mut merch_state
        ));

        merch_save_state_in_db(&mut db.conn, None, None, &merch_state)?;
        Ok(())
    }

    pub fn activate(conn: &mut Conn, db_url: &String) -> Result<(), String> {
        let rng = &mut rand::thread_rng();
        let mut db = handle_error_result!(get_merch_db_connection(db_url.clone()));
        let key = String::from("cli:merch_db");

        let ser_merch_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &MERCH_STATE_KEY.to_string()),
            "Could not load the merchant state DB"
        );
        let mut merch_state: MerchantState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_merch_state));

        let msg2 = conn.wait_for(None, false);

        let channel_token: ChannelToken<Bls12> =
            serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        let s0: Wallet<Bls12> = serde_json::from_str(msg2[1].as_ref()).unwrap();

        let pay_token = zkproofs::activate::merchant_init(
            // &mut db as &mut dyn StateDatabase,
            rng,
            &s0,
            &mut merch_state,
        );

        let msg3 = [handle_error_result!(serde_json::to_string(&pay_token))];
        conn.send(&msg3);

        // save the channel token for the channel
        save_channel_token(&mut db.conn, &channel_token)?;

        merch_save_state_in_db(&mut db.conn, None, None, &merch_state)
    }

    pub fn load_merchant_state_info(
        db_url: &String,
    ) -> Result<
        (
            ChannelState<Bls12>,
            ChannelToken<Bls12>,
            MerchantState<Bls12>,
        ),
        String,
    > {
        let mut db = handle_error_result!(get_merch_db_connection(db_url.clone()));
        let key = String::from("cli:merch_db");

        // load the channel state from DB
        let ser_channel_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &CHANNEL_STATE_KEY.to_string()),
            "Could not load the merchant channel state"
        );
        let channel_state: ChannelState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        let ser_channel_token = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &CHANNEL_TOKEN_KEY.to_string()),
            "Could not load the merchant channel token"
        );

        let channel_token: ChannelToken<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        // load the merchant state from DB
        let ser_merch_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &MERCH_STATE_KEY.to_string()),
            "Could not load the merchant state DB"
        );

        let merch_state: MerchantState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_merch_state));

        Ok((channel_state, channel_token, merch_state))
    }

    pub fn unlink(
        conn: &mut Conn,
        db_url: &String,
        channel_state: &mut ChannelState<Bls12>,
        merch_state: &mut MerchantState<Bls12>,
    ) -> Result<(), String> {
        let rng = &mut rand::thread_rng();
        let db = handle_error_result!(get_merch_db_connection(db_url.clone()));

        let msg0 = conn.wait_for(None, false);
        // get the session id
        let session_id_vec = hex::decode(msg0.get(0).unwrap()).unwrap();
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(session_id_vec.as_slice());

        let unlink_payment: zkproofs::Payment<Bls12> =
            serde_json::from_str(msg0.get(1).unwrap()).unwrap();
        let new_close_token = handle_error_result!(zkproofs::unlink::merchant_update_state(
            rng,
            &channel_state,
            &session_id,
            &unlink_payment,
            merch_state,
        ));

        let msg1 = [handle_error_result!(serde_json::to_string(
            &new_close_token
        ))];
        let msg2 = conn.send_and_wait(
            &msg1,
            Some(String::from(
                "Sent new close token and getting revoked state back",
            )),
            true,
        );

        let ser_rt_pair = msg2.get(0).unwrap();
        let rt_pair = handle_error_result!(serde_json::from_str(ser_rt_pair));
        let new_pay_token = handle_option_result!(zkproofs::unlink::merchant_validate_rev_lock(
            &session_id,
            &rt_pair,
            merch_state
        ));

        let msg3 = [handle_error_result!(serde_json::to_string(&new_pay_token))];
        let msg4 = conn.send_and_wait(&msg3, Some(String::from("Sending new pay token")), true);

        let unlink_ok: bool = serde_json::from_str(msg4.get(0).unwrap()).unwrap();
        if !unlink_ok {
            return Err(format!("failed to execute unlink protocol successfully."));
        }
        Ok(())
    }

    pub fn pay(
        cmd_amount: Option<i64>,
        conn: &mut Conn,
        db_url: &String,
        channel_state: &mut ChannelState<Bls12>,
        merch_state: &mut MerchantState<Bls12>,
    ) -> Result<(), String> {
        let rng = &mut rand::thread_rng();
        let mut db = handle_error_result!(get_merch_db_connection(db_url.clone()));

        // step 1 - get the first message
        let msg0 = conn.wait_for(None, false);

        // get the session id
        let session_id_vec = hex::decode(msg0.get(0).unwrap()).unwrap();
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(session_id_vec.as_slice());

        // get the nonce
        let nonce_vec = hex::decode(msg0.get(1).unwrap()).unwrap();
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(nonce_vec.as_slice());

        let amount_vec = hex::decode(msg0.get(2).unwrap()).unwrap();
        let mut amount_buf = [0u8; 8];
        amount_buf.copy_from_slice(amount_vec.as_slice());
        let amount = i64::from_be_bytes(amount_buf);

        let is_ok = zkproofs::pay::merchant_prepare(
            &session_id,
            FixedSizeArray16(nonce),
            amount,
            merch_state,
        );

        // confirm that payment is ok or not
        let msg1 = [handle_error_result!(serde_json::to_string(&is_ok))];
        let msg2 = conn.send_and_wait(
            &msg1,
            Some(String::from(
                "Sent ok prepare msg and wait for payment proof",
            )),
            false,
        );

        let payment: zkproofs::Payment<Bls12> = serde_json::from_str(msg2.get(0).unwrap()).unwrap();
        let new_close_token = zkproofs::pay::merchant_update_state(
            rng,
            &channel_state,
            &session_id,
            &payment,
            merch_state,
        );

        let msg3 = [handle_error_result!(serde_json::to_string(
            &new_close_token
        ))];
        let msg4 = conn.send_and_wait(
            &msg3,
            Some(String::from(
                "Sent new close token and getting revoked state back",
            )),
            true,
        );

        let ser_rt_pair = msg4.get(0).unwrap();
        let rt_pair = handle_error_result!(serde_json::from_str(ser_rt_pair));
        let new_pay_token = handle_option_result!(zkproofs::pay::merchant_validate_rev_lock(
            &session_id,
            &rt_pair,
            merch_state
        ));

        let msg5 = [handle_error_result!(serde_json::to_string(&new_pay_token))];
        let msg6 = conn.send_and_wait(&msg5, Some(String::from("Sending new pay token")), true);

        let pay_token_ok: bool = serde_json::from_str(msg6.get(0).unwrap()).unwrap();
        if !pay_token_ok {
            return Err(format!("failed to execute pay protocol successfully."));
        }
        println!("[!] valid pay tokend delivered: {}", pay_token_ok);
        merch_save_state_in_db(&mut db.conn, Some(&channel_state), None, &merch_state)
    }

    pub fn merch_save_state_in_db(
        db_conn: &mut redis::Connection,
        channel_state: Option<&ChannelState<Bls12>>,
        channel_token: Option<&ChannelToken<Bls12>>,
        merch_state: &MerchantState<Bls12>,
    ) -> Result<(), String> {
        let key = String::from("cli:merch_db");
        match channel_state {
            Some(n) => {
                let channel_state_json_str = handle_error_result!(serde_json::to_string(n));
                store_file_in_db(
                    db_conn,
                    &key,
                    &CHANNEL_STATE_KEY.to_string(),
                    &channel_state_json_str,
                )?
            }
            None => false, // do nothing
        };

        match channel_token {
            Some(n) => {
                let channel_token_json_str = handle_error_result!(serde_json::to_string(n));
                store_file_in_db(
                    db_conn,
                    &key,
                    &CHANNEL_TOKEN_KEY.to_string(),
                    &channel_token_json_str,
                )?
            }
            None => false, // do nothing
        };

        let merch_state_json_str = handle_error_result!(serde_json::to_string(merch_state));
        store_file_in_db(
            db_conn,
            &key,
            &MERCH_STATE_KEY.to_string(),
            &merch_state_json_str,
        )?;
        Ok(())
    }

    pub fn save_channel_token(
        db_conn: &mut redis::Connection,
        channel_token: &ChannelToken<Bls12>,
    ) -> Result<(), String> {
        let key = String::from("cli:merch_channels");
        let channel_id = channel_token.compute_channel_id();
        let channel_id_str = handle_error_result!(serde_json::to_string(&channel_id));

        let channel_token_key = format!("id:{}", channel_id_str);
        let channel_token_json_str = handle_error_result!(serde_json::to_string(&channel_token));
        store_file_in_db(db_conn, &key, &channel_token_key, &channel_token_json_str)?;
        Ok(())
    }

    pub fn list_channels(db_conn: &mut redis::Connection) {
        let key = String::from("cli:merch_channels");

        let channel_ids: Vec<String> = db_conn.hkeys(key).unwrap();
        println!("list channels...");
        for id in channel_ids {
            println!("{}", id);
        }
    }

    pub fn close(
        db_url: &String,
        close_token: Option<PathBuf>,
        out_file: PathBuf,
        channel_id: String,
    ) -> Result<(), String> {
        // output the merch-close-tx (only thing merchant can broadcast to close channel)
        let mut db = handle_error_result!(get_merch_db_connection(db_url.clone()));

        if channel_id == "" {
            list_channels(&mut db.conn);
            return Ok(());
        }

        let key1 = String::from("cli:merch_db");
        let ser_merch_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key1, &MERCH_STATE_KEY.to_string()),
            "Could not load the merchant state DB"
        );
        let merch_state: MerchantState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_merch_state));

        let key2 = String::from("cli:merch_channels");
        let channel_token_key = format!("id:{}", channel_id);
        let ser_channel_token = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key2, &channel_token_key),
            "Invalid channel ID"
        );
        let channel_token: ChannelToken<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        // load the channel state from DB
        let ser_channel_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key1, &CHANNEL_STATE_KEY.to_string()),
            "Could not load the merchant channel state"
        );
        let channel_state: ChannelState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        match close_token {
            Some(c) => {
                let cust_close_json = handle_error_result!(read_pathfile(c));
                let cust_close_msg: ChannelcloseC<Bls12> =
                    handle_error_result!(serde_json::from_str(&cust_close_json));
                let rt_pair = handle_error_result!(zkproofs::force_merchant_close(
                    &channel_state,
                    &channel_token,
                    &cust_close_msg,
                    &merch_state,
                ));

                let rt_pair_json = handle_error_result!(serde_json::to_string(&rt_pair));
                write_pathfile(out_file, rt_pair_json)?;
            }
            None => {
                // extract merch-expiry-tx from
                println!("extracting expiry tx stored in merch state.");
            }
        };
        Ok(())
    }
}
