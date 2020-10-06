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
use libc::{c_int, c_void};
use rand::Rng;
use redis::Commands;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::ptr;
use std::str::FromStr;
use std::thread::sleep;
use std::time;
use structopt::StructOpt;
use zkchan_tx::Testnet;
// use zkchannels::bindings::Receive_return;
use pairing::bls12_381::Bls12;
use zkchannels::cl;
use zkchannels::database::create_db_connection;
use zkchannels::database::{RedisDatabase, StateDatabase};
use zkchannels::mpc::TransactionFeeInfo;
use zkchannels::zkproofs;
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
    #[structopt(short = "d", long = "bal-min-cust", default_value = "546")]
    bal_min_cust: i64,
    #[structopt(short = "e", long = "bal-min-merch", default_value = "546")]
    bal_min_merch: i64,
    #[structopt(short = "v", long = "val-cpfp", default_value = "1000")]
    val_cpfp: i64,
    #[structopt(short = "f", long = "fee-cc", default_value = "1000")]
    fee_cc: i64,
    #[structopt(short = "m", long = "min-fee", default_value = "0")]
    min_fee: i64,
    #[structopt(short = "s", long = "max-fee", default_value = "10000")]
    max_fee: i64,
    #[structopt(short = "g", long = "fee-mc", default_value = "1000")]
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
    #[structopt(short = "b", long = "self-delay", default_value = "1487")]
    self_delay: u16,
    #[structopt(short = "n", long = "channel-name", default_value = "")]
    channel_name: String,
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct Init {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(long = "txid")]
    txid: Option<String>,
    #[structopt(long = "index")]
    index: Option<u32>,
    #[structopt(short = "a", long = "input-sats")]
    input_sats: Option<i64>,
    #[structopt(short = "o", long = "output-sats")]
    output_sats: Option<i64>,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String,
    #[structopt(short = "f", long = "tx-fee", default_value = "1000")]
    tx_fee: i64,
    #[structopt(short = "n", long = "channel-name", default_value = "")]
    channel_name: String,
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
    #[structopt(short = "f", long = "file")]
    file: PathBuf,
    #[structopt(short = "e", long = "from-merch")]
    from_merch_close: bool,
    #[structopt(short = "n", long = "channel-id", default_value = "")]
    channel_id: String,
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
    let min_threshold = 546; // dust limit
    let tx_fee_info = TransactionFeeInfo {
        bal_min_cust: min_threshold,
        bal_min_merch: min_threshold,
        val_cpfp: 1000,
        fee_cc: 1000,
        fee_mc: 1000,
        min_fee: 0,
        max_fee: 10000,
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
#[structopt(name = "zkchannels")]
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
                val_cpfp: setfees.val_cpfp,
                fee_cc: setfees.fee_cc,
                fee_mc: setfees.fee_mc,
                min_fee: setfees.min_fee,
                max_fee: setfees.max_fee,
            };
            println!("{}", tx_fee_info);
            print_error_result!(store_tx_fee_info(db_url, &tx_fee_info));
            // TODO: integrate setting tx fees and other config items
            // confy::store("zkchannel_cfg", &cfg)?;
        }
        Command::OPEN(open) => match open.party {
            Party::MERCH => {
                match merch::open(&cfg, create_connection!(open), &db_url, open.self_delay) {
                    Err(e) => println!("Channel opening phase failed with error: {}", e),
                    _ => (),
                }
            }
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
            // TODO: clean this up
            Party::CUST => match cust::init(
                create_connection!(init),
                &db_url,
                init.txid.unwrap(),
                init.index.unwrap(),
                init.input_sats.unwrap(),
                init.output_sats.unwrap(),
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
                let (mut channel_state, channel_token, mut merch_state) =
                    merch::load_merchant_state_info(&db_url).unwrap();
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
                let (mut channel_state, channel_token, mut merch_state) =
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
            Party::MERCH => {
                print_error_result!(merch::close(&db_url, close.file, close.channel_id))
            }
            Party::CUST => print_error_result!(cust::close(
                &db_url,
                close.file,
                close.from_merch_close,
                close.channel_id
            )),
        },
    }

    println!("******************************************");
    Ok(())
}

mod cust {
    use super::*;
    use pairing::bls12_381::Bls12;
    use std::ptr;
    use zkchan_tx::fixed_size_array::FixedSizeArray32;
    use zkchan_tx::txutil::{
        customer_form_escrow_transaction, customer_sign_escrow_transaction,
        customer_sign_merch_close_transaction,
    };
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
        txid: String,
        index: u32,
        input_sats: i64,
        output_sats: i64,
        tx_fee: i64,
        channel_name: String,
    ) -> Result<(), String> {
        if channel_name == "" {
            return Err(String::from("missing channel-name"));
        }

        let mut rng = &mut rand::thread_rng();
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
        println!("Verified the closing token...");
        // get the initial customer state
        let init_state = zkproofs::get_initial_state(&cust_state);

        // prepare and send
        let msg2 = [handle_error_result!(serde_json::to_string(&init_state))];
        let msg3 = conn.send_and_wait(&msg2, None, false);

        let init_close_token: cl::Signature<Bls12> =
            serde_json::from_str(&msg3.get(0).unwrap()).unwrap();
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

        println!("Can now proceed with channel funding");
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
            Some(String::from("Sending session id and unlink payment")),
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
            Some(String::from("Sending session id and revoked state")),
            true,
        );
        let ser_pay_token = msg3.get(0).unwrap();
        let new_pay_token = handle_error_result!(serde_json::from_str(&ser_pay_token));

        // verify the pay token and update internal state
        let is_ok =
            zkproofs::unlink::customer_finalize(&mut channel_state, &mut cust_state, new_pay_token);
        let msg4 = [handle_error_result!(serde_json::to_string(&is_ok))];
        let msg2 = conn.send(&msg4);

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

        Ok(())
    }

    pub fn close(
        db_url: &String,
        out_file: PathBuf,
        from_merch_close: bool,
        channel_id: String,
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
        let mut cust_state: CustomerState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        // load the channel token from DB
        let channel_token_key = format!("cust:{}:channel_token", channel_id);
        let ser_channel_token =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_token_key));
        let channel_token: ChannelToken<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

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
    use zkchan_tx::fixed_size_array::FixedSizeArray32;
    use zkchan_tx::transactions::btc::merchant_form_close_transaction;
    use zkchannels::channels_zk::{ChannelState, ChannelToken, MerchantState};
    use zkchannels::database::StateDatabase;
    use zkchannels::wallet::Wallet;

    static MERCH_STATE_KEY: &str = "merch_state";
    static CHANNEL_TOKEN_KEY: &str = "channel_token";
    static CHANNEL_STATE_KEY: &str = "channel_state";

    pub fn open(
        _cfg: &ZKChannelConfig,
        conn: &mut Conn,
        db_url: &String,
        self_delay: u16,
    ) -> Result<(), String> {
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

                // let mut channel_state = ChannelState::new(
                //     String::from("Channel"),
                //     self_delay,
                //     tx_fee_info.bal_min_cust,
                //     tx_fee_info.bal_min_merch,
                //     tx_fee_info.val_cpfp,
                //     false,
                // );
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
            get_file_from_db(&mut db.conn, &key, &CHANNEL_STATE_KEY.to_string()),
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
        let mut db = handle_error_result!(get_merch_db_connection(db_url.clone()));

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
        let msg2 = conn.send_and_wait(&msg1, Some(String::from("Sending new close token")), true);

        let ser_rt_pair = msg2.get(1).unwrap();
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

        match channel_state {
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
        let channel_id_str = format!("{}", channel_id);

        let channel_token_key = format!("id:{}", channel_id_str);
        let channel_token_json_str = handle_error_result!(serde_json::to_string(&channel_token));
        store_file_in_db(db_conn, &key, &channel_token_key, &channel_token_json_str)?;
        Ok(())
    }

    pub fn list_channels(db_conn: &mut redis::Connection) {
        let key = String::from("cli:merch_channels");

        let channel_ids: Vec<String> = db_conn.hkeys(key).unwrap();
        println!("List zkchannels...");
        for id in channel_ids {
            println!("{}", id);
        }
    }

    pub fn close(db_url: &String, out_file: PathBuf, channel_id: String) -> Result<(), String> {
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
        let mut merch_state: MerchantState<Bls12> =
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
            get_file_from_db(&mut db.conn, &key2, &CHANNEL_STATE_KEY.to_string()),
            "Could not load the merchant channel state"
        );
        let channel_state: ChannelState<Bls12> =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        Ok(())
    }
}
