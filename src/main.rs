extern crate bufstream;
extern crate rand;
extern crate redis;
extern crate secp256k1;
extern crate serde;
extern crate sha2;
extern crate structopt;
extern crate zkchan_tx;
extern crate zkchannels;

use bufstream::BufStream;
use rand::Rng;
use redis::Commands;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread::sleep;
use std::time;
use structopt::StructOpt;
use zkchan_tx::Testnet;
use zkchannels::database::create_db_connection;
use zkchannels::mpc;
use zkchannels::util::VAL_CPFP;
use zkchannels::FundingTxInfo;

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
    #[structopt(short = "d", long = "dust-limit", default_value = "546")]
    min_threshold: i64,
    #[structopt(short = "d", long = "self-delay", default_value = "1487")]
    self_delay: u16,
    #[structopt(short = "f", long = "fee-cc", default_value = "1000")]
    fee_cc: i64,
    #[structopt(short = "m", long = "min-fee", default_value = "0")]
    min_fee: i64,
    #[structopt(short = "s", long = "max-fee", default_value = "10000")]
    max_fee: i64,
    #[structopt(short = "g", long = "fee-mc", default_value = "1000")]
    fee_mc: i64,
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
    #[structopt(short = "d", long = "dust-limit", default_value = "546")]
    min_threshold: i64,
    #[structopt(short = "f", long = "fee-cc", default_value = "1000")]
    fee_cc: i64,
    #[structopt(short = "g", long = "fee-mc", default_value = "1000")]
    fee_mc: i64,
    #[structopt(short = "m", long = "min-fee", default_value = "0")]
    min_fee: i64,
    #[structopt(short = "s", long = "max-fee", default_value = "10000")]
    max_fee: i64,
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
pub struct Pay {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(short = "a", long = "amount", allow_hyphen_values = true)]
    amount: Option<i64>,
    #[structopt(short = "f", long = "fee-cc", allow_hyphen_values = true)]
    fee_cc: Option<i64>,
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
    #[structopt(name = "open")] // for initializing channel state and cust/merch state
    OPEN(Open),
    #[structopt(name = "init")] // for creating/signing txs between cust/merch
    INIT(Init),
    #[structopt(name = "activate")] // for activating channel
    ACTIVATE(Activate),
    #[structopt(name = "unlink")] // for unlinking channel
    UNLINK(Pay),
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

#[derive(StructOpt, Debug)]
#[structopt(name = "zkchannels-mpc")]
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
    pub raw_fd: RawFd,
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
            raw_fd: 0,
        }
    }

    pub fn send(&mut self, msg: &[String]) {
        for i in 1..6 {
            match TcpStream::connect(self.out_addr) {
                Ok(stream) => {
                    self.raw_fd = stream.as_raw_fd();
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
                    self.raw_fd = stream.as_raw_fd();
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

fn main() {
    let args = Cli::from_args();
    let db_url = "redis://127.0.0.1/".to_string(); // make constant

    println!("******************************************");

    match args.command {
        Command::OPEN(open) => match open.party {
            Party::MERCH => match merch::open(
                create_connection!(open),
                &db_url,
                open.fee_mc,
                open.min_threshold,
                open.self_delay,
            ) {
                Err(e) => println!("Channel opening phase failed with error: {}", e),
                _ => (),
            },
            Party::CUST => {
                match cust::open(
                    create_connection!(open),
                    &db_url,
                    open.cust_bal,
                    open.merch_bal,
                    open.fee_cc,
                    open.min_fee,
                    open.max_fee,
                    open.channel_name,
                ) {
                    Err(e) => println!("Channel opening phase failed with error: {}", e),
                    _ => (),
                }
            }
        },
        Command::INIT(init) => match init.party {
            Party::MERCH => match merch::init(
                create_connection!(init),
                &db_url,
                init.fee_cc,
                init.fee_mc,
                init.min_fee,
                init.max_fee,
            ) {
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
                init.channel_name,
                init.fee_mc,
                init.min_fee,
                init.max_fee,
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
                let (mut channel_state, mut merch_state) =
                    merch::load_merchant_state_info(&db_url).unwrap();
                merch::pay(
                    Some(0),
                    create_connection!(unlink),
                    &db_url,
                    &mut channel_state,
                    &mut merch_state,
                )
                .unwrap()
            }
            Party::CUST => cust::pay(
                0,
                1000,
                create_connection!(unlink),
                &db_url,
                unlink.channel_name,
                unlink.verbose,
            )
            .unwrap(),
        },
        Command::PAY(pay) => match pay.party {
            Party::MERCH => {
                let (mut channel_state, mut merch_state) =
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
                    pay.fee_cc.unwrap_or(1000),
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
}

mod cust {
    use super::*;
    use zkchan_tx::fixed_size_array::FixedSizeArray32;
    use zkchan_tx::transactions::btc::merchant_form_close_transaction;
    use zkchan_tx::txutil::{
        customer_form_escrow_transaction, customer_sign_escrow_transaction, customer_sign_merch_close_transaction,
    };
    use zkchannels::bindings::ConnType_NETIO;
    // ConnType_CUSTOM
    use zkchannels::channels_mpc::{
        ChannelMPCState, ChannelMPCToken, CustomerMPCState, NetworkConfig,
    };
    use zkchannels::database::MaskedTxMPCInputs;
    use zkchannels::util;
    // use std::os::unix::io::AsRawFd;

    pub fn open(
        conn: &mut Conn,
        db_url: &String,
        b0_cust: i64,
        b0_merch: i64,
        fee_cc: i64,
        min_fee: i64,
        max_fee: i64,
        channel_name: String,
    ) -> Result<(), String> {
        if channel_name == "" {
            return Err(String::from("missing channel-name"));
        }

        let rng = &mut rand::thread_rng();
        let mut db_conn = handle_error_result!(create_db_connection(db_url.clone()));

        println!("Waiting for merchant's channel_state and pk_m...");
        let msg0 = conn.wait_for(None, false);
        let channel_state: ChannelMPCState = serde_json::from_str(&msg0.get(0).unwrap()).unwrap();
        let pk_m: secp256k1::PublicKey = serde_json::from_str(&msg0.get(1).unwrap()).unwrap();
        let fee_mc: i64 = serde_json::from_str(&msg0.get(2).unwrap()).unwrap();

        // check cust-bal meets min bal
        let cust_min_bal = fee_cc + channel_state.get_min_threshold() + VAL_CPFP;
        if b0_cust < cust_min_bal {
            return Err(format!("cust-bal must be greater than {}.", cust_min_bal));
        }

        // check merch-bal meets min bal
        let merch_min_bal = fee_mc + channel_state.get_min_threshold() + VAL_CPFP;
        if b0_merch < merch_min_bal {
            return Err(format!("merch-bal must be greater than {}.", merch_min_bal));
        }

        let (channel_token, cust_state) = mpc::init_customer(
            rng,
            &pk_m,
            b0_cust,
            b0_merch,
            fee_cc,
            min_fee,
            max_fee,
            fee_mc,
            channel_name.as_str()
        );

        println!("Saving the initial customer state...");
        cust_save_state_in_db(
            &mut db_conn,
            channel_name,
            channel_state,
            channel_token,
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
        channel_name: String,
        fee_mc: i64,
        min_fee: i64,
        max_fee: i64,
    ) -> Result<(), String> {
        if channel_name == "" {
            return Err(String::from("missing channel-name"));
        }

        let mut rng = &mut rand::thread_rng();
        let mut db_conn = handle_error_result!(create_db_connection(db_url.clone()));
        let key = format!("id:{}", channel_name);

        // load the customer state from DB
        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let ser_cust_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &cust_state_key));
        let mut cust_state: CustomerMPCState =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        // load the channel state from DB
        let channel_state_key = format!("cust:{}:channel_state", channel_name);
        let ser_channel_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_state_key));
        let channel_state: ChannelMPCState =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the channel token from DB
        let channel_token_key = format!("cust:{}:channel_token", channel_name);
        let ser_channel_token =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_token_key));
        let mut channel_token: ChannelMPCToken =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        let to_self_delay_be = channel_state.get_self_delay_be();

        let cust_sk = cust_state.get_secret_key();
        let cust_pk = cust_state.pk_c.serialize().to_vec();
        let merch_pk = channel_token.pk_m.serialize().to_vec();

        // generate a new change pk
        println!("generating a change pk/sk pair");
        let (change_pk, change_sk) = generate_keypair(&mut rng);
        let change_pk_vec = change_pk.serialize().to_vec();

        println!("change pk: {}", hex::encode(&change_pk_vec));

        let input_txid = handle_error_result!(hex::decode(txid));

        // form the escrow transaction
        let (escrow_txid_be, _, escrow_prevout) =
            handle_error_result!(customer_form_escrow_transaction(
                input_txid.clone(),
                index,
                cust_sk.clone(),
                input_sats,
                output_sats,
                cust_pk.clone(),
                merch_pk.clone(),
                Some(change_pk_vec.clone()),
                false
            ));

        // form the merch-close-tx
        let cust_bal = cust_state.cust_balance;
        let merch_bal = cust_state.merch_balance;
        let merch_close_pk = channel_state.merch_payout_pk.unwrap().serialize().to_vec();
        let (merch_tx_preimage, _) =
            handle_error_result!(merchant_form_close_transaction::<Testnet>(
                escrow_txid_be.to_vec(),
                cust_pk.clone(),
                merch_pk.clone(),
                merch_close_pk,
                cust_bal,
                merch_bal,
                fee_mc,
                util::VAL_CPFP,
                to_self_delay_be
            ));

        // get the cust-sig on the merch-close-tx
        let cust_sig = handle_error_result!(customer_sign_merch_close_transaction(
            cust_sk.clone(),
            merch_tx_preimage
        ));

        let init_cust_state = handle_error_result!(cust_state.get_initial_cust_state());
        // customer sends pk_c, n_0, rl_0, B_c, B_m, and escrow_txid/prevout to the merchant
        let msg0 = [
            handle_error_result!(serde_json::to_string(&cust_sig)),
            handle_error_result!(serde_json::to_string(&escrow_txid_be)),
            handle_error_result!(serde_json::to_string(&escrow_prevout)),
            handle_error_result!(serde_json::to_string(&init_cust_state)),
        ];

        println!("Sending cust-sig, escrow-txid/prevout and init cust state");
        let msg1 = conn.send_and_wait(&msg0, None, false);

        // get the merch_txid, merch_prevout to complete funding_tx
        let merch_txid: [u8; 32] = serde_json::from_str(&msg1.get(0).unwrap()).unwrap();
        let merch_prevout: [u8; 32] = serde_json::from_str(&msg1.get(1).unwrap()).unwrap();
        // form and sign the cust-close-from-escrow-tx and from-merch-close-tx
        let escrow_sig: Vec<u8> = serde_json::from_str(&msg1.get(2).unwrap()).unwrap();
        let merch_sig: Vec<u8> = serde_json::from_str(&msg1.get(3).unwrap()).unwrap();
        println!("Received signatures on cust-close-txs");

        let funding_tx = FundingTxInfo {
            init_cust_bal: cust_bal,
            init_merch_bal: merch_bal,
            min_fee: min_fee,
            max_fee: max_fee,
            fee_mc: fee_mc,
            escrow_txid: FixedSizeArray32(escrow_txid_be),
            escrow_prevout: FixedSizeArray32(escrow_prevout),
            merch_txid: FixedSizeArray32(merch_txid),
            merch_prevout: FixedSizeArray32(merch_prevout),
        };

        cust_state.set_funding_tx_info(&mut channel_token, &funding_tx)?;

        // now sign the customer's initial closing txs
        println!("Signing the initial closing transactions...");
        let got_close_tx = match cust_state.sign_initial_closing_transaction::<Testnet>(
            &channel_state,
            &channel_token,
            &escrow_sig,
            &merch_sig,
        ) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string()),
        };

        // handle_error_result!(serde_json::to_string(&init_hash))];
        let (init_cust_state, init_hash) =
            handle_error_result!(mpc::get_initial_state(&cust_state));
        let msg2 = [
            handle_error_result!(serde_json::to_string(&channel_token)),
            handle_error_result!(serde_json::to_string(&init_cust_state)),
            handle_error_result!(serde_json::to_string(&init_hash)),
        ];
        let msg3 = conn.send_and_wait(&msg2, None, false);

        let res: bool = serde_json::from_str(&msg3.get(0).unwrap()).unwrap();
        assert!(res);

        if got_close_tx {
            cust_save_state_in_db(
                &mut db_conn,
                channel_name,
                channel_state,
                channel_token,
                cust_state,
            )?;
        }

        // proceed to sign the escrow-tx after initial closing tx signed
        let (signed_tx, _, _, _) =
            handle_error_result!(customer_sign_escrow_transaction(
                input_txid,
                index,
                cust_sk.clone(),
                input_sats,
                output_sats,
                cust_pk.clone(),
                merch_pk.clone(),
                Some(change_pk_vec),
                false
            ));

        println!("Can now broadcast the signed escrow transaction");
        write_file("signed_escrow_tx.txt", hex::encode(&signed_tx))?;
        write_file(
            "change_sk.txt",
            handle_error_result!(serde_json::to_string(&change_sk)),
        )?;

        Ok(())
    }

    pub fn activate(conn: &mut Conn, db_url: &String, channel_name: String) -> Result<(), String> {
        let rng = &mut rand::thread_rng();
        let mut db_conn = handle_error_result!(create_db_connection(db_url.clone()));
        let key = format!("id:{}", channel_name);

        // load the customer state from DB
        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let ser_cust_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &cust_state_key));
        let mut cust_state: CustomerMPCState =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        // load the channel token from DB
        let channel_token_key = format!("cust:{}:channel_token", channel_name);
        let ser_channel_token =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_token_key));
        let channel_token: ChannelMPCToken =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        let s0 = handle_error_result!(mpc::activate_customer(rng, &mut cust_state));

        // send the channel token and initial state
        let msg1 = [
            handle_error_result!(serde_json::to_string(&channel_token)),
            handle_error_result!(serde_json::to_string(&s0)),
        ];
        println!("Sending channel token and state (s0)");
        let msg2 = conn.send_and_wait(&msg1, None, false);

        let pay_token: [u8; 32] = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        println!("Obtained pay token (p0): {}", hex::encode(&pay_token));
        handle_error_result!(mpc::activate_customer_finalize(pay_token, &mut cust_state));

        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let cust_state_json_str = handle_error_result!(serde_json::to_string(&cust_state));
        store_file_in_db(&mut db_conn, &key, &cust_state_key, &cust_state_json_str)?;

        Ok(())
    }

    pub fn pay(
        amount: i64,
        fee_cc: i64,
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
        let mut channel_state: ChannelMPCState =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the customer state from DB
        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let ser_cust_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &cust_state_key));
        let mut cust_state: CustomerMPCState =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        if verbose {
            println!("Payment amount: {}", amount);
            println!("Customer balance: {}", cust_state.cust_balance);
            println!("Merchant balance: {}", cust_state.merch_balance);
        }

        // load the channel token from DB
        let channel_token_key = format!("cust:{}:channel_token", channel_name);
        let ser_channel_token =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_token_key));
        let mut channel_token: ChannelMPCToken =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        let old_state = cust_state.get_current_state();

        // prepare phase
        let (new_state, rev_state) =
            match mpc::pay_prepare_customer(rng, &mut channel_state, amount, &mut cust_state) {
                Ok(n) => n,
                Err(e) => return Err(e),
            };
        if verbose {
            let chan_id = channel_token.compute_channel_id().unwrap();
            println!("====================================");
            println!("Updating channel: ID={}", hex::encode(&chan_id));
            println!("old state: {}", &old_state);
            println!("new state: {}", &new_state);
            println!("====================================");
        }
        let amount_str = hex::encode(amount.to_be_bytes());
        let old_nonce_str = hex::encode(&old_state.get_nonce());
        let rev_lock_com_str = hex::encode(&rev_state.rev_lock_com.0);

        let msg = [old_nonce_str, rev_lock_com_str, amount_str];
        let msg1 = conn.send_and_wait(
            &msg,
            Some(String::from("amount, nonce and rev_lock com")),
            true,
        );
        let pay_token_mask_com_vec = hex::decode(msg1.get(0).unwrap()).unwrap();
        let mut pay_token_mask_com = [0u8; 32];
        pay_token_mask_com.copy_from_slice(pay_token_mask_com_vec.as_slice());

        let nc = NetworkConfig {
            conn_type: ConnType_NETIO,
            path: String::new(),
            dest_ip: String::from("127.0.0.1"),
            dest_port: conn.own_port,
            peer_raw_fd: conn.raw_fd,
        };
        cust_state.set_network_config(nc);

        // execute the mpc phase
        let mut is_ok = match mpc::pay_update_customer(
            &mut channel_state,
            &mut channel_token,
            old_state,
            new_state,
            fee_cc,
            pay_token_mask_com,
            rev_state.rev_lock_com.0,
            amount,
            &mut cust_state,
        ) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string()),
        };

        let msg1a = [handle_error_result!(serde_json::to_string(&is_ok))];
        let msg2 = conn.send_and_wait(&msg1a, None, false);

        let mask_bytes: MaskedTxMPCInputs = serde_json::from_str(msg2.get(0).unwrap()).unwrap();

        // unmask the closing tx
        is_ok = is_ok
            && mpc::pay_unmask_sigs_customer(
                &mut channel_state,
                &mut channel_token,
                mask_bytes,
                &mut cust_state,
            )
            .unwrap();

        let msg3 = [serde_json::to_string(&rev_state).unwrap()];

        // send the revoked state and wait for the pt_mask_bytes and pt_mask_r
        let msg4 = conn.send_and_wait(&msg3, None, false);
        let pt_mask_bytes_vec = hex::decode(msg4.get(0).unwrap()).unwrap();
        let pt_mask_r_vec = hex::decode(msg4.get(1).unwrap()).unwrap();

        let mut pt_mask_bytes = [0u8; 32];
        pt_mask_bytes.copy_from_slice(pt_mask_bytes_vec.as_slice());
        let mut pt_mask_r = [0u8; 16];
        pt_mask_r.copy_from_slice(pt_mask_r_vec.as_slice());

        // unmask the pay token
        is_ok =
            is_ok && handle_error_result!(mpc::pay_unmask_pay_token_customer(pt_mask_bytes, pt_mask_r, &mut cust_state));

        conn.send(&[is_ok.to_string()]);
        match is_ok {
            true => println!("Transaction succeeded!"),
            false => println!("Transaction failed!"),
        }

        cust_save_state_in_db(
            &mut db_conn,
            channel_name,
            channel_state,
            channel_token,
            cust_state,
        )
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
        let channel_state: ChannelMPCState =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the customer state from DB
        let cust_state_key = format!("cust:{}:cust_state", channel_id);
        let ser_cust_state =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &cust_state_key));
        let cust_state: CustomerMPCState =
            handle_error_result!(serde_json::from_str(&ser_cust_state));

        // load the channel token from DB
        let channel_token_key = format!("cust:{}:channel_token", channel_id);
        let ser_channel_token =
            handle_error_result!(get_file_from_db(&mut db_conn, &key, &channel_token_key));
        let channel_token: ChannelMPCToken =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        let from_escrow = !from_merch_close;

        let (signed_tx, txid_be, _) = handle_error_result!(mpc::customer_close(
            &channel_state,
            &channel_token,
            from_escrow,
            &cust_state
        ));

        if from_escrow {
            println!("cust-close from escrow txid: {}", hex::encode(txid_be));
        } else {
            println!("cust-close from merch txid: {}", hex::encode(txid_be));
        }
        // write out to a file
        write_pathfile(out_file, hex::encode(signed_tx))?;
        Ok(())
    }

    fn cust_save_state_in_db(
        db_conn: &mut redis::Connection,
        channel_name: String,
        channel_state: ChannelMPCState,
        channel_token: ChannelMPCToken,
        cust_state: CustomerMPCState,
    ) -> Result<(), String> {
        let key = format!("id:{}", channel_name);

        let channel_state_key = format!("cust:{}:channel_state", channel_name);
        let channel_state_json_str = handle_error_result!(serde_json::to_string(&channel_state));
        store_file_in_db(db_conn, &key, &channel_state_key, &channel_state_json_str)?;

        let channel_token_key = format!("cust:{}:channel_token", channel_name);
        let channel_token_json_str = handle_error_result!(serde_json::to_string(&channel_token));
        store_file_in_db(db_conn, &key, &channel_token_key, &channel_token_json_str)?;

        let cust_state_key = format!("cust:{}:cust_state", channel_name);
        let cust_state_json_str = handle_error_result!(serde_json::to_string(&cust_state));
        store_file_in_db(db_conn, &key, &cust_state_key, &cust_state_json_str)?;
        Ok(())
    }
}

mod merch {
    use super::*;
    use zkchan_tx::fixed_size_array::FixedSizeArray32;
    use zkchan_tx::transactions::btc::merchant_form_close_transaction;
    use zkchannels::bindings::ConnType_NETIO;
    use zkchannels::channels_mpc::{
        ChannelMPCState, ChannelMPCToken, InitCustState, MerchantMPCState, NetworkConfig,
    };
    use zkchannels::database::{RedisDatabase, StateDatabase};
    use zkchannels::wallet::State;
    use zkchannels::util;

    static MERCH_STATE_KEY: &str = "merch_state";
    static CHANNEL_STATE_KEY: &str = "channel_state";

    pub fn open(
        conn: &mut Conn,
        db_url: &String,
        fee_mc: i64,
        min_threshold: i64,
        self_delay: u16,
    ) -> Result<(), String> {
        let merch_state_info = load_merchant_state_info(&db_url);

        let (channel_state, merch_state) = match merch_state_info {
            Err(_) => {
                // create a new channel state and merchant state DB
                let rng = &mut rand::thread_rng();

                let mut channel_state =
                    ChannelMPCState::new(String::from("Channel"), self_delay, min_threshold, false);
                if min_threshold == 0 {
                    let s = format!("Dust limit must be greater than 0!");
                    return Err(s);
                }
                // set dust limit if it's set above
                channel_state.set_min_threshold(min_threshold);

                let mut db = handle_error_result!(RedisDatabase::new("cli", db_url.clone()));

                let merch_state =
                    mpc::init_merchant(rng, db_url.clone(), &mut channel_state, "Merchant");

                merch_save_state_in_db(&mut db.conn, Some(&channel_state), &merch_state)?;

                (channel_state, merch_state)
            }
            Ok(n) => (n.0, n.1),
        };

        // send initial channel info
        let msg1 = [
            handle_error_result!(serde_json::to_string(&channel_state)),
            handle_error_result!(serde_json::to_string(&merch_state.pk_m)),
            handle_error_result!(serde_json::to_string(&fee_mc)),
        ];
        conn.send(&msg1);

        Ok(())
    }

    pub fn init(
        conn: &mut Conn,
        db_url: &String,
        fee_cc: i64,
        fee_mc: i64,
        min_fee: i64,
        max_fee: i64,
    ) -> Result<(), String> {
        // build tx and sign it
        let mut db = handle_error_result!(RedisDatabase::new("cli", db_url.clone()));
        let key = String::from("cli:merch_db");

        // load the channel state from DB
        let ser_channel_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &CHANNEL_STATE_KEY.to_string()),
            "Could not load the merchant channel state"
        );
        let channel_state: ChannelMPCState =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the merchant state from DB
        let ser_merch_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &MERCH_STATE_KEY.to_string()),
            "Could not load the merchant state DB"
        );
        let mut merch_state: MerchantMPCState =
            handle_error_result!(serde_json::from_str(&ser_merch_state));

        let msg0 = conn.wait_for(None, false);

        // wait for cust_sig, escrow_txid and escrow_prevout
        let cust_sig: Vec<u8> = serde_json::from_str(&msg0.get(0).unwrap()).unwrap();
        let escrow_txid: [u8; 32] = serde_json::from_str(&msg0.get(1).unwrap()).unwrap();
        let escrow_prevout: [u8; 32] = serde_json::from_str(&msg0.get(2).unwrap()).unwrap();
        let init_cust_state: InitCustState = serde_json::from_str(&msg0.get(3).unwrap()).unwrap();

        let to_self_delay_be = channel_state.get_self_delay_be();

        let cust_pk = init_cust_state.pk_c.serialize().to_vec();
        let cust_close_pk = init_cust_state.close_pk.serialize().to_vec();
        let rev_lock = init_cust_state.rev_lock.0;

        let merch_pk = merch_state.pk_m.serialize().to_vec();
        let merch_close_pk = merch_state.payout_pk.serialize().to_vec();

        let cust_bal = init_cust_state.cust_bal;
        let merch_bal = init_cust_state.merch_bal;

        // form the merch-close-tx
        let (merch_tx_preimage, tx_params) =
            handle_error_result!(merchant_form_close_transaction::<Testnet>(
                escrow_txid.to_vec(),
                cust_pk.clone(),
                merch_pk,
                merch_close_pk,
                cust_bal,
                merch_bal,
                fee_mc,
                util::VAL_CPFP,
                to_self_delay_be
            ));

        // verify signature from merchant
        let is_ok =
            handle_error_result!(zkchan_tx::txutil::merchant_verify_merch_close_transaction(
                &merch_tx_preimage,
                &cust_sig,
                &cust_pk
            ));
        if is_ok {
            merch_state.store_merch_close_tx(
                &escrow_txid.to_vec(),
                &cust_pk,
                cust_bal,
                merch_bal,
                fee_mc,
                to_self_delay_be,
                &cust_sig,
            );
        }

        let (merch_txid, merch_prevout) = handle_error_result!(
            zkchan_tx::txutil::merchant_generate_transaction_id(tx_params)
        );

        // construct the funding tx info given info available
        let funding_tx = FundingTxInfo {
            init_cust_bal: cust_bal,
            init_merch_bal: merch_bal,
            min_fee: min_fee,
            max_fee: max_fee,
            fee_mc,
            escrow_txid: FixedSizeArray32(escrow_txid),
            escrow_prevout: FixedSizeArray32(escrow_prevout),
            merch_txid: FixedSizeArray32(merch_txid.clone()),
            merch_prevout: FixedSizeArray32(merch_prevout.clone()),
        };

        // now proceed to sign the cust-close transactions (escrow + merch-close-tx)
        println!("Signing customer's initial closing tx...");
        let (escrow_sig, merch_sig) = merch_state.sign_initial_closing_transaction::<Testnet>(
            funding_tx,
            rev_lock,
            cust_pk,
            cust_close_pk,
            to_self_delay_be,
            fee_cc,
        );

        let msg3 = [
            handle_error_result!(serde_json::to_string(&merch_txid)),
            handle_error_result!(serde_json::to_string(&merch_prevout)),
            handle_error_result!(serde_json::to_string(&escrow_sig)),
            handle_error_result!(serde_json::to_string(&merch_sig)),
        ];
        let msg4 = conn.send_and_wait(&msg3, None, false);

        let channel_token: ChannelMPCToken = serde_json::from_str(&msg4.get(0).unwrap()).unwrap();
        let init_cust_state: InitCustState = serde_json::from_str(&msg4.get(1).unwrap()).unwrap();
        let init_hash: [u8; 32] = serde_json::from_str(&msg4.get(2).unwrap()).unwrap();

        let res = handle_error_result!(mpc::validate_channel_params(
            &mut db as &mut dyn StateDatabase,
            &channel_token,
            &init_cust_state,
            init_hash,
            &mut merch_state
        ));
        println!("Initial state for customer is correct: {}", res);

        let msg5 = [handle_error_result!(serde_json::to_string(&res))];

        conn.send(&msg5);

        merch_save_state_in_db(&mut db.conn, None, &merch_state)?;
        Ok(())
    }

    pub fn activate(conn: &mut Conn, db_url: &String) -> Result<(), String> {
        let mut db = handle_error_result!(RedisDatabase::new("cli", db_url.clone()));
        let key = String::from("cli:merch_db");

        let ser_merch_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &MERCH_STATE_KEY.to_string()),
            "Could not load the merchant state DB"
        );
        let mut merch_state: MerchantMPCState =
            handle_error_result!(serde_json::from_str(&ser_merch_state));

        let msg2 = conn.wait_for(None, false);

        let channel_token: ChannelMPCToken = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        let s0: State = serde_json::from_str(msg2[1].as_ref()).unwrap();

        let pay_token = handle_error_result!(mpc::activate_merchant(
            &mut db as &mut dyn StateDatabase,
            channel_token.clone(),
            &s0,
            &mut merch_state
        ));

        let msg3 = [handle_error_result!(serde_json::to_string(&pay_token))];
        conn.send(&msg3);

        // save the channel token for the channel
        save_channel_token(&mut db.conn, &channel_token)?;

        merch_save_state_in_db(&mut db.conn, None, &merch_state)
    }

    pub fn load_merchant_state_info(
        db_url: &String,
    ) -> Result<(ChannelMPCState, MerchantMPCState), String> {
        let mut db = handle_error_result!(RedisDatabase::new("cli", db_url.clone()));
        let key = String::from("cli:merch_db");

        // load the channel state from DB
        let ser_channel_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &CHANNEL_STATE_KEY.to_string()),
            "Could not load the merchant channel state"
        );
        let channel_state: ChannelMPCState =
            handle_error_result!(serde_json::from_str(&ser_channel_state));

        // load the merchant state from DB
        let ser_merch_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key, &MERCH_STATE_KEY.to_string()),
            "Could not load the merchant state DB"
        );
        let merch_state: MerchantMPCState =
            handle_error_result!(serde_json::from_str(&ser_merch_state));

        Ok((channel_state, merch_state))
    }

    pub fn pay(
        cmd_amount: Option<i64>,
        conn: &mut Conn,
        db_url: &String,
        channel_state: &mut ChannelMPCState,
        merch_state: &mut MerchantMPCState,
    ) -> Result<(), String> {
        let rng = &mut rand::thread_rng();
        let mut db = handle_error_result!(RedisDatabase::new("cli", db_url.clone()));

        let msg0 = conn.wait_for(None, false);
        let nonce_vec = hex::decode(msg0.get(0).unwrap()).unwrap();
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(nonce_vec.as_slice());

        let rev_lock_com_vec = hex::decode(msg0.get(1).unwrap()).unwrap();
        let mut rev_lock_com = [0u8; 32];
        rev_lock_com.copy_from_slice(rev_lock_com_vec.as_slice());

        // only if amount not specified above
        let amount = match cmd_amount {
            Some(a) => a,
            None => {
                let amount_vec = hex::decode(msg0.get(2).unwrap()).unwrap();
                let mut amount_buf = [0u8; 8];
                amount_buf.copy_from_slice(amount_vec.as_slice());
                i64::from_be_bytes(amount_buf)
            }
        };
        println!(
            "Payment request => nonce: {}, amount: {}",
            hex::encode(&nonce),
            amount
        );

        let pay_token_mask_com = handle_error_result!(mpc::pay_prepare_merchant(
            rng,
            &mut db as &mut dyn StateDatabase,
            &channel_state,
            nonce,
            rev_lock_com.clone(),
            amount,
            merch_state
        ));

        let msg1 = [hex::encode(&pay_token_mask_com)];
        conn.send(&msg1);

        let nc = NetworkConfig {
            conn_type: ConnType_NETIO,
            path: String::new(),
            dest_ip: String::from("127.0.0.1"),
            dest_port: conn.other_port,
            peer_raw_fd: conn.raw_fd,
        };
        merch_state.set_network_config(nc);

        // execute mpc context
        let _mpc_ok = handle_error_result!(mpc::pay_update_merchant(
            rng,
            &mut db as &mut dyn StateDatabase,
            channel_state,
            nonce.clone(),
            pay_token_mask_com,
            rev_lock_com,
            amount,
            merch_state
        ));

        // confirm customer got mpc output
        let msg1a = conn.wait_for(None, false);
        let cust_mpc_ok: bool = serde_json::from_str(msg1a.get(0).unwrap()).unwrap();
        if !cust_mpc_ok {
            return Err(format!("failed to execute MPC successfully."));
        }

        let masked_inputs = mpc::pay_confirm_mpc_result(
            &mut db as &mut dyn StateDatabase,
            cust_mpc_ok,
            nonce,
            merch_state,
        )
        .unwrap();
        let msg3 = [handle_error_result!(serde_json::to_string(&masked_inputs))];
        let msg4 = conn.send_and_wait(&msg3, Some(String::from("Received revoked state")), true);
        let rev_state = serde_json::from_str(msg4.get(0).unwrap()).unwrap();

        let (pt_mask_bytes, pt_mask_r) = match mpc::pay_validate_rev_lock_merchant(
            &mut db as &mut dyn StateDatabase,
            rev_state,
            merch_state,
        ) {
            Ok(n) => (n.0, n.1),
            _ => {
                return Err(String::from(
                    "Failed to get the pay token mask and randomness!",
                ));
            }
        };

        let msg5 = [hex::encode(&pt_mask_bytes), hex::encode(&pt_mask_r)];
        let msg6 = conn.send_and_wait(&msg5, Some(String::from("Sending masked pt bytes")), true);

        if msg6.get(0).unwrap() == "true" {
            println!("Transaction succeeded!")
        } else {
            println!("Transaction failed!")
        }
        println!("******************************************");

        merch_save_state_in_db(&mut db.conn, Some(&channel_state), &merch_state)
    }

    pub fn merch_save_state_in_db(
        db_conn: &mut redis::Connection,
        channel_state: Option<&ChannelMPCState>,
        merch_state: &MerchantMPCState,
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
        channel_token: &ChannelMPCToken,
    ) -> Result<(), String> {
        let key = String::from("cli:merch_channels");
        let channel_id = channel_token.compute_channel_id().unwrap();
        let channel_id_str = hex::encode(channel_id.to_vec());

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
        let mut db = handle_error_result!(RedisDatabase::new("cli", db_url.clone()));

        if channel_id == "" {
            list_channels(&mut db.conn);
            return Ok(());
        }

        let key1 = String::from("cli:merch_db");
        let ser_merch_state = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key1, &MERCH_STATE_KEY.to_string()),
            "Could not load the merchant state DB"
        );
        let merch_state: MerchantMPCState =
            handle_error_result!(serde_json::from_str(&ser_merch_state));

        let key2 = String::from("cli:merch_channels");
        let channel_token_key = format!("id:{}", channel_id);
        let ser_channel_token = handle_error_with_string!(
            get_file_from_db(&mut db.conn, &key2, &channel_token_key),
            "Invalid channel ID"
        );
        let channel_token: ChannelMPCToken =
            handle_error_result!(serde_json::from_str(&ser_channel_token));

        let escrow_txid = channel_token.escrow_txid.0.to_vec();

        let (merch_close_tx, txid_be, _) =
            handle_error_result!(mpc::merchant_close(&escrow_txid, &merch_state));
        write_pathfile(out_file, hex::encode(merch_close_tx))?;
        println!("merch-close-tx signed txid: {}", hex::encode(txid_be));
        Ok(())
    }
}
