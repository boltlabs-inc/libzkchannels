extern crate rand;
extern crate zkchannels;
extern crate secp256k1;
extern crate structopt;
extern crate serde;
extern crate bufstream;
extern crate sha2;
extern crate wagyu_bitcoin as bitcoin;
extern crate wagyu_model;

#[cfg(feature = "mpc-bitcoin")]
use zkchannels::mpc;
use structopt::StructOpt;
use std::str::FromStr;
use serde::Deserialize;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::sleep;
use std::time;
use bufstream::BufStream;
use rand::Rng;
use std::io::{BufRead, Write, Read};
use std::path::PathBuf;
use zkchannels::FundingTxInfo;
use std::fs::File;

macro_rules! handle_serde_error {
    ($e:expr) => (match $e {
        Ok(val) => val,
        Err(err) => return Err(err.to_string()),
    });
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, StructOpt, Deserialize)]
pub struct Init {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(long = "funding-tx")]
    funding_tx_file: Option<PathBuf>,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String,
    #[structopt(short = "d", long = "dust-limit", default_value = "0")]
    dust_limit: i64,
    #[structopt(short = "t", long = "tx-fee", default_value = "0")]
    tx_fee: i64
}

#[derive(Debug, StructOpt, Deserialize)]
pub struct Pay {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(short = "a", long = "amount")]
    amount: Option<i64>,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String,
    #[structopt(short)]
    verbose: bool
}

#[derive(Debug, StructOpt, Deserialize)]
pub struct Close {
    #[structopt(long = "party")]
    party: Party,
    #[structopt(short = "f", long = "file")]
    file: PathBuf,
    #[structopt(short = "e", long = "from-escrow")]
    from_escrow: bool,
    #[structopt(short = "c", long = "channel-token")]
    channel_token: Option<PathBuf>
}

#[derive(Debug, StructOpt, Deserialize)]
pub enum Command {
    #[structopt(name = "init")]
    INIT(Init),
    #[structopt(name = "unlink")]
    UNLINK(Pay),
    #[structopt(name = "pay")]
    PAY(Pay),
    #[structopt(name = "close")]
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
        Err(e) => return Err(e.to_string())
    };
    let mut content = String::new();
    let content_len = match file.read_to_string(&mut content) {
      Ok(n) => n,
        Err(e) => return Err(e.to_string())
    };
    assert!(content_len > 0);
    Ok(content)
}

pub fn read_pathfile(path_buf: PathBuf) -> Result<String, String> {
    let mut file = match File::open(path_buf) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string())
    };
    let mut content = String::new();
    let content_len = match file.read_to_string(&mut content) {
      Ok(n) => n,
        Err(e) => return Err(e.to_string())
    };
    assert!(content_len > 0);
    Ok(content)
}

pub fn write_file(file_name: &'static str, content: String) -> Result<(), String> {
    let mut file = match File::create(file_name) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string())
    };
    match file.write_all(content.as_ref()) {
        Ok(n) => Ok(n),
        Err(e) => return Err(e.to_string())
    }
}

pub fn write_pathfile(path_buf: PathBuf, content: String) -> Result<(), String> {
    let mut file = match File::create(path_buf) {
        Ok(n) => n,
        Err(e) => return Err(e.to_string())
    };
    match file.write_all(content.as_ref()) {
        Ok(n) => Ok(n),
        Err(e) => return Err(e.to_string())
    }
}


#[derive(StructOpt, Debug)]
#[structopt(name = "zkchannels-mpc")]
struct Cli {
    #[structopt(subcommand, help = "Options: init, pay, or close")]
    command: Command,
}

pub struct Conn {
    in_addr: SocketAddr,
    out_addr: SocketAddr,
}

impl Conn {
    pub fn new(own_ip: String, own_port: String, other_ip: String, other_port: String) -> Conn {
        let in_addr = own_ip + ":" + own_port.as_ref();
        let in_addr_sock = SocketAddr::from_str(in_addr.as_ref()).unwrap();

        let out_addr = other_ip + ":" + other_port.as_ref();
        let out_addr_sock = SocketAddr::from_str(out_addr.as_ref()).unwrap();

        Conn { in_addr: in_addr_sock, out_addr: out_addr_sock }
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

    pub fn send_and_wait(&mut self, msg: &[String], label: Option<String>, verbose: bool) -> Vec<String> {
        self.send(msg);
        self.wait_for(label, verbose)
    }

    pub fn wait_for(&mut self, label: Option<String>, verbose: bool) -> Vec<String> {
        let listener = TcpListener::bind(self.in_addr).unwrap();
        let mut out: Vec<String> = vec! {};

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let mut buf_stream = BufStream::new(stream);
                    loop {
                        let mut reads = String::new();
                        buf_stream.read_line(&mut reads).unwrap();
                        if reads == "end\n" {
                            if verbose && label.is_some() { println!("{}: {:?}", label.unwrap(), out); }
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

#[cfg(feature = "mpc-bitcoin")]
fn main() {
    println!("******************************************");

    let args = Cli::from_args();

    match args.command {
        Command::INIT(init) => match init.party {
            Party::MERCH => match merch::init(&mut Conn::new(init.own_ip, init.own_port, init.other_ip, init.other_port), init.dust_limit) {
                Err(e) => println!("Initialize phase failed with error: {}", e),
                _ => ()
            },
            Party::CUST => match cust::init(&mut Conn::new(init.own_ip, init.own_port, init.other_ip, init.other_port), init.funding_tx_file) {
                Err(e) => println!("Initialize phase failed with error: {}", e),
                _ => ()
            },
        },
        Command::UNLINK(unlink) => match unlink.party {
            Party::MERCH => merch::pay(0,
                                       &mut Conn::new(unlink.own_ip, unlink.own_port, unlink.other_ip, unlink.other_port)).unwrap(),
            Party::CUST => cust::pay(0,
                                     &mut Conn::new(unlink.own_ip, unlink.own_port, unlink.other_ip, unlink.other_port),
                                     unlink.verbose).unwrap(),
        },
        Command::PAY(pay) => match pay.party {
            Party::MERCH => match merch::pay(pay.amount.unwrap(),
                                       &mut Conn::new(pay.own_ip, pay.own_port, pay.other_ip, pay.other_port)) {
                Err(e) => println!("Pay phase failed with error: {}", e),
                _ => ()
            },
            Party::CUST => match cust::pay(pay.amount.unwrap(),
                                     &mut Conn::new(pay.own_ip, pay.own_port, pay.other_ip, pay.other_port),
                                     pay.verbose) {
                Err(e) => println!("Pay protocol failed with error: {}", e),
                _ => ()
            },
        },
        Command::CLOSE(close) => match close.party {
            Party::MERCH => merch::close(close.file, close.channel_token).unwrap(),
            Party::CUST => cust::close(close.file, close.from_escrow).unwrap(),
        },
    }

    println!("******************************************");
}

#[cfg(feature = "mpc-bitcoin")]
mod cust {
    use super::*;
    use zkchannels::channels_mpc::{ChannelMPCToken, ChannelMPCState, CustomerMPCState, MaskedTxMPCInputs};
    use zkchannels::mpc::RevokedState;

    pub fn init(conn: &mut Conn, funding_tx_file: Option<PathBuf>) -> Result<(), String> {
        let rng = &mut rand::thread_rng();

        let msg0 = conn.wait_for(None, false);
        let channel_state: ChannelMPCState = serde_json::from_str(&msg0.get(0).unwrap()).unwrap();
        let pk_m: secp256k1::PublicKey = serde_json::from_str(&msg0.get(1).unwrap()).unwrap();

        let ser_funding_tx = match funding_tx_file {
            Some(f) => read_pathfile(f).unwrap(),
            None => {
                let s = String::from("--funding-tx argument is required for customer");
                println!("{}", s);
                return Err(s);
            }
        };
        let funding_tx: FundingTxInfo = serde_json::from_str(&ser_funding_tx).unwrap();
        // TODO: validate the FundingTxInfo struct with respect to Bitcoin client

        let (channel_token, mut cust_state) = mpc::init_customer(rng, &pk_m, funding_tx, "Customer");

        let s0 = mpc::activate_customer(rng, &mut cust_state);

        let msg1 = [handle_serde_error!(serde_json::to_string(&channel_token)), handle_serde_error!(serde_json::to_string(&s0))];
        let msg2 = conn.send_and_wait(&msg1, Some(String::from("Sending channel token and state (s0)")), true);

        let pay_token: [u8; 32] = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        println!("Obtained pay token (p0): {:?}", pay_token);
        mpc::activate_customer_finalize(pay_token, &mut cust_state);

        println!("Saving the customer state...");
        save_state_cust(channel_state, channel_token, cust_state)
    }

    pub fn pay(amount: i64, conn: &mut Conn, verbose: bool) -> Result<(), String> {
        let rng = &mut rand::thread_rng();

        let ser_channel_state = read_file("cust_channel_state.json").unwrap();
        let mut channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();

        let ser_cust_state = read_file("cust_state.json").unwrap();
        let mut cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();

        let ser_channel_token = read_file("cust_channel_token.json").unwrap();
        let mut channel_token: ChannelMPCToken = handle_serde_error!(serde_json::from_str(&ser_channel_token));

        let t = cust_state.get_randomness();
        let old_state = cust_state.get_current_state();
//        // check if there is sufficient balance for payment
//        if amount > old_state.bc {
//            println!("Insufficient funds to make payment. Current balance is {}", old_state.bc);
//            return Err(String::from("Insufficient funds!"));
//        }

        // prepare phase
        let (new_state, r_com, rev_lock, rev_secret) = match mpc::pay_prepare_customer(rng, &mut channel_state, amount, &mut cust_state) {
            Ok(n) => n,
            Err(e) => return Err(e)
        };
        if verbose {
            println!("old state: {}", &old_state);
            println!("new state: {}", &new_state);
        }

        let msg = [hex::encode(&old_state.get_nonce()), hex::encode(&r_com)];
        let msg1 = conn.send_and_wait(&msg, Some(String::from("nonce and rev_lock com")), true);
        let pay_token_mask_com_vec = hex::decode(msg1.get(0).unwrap()).unwrap();
        let mut pay_token_mask_com = [0u8; 32];
        pay_token_mask_com.copy_from_slice(pay_token_mask_com_vec.as_slice());

        // execute the mpc phase
        let result = mpc::pay_customer(&mut channel_state, &mut channel_token, old_state, new_state, pay_token_mask_com, r_com, amount, &mut cust_state);
        let mut is_ok = result.is_ok() && result.unwrap();

        let msg2 = conn.wait_for(None, false);
        let mask_bytes: MaskedTxMPCInputs = serde_json::from_str(msg2.get(0).unwrap()).unwrap();

        // unmask the closing tx
        is_ok = is_ok && mpc::pay_unmask_tx_customer(&mut channel_state, &mut channel_token, mask_bytes, &mut cust_state);

        let rev_state = RevokedState::new(old_state.get_nonce(),r_com, rev_lock, rev_secret, t);
        let msg3 = [serde_json::to_string(&rev_state).unwrap()];
        let msg4 = conn.send_and_wait(&msg3, None, false);
        let pt_mask_bytes_vec = hex::decode(msg4.get(0).unwrap()).unwrap();
        let mut pt_mask_bytes = [0u8; 32];
        pt_mask_bytes.copy_from_slice(pt_mask_bytes_vec.as_slice());

        // unmask the pay token
        is_ok = is_ok && mpc::pay_unmask_pay_token_customer(pt_mask_bytes, &mut cust_state);

        conn.send(&[is_ok.to_string()]);
        match is_ok {
            true => println!("Transaction succeeded!"),
            false => println!("Transaction failed!")
        }

        save_state_cust(channel_state, channel_token, cust_state)
    }

    pub fn close(out_file: PathBuf, from_escrow: bool) -> Result<(), String> {
        let ser_cust_state = read_file("cust_state.json").unwrap();
        let cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();

        let closing_tx = match from_escrow {
            true => cust_state.get_cust_close_escrow_tx(),
            false => cust_state.get_cust_close_merch_tx()
        };

        // write out to a file
        write_pathfile(out_file, closing_tx)?;
        Ok(())
    }

    fn save_state_cust(channel_state: ChannelMPCState, channel_token: ChannelMPCToken, cust_state: CustomerMPCState) -> Result<(), String> {
        write_file("cust_channel_state.json", handle_serde_error!(serde_json::to_string(&channel_state)))?;
        write_file("cust_state.json", handle_serde_error!(serde_json::to_string(&cust_state)))?;
        write_file("cust_channel_token.json", handle_serde_error!(serde_json::to_string(&channel_token)))?;

        Ok(())
    }
}

#[cfg(feature = "mpc-bitcoin")]
mod merch {
    use super::*;
    use zkchannels::channels_mpc::{ChannelMPCState, ChannelMPCToken, MerchantMPCState};
    use zkchannels::wallet::State;

    pub fn init(conn: &mut Conn, dust_limit: i64) -> Result<(), String> {
        let rng = &mut rand::thread_rng();

        let mut channel_state = ChannelMPCState::new(String::from("Channel"), false);
        if dust_limit == 0 {
            let s = format!("Dust limit must be greater than 0!");
            return Err(s);
        }
        channel_state.set_dust_limit(dust_limit);

        let mut merch_state = mpc::init_merchant(rng, &mut channel_state, "Merchant");

        let msg1 = [handle_serde_error!(serde_json::to_string(&channel_state)), handle_serde_error!(serde_json::to_string(&merch_state.pk_m))];

        let msg2 = conn.send_and_wait(&msg1, Some(String::from("Sending channel state and pk_m")), true);

        let channel_token: ChannelMPCToken = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        let s0: State = serde_json::from_str(msg2[1].as_ref()).unwrap();

        let pay_token = mpc::activate_merchant(channel_token, &s0, &mut merch_state);

        let msg3 = [handle_serde_error!(serde_json::to_string(&pay_token))];
        conn.send(&msg3);

        save_state_merch(channel_state, merch_state)
    }

    pub fn pay(amount: i64, conn: &mut Conn) -> Result<(), String> {
        let rng = &mut rand::thread_rng();

        let ser_channel_state = read_file("merch_channel_state.json").unwrap();
        let mut channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();

        let ser_merch_state = read_file("merch_state.json").unwrap();
        let mut merch_state: MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();

        let msg0 = conn.wait_for(None, false);
        let nonce_vec = hex::decode(msg0.get(0).unwrap()).unwrap();
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(nonce_vec.as_slice());
        let rev_lock_com_vec = hex::decode(msg0.get(1).unwrap()).unwrap();
        let mut rev_lock_com = [0u8; 32];
        rev_lock_com.copy_from_slice(rev_lock_com_vec.as_slice());

        let pay_token_mask_com = mpc::pay_prepare_merchant(rng, nonce, &mut merch_state);

        let msg1 = [hex::encode(&pay_token_mask_com)];
        conn.send(&msg1);

        let result = mpc::pay_merchant(rng, &mut channel_state, nonce, pay_token_mask_com, rev_lock_com, amount, &mut merch_state);
        let masked_inputs = result.unwrap();
        let msg3 = [handle_serde_error!(serde_json::to_string(&masked_inputs))];
        let msg4 = conn.send_and_wait(&msg3, Some(String::from("Received revoked state")), true);
        let rev_state = serde_json::from_str(msg4.get(0).unwrap()).unwrap();

        let pt_mask_bytes = mpc::pay_validate_rev_lock_merchant(rev_state, &mut merch_state);

        let msg5 = [hex::encode(&pt_mask_bytes.unwrap())];
        let msg6 = conn.send_and_wait(&msg5, Some(String::from("Sending masked pt bytes")), true);

        if msg6.get(0).unwrap() == "true" {
            println!("Transaction succeeded!")
        } else {
            println!("Transaction failed!")
        }

        save_state_merch(channel_state, merch_state)
    }

    fn save_state_merch(channel_state: ChannelMPCState, merch_state: MerchantMPCState) -> Result<(), String> {
        write_file("merch_channel_state.json", handle_serde_error!(serde_json::to_string(&channel_state)))?;
        write_file("merch_state.json", handle_serde_error!(serde_json::to_string(&merch_state)))?;
        Ok(())
    }

    pub fn close(out_file: PathBuf, channel_token_file: Option<PathBuf>) -> Result<(), String> {
        // output the merch-close-tx (only thing merchant can broadcast to close channel)
        let ser_merch_state = read_file("merch_state.json").unwrap();
        let merch_state: MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();

        let ser_channel_token = match channel_token_file {
            Some(ctf) => read_pathfile(ctf).unwrap(),
            None => return Err(String::from("Channel-token file required!"))
        };
        let channel_token: ChannelMPCToken = serde_json::from_str(&ser_channel_token).unwrap();

        let channel_id = match channel_token.compute_channel_id() {
            Ok(n) => hex::encode(&n),
            Err(e) => return Err(e.to_string())
        };

        // TODO: get the merch-close-tx for the given channel-id
        let merch_close_tx = String::from("retrieve the merch-close-tx here from merch-state for channel-id");
        write_pathfile(out_file, merch_close_tx)?;
        Ok(())
    }
}
