extern crate rand;
extern crate zkchannels;
extern crate secp256k1;
extern crate structopt;
extern crate serde;
extern crate bufstream;
extern crate sha2;

#[cfg(feature = "mpc-bitcoin")]
use zkchannels::mpc;
use structopt::StructOpt;
use std::str::FromStr;
use serde::Deserialize;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread::{spawn, sleep};
use std::time;
use bufstream::BufStream;
use sha2::{Sha256, Digest};
use rand::{RngCore, Rng};
use std::io::{BufRead, Write, Read};
use zkchannels::mpc::FixedSizeArray;

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Command {
    INIT,
    PAY,
    CLOSE,
}

impl FromStr for Command {
    type Err = serde_json::error::Error;
    fn from_str(s: &str) -> Result<Command, serde_json::error::Error> {
        Ok(serde_json::from_str(&format!("\"{}\"", s))?)
    }
}

#[derive(StructOpt)]
struct Cli {
    command: Command,
    #[structopt(short = "c", long = "party")]
    party: Party,
    #[structopt(short = "a", long = "amount", required_if("command", "pay"))]
    amount: Option<i64>,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String,
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
                Ok(mut stream) => {
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

#[cfg(not(feature = "mpc-bitcoin"))]
fn main() {
    println!("Not activated!");
}

#[cfg(feature = "mpc-bitcoin")]
fn main() {
    println!("******************************************");

    let args = Cli::from_args();
    let mut conn = &mut Conn::new(args.own_ip, args.own_port, args.other_ip, args.other_port);

    match args.command {
        Command::INIT => match args.party {
            Party::MERCH => merch::init(&mut conn),
            Party::CUST => cust::init(&mut conn),
        },
        Command::PAY => match args.party {
            Party::MERCH => merch::pay(args.amount.unwrap(), &mut conn),
            Party::CUST => cust::pay(args.amount.unwrap(), &mut conn),
        },
        Command::CLOSE => match args.party {
            Party::MERCH => println!("close can only be called on CUST"),
            Party::CUST => cust::close(&mut conn),
        },
    }

    println!("******************************************");
}

#[cfg(feature = "mpc-bitcoin")]
mod cust {
    use super::*;
    use zkchannels::channels_mpc::{ChannelMPCToken, ChannelMPCState, CustomerMPCState, MaskedTxMPCInputs};
    use std::fs::File;
    use zkchannels::mpc::RevokedState;

    pub fn init(conn: &mut Conn) {
        let rng = &mut rand::thread_rng();

        let msg0 = conn.wait_for(None, false);
        let channel_state: ChannelMPCState = serde_json::from_str(&msg0.get(0).unwrap()).unwrap();
        let pk_m: secp256k1::PublicKey = serde_json::from_str(&msg0.get(1).unwrap()).unwrap();

        // TODO: generating real funding tx
        let tx = generate_funding_tx(rng);

        let (channel_token, mut cust_state) = mpc::init_customer(rng, &pk_m, tx, 100, 100, "Cust");

        let s0 = mpc::activate_customer(rng, &mut cust_state);

        let msg1 = [serde_json::to_string(&channel_token).unwrap(), serde_json::to_string(&s0).unwrap()];
        let msg2 = conn.send_and_wait(&msg1, Some(String::from("Sending channel token and state (s0)")), true);

        let pay_token: [u8; 32] = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        println!("Obtained pay token (p0): {:?}", pay_token);
        mpc::activate_customer_finalize(pay_token, &mut cust_state);

        println!("Saving the customer state...");
        save_state_cust(channel_state, channel_token, cust_state);
    }

    pub fn pay(amount: i64, conn: &mut Conn) {
        let rng = &mut rand::thread_rng();

        let mut file = File::open("cust_channel_state.txt").unwrap();
        let mut ser_channel_state = String::new();
        file.read_to_string(&mut ser_channel_state).unwrap();
        let mut channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();
        let mut file1 = File::open("cust_state.txt").unwrap();
        let mut ser_cust_state = String::new();
        file1.read_to_string(&mut ser_cust_state).unwrap();
        let mut cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();
        let mut file2 = File::open("cust_channel_token.txt").unwrap();
        let mut ser_channel_token = String::new();
        file2.read_to_string(&mut ser_channel_token).unwrap();
        let mut channel_token: ChannelMPCToken = serde_json::from_str(&ser_channel_token).unwrap();

        let t = cust_state.get_randomness();
        let old_state = cust_state.get_current_state();

        let (new_state, r_com, rev_lock, rev_secret) = mpc::pay_prepare_customer(rng, &mut channel_state, amount, &mut cust_state);

        let msg = [hex::encode(old_state.nonce), hex::encode(&r_com)];
        let msg1 = conn.send_and_wait(&msg, Some(String::from("nonce and rev_lock com")), true);
        let pay_token_mask_com_vec = hex::decode(msg1.get(0).unwrap()).unwrap();
        let mut pay_token_mask_com = [0u8; 32];
        pay_token_mask_com.copy_from_slice(pay_token_mask_com_vec.as_slice());

        let result = mpc::pay_customer(&mut channel_state, &mut channel_token, old_state, new_state, pay_token_mask_com, r_com, amount, &mut cust_state);
        let mut is_ok = result.is_ok() && result.unwrap();

        let msg2 = conn.wait_for(None, false);
        let mask_bytes: MaskedTxMPCInputs = serde_json::from_str(msg2.get(0).unwrap()).unwrap();

        is_ok = is_ok && mpc::pay_unmask_tx_customer(&mut channel_state, &mut channel_token, mask_bytes, &mut cust_state);

        let rev_state = RevokedState::new(old_state.nonce,r_com, rev_lock, rev_secret, t);
        let msg3 = [serde_json::to_string(&rev_state).unwrap()];
        let msg4 = conn.send_and_wait(&msg3, None, false);
        let pt_mask_bytes_vec = hex::decode(msg4.get(0).unwrap()).unwrap();
        let mut pt_mask_bytes = [0u8; 32];
        pt_mask_bytes.copy_from_slice(pt_mask_bytes_vec.as_slice());

        is_ok = is_ok && mpc::pay_unmask_pay_token_customer(pt_mask_bytes, &mut cust_state);

        conn.send(&[is_ok.to_string()]);
        match is_ok {
            true => println!("Transaction succeeded!"),
            false => println!("Transaction failed!")
        }

        save_state_cust(channel_state, channel_token, cust_state);
    }

    pub fn close(conn: &mut Conn) {
        let mut file1 = File::open("cust_state.txt").unwrap();
        let mut ser_cust_state = String::new();
        file1.read_to_string(&mut ser_cust_state).unwrap();
        let cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();
    }

    fn save_state_cust(channel_state: ChannelMPCState, channel_token: ChannelMPCToken, cust_state: CustomerMPCState) {
        let mut file = File::create("cust_channel_state.txt").unwrap();
        file.write_all(serde_json::to_string(&channel_state).unwrap().as_ref());
        let mut file1 = File::create("cust_state.txt").unwrap();
        file1.write_all(serde_json::to_string(&cust_state).unwrap().as_ref());
        let mut file2 = File::create("cust_channel_token.txt").unwrap();
        file2.write_all(serde_json::to_string(&channel_token).unwrap().as_ref());
    }
}

#[cfg(feature = "mpc-bitcoin")]
mod merch {
    use super::*;
    use zkchannels::channels_mpc::{ChannelMPCState, ChannelMPCToken, MerchantMPCState};
    use zkchannels::wallet::State;
    use std::fs::File;

    pub fn init(conn: &mut Conn) {
        let rng = &mut rand::thread_rng();

        let mut channel_state = ChannelMPCState::new("Channel".parse().unwrap(), false);
        let mut merch_state = mpc::init_merchant(rng, &mut channel_state, "Merch");

        let msg1 = [serde_json::to_string(&channel_state).unwrap(), serde_json::to_string(&merch_state.pk_m).unwrap()];

        let msg2 = conn.send_and_wait(&msg1, Some(String::from("Sending channel state and pk_m")), true);

        let channel_token: ChannelMPCToken = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        let s0: State = serde_json::from_str(msg2[1].as_ref()).unwrap();

        let pay_token = mpc::activate_merchant(channel_token, &s0, &mut merch_state);

        let msg3 = [serde_json::to_string(&pay_token).unwrap()];
        conn.send(&msg3);

        save_state_merch(channel_state, merch_state);
    }

    pub fn pay(amount: i64, conn: &mut Conn) {
        let rng = &mut rand::thread_rng();

        let mut file = File::open("merch_channel_state.txt").unwrap();
        let mut ser_channel_state = String::new();
        file.read_to_string(&mut ser_channel_state).unwrap();
        let mut channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();
        let mut file1 = File::open("merch_state.txt").unwrap();
        let mut ser_merch_state = String::new();
        file1.read_to_string(&mut ser_merch_state).unwrap();
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
        let msg3 = [serde_json::to_string(&masked_inputs).unwrap()];
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

        save_state_merch(channel_state, merch_state);
    }

    fn save_state_merch(channel_state: ChannelMPCState, merch_state: MerchantMPCState) {
        let mut file = File::create("merch_channel_state.txt").unwrap();
        file.write_all(serde_json::to_string(&channel_state).unwrap().as_ref());
        let mut file1 = File::create("merch_state.txt").unwrap();
        file1.write_all(serde_json::to_string(&merch_state).unwrap().as_ref());
    }
}

#[cfg(feature = "mpc-bitcoin")]
fn generate_funding_tx<R: Rng>(csprng: &mut R) -> mpc::FundingTxInfo {
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

        return mpc::FundingTxInfo { escrow_txid: FixedSizeArray(escrow_txid),
                                    merch_txid: FixedSizeArray(merch_txid),
                                    escrow_prevout: FixedSizeArray(escrow_prevout),
                                    merch_prevout: FixedSizeArray(merch_prevout) };
}
