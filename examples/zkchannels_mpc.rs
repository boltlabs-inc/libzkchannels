extern crate rand;
extern crate zkchannels;
extern crate time;
extern crate secp256k1;
extern crate structopt;
extern crate serde;
extern crate bufstream;
extern crate sha2;

#[cfg(feature = "mpc-bitcoin")]
use zkchannels::mpc;
use std::time::Instant;
use zkchannels::handle_bolt_result;
use structopt::StructOpt;
use std::str::FromStr;
use serde::Deserialize;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread::spawn;
use bufstream::BufStream;
use sha2::{Sha256, Digest};
use rand::{RngCore, Rng};
use std::io::{BufRead, Write, Read};

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
    #[structopt(short = "i", long = "own-ip")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip")]
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
        match TcpStream::connect(self.out_addr) {
            Ok(mut stream) => {
                let mut buf_stream = BufStream::new(stream);
                for msg0 in msg {
                    buf_stream.write((msg0.to_owned() + "\n").as_ref()).unwrap();
                }
                buf_stream.write(b"end\n").unwrap();
                buf_stream.flush().unwrap();
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
            }
        }
    }

    pub fn send_and_wait(&mut self, msg: &[String]) -> Vec<String> {
        self.send(msg);
        self.wait_for()
    }

    pub fn wait_for(&mut self) -> Vec<String> {
        let listener = TcpListener::bind(self.in_addr).unwrap();
        let mut out: Vec<String> = vec! {};

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buf_stream = BufStream::new(stream);
                    loop {
                        let mut reads = String::new();
                        buf_stream.read_line( &mut reads).unwrap();
                        if reads.contains("end") {
                            return out;
                        }
                        if reads != "" {
                            out.push(reads);
                        }
                    }
                },
                Err(err) => println!("Not good: {:?}", err),
            }
        }

        out
    }
}

fn main() {
    println!("******************************************");
    println!(" MPC example goes here!");

    let args = Cli::from_args();
    let mut conn = &mut Conn::new(args.own_ip, args.own_port, args.other_ip, args.other_port);

    match args.command {
        Command::INIT => match args.party {
            Party::MERCH => merch::init(&mut conn),
            Party::CUST => cust::init(&mut conn),
        },
        Command::PAY => match args.party {
            Party::MERCH => merch::pay(&mut conn),
            Party::CUST => cust::pay(&mut conn),
        },
        Command::CLOSE => match args.party {
            Party::MERCH => println!("close can only be called on CUST"),
            Party::CUST => cust::close(&mut conn),
        },
    }

    println!("******************************************");
}


mod cust {
    use super::*;
    use zkchannels::channels_mpc::{ChannelMPCToken, ChannelMPCState, CustomerMPCState};
    use std::fs::File;

    pub fn init(conn: &mut Conn) {
        let rng = &mut rand::thread_rng();

        let msg0 = conn.wait_for();
        let channel_state: ChannelMPCState = serde_json::from_str(&msg0.get(0).unwrap()).unwrap();
        let pk_m: secp256k1::PublicKey = serde_json::from_str(&msg0.get(1).unwrap()).unwrap();
        let tx = generate_funding_tx(rng);
        let (channel_token, mut cust_state) = mpc::init_customer(rng, &pk_m, tx, 100, 100, "Cust");
        let s0 = mpc::activate_customer(rng, &mut cust_state);
        let msg1 = [serde_json::to_string(&channel_token).unwrap(), serde_json::to_string(&s0).unwrap()];
        let msg2 = conn.send_and_wait(&msg1);
        let pay_token: [u8; 32] = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();

        mpc::activate_customer_finalize(pay_token, &mut cust_state);

        let mut file = File::create("cust_channel_state.txt").unwrap();
        file.write_all(serde_json::to_string(&channel_state).unwrap().as_ref());

        let mut file1 = File::create("cust_state.txt").unwrap();
        file1.write_all(serde_json::to_string(&cust_state).unwrap().as_ref());

        let mut file2 = File::create("cust_channel_token.txt").unwrap();
        file2.write_all(serde_json::to_string(&channel_token).unwrap().as_ref());
    }

    pub fn pay(conn: &mut Conn) {
        let mut file = File::open("cust_channel_state.txt").unwrap();
        let mut ser_channel_state = String::new();
        file.read_to_string(&mut ser_channel_state).unwrap();
        let channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();
        let mut file1 = File::open("cust_state.txt").unwrap();
        let mut ser_cust_state = String::new();
        file1.read_to_string(&mut ser_cust_state).unwrap();
        let cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();
        let mut file2 = File::open("cust_channel_token.txt").unwrap();
        let mut ser_channel_token = String::new();
        file2.read_to_string(&mut ser_channel_token).unwrap();
        let channel_token: ChannelMPCToken = serde_json::from_str(&ser_channel_token).unwrap();

    }

    pub fn close(conn: &mut Conn) {
        let mut file1 = File::open("cust_state.txt").unwrap();
        let mut ser_cust_state = String::new();
        file1.read_to_string(&mut ser_cust_state).unwrap();
        let cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();

    }
}

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

        let msg2 = conn.send_and_wait(&msg1);

        let channel_token: ChannelMPCToken = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        let s0: State = serde_json::from_str(msg2[1].as_ref()).unwrap();

        let pay_token = mpc::activate_merchant(channel_token, &s0, &mut merch_state);

        let msg3 = [serde_json::to_string(&pay_token).unwrap()];
        conn.send(&msg3);

        let mut file = File::create("merch_channel_state.txt").unwrap();
        file.write_all(serde_json::to_string(&channel_state).unwrap().as_ref());


        let mut file1 = File::create("merch_state.txt").unwrap();
        file1.write_all(serde_json::to_string(&merch_state).unwrap().as_ref());

    }

    pub fn pay(conn: &mut Conn) {
        let mut file = File::open("merch_channel_state.txt").unwrap();
        let mut ser_channel_state = String::new();
        file.read_to_string(&mut ser_channel_state).unwrap();
        let cust_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();
        let mut file1 = File::open("merch_state.txt").unwrap();
        let mut ser_merch_state = String::new();
        file1.read_to_string(&mut ser_merch_state).unwrap();
        let cust_state: MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();

    }
}

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

    return mpc::FundingTxInfo { escrow_txid, merch_txid, escrow_prevout, merch_prevout };
}