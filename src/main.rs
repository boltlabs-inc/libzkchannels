extern crate rand;
extern crate zkchannels;
extern crate secp256k1;
extern crate structopt;
extern crate serde;
extern crate bufstream;
extern crate sha2;
extern crate wagyu_bitcoin as bitcoin;

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
use zkchannels::fixed_size_array::FixedSizeArray32;
use std::path::{PathBuf, Path};
use bitcoin::network::BitcoinNetwork;
use bitcoin::Testnet;
use zkchannels::transactions::{Input, BitcoinTxConfig, MultiSigOutput, Output, SATOSHI};
use zkchannels::transactions::btc::{create_escrow_transaction, sign_escrow_transaction};

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

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct Escrow {
    #[structopt(short = "t", long = "txid")]
    txid: String,
    #[structopt(short = "i", long = "index")]
    index: u32,
    #[structopt(short = "a", long = "input_sats")]
    input_sats: i64,
    #[structopt(short = "o", long = "output_sats")]
    output_sats: i64,
    #[structopt(long = "cust_sk")]
    cust_privkey: String,
    #[structopt(long = "cust_pk")]
    cust_pubkey: String,
    #[structopt(long = "merch_pk")]
    merch_pubkey: String,
    #[structopt(long = "change_pk")]
    change_pubkey: Option<String>,
    #[structopt(long = "file")]
    file: PathBuf
}

#[derive(Debug, StructOpt, Deserialize)]
pub struct Initial {
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String
}

#[derive(Debug, StructOpt, Deserialize)]
pub struct Connect {
    #[structopt(short = "a", long = "amount")]
    amount: Option<i64>,
    #[structopt(short = "i", long = "own-ip", default_value = "127.0.0.1")]
    own_ip: String,
    #[structopt(short = "p", long = "own-port")]
    own_port: String,
    #[structopt(short = "j", long = "other-ip", default_value = "127.0.0.1")]
    other_ip: String,
    #[structopt(short = "q", long = "other-port")]
    other_port: String
}

#[derive(Debug, StructOpt, Deserialize)]
pub struct Close {
    #[structopt(short = "f", long = "file")]
    file: PathBuf,
    #[structopt(short = "e", long = "escrow")]
    from_escrow: bool
}

#[derive(Debug, StructOpt, Deserialize)]
pub enum Command {
    #[structopt(name = "escrow")]
    ESCROW(Escrow),
    #[structopt(name = "init")]
    INIT(Initial),
    #[structopt(name = "pay")]
    PAY(Connect),
    #[structopt(name = "close")]
    CLOSE(Close),
}

impl FromStr for Command {
    type Err = serde_json::error::Error;
    fn from_str(s: &str) -> Result<Command, serde_json::error::Error> {
        Ok(serde_json::from_str(&format!("\"{}\"", s))?)
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "zkchannels-mpc")]
struct Cli {
    #[structopt(subcommand, help = "Options: escrow, init, pay, or close")]
    command: Command,
    #[structopt(short = "c", long = "party")]
    party: Party
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
    // println!("{:?}", args.command);

    match args.command {
        Command::INIT(init) => match args.party {
            Party::MERCH => merch::init(&mut Conn::new(init.own_ip, init.own_port, init.other_ip, init.other_port)),
            Party::CUST => cust::init(&mut Conn::new(init.own_ip, init.own_port, init.other_ip, init.other_port)),
        },
        Command::PAY(payment) => match args.party {
            Party::MERCH => merch::pay(payment.amount.unwrap(),
                                       &mut Conn::new(payment.own_ip, payment.own_port, payment.other_ip, payment.other_port)),
            Party::CUST => cust::pay(payment.amount.unwrap(),
                                     &mut Conn::new(payment.own_ip, payment.own_port, payment.other_ip, payment.other_port)),
        },
        Command::CLOSE(close) => match args.party {
            Party::MERCH => merch::close(close.file),
            Party::CUST => cust::close(close.file, close.from_escrow),
        },
        Command::ESCROW(escrow) => match args.party {
            Party::CUST => cust::construct_escrow_transaction(escrow),
            _ => println!("Customer is supposed to fund the channel")
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
    use zkchannels::transactions::btc::create_input;

    pub fn init(conn: &mut Conn) {
        let rng = &mut rand::thread_rng();

        let msg0 = conn.wait_for(None, false);
        let channel_state: ChannelMPCState = serde_json::from_str(&msg0.get(0).unwrap()).unwrap();
        let pk_m: secp256k1::PublicKey = serde_json::from_str(&msg0.get(1).unwrap()).unwrap();

        // TODO: generating real funding tx and replace with external values
        // TODO: validate the FundingTxInfo struct with respect to Bitcoin client
        let b0_cust = 100;
        let b0_merch = 100;
        let tx = generate_funding_tx(rng, b0_cust, b0_merch);

        let (channel_token, mut cust_state) = mpc::init_customer(rng, &pk_m, tx, "Cust");

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

        let mut file = File::open("cust_channel_state.json").unwrap();
        let mut ser_channel_state = String::new();
        file.read_to_string(&mut ser_channel_state).unwrap();
        let mut channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();
        let mut file1 = File::open("cust_state.json").unwrap();
        let mut ser_cust_state = String::new();
        file1.read_to_string(&mut ser_cust_state).unwrap();
        let mut cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();
        let mut file2 = File::open("cust_channel_token.json").unwrap();
        let mut ser_channel_token = String::new();
        file2.read_to_string(&mut ser_channel_token).unwrap();
        let mut channel_token: ChannelMPCToken = serde_json::from_str(&ser_channel_token).unwrap();

        let t = cust_state.get_randomness();
        let old_state = cust_state.get_current_state();

        let (new_state, r_com, rev_lock, rev_secret) = mpc::pay_prepare_customer(rng, &mut channel_state, amount, &mut cust_state);

        let msg = [hex::encode(&old_state.get_nonce()), hex::encode(&r_com)];
        let msg1 = conn.send_and_wait(&msg, Some(String::from("nonce and rev_lock com")), true);
        let pay_token_mask_com_vec = hex::decode(msg1.get(0).unwrap()).unwrap();
        let mut pay_token_mask_com = [0u8; 32];
        pay_token_mask_com.copy_from_slice(pay_token_mask_com_vec.as_slice());

        let result = mpc::pay_customer(&mut channel_state, &mut channel_token, old_state, new_state, pay_token_mask_com, r_com, amount, &mut cust_state);
        let mut is_ok = result.is_ok() && result.unwrap();

        let msg2 = conn.wait_for(None, false);
        let mask_bytes: MaskedTxMPCInputs = serde_json::from_str(msg2.get(0).unwrap()).unwrap();

        is_ok = is_ok && mpc::pay_unmask_tx_customer(&mut channel_state, &mut channel_token, mask_bytes, &mut cust_state);

        let rev_state = RevokedState::new(old_state.get_nonce(),r_com, rev_lock, rev_secret, t);
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

    pub fn close(outfile: PathBuf, from_escrow: bool) {
        let mut file1 = File::open("cust_state.json").unwrap();
        let mut ser_cust_state = String::new();
        file1.read_to_string(&mut ser_cust_state).unwrap();
        let cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();

        let closing_tx = match from_escrow {
            true => cust_state.get_cust_close_escrow_tx(),
            false => cust_state.get_cust_close_merch_tx()
        };

        // write out to a file
        let mut out = File::create(outfile).unwrap();
        out.write_all(closing_tx.as_ref());
    }

    fn save_state_cust(channel_state: ChannelMPCState, channel_token: ChannelMPCToken, cust_state: CustomerMPCState) {
        let mut file = File::create("cust_channel_state.json").unwrap();
        file.write_all(serde_json::to_string(&channel_state).unwrap().as_ref());
        let mut file1 = File::create("cust_state.json").unwrap();
        file1.write_all(serde_json::to_string(&cust_state).unwrap().as_ref());
        let mut file2 = File::create("cust_channel_token.json").unwrap();
        file2.write_all(serde_json::to_string(&channel_token).unwrap().as_ref());
    }

    pub fn construct_escrow_transaction(escrow: Escrow) {
        let input = Input {
            private_key: escrow.cust_privkey, // testnet
            address_format: "p2sh_p2wpkh",
            transaction_id: escrow.txid,
            index: escrow.index,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(escrow.input_sats), // assumes already in sats
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let config = BitcoinTxConfig {
            version: 2,
            lock_time: 0
        };

        let musig_output = MultiSigOutput {
            pubkey1: hex::decode(escrow.merch_pubkey).unwrap(),
            pubkey2: hex::decode(escrow.cust_pubkey).unwrap(),
            address_format: "native_p2wsh",
            amount: escrow.output_sats // assumes already in sats
        };

        // test if we need a change output pubkey
        let change_sats = escrow.input_sats - escrow.output_sats;
        let change_output = match change_sats > 0 && escrow.change_pubkey.is_some() {
            true => Some(Output { pubkey: hex::decode(escrow.change_pubkey.unwrap()).unwrap(),
                             amount: change_sats }),
            false => None
        };

        if change_output.is_none() {
            println!("Require a change pubkey to generate a valid escrow transaction!");
            return;
        }

        let (escrow_tx_preimage, full_escrow_tx) = create_escrow_transaction::<Testnet>(&config, &input, &musig_output, &change_output.unwrap());
        let (signed_tx, txid, hash_prevout) = sign_escrow_transaction::<Testnet>(full_escrow_tx, input.private_key);

        println!("writing `txid` and `hash_prevout` to {:?}", escrow.file);
        println!("signed tx: {}", signed_tx);

        // assuming single-funded channels for now
        let funding_tx = mpc::FundingTxInfo {
            init_cust_bal: escrow.output_sats,
            init_merch_bal: 0,
            escrow_txid: FixedSizeArray32(txid),
            escrow_prevout: FixedSizeArray32(hash_prevout),
            merch_txid: FixedSizeArray32([0u8; 32]),
            merch_prevout: FixedSizeArray32([0u8; 32])
        };

        let mut file = File::create(escrow.file).unwrap();
        file.write_all(serde_json::to_string(&funding_tx).unwrap().as_ref());
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

        let mut file = File::open("merch_channel_state.json").unwrap();
        let mut ser_channel_state = String::new();
        file.read_to_string(&mut ser_channel_state).unwrap();
        let mut channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();
        let mut file1 = File::open("merch_state.json").unwrap();
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
        let mut file = File::create("merch_channel_state.json").unwrap();
        file.write_all(serde_json::to_string(&channel_state).unwrap().as_ref());
        let mut file1 = File::create("merch_state.json").unwrap();
        file1.write_all(serde_json::to_string(&merch_state).unwrap().as_ref());
    }

    pub fn close(outfile: PathBuf) {
        // output the merch-close-tx (only thing merchant can broadcast to close channel)
        let mut file1 = File::open("merch_state.json").unwrap();
        let mut ser_merch_state = String::new();
        file1.read_to_string(&mut ser_merch_state).unwrap();
        let merch_state: MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();

    }

}

#[cfg(feature = "mpc-bitcoin")]
fn generate_funding_tx<R: Rng>(csprng: &mut R, b0_cust: i64, b0_merch: i64) -> mpc::FundingTxInfo {
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

        return mpc::FundingTxInfo { init_cust_bal: b0_cust, init_merch_bal: b0_merch,
                                    escrow_txid: FixedSizeArray32(escrow_txid),
                                    merch_txid: FixedSizeArray32(merch_txid),
                                    escrow_prevout: FixedSizeArray32(escrow_prevout),
                                    merch_prevout: FixedSizeArray32(merch_prevout) };
}
