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
use std::io::{BufRead, Write, Read};
use std::path::PathBuf;
use zkchannels::FundingTxInfo;
use std::fs::File;
use bitcoin::Testnet;

macro_rules! handle_file_error {
    ($e:expr, $f:expr) => (match $e {
        Ok(val) => val,
        Err(err) => return Err(format!("- {:?}: {}", $f, err)),
    });
}
macro_rules! handle_serde_error {
    ($e:expr) => (match $e {
        Ok(val) => val,
        Err(err) => return Err(err.to_string()),
    });
}

macro_rules! create_connection {
    ($e: expr) => (&mut Conn::new($e.own_ip, $e.own_port, $e.other_ip, $e.other_port));
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
    #[structopt(short = "d", long = "dust-limit", default_value = "0")]
    dust_limit: i64,
    #[structopt(short = "t", long = "tx-fee", default_value = "0")]
    tx_fee: i64
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
    other_port: String
}

#[derive(Debug, StructOpt, Deserialize)]
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
        Command::OPEN(open) => match open.party {
            Party::MERCH => match merch::open(create_connection!(open), open.dust_limit) {
                Err(e) => println!("Channel opening phase failed with error: {}", e),
                _ => ()
            },
            Party::CUST => match cust::open(create_connection!(open), open.cust_bal, open.merch_bal) {
                Err(e) => println!("Channel opening phase failed with error: {}", e),
                _ => ()
            },
        },
        Command::INIT(init) => match init.party {
            Party::MERCH => match merch::init(create_connection!(init)) {
                Err(e) => println!("Initialize phase failed with error: {}", e),
                _ => ()
            },
            Party::CUST => match cust::init(create_connection!(init), init.funding_tx_file) {
                Err(e) => println!("Initialize phase failed with error: {}", e),
                _ => ()
            },
        },
        Command::ACTIVATE(activate) => match activate.party {
            Party::MERCH => merch::activate(create_connection!(activate)).unwrap(),
            Party::CUST => cust::activate(create_connection!(activate)).unwrap()
        },
        Command::UNLINK(unlink) => match unlink.party {
            Party::MERCH => merch::pay(0, create_connection!(unlink)).unwrap(),
            Party::CUST => cust::pay(0, create_connection!(unlink), unlink.verbose).unwrap(),
        },
        Command::PAY(pay) => match pay.party {
            Party::MERCH => match merch::pay(pay.amount.unwrap(), create_connection!(pay)) {
                Err(e) => println!("Pay phase failed with error: {}", e),
                _ => ()
            },
            Party::CUST => match cust::pay(pay.amount.unwrap(), create_connection!(pay), pay.verbose) {
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

    pub fn open(conn: &mut Conn, b0_cust: i64, b0_merch: i64) -> Result<(), String> {
        let rng = &mut rand::thread_rng();

        println!("Waiting for merchant's channel_state and pk_m...");
        let msg0 = conn.wait_for(None, false);
        let channel_state: ChannelMPCState = serde_json::from_str(&msg0.get(0).unwrap()).unwrap();
        let pk_m: secp256k1::PublicKey = serde_json::from_str(&msg0.get(1).unwrap()).unwrap();

        if b0_cust == 0 && b0_merch == 0 {
            return Err(String::from("cust-bal or merch-bal must be greater than 0."));
        }

        let (channel_token, cust_state) = mpc::init_customer(rng, &pk_m,
                                                                 b0_cust, b0_merch, "Customer");

        println!("Saving the initial customer state...");
        save_state_cust(channel_state, channel_token, cust_state)
    }

    pub fn init(conn: &mut Conn, funding_tx_file: Option<PathBuf>) -> Result<(), String> {
        // at this point, escrow-tx and merch-close-tx have been formed but not signed!
        let ser_funding_tx = match funding_tx_file {
            Some(f) => handle_file_error!(read_pathfile(f.clone()), f),
            None => {
                let s = String::from("--funding-tx argument is required for customer");
                println!("{}", s);
                return Err(s);
            }
        };
        let funding_tx: FundingTxInfo = serde_json::from_str(&ser_funding_tx).unwrap();

        let ser_channel_state = read_file("cust_channel_state.json").unwrap();
        let channel_state: ChannelMPCState = handle_serde_error!(serde_json::from_str(&ser_channel_state));

        let ser_channel_token = read_file("cust_channel_token.json").unwrap();
        let mut channel_token: ChannelMPCToken = handle_serde_error!(serde_json::from_str(&ser_channel_token));

        let ser_cust_state = read_file("cust_state.json").unwrap();
        let mut cust_state: CustomerMPCState = handle_serde_error!(serde_json::from_str(&ser_cust_state));

        mpc::init_funding(&funding_tx, &mut channel_token, &mut cust_state);

        let init_cust_state = match cust_state.get_init_cust_state() {
            Ok(n) => n,
            Err(e) => return Err(e.to_string())
        };

        // customer sends pk_c, n_0, rl_0 to the merchant
        let pubkeys = cust_state.get_pubkeys(&channel_state, &channel_token);

        let msg1 = [handle_serde_error!(serde_json::to_string(&init_cust_state)),
                               handle_serde_error!(serde_json::to_string(&funding_tx)),
                               handle_serde_error!(serde_json::to_string(&pubkeys))];
        let msg2 = conn.send_and_wait(&msg1, Some(String::from("Sending initial cust state")), true);

        // form and sign the cust-close-from-escrow-tx and from-merch-close-tx
        let escrow_sig: Vec<u8> = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        let merch_sig: Vec<u8> = serde_json::from_str(&msg2.get(1).unwrap()).unwrap();

        // now sign the customer's initial closing txs
        let got_close_tx = match cust_state.sign_initial_closing_transaction::<Testnet>(&channel_state, &channel_token, &escrow_sig, &merch_sig) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string())
        };

        if got_close_tx {
            save_state_cust(channel_state, channel_token, cust_state)?;
        }

        // TODO: now proceed to signing the escrow and merch-close-txs

        Ok(())
    }

    pub fn activate(conn: &mut Conn) -> Result<(), String> {
        let rng = &mut rand::thread_rng();

        let ser_cust_state = read_file("cust_state.json").unwrap();
        let mut cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();

        let ser_channel_token = read_file("cust_channel_token.json").unwrap();
        let channel_token: ChannelMPCToken = handle_serde_error!(serde_json::from_str(&ser_channel_token));

        let s0 = mpc::activate_customer(rng, &mut cust_state);

        // send the channel token and initial state
        let msg1 = [handle_serde_error!(serde_json::to_string(&channel_token)), handle_serde_error!(serde_json::to_string(&s0))];
        let msg2 = conn.send_and_wait(&msg1, Some(String::from("Sending channel token and state (s0)")), true);

        let pay_token: [u8; 32] = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        println!("Obtained pay token (p0): {}", hex::encode(&pay_token));
        mpc::activate_customer_finalize(pay_token, &mut cust_state);

        write_file("cust_state.json", handle_serde_error!(serde_json::to_string(&cust_state)))?;
        Ok(())
    }

    pub fn pay(amount: i64, conn: &mut Conn, verbose: bool) -> Result<(), String> {
        let rng = &mut rand::thread_rng();

        let ser_channel_state = read_file("cust_channel_state.json").unwrap();
        let mut channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();

        let ser_cust_state = read_file("cust_state.json").unwrap();
        let mut cust_state: CustomerMPCState = serde_json::from_str(&ser_cust_state).unwrap();

        println!("Payment amount: {}", amount);
        println!("Current balance: {}", cust_state.cust_balance);
        println!("Merchant balance: {}", cust_state.merch_balance);

        let ser_channel_token = read_file("cust_channel_token.json").unwrap();
        let mut channel_token: ChannelMPCToken = handle_serde_error!(serde_json::from_str(&ser_channel_token));

        let old_state = cust_state.get_current_state();

        // prepare phase
        let (new_state, rev_state) = match mpc::pay_prepare_customer(rng, &mut channel_state, amount, &mut cust_state) {
            Ok(n) => n,
            Err(e) => return Err(e)
        };
        if verbose {
            let chan_id = channel_token.compute_channel_id().unwrap();
            println!("====================================");
            println!("Updating channel: ID={}", hex::encode(&chan_id));
            println!("old state: {}", &old_state);
            println!("new state: {}", &new_state);
            println!("====================================");
        }

        let msg = [hex::encode(&old_state.get_nonce()), hex::encode(&rev_state.rev_lock_com.0)];
        let msg1 = conn.send_and_wait(&msg, Some(String::from("nonce and rev_lock com")), true);
        let pay_token_mask_com_vec = hex::decode(msg1.get(0).unwrap()).unwrap();
        let mut pay_token_mask_com = [0u8; 32];
        pay_token_mask_com.copy_from_slice(pay_token_mask_com_vec.as_slice());

        // execute the mpc phase
        let result = mpc::pay_customer(&mut channel_state, &mut channel_token, old_state, new_state, pay_token_mask_com, rev_state.rev_lock_com.0, amount, &mut cust_state);
        let mut is_ok = result.is_ok() && result.unwrap();

        let msg2 = conn.wait_for(None, false);
        let mask_bytes: MaskedTxMPCInputs = serde_json::from_str(msg2.get(0).unwrap()).unwrap();

        // unmask the closing tx
        is_ok = is_ok && mpc::pay_unmask_tx_customer(&mut channel_state, &mut channel_token, mask_bytes, &mut cust_state);

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
        is_ok = is_ok && mpc::pay_unmask_pay_token_customer(pt_mask_bytes, pt_mask_r, &mut cust_state);

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
    use zkchannels::channels_mpc::{ChannelMPCState, ChannelMPCToken, MerchantMPCState, InitCustState};
    use zkchannels::wallet::State;
    use zkchannels::transactions::ClosePublicKeys;

    pub fn open(conn: &mut Conn, dust_limit: i64) -> Result<(), String> {
        let rng = &mut rand::thread_rng();

        let mut channel_state = ChannelMPCState::new(String::from("Channel"), false);
        if dust_limit == 0 {
            let s = format!("Dust limit must be greater than 0!");
            return Err(s);
        }
        channel_state.set_dust_limit(dust_limit);

        let merch_state = mpc::init_merchant(rng, &mut channel_state, "Merchant");

        let msg1 = [handle_serde_error!(serde_json::to_string(&channel_state)), handle_serde_error!(serde_json::to_string(&merch_state.pk_m))];
        conn.send(&msg1);

        save_state_merch(channel_state, merch_state)
    }

    pub fn init(conn: &mut Conn) -> Result<(), String> {
        // build tx and sign it
        let ser_channel_state = read_file("merch_channel_state.json").unwrap();
        let channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();

        let ser_merch_state = read_file("merch_state.json").unwrap();
        let merch_state: MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();

        let msg2 = conn.wait_for(None, false);
        let init_cust_state: InitCustState = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        let funding_tx: FundingTxInfo = serde_json::from_str(&msg2.get(1).unwrap()).unwrap();
        let pubkeys: ClosePublicKeys = serde_json::from_str(&msg2.get(2).unwrap()).unwrap();
        let pkc = init_cust_state.pk_c.serialize().to_vec();

        if pkc != pubkeys.cust_pk {
            return Err(String::from("Customer pk for channel doesn't match initial state"));
        }

        let (escrow_sig, merch_sig) = merch_state.sign_initial_closing_transaction::<Testnet>(&channel_state, &funding_tx, &pubkeys);

        let msg3 = [handle_serde_error!(serde_json::to_string(&escrow_sig)), handle_serde_error!(serde_json::to_string(&merch_sig))];
        conn.send(&msg3);

        Ok(())
    }

    pub fn activate(conn: &mut Conn) -> Result<(), String> {
        let ser_merch_state = read_file("merch_state.json").unwrap();
        let mut merch_state: MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();

        let msg2 = conn.wait_for(None, false);
        // TODO: verify msg2

        let channel_token: ChannelMPCToken = serde_json::from_str(&msg2.get(0).unwrap()).unwrap();
        let s0: State = serde_json::from_str(msg2[1].as_ref()).unwrap();

        let pay_token = mpc::activate_merchant(channel_token, &s0, &mut merch_state);

        let msg3 = [handle_serde_error!(serde_json::to_string(&pay_token))];
        conn.send(&msg3);

        // save_state_merch(channel_state, merch_state)
        write_file("merch_state.json", handle_serde_error!(serde_json::to_string(&merch_state)))?;
        Ok(())
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
        println!("Customer revealed a nonce: {}", hex::encode(&nonce));
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

        let (pt_mask_bytes, pt_mask_r) = match mpc::pay_validate_rev_lock_merchant(rev_state, &mut merch_state) {
            Ok(n) => (n.0, n.1),
            _ => return Err(String::from("Failed to get the pay token mask and randomness!"))
        };

        let msg5 = [hex::encode(&pt_mask_bytes), hex::encode(&pt_mask_r)];
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
        let _merch_state: MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();

        let ser_channel_token = match channel_token_file {
            Some(ctf) => handle_file_error!(read_pathfile(ctf.clone()), ctf),
            None => return Err(String::from("Channel-token file required!"))
        };
        let channel_token: ChannelMPCToken = serde_json::from_str(&ser_channel_token).unwrap();

        let _channel_id = match channel_token.compute_channel_id() {
            Ok(n) => hex::encode(&n),
            Err(e) => return Err(e.to_string())
        };

        // TODO: get the merch-close-tx for the given channel-id
        let merch_close_tx = String::from("retrieve the merch-close-tx here from merch-state for channel-id");
        write_pathfile(out_file, merch_close_tx)?;
        Ok(())
    }
}
