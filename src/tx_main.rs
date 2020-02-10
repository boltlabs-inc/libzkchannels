extern crate rand;
extern crate zkchannels;
extern crate secp256k1_boltlabs as secp256k1;
extern crate structopt;
extern crate serde;
extern crate bufstream;
extern crate sha2;
extern crate wagyu_bitcoin as bitcoin;
extern crate wagyu_model;

use structopt::StructOpt;
use std::str::FromStr;
use serde::Deserialize;
use bitcoin::{Testnet};
use wagyu_model::Transaction;
use std::path::PathBuf;
use std::io::prelude::*;
use std::fs::File;
use zkchannels::fixed_size_array::FixedSizeArray32;
use zkchannels::transactions::{Input, BitcoinTxConfig, MultiSigOutput, Output};
use zkchannels::transactions::btc::{create_escrow_transaction, sign_escrow_transaction, serialize_p2wsh_escrow_redeem_script,
                                    create_merch_close_transaction_params, create_merch_close_transaction_preimage, get_private_key,
                                    generate_signature_for_multi_sig_transaction, completely_sign_multi_sig_transaction};
use zkchannels::FundingTxInfo;

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

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct Escrow {
    #[structopt(short = "t", long = "txid")]
    txid: String,
    #[structopt(short = "i", long = "index")]
    index: u32,
    #[structopt(short = "a", long = "input-sats")]
    input_sats: i64,
    #[structopt(short = "o", long = "output-sats")]
    output_sats: i64,
    #[structopt(long = "cust-sk")]
    cust_privkey: String,
    #[structopt(long = "cust-pk")]
    cust_pubkey: String,
    #[structopt(long = "merch-pk")]
    merch_pubkey: String,
    #[structopt(long = "change-pk")]
    change_pubkey: Option<String>,
    #[structopt(long = "funding-tx")]
    file: PathBuf,
    #[structopt(long = "tx-signed")]
    tx_signed: Option<PathBuf>
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct CreateMerchClose {
    #[structopt(long = "funding-tx")]
    funding_tx_file: PathBuf,
    #[structopt(long = "cust-pk")]
    cust_pubkey: String,
    #[structopt(long = "merch-pk")]
    merch_pubkey: String,
    #[structopt(long = "merch-sk")]
    merch_privkey: Option<String>,
    #[structopt(long = "merch-close-pk")]
    merch_close_pubkey: String,
    #[structopt(long = "tx-preimage")]
    tx_preimage: Option<PathBuf>,
    #[structopt(long = "tx-signed")]
    tx_signed: Option<PathBuf>,
    #[structopt(long = "cust-sig")]
    cust_sig: Option<PathBuf>,
}

#[derive(Clone, Debug, StructOpt, Deserialize)]
pub struct SignMerchClose {
    #[structopt(long = "tx-preimage")]
    tx_preimage: PathBuf,
    #[structopt(long = "cust-sk")]
    cust_privkey: String,
    #[structopt(long = "cust-sig")]
    cust_sig: Option<PathBuf>
}

#[derive(Debug, StructOpt, Deserialize)]
pub enum Command {
    #[structopt(name = "escrow")]
    Escrow(Escrow),
    #[structopt(name = "create-merch-close")]
    CreateMerchClose(CreateMerchClose),
    #[structopt(name = "sign-merch-close")]
    SignMerchClose(SignMerchClose)
}

impl FromStr for Command {
    type Err = serde_json::error::Error;
    fn from_str(s: &str) -> Result<Command, serde_json::error::Error> {
        Ok(serde_json::from_str(&format!("\"{}\"", s))?)
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "zkchannels-tx")]
struct Cli {
    #[structopt(subcommand, help = "Options: escrow, merch-close or sign-merch-close")]
    command: Command,
}

fn main() {
    println!("******************************************");

    let args = Cli::from_args();
    match args.command {
        Command::Escrow(escrow) => cust::generate_escrow_transaction(escrow).unwrap(),
        Command::CreateMerchClose(merch_close) => merch::generate_merch_close_transaction(merch_close).unwrap(),
        Command::SignMerchClose(sign_merch_close) => cust::sign_merch_close_tx_preimage(sign_merch_close).unwrap()
    }
    println!("******************************************");
}

mod cust {
    use super::*;

    pub fn generate_escrow_transaction(escrow: Escrow) -> Result<(), String> {
        let input = Input {
            address_format: "p2sh_p2wpkh",
            transaction_id: hex::decode(escrow.txid).unwrap(),
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
            true => Some(Output {
                pubkey: hex::decode(escrow.change_pubkey.unwrap()).unwrap(),
                amount: change_sats
            }),
            false => return Err(String::from("Require a change pubkey to generate a valid escrow transaction!"))
        };

        let cust_privkey = handle_serde_error!(hex::decode(escrow.cust_privkey));
        let private_key = get_private_key::<Testnet>(cust_privkey)?;
        let (_escrow_tx_preimage, full_escrow_tx) = match create_escrow_transaction::<Testnet>(&config, &input, &musig_output, &change_output.unwrap(), private_key.clone()) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string())
        };
        let (signed_tx, txid, hash_prevout) = sign_escrow_transaction::<Testnet>(full_escrow_tx, private_key);
        let signed_tx_hex = hex::encode(&signed_tx);

        println!("writing txid and hash_prevout to: {:?}", escrow.file);
        match escrow.tx_signed {
            Some(n) => {
                println!("writing signed tx: {:?}", n);
                write_pathfile(n, signed_tx_hex)?
            },
            _ => println!("signed tx: {}", signed_tx_hex)
        }

        // assuming single-funded channels for now
        let funding_tx = FundingTxInfo {
            init_cust_bal: escrow.output_sats,
            init_merch_bal: 0,
            escrow_txid: FixedSizeArray32(txid),
            escrow_prevout: FixedSizeArray32(hash_prevout),
            merch_txid: FixedSizeArray32([0u8; 32]),
            merch_prevout: FixedSizeArray32([0u8; 32])
        };

        write_pathfile(escrow.file, handle_serde_error!(serde_json::to_string(&funding_tx)))?;
        Ok(())
    }

    pub fn sign_merch_close_tx_preimage(args: SignMerchClose) -> Result<(), String> {
        // retrieve the merch-close-tx preimage
        let merch_tx_preimage = match read_pathfile(args.tx_preimage) {
            Ok(n) => match hex::decode(n) {
                Ok(h) => h, // TODO: read & validate the tx matches expected amount in funding tx before signing
                Err(e) => return Err(e.to_string())
            },
            Err(e) => return Err(e.to_string())
        };
        // customer signs the preimage and sends signature to merchant
        let cust_privkey = handle_serde_error!(hex::decode(args.cust_privkey));
        let private_key = get_private_key::<Testnet>(cust_privkey)?;
        let cust_sig = generate_signature_for_multi_sig_transaction::<Testnet>(&merch_tx_preimage, &private_key).unwrap();
        let cust_sig_hex = hex::encode(cust_sig);
        // write the signature to a file
        match args.cust_sig {
            Some(sig_file) => {
                println!("writing the customer signature: {:?}", sig_file);
                write_pathfile(sig_file, cust_sig_hex)?
            },
            None => println!("Cust signature: {}", cust_sig_hex)
        };
        Ok(())
    }
}

mod merch {
    use super::*;

    pub fn validate_signature(_preimage: &Vec<u8>, _sig_and_len: &Vec<u8>, _pk: &Vec<u8>) -> bool {
        // TODO: verify the signature with respect to preimage and cust-pubkey
        println!("verifying the cust signature on merch-close-tx preimage!");
        return true;
    }

    pub fn generate_merch_close_transaction(merch_close: CreateMerchClose) -> Result<(), String> {
        let ser_funding_tx = read_pathfile(merch_close.funding_tx_file.clone()).unwrap();
        let mut funding_tx: FundingTxInfo = serde_json::from_str(&ser_funding_tx).unwrap();

        // construct
        let escrow_index = 0;
        let merch_pk = hex::decode(merch_close.merch_pubkey).unwrap();
        let cust_pk = hex::decode(merch_close.cust_pubkey).unwrap();
        let merch_close_pk = hex::decode(merch_close.merch_close_pubkey).unwrap();
        // hard code self delay (for now)
        let to_self_delay: [u8; 2] = [0xcf, 0x05]; // little-endian format

        let redeem_script = serialize_p2wsh_escrow_redeem_script(&merch_pk, &cust_pk);

        let input = Input {
            address_format: "native_p2wsh",
            // outpoint of escrow
            transaction_id: funding_tx.escrow_txid.0.to_vec(),
            index: escrow_index,
            redeem_script: Some(redeem_script),
            script_pub_key: None,
            utxo_amount: Some(funding_tx.init_cust_bal + funding_tx.init_merch_bal),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let tx_params =
            create_merch_close_transaction_params::<Testnet>(&input, &cust_pk, &merch_pk, &merch_close_pk, &to_self_delay)?;

        let (merch_tx_preimage, _) = create_merch_close_transaction_preimage::<Testnet>(&tx_params);

        // let's check customer siganture on tx preimage
        if merch_close.cust_sig.is_none() {
            // if customer signature isn't provided then we're generating an initial tx preimage for merch-close-tx that customer can sign
            let hex_tx_preimage = hex::encode(merch_tx_preimage);
            match merch_close.tx_preimage {
                Some(n) => {
                    println!("writing the initial preimage for merch-close-tx: {:?}", n);
                    write_pathfile(n, hex_tx_preimage)?
                },
                _ => println!("Merch-close-tx preimage: {}", hex_tx_preimage)
            };
        } else {

            // check if merch-sk provided
            let merch_sk = match merch_close.merch_privkey {
                Some(sk) => match hex::decode(sk) {
                    Ok(s) => get_private_key::<Testnet>(s)?,
                    Err(e) => return Err(e.to_string())
                },
                None => return Err(String::from("need merch private key to sign the merch-close-tx"))
            };
            // if cust signature provided, then merchant signs the preimage
            let cust_sig_and_len_byte = match read_pathfile(merch_close.cust_sig.unwrap()) {
                Ok(n) => match hex::decode(n) {
                    Ok(h) => match validate_signature(&merch_tx_preimage, &h, &cust_pk) {
                        true => h,
                        false => {
                            println!("could not verify the cust-sig with cust-pk on created merch-close-tx!");
                            return Err(String::from("invalid cust-sig!"));
                        }
                    },
                    Err(e) => return Err(e.to_string())
                },
                Err(e) => return Err(e)
            };

            let (signed_merch_close_tx, txid, hash_prevout) =
                completely_sign_multi_sig_transaction::<Testnet>(&tx_params, &cust_sig_and_len_byte, &merch_sk);
            let signed_merch_tx = hex::encode(signed_merch_close_tx.to_transaction_bytes().unwrap());

            // let's update the funding tx object
            funding_tx.merch_txid.0.copy_from_slice(&txid);
            funding_tx.merch_prevout.0.copy_from_slice(&hash_prevout);
            let updated_ser_funding_tx = handle_serde_error!(serde_json::to_string(&funding_tx));
            write_pathfile(merch_close.funding_tx_file, updated_ser_funding_tx)?;

            match merch_close.tx_signed {
                Some(n) => {
                    println!("writing the signed merch-close-tx: {:?}", n);
                    write_pathfile(n, signed_merch_tx)?
                },
                _ => println!("Merch-close-tx signed: {}", signed_merch_tx)
            }
        }
        Ok(())
    }

}
