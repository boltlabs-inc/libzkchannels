use super::*;
use bitcoin::network::BitcoinNetwork;
use bitcoin::{BitcoinFormat, BitcoinTransaction, BitcoinTransactionInput, BitcoinTransactionOutput,
              BitcoinTransactionParameters, BitcoinAmount, BitcoinPrivateKey};
use bitcoin::address::BitcoinAddress;
use bitcoin::SignatureHash::SIGHASH_ALL;
use wagyu_model::crypto::hash160;
use wagyu_model::Transaction;
use wagyu_model::PrivateKey;
use std::str::FromStr;
use util::hash_to_slice;
use sha2::{Digest, Sha256};

pub const SATOSHI: i64 = 100000000;

pub struct Input {
    pub address_format: &'static str,
    pub transaction_id: Vec<u8>,
    pub index: u32,
    pub redeem_script: Option<Vec<u8>>,
    pub script_pub_key: Option<&'static str>,
    pub utxo_amount: Option<i64>,
    pub sequence: Option<[u8; 4]>
}

pub struct Output {
    pub pubkey: Vec<u8>,
    pub amount: i64
}

pub struct MultiSigOutput {
    pub cust_pubkey: Vec<u8>,
    pub merch_pubkey: Vec<u8>,
    pub address_format: &'static str,
    pub amount: i64
}

pub struct BitcoinTxConfig {
    pub version: u32,
    pub lock_time: u32
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClosePublicKeys {
    pub cust_pk: Vec<u8>,
    pub cust_close_pk: Vec<u8>,
    pub merch_pk: Vec<u8>,
    pub merch_close_pk: Vec<u8>,
    pub merch_disp_pk: Vec<u8>,
    pub rev_lock: FixedSizeArray32
}

/* Bitcoin transactions */
pub mod btc {
    use super::*;

    pub fn serialize_p2wsh_escrow_redeem_script(cust_pubkey: &Vec<u8>, merch_pubkey: &Vec<u8>) -> Vec<u8> {
        let mut script: Vec<u8> = Vec::new();
        script.extend(vec![0x52, 0x21]); // OP_2 + OP_DATA (pk1 len)
        script.extend(merch_pubkey.iter());
        script.push(0x21); // OP_DATA (pk2 len)
        script.extend(cust_pubkey.iter());
        script.extend(vec![0x52, 0xae]); // OP_2 OP_CHECKMULTISIG

        return script;
    }

    pub fn serialize_p2wsh_merch_close_redeem_script(cust_pubkey: &Vec<u8>, merch_pubkey: &Vec<u8>, merch_close_pubkey: &Vec<u8>, to_self_delay: &[u8; 2]) -> Vec<u8> {
//    # P2WSH merch-close scriptPubKey
//    # 0x63      OP_IF
//    # 0x52      OP_2
//    # 0x21      OP_DATA - len(merch_pubkey)
//    # merch_pubkey
//    # 0x21      OP_DATA - len(cust_pubkey)
//    # cust_pubkey
//    # 0x52      OP_2
//    # 0xae      OP_CHECKMULTISIG
//    # 0x67      OP_ELSE
//    # 0x__      OP_DATA - len(to_self_delay) (probably ~0x02)
//    # to_self_delay
//    # 0xb2      OP_CHECKSEQUENCEVERIFY
//    # 0x75      OP_DROP
//    # 0x21      OP_DATA - len(merch_close_pubkey)
//    # merch_close_pk
//    # 0xac      OP_CHECKSIG
//    # 0x68      OP_ENDIF

        let mut script: Vec<u8> = Vec::new();
        script.extend(vec![0x63, 0x52, 0x21]); // OP_IF + OP_2 + OP_DATA (pk1 len)
        script.extend(merch_pubkey.iter());
        script.push(0x21); // OP_DATA (pk2 len)
        script.extend(cust_pubkey.iter());
        script.extend(vec![0x52, 0xae, 0x67]); // OP_2 OP_CHECKMULTISIG
        script.push(0x02); // len for sequence
        script.extend(to_self_delay.iter()); // short sequence
        script.extend(vec![0xb2, 0x75, 0x21]);
        script.extend(merch_close_pubkey.iter());
        script.extend(vec![0xac, 0x68]);

        return script;
    }

    // given two public keys, create a multi-sig address via P2WSH script
    pub fn create_p2wsh_scriptpubkey<N: BitcoinNetwork>(cust_pubkey: &Vec<u8>, merch_pubkey: &Vec<u8>) -> Vec<u8> {
        // manually construct the script
        let mut script: Vec<u8> = Vec::new();
        script.extend(vec![0x52, 0x21]); // OP_2 + OP_DATA (pk1 len)
        script.extend(merch_pubkey.iter());
        script.push(0x21); // OP_DATA (pk2 len)
        script.extend(cust_pubkey.iter());
        script.extend(vec![0x52, 0xae]); // OP_2 OP_CHECKMULTISIG

        // compute SHA256 hash of script
        let script_hash = hash_to_slice(&script);
        let mut script_pubkey = Vec::new();
        script_pubkey.extend(vec![0x00, 0x20]); // len of hash
        script_pubkey.extend_from_slice(&script_hash);

        return script_pubkey;
    }

    pub fn create_p2wpkh_scriptpubkey<N: BitcoinNetwork>(pubkey: &Vec<u8>) -> Vec<u8> {
        let script_hash = hash160(pubkey.as_slice());
        let mut script_pubkey = Vec::new();
        script_pubkey.extend(vec![0x00, 0x14]); // len of hash
        script_pubkey.extend_from_slice(&script_hash);

        return script_pubkey;
    }

    pub fn get_private_key<N: BitcoinNetwork>(private_key: Vec<u8>) -> Result<BitcoinPrivateKey<N>, String> {
        let sk = match secp256k1::SecretKey::from_slice(&private_key) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string())
        };
        let private_key = BitcoinPrivateKey::<N>::from_secp256k1_secret_key(sk, false);
        Ok(private_key)
    }

    pub fn get_merch_close_timelocked_p2wsh_address(cust_pubkey: &Vec<u8>, merch_pubkey: &Vec<u8>, merch_close_pubkey: &Vec<u8>, to_self_delay: &[u8; 2]) -> Vec<u8> {
        // get the script
        let script = serialize_p2wsh_merch_close_redeem_script(cust_pubkey, merch_pubkey, merch_close_pubkey, to_self_delay);
        // compute SHA256 hash of script
        let script_hash = hash_to_slice(&script);
        let mut script_pubkey = Vec::new();
        script_pubkey.extend(vec![0x00, 0x20]); // len of hash
        script_pubkey.extend_from_slice(&script_hash);

        return script_pubkey;
    }

    pub fn get_cust_close_timelocked_p2wsh_address(rev_lock: &[u8; 32], merch_disp_pubkey: &Vec<u8>, cust_close_pubkey: &Vec<u8>, to_self_delay: &[u8; 2]) -> Vec<u8> {
//    # P2WSH cust-close scriptPubKey
//    # 0x63      OP_IF
//    # 0xa8      OP_SHA256
//    # 0x20      OP_DATA - len(revocation_lock {sha256[revocation-secret]})
//    # revocation_lock
//    # 0x88      OP_EQUALVERIFY
//    # 0x21      OP_DATA - len(merch_disp_pubkey)
//    # merch_disp_pubkey
//    # 0x67      OP_ELSE
//    # 0x__      OP_DATA - len(to_self_delay) (probably ~0x02)
//    # to_self_delay
//    # 0xb2      OP_CHECKSEQUENCEVERIFY
//    # 0x75      OP_DROP
//    # 0x21      OP_DATA - len(cust_close_pubkey)
//    # cust_close_pk
//    # 0x68      OP_ENDIF
//    # 0xac      OP_CHECKSIG
        let mut script: Vec<u8> = Vec::new();
        script.extend(vec![0x63, 0xa8, 0x20]);
        script.extend(rev_lock.iter());
        script.extend(vec![0x88, 0x21]);
        script.extend(merch_disp_pubkey.iter());
        script.push(0x67);
        script.push(0x02); // len for sequence
        script.extend(to_self_delay.iter()); // short sequence
        script.extend(vec![0xb2, 0x75, 0x21]);
        script.extend(cust_close_pubkey.iter());
        script.extend(vec![0x68, 0xac]);

        // println!("get_cust_close_timelocked_p2wsh_address script: {}", hex::encode(&script));

        // compute SHA256 hash of script
        let script_hash = hash_to_slice(&script);
        let mut script_pubkey = Vec::new();
        script_pubkey.extend(vec![0x00, 0x20]); // len of hash
        script_pubkey.extend_from_slice(&script_hash);

        return script_pubkey;
    }

    pub fn create_opreturn_output(rev_lock: &[u8; 32], cust_close_pubkey: &Vec<u8>) -> Vec<u8> {
        let mut ret_val: Vec<u8> = Vec::new();
        let len = (rev_lock.len() + cust_close_pubkey.len()) as u8;
        ret_val.extend(vec![0x6a, len as u8]); // # OP_RETURN + OP_DATA
        ret_val.extend(rev_lock.iter()); // 32 bytes
        ret_val.extend(cust_close_pubkey.iter()); // 33 bytes
        return ret_val;
    }

    pub fn create_reverse_input(txid_be: &[u8; 32], index: u32, input_amount: i64) -> Input {
        let mut txid_buf_le = txid_be.clone();
        txid_buf_le.reverse();
        // let txid_str = hex::encode(&txid_buf);
        // println!("txid: {}", txid_str);
        Input {
            address_format: "p2wsh",
            // outpoint
            transaction_id: txid_buf_le.to_vec(),
            index: index,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(input_amount),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        }
    }

    macro_rules! check_pk_valid {
        ($x: expr) => (match secp256k1::PublicKey::from_slice(&$x) {
            Ok(_p) => true,
            Err(e) => return Err(e.to_string())
        });
    }

    // creates a funding transaction with the following input/outputs
    // input => p2pkh or p2sh_p2wpkh
    // output1 => multi-sig addr via p2wsh
    // output2 => change output to p2wpkh
    pub fn create_escrow_transaction<N: BitcoinNetwork>(config: &BitcoinTxConfig, input: &Input, output1: &MultiSigOutput, output2: &Output, private_key: BitcoinPrivateKey<N>) -> Result<(Vec<u8>, BitcoinTransaction<N>), String> {
        // check that specified public keys are valid
        check_pk_valid!(output1.cust_pubkey);
        check_pk_valid!(output1.merch_pubkey);
        check_pk_valid!(output2.pubkey);
        // types of UTXO inputs to support
        let address_format = match input.address_format {
            "p2pkh" => BitcoinFormat::P2PKH,
            "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
            "p2wsh" => BitcoinFormat::P2WSH,
            _ => panic!("do not currently support specified address format as funding input: {}", input.address_format)
        };
        let address = private_key.to_address(&address_format).unwrap();
        let redeem_script = match (input.redeem_script.as_ref(), address_format.clone()) {
            (Some(script), _) => Some(script.clone()),
            (None, BitcoinFormat::P2SH_P2WPKH) => {
                let mut redeem_script = vec![0x00, 0x14];
                redeem_script.extend(&hash160(
                    &private_key.to_public_key().to_secp256k1_public_key().serialize(),
                ));
                // println!("redeem_script: {}", hex::encode(&redeem_script));
                Some(redeem_script)
            }
            (None, _) => None,
        };
        let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
        let sequence = input.sequence.map(|seq| seq.to_vec());

        let transaction_input = BitcoinTransactionInput::<N>::new(
            input.transaction_id.clone(),
            input.index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
            redeem_script,
            script_pub_key,
            sequence,
            SIGHASH_ALL,
        )
            .unwrap();

        let mut input_vec = vec![];
        input_vec.push(transaction_input);

        let mut output_vec = vec![];

        // add multi-sig output as P2WSH output
        let output1_script_pubkey = create_p2wsh_scriptpubkey::<N>(&output1.cust_pubkey, &output1.merch_pubkey);
        let multisig_output = BitcoinTransactionOutput { amount: BitcoinAmount(output1.amount), script_pub_key: output1_script_pubkey };
        //let out1 = multisig_output.serialize().unwrap();
        //println!("output1 script pubkey: {}", hex::encode(out1));

        // add P2WPKH output
        let output2_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&output2.pubkey);
        let change_output = BitcoinTransactionOutput { amount: BitcoinAmount(output2.amount), script_pub_key: output2_script_pubkey };
        //let out2 = change_output.serialize().unwrap();
        //println!("output2 script pubkey: {}", hex::encode(out2));

        output_vec.push(multisig_output);
        output_vec.push(change_output);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: config.version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: config.lock_time,
            segwit_flag: true,
        };

        let transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let hash_preimage = transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();
        // return hash preimage of transaction and the transaction itself (for later signing)
        Ok((hash_preimage, transaction))
    }

    // signs a given transaction using a specified private key
    // assumes that transaction has already been loaded
    pub fn sign_escrow_transaction<N: BitcoinNetwork>(unsigned_tx: BitcoinTransaction<N>, private_key: BitcoinPrivateKey<N>) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let signed_tx = unsigned_tx.sign(&private_key).unwrap();
        // assume little endian here
        let tx_id_hex = signed_tx.to_transaction_id().unwrap();

        let signed_tx_hex = signed_tx.to_transaction_bytes().unwrap();
        let txid = hex::decode(tx_id_hex.to_string()).unwrap();

        let mut txid_buf = [0u8; 32];
        let mut hash_prevout = [0u8; 32];
        txid_buf.copy_from_slice(txid.as_slice());
        let mut txid_buf_be = txid_buf.clone();
        txid_buf_be.reverse();

        let mut prevout_preimage: Vec<u8> = Vec::new();
        prevout_preimage.extend(txid_buf_be.iter()); // txid (big endian)
        prevout_preimage.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result = Sha256::digest(&Sha256::digest(&prevout_preimage));
        hash_prevout.copy_from_slice(&result);

        return (signed_tx_hex, txid_buf_be, hash_prevout);
    }

    pub fn get_var_length_int(value: u64) -> Result<Vec<u8>, String> {
        match value {
            // bounded by u8::max_value()
            0..=252 => Ok(vec![value as u8]),
            // bounded by u16::max_value()
            253..=65535 => Ok([vec![0xfd], (value as u16).to_le_bytes().to_vec()].concat()),
            // bounded by u32::max_value()
            65536..=4294967295 => Ok([vec![0xfe], (value as u32).to_le_bytes().to_vec()].concat()),
            // bounded by u64::max_value()
            _ => Ok([vec![0xff], value.to_le_bytes().to_vec()].concat()),
        }
    }

    pub fn completely_sign_multi_sig_transaction<N: BitcoinNetwork>(tx_params: &BitcoinTransactionParameters<N>, signature: &Vec<u8>, prepend_signature: bool, script_data: Option<Vec<u8>>, private_key: &BitcoinPrivateKey<N>) -> (BitcoinTransaction<N>, [u8; 32], [u8; 32]) {
        let mut tx_params2 = tx_params.clone();
        let checksig_bug = vec![0x00]; // OP_CHECKSIG bug
        tx_params2.inputs[0].witnesses.append( &mut vec![checksig_bug]);
        tx_params2.inputs[0].additional_witness = Some((signature.clone(), prepend_signature));
        tx_params2.inputs[0].witness_script_data = script_data;
        let transaction = BitcoinTransaction::<N>::new(&tx_params2).unwrap();

        let signed_tx = transaction.sign(private_key).unwrap();
        // assume little endian here
        let tx_id_hex = signed_tx.to_transaction_id().unwrap();
        let txid = hex::decode(tx_id_hex.to_string()).unwrap();

        let mut txid_buf = [0u8; 32];
        let mut hash_prevout = [0u8; 32];
        txid_buf.copy_from_slice(txid.as_slice());
        let mut txid_buf_be = txid_buf.clone();
        txid_buf_be.reverse();

        // get the txid and prevout
        let mut prevout_preimage: Vec<u8> = Vec::new();
        prevout_preimage.extend(txid_buf_be.iter()); // txid
        prevout_preimage.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result = Sha256::digest(&Sha256::digest(&prevout_preimage));
        hash_prevout.copy_from_slice(&result);

        return (signed_tx, txid_buf_be, hash_prevout);
    }

    pub fn generate_signature_for_multi_sig_transaction<N: BitcoinNetwork>(preimage: &Vec<u8>, private_key: &BitcoinPrivateKey<N>) -> Result<Vec<u8>, String> {
        let transaction_hash = Sha256::digest(&Sha256::digest(preimage));
        let sighash_code = SIGHASH_ALL as u32;

        // Signature
        let mut signature = secp256k1::Secp256k1::signing_only()
            .sign(
                &secp256k1::Message::from_slice(&transaction_hash).unwrap(),
                &private_key.to_secp256k1_secret_key(),
            )
            .serialize_der()
            .to_vec();
        signature.push(sighash_code.to_le_bytes()[0]);
        let signature = [get_var_length_int(signature.len() as u64)?, signature].concat();
        Ok(signature)
    }

    pub fn sign_merch_close_transaction<N: BitcoinNetwork>(unsigned_tx: BitcoinTransaction<N>, private_key: String) -> String {
        let private_key = BitcoinPrivateKey::<N>::from_str(private_key.as_str()).unwrap();

        let signed_tx = unsigned_tx.sign(&private_key).unwrap();
        let signed_tx_hex = hex::encode(signed_tx.to_transaction_bytes().unwrap());

        return signed_tx_hex;
    }

    // creates a merch-close-tx that spends from a P2WSH to another
    pub fn create_merch_close_transaction_params<N: BitcoinNetwork>(input: &Input, cust_pubkey: &Vec<u8>, merch_pubkey: &Vec<u8>, merch_close_pubkey: &Vec<u8>, self_delay: &[u8; 2]) -> Result<BitcoinTransactionParameters<N>, String> {
        let version = 2;
        let lock_time = 0;
        let address_format = match input.address_format {
            "p2pkh" => BitcoinFormat::P2PKH,
            "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
            "p2wsh" => BitcoinFormat::P2WSH,
            _ => return Err(format!("do not currently support specified address format: {}", input.address_format))
        };

        let redeem_script = match (input.redeem_script.as_ref(), address_format.clone()) {
            (Some(script), _) => Some(script.clone()),
            (None, BitcoinFormat::P2SH_P2WPKH) => {
                let redeem_script = serialize_p2wsh_escrow_redeem_script(cust_pubkey, merch_pubkey);
                // println!("redeem_script: {}", hex::encode(&redeem_script));
                Some(redeem_script)
            }
            (None, _) => None,
        };

        let address = match address_format {
            BitcoinFormat::P2WSH => BitcoinAddress::<N>::p2wsh(redeem_script.as_ref().unwrap()).unwrap(),
            _ => return Err(format!("address format {} not supported right now", address_format))
        };
        // println!("address: {}", address);
        let sequence = input.sequence.map(|seq| seq.to_vec());
        // println!("redeem_script: {}", hex::encode(redeem_script.as_ref().unwrap()));

        let escrow_tx_input = BitcoinTransactionInput::<N>::new(
            input.transaction_id.clone(),
            input.index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
            redeem_script,
            None,
            sequence,
            SIGHASH_ALL,
        ).unwrap();

        let mut input_vec = vec![];
        input_vec.push(escrow_tx_input);

        let musig_script_pubkey = get_merch_close_timelocked_p2wsh_address(cust_pubkey, merch_pubkey, merch_close_pubkey, self_delay);
        let musig_output = BitcoinTransactionOutput { amount: BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap(), script_pub_key: musig_script_pubkey };
        // println!("Multi-sig output script pubkey: {}", hex::encode(musig_output.serialize().unwrap()));

        let mut output_vec = vec![];
        output_vec.push(musig_output);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: lock_time,
            segwit_flag: true,
        };

        Ok(transaction_parameters)
    }

    pub fn create_merch_close_transaction_preimage<N: BitcoinNetwork>(transaction_parameters: &BitcoinTransactionParameters<N>) -> (Vec<u8>, BitcoinTransaction<N>) {
        let transaction = BitcoinTransaction::<N>::new(transaction_parameters).unwrap();
        let hash_preimage = transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();

        return (hash_preimage, transaction);
    }

    pub fn create_cust_close_transaction<N: BitcoinNetwork>(input: &Input, pubkeys: &ClosePublicKeys, self_delay: &[u8; 2],
                                                            cust_bal: i64, merch_bal: i64, from_escrow: bool) -> (Vec<u8>, BitcoinTransactionParameters<N>, BitcoinTransaction<N>) {

        let config = BitcoinTxConfig {
            version: 2,
            lock_time: 0
        };
        let address_format = match input.address_format {
            "p2wsh" => BitcoinFormat::P2WSH,
            _ => panic!("do not currently support specified address format: {}", input.address_format)
        };

        let redeem_script = match from_escrow {
            true => {
                let redeem_script = serialize_p2wsh_escrow_redeem_script(&pubkeys.cust_pk, &pubkeys.merch_pk);
                // println!("escrow-tx redeem_script: {}", hex::encode(&redeem_script));
                Some(redeem_script)
            },
            false => {
                let redeem_script = serialize_p2wsh_merch_close_redeem_script(&pubkeys.cust_pk, &pubkeys.merch_pk, &pubkeys.merch_close_pk, self_delay);
                // println!("merch-close-tx redeem_script: {}", hex::encode(&redeem_script));
                Some(redeem_script)
            }
        };
        let address = match address_format {
            BitcoinFormat::P2WSH => BitcoinAddress::<N>::p2wsh(redeem_script.as_ref().unwrap()).unwrap(),
            _ => panic!("do not currently support specified address format")
        };
        // println!("address: {}", address);
        let sequence = input.sequence.map(|seq| seq.to_vec());

        let escrow_tx_input = BitcoinTransactionInput::<N>::new(
            input.transaction_id.clone(),
            input.index,
            Some(address),
            Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
            redeem_script,
            None,
            sequence,
            SIGHASH_ALL,
        )
            .unwrap();

        let mut input_vec = vec![];
        input_vec.push(escrow_tx_input);

        // output 1: P2WSH output to customer (handles spending from escrow-tx or merch-close-tx
        let output1_script_pubkey = get_cust_close_timelocked_p2wsh_address(&pubkeys.rev_lock.0, &pubkeys.merch_disp_pk, &pubkeys.cust_close_pk, self_delay);
        // println!("(1) to_customer: {}", hex::encode(&output1_script_pubkey));
        let to_customer = BitcoinTransactionOutput { amount: BitcoinAmount::from_satoshi(cust_bal).unwrap(), script_pub_key: output1_script_pubkey };
        // println!("to_customer: {}", hex::encode(to_customer.serialize().unwrap()));

        // output 2: P2WPKH output to merchant
        let output2_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&pubkeys.merch_close_pk);
        // println!("(2) to_merchant: {}", hex::encode(&output2_script_pubkey));
        let to_merchant = BitcoinTransactionOutput { amount: BitcoinAmount::from_satoshi(merch_bal).unwrap(), script_pub_key: output2_script_pubkey };
        // println!("to_merchant: {}", hex::encode(to_merchant.serialize().unwrap()));

        // output 3: OP_RETURN output
        let output3_script_pubkey = create_opreturn_output(&pubkeys.rev_lock.0, &pubkeys.cust_close_pk);
        // println!("(3) OP_RETURN: {}", hex::encode(&output3_script_pubkey));
        let op_return_out = BitcoinTransactionOutput { amount: BitcoinAmount::from_satoshi(0).unwrap(), script_pub_key: output3_script_pubkey };
        // println!("op_return: {}", hex::encode(op_return_out.serialize().unwrap()));

        let mut output_vec = vec![];
        output_vec.push(to_customer);
        output_vec.push(to_merchant);
        output_vec.push(op_return_out);

        let transaction_parameters = BitcoinTransactionParameters::<N> {
            version: config.version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time: config.lock_time,
            segwit_flag: true,
        };

        let transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let hash_preimage = transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();

        return (hash_preimage, transaction_parameters, transaction);
    }
}

/* Zcash transactions - shielded and transparent */
pub mod zec {
}


#[cfg(test)]
mod tests {
    use super::*;
    use transactions::{Input, Output, BitcoinTxConfig, MultiSigOutput};
    use std::str::FromStr;
    use bitcoin::Testnet;

    #[test]
    fn test_bitcoin_p2sh_address() {
        let expected_scriptpubkey = hex::decode("0020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd").unwrap();
        let pubkey1 = hex::decode("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb").unwrap();
        let pubkey2 = hex::decode("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1").unwrap();
        let output_scriptpubkey = transactions::btc::create_p2wsh_scriptpubkey::<Testnet>(&pubkey1, &pubkey2);

        println!("expected script_pubkey: {}", hex::encode(&output_scriptpubkey));

         assert_eq!(output_scriptpubkey, expected_scriptpubkey);
    }

    #[test]
    fn test_bitcoin_testnet_escrow_tx() {
        let input = Input {
            address_format: "p2sh_p2wpkh",
            transaction_id: hex::decode("f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1").unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(40 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let config = BitcoinTxConfig {
            version: 2,
            lock_time: 0
        };

        let musig_output = MultiSigOutput {
            cust_pubkey: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            merch_pubkey: hex::decode("037bed6ab680a171ef2ab564af25eff15c0659313df0bbfb96414da7c7d1e65882").unwrap(),
            address_format: "p2wsh",
            amount: 39 * SATOSHI
        };

        // address => "n1Z8M5eoimzqvAmufqrSXFAGzKtJ8QoDnD"
        // private_key => "cVKYvWfApKiQJjLJhHokq7eEEFcx8Y1vsJYE9tVb5ccj3ZaCY82X" // testnet
        let change_output = Output { pubkey: hex::decode("021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67").unwrap(),
                                     amount: (1 * SATOSHI) };

        let private_key = BitcoinPrivateKey::<Testnet>::from_str("cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn").unwrap();
        let (escrow_tx_preimage, full_escrow_tx) = transactions::btc::create_escrow_transaction::<Testnet>(&config, &input, &musig_output, &change_output, private_key.clone()).unwrap();

        let expected_escrow_preimage = "020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4000000001976a914a496306b960746361e3528534d04b1ac4726655a88ac00286bee00000000ffffffff51bbd879074a16332d89cd524d8672b9cbe2096ed6825847141b9798cb915ad80000000001000000";

        // println!("escrow tx raw preimage: {}", hex::encode(&escrow_tx_preimage));
        // println!("escrow tx: {}", full_escrow_tx);
        assert_eq!(escrow_tx_preimage, hex::decode(expected_escrow_preimage).unwrap());
        let (signed_tx, txid, hash_prevout) = transactions::btc::sign_escrow_transaction(full_escrow_tx, private_key);
        println!("signed_tx: {}", hex::encode(signed_tx));
        println!("txid: {}", hex::encode(txid));
        println!("hash prevout: {}", hex::encode(hash_prevout));
    }

    #[test]
    fn test_bitcoin_testnet_merch_close_tx() {
        // construct redeem script for this transaction to be able to spend from escrow-tx
        let cust_pk = hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap();
        let cust_private_key = "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV";
        let merch_pk = hex::decode("03af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb353").unwrap();
        let merch_private_key = "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV"; // testnet
        let merch_close_pk = hex::decode("02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af").unwrap();

        let expected_redeem_script = hex::decode("522103af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb35321027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae").unwrap();
        let redeem_script = transactions::btc::serialize_p2wsh_escrow_redeem_script(&cust_pk, &merch_pk);

        println!("expected redeem_script: {}", hex::encode(&redeem_script));
        assert_eq!(redeem_script, expected_redeem_script);

        // customer private key
        let input = Input {
            address_format: "p2wsh",
            // outpoint + txid
            transaction_id: hex::decode("5eb0c50e6f725b88507cda84f339aba539bc99853436db610d6a476a207f82d9").unwrap(),
            index: 0,
            redeem_script: Some(redeem_script),
            script_pub_key: None,
            utxo_amount: Some(10 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let config = BitcoinTxConfig {
            version: 2,
            lock_time: 0
        };

        let to_self_delay: [u8; 2] = [0xcf, 0x05]; // little-endian format

        let c_private_key = BitcoinPrivateKey::<Testnet>::from_str(cust_private_key).unwrap();
        let m_private_key = BitcoinPrivateKey::<Testnet>::from_str(merch_private_key).unwrap();
        let tx_params= transactions::btc::create_merch_close_transaction_params::<Testnet>(&input, &cust_pk, &merch_pk, &merch_close_pk, &to_self_delay).unwrap();

        let (merch_tx_preimage, _) = transactions::btc::create_merch_close_transaction_preimage::<Testnet>(&tx_params);
        println!("merch-close tx raw preimage: {}", hex::encode(&merch_tx_preimage));
        let expected_merch_tx_preimage = hex::decode("02000000fdd1def69203bbf96a6ebc56166716401302fcd06eadd147682e8898ba19bee43bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044d9827f206a476a0d61db36348599bc39a5ab39f384da7c50885b726f0ec5b05e0000000047522103af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb35321027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae00ca9a3b00000000ffffffffa87408648d6dfa0d6bd01786008047f225669b9fc634a38452e9ea1448a524b00000000001000000").unwrap();
        assert_eq!(merch_tx_preimage, expected_merch_tx_preimage);

        // customer signs the preimage and sends signature to merchant
        let cust_signature = transactions::btc::generate_signature_for_multi_sig_transaction::<Testnet>(&merch_tx_preimage, &c_private_key).unwrap();

        // merchant takes the signature and signs the transaction
        let (signed_merch_close_tx, txid, hash_prevout) = transactions::btc::completely_sign_multi_sig_transaction::<Testnet>(&tx_params, &cust_signature, false, None, &m_private_key);
        let merch_tx = hex::encode(signed_merch_close_tx.to_transaction_bytes().unwrap());
        println!("========================");
        println!("merch-close signed_tx: {}", merch_tx);
        println!("========================");
        println!("txid: {}", hex::encode(txid));
        println!("hash prevout: {}", hex::encode(hash_prevout));
        println!("========================");
    }

    #[test]
    fn test_bitcoin_testnet_cust_close_from_escrow_tx() {
        let spend_from_escrow = true;
        let input = Input {
            address_format: "p2wsh",
            // outpoint + txid
            transaction_id: hex::decode("f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1").unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(10 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };
        let cust_private_key = "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn"; // for cust-pk
        let merch_private_key = "cNTSD7W8URSCmfPTvNf2B5gyKe2wwyNomkCikVhuHPCsFgBUKrAV"; // for merch-pk
        let mut pubkeys = ClosePublicKeys {
            cust_pk: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            cust_close_pk: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            merch_pk: hex::decode("03af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb353").unwrap(),
            merch_close_pk: hex::decode("02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af").unwrap(),
            merch_disp_pk: hex::decode("021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67").unwrap(),
            rev_lock: FixedSizeArray32([0u8; 32])
        };
        let rev_lock = hex::decode("3111111111111111111111111111111111111111111111111111111111111111").unwrap();
        pubkeys.rev_lock.0.copy_from_slice(&rev_lock);

        let cust_bal = 8 * SATOSHI;
        let merch_bal = 2 * SATOSHI;
        let to_self_delay: [u8; 2] = [0xcf, 0x05]; // little-endian format
        let (tx_preimage, tx_params, _) =
            transactions::btc::create_cust_close_transaction::<Testnet>(&input, &pubkeys, &to_self_delay, cust_bal, merch_bal, spend_from_escrow);
        println!("cust-close from escrow tx raw preimage: {}", hex::encode(&tx_preimage));
        let expected_tx_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff40000000047522103af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb35321027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae00ca9a3b00000000ffffffff73bca1a59fcb04fe71d242be5d73021d02bbc6cdec66e9cb963060ff5028928e0000000001000000").unwrap();
        assert_eq!(tx_preimage, expected_tx_preimage);

        // merchant signs the preimage (note this would happen via MPC)
        let m_private_key = BitcoinPrivateKey::<Testnet>::from_str(merch_private_key).unwrap();
        let merch_signature = transactions::btc::generate_signature_for_multi_sig_transaction::<Testnet>(&tx_preimage, &m_private_key).unwrap();

        // customer signs the transaction and embed the merch-signature
        let c_private_key = BitcoinPrivateKey::<Testnet>::from_str(cust_private_key).unwrap();
        let (signed_cust_close_tx, txid, hash_prevout) = transactions::btc::completely_sign_multi_sig_transaction::<Testnet>(&tx_params, &merch_signature, false, None, &c_private_key);
        let cust_close_tx = hex::encode(signed_cust_close_tx.to_transaction_bytes().unwrap());

        println!("========================");
        println!("cust-close-from-escrow signed_tx: {}", cust_close_tx);
        println!("========================");
        println!("txid: {}", hex::encode(txid));
        println!("hash prevout: {}", hex::encode(hash_prevout));
        println!("========================");
    }

    #[test]
    fn test_bitcoin_testnet_cust_close_from_merch_tx() {
        let spend_from_escrow = false;
        let input = Input {
            address_format: "p2wsh",
            // outpoint + txid
            transaction_id: hex::decode("f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1").unwrap(),
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(10 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let mut pubkeys = ClosePublicKeys {
            cust_pk: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            cust_close_pk: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            merch_pk: hex::decode("024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b1").unwrap(),
            merch_close_pk: hex::decode("02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af").unwrap(),
            merch_disp_pk: hex::decode("021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67").unwrap(),
            rev_lock: FixedSizeArray32([0u8; 32])
        };
        let rev_lock = hex::decode("3111111111111111111111111111111111111111111111111111111111111111").unwrap();
        pubkeys.rev_lock.0.copy_from_slice(&rev_lock);

        let cust_bal = 8 * SATOSHI;
        let merch_bal = 2 * SATOSHI;
        let to_self_delay: [u8; 2] = [0xcf, 0x05]; // little-endian format
        let (tx_preimage, _, _) =
            transactions::btc::create_cust_close_transaction::<Testnet>(&input, &pubkeys, &to_self_delay, cust_bal, merch_bal, spend_from_escrow);
        println!("cust-close from merch tx raw preimage: {}", hex::encode(&tx_preimage));
        let expected_tx_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff40000000072635221024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b121027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae6702cf05b2752102ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5afac6800ca9a3b00000000ffffffff73bca1a59fcb04fe71d242be5d73021d02bbc6cdec66e9cb963060ff5028928e0000000001000000").unwrap();
        assert_eq!(tx_preimage, expected_tx_preimage);
    }


}
