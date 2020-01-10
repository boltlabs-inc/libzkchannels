use super::*;
use bitcoin::network::BitcoinNetwork;
use bitcoin::{BitcoinFormat, BitcoinTransaction, BitcoinTransactionInput, BitcoinTransactionOutput, BitcoinTransactionParameters, BitcoinAmount, BitcoinPrivateKey, BitcoinPublicKey, BitcoinTransactionId};
use bitcoin::address::BitcoinAddress;
use bitcoin::SignatureHash::SIGHASH_ALL;
use wagyu_model::crypto::hash160;
use wagyu_model::{Transaction, PublicKey};
use wagyu_model::PrivateKey;
use std::str::FromStr;
use util::hash_to_slice;

const SATOSHI: i64 = 100000000;

pub struct Input {
    pub private_key: &'static str,
    pub address_format: &'static str,
    pub transaction_id: &'static str,
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
    pub pubkey1: Vec<u8>,
    pub pubkey2: Vec<u8>,
    pub address_format: &'static str,
    pub amount: i64
}

pub struct BitcoinTxConfig {
    pub version: u32,
    pub lock_time: u32
}

fn serialize_p2wsh_escrow_redeem_script(merch_pubkey: &Vec<u8>, cust_pubkey: &Vec<u8>) -> Vec<u8> {
    let mut script: Vec<u8> = Vec::new();
    script.extend(vec![0x52, 0x21]); // OP_2 + OP_DATA (pk1 len)
    script.extend(merch_pubkey.iter());
    script.push(0x21); // OP_DATA (pk2 len)
    script.extend(cust_pubkey.iter());
    script.extend(vec![0x52, 0xae]); // OP_2 OP_CHECKMULTISIG

    return script;
}

fn serialize_p2wsh_merch_close_redeem_script(merch_pubkey: &Vec<u8>, cust_pubkey: &Vec<u8>, merch_close_pubkey: &Vec<u8>, to_self_delay: &[u8; 2]) -> Vec<u8> {
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
fn create_p2wsh_scriptpubkey<N: BitcoinNetwork>(pubkey1: &Vec<u8>, pubkey2: &Vec<u8>) -> Vec<u8> {
    // manually construct the script
    let mut script: Vec<u8> = Vec::new();
    script.extend(vec![0x52, 0x21]); // OP_2 + OP_DATA (pk1 len)
    script.extend(pubkey1.iter());
    script.push(0x21); // OP_DATA (pk2 len)
    script.extend(pubkey2.iter());
    script.extend(vec![0x52, 0xae]); // OP_2 OP_CHECKMULTISIG

    // compute SHA256 hash of script
    let script_hash = hash_to_slice(&script);
    let mut script_pubkey = Vec::new();
    script_pubkey.extend(vec![0x00, 0x20]); // len of hash
    script_pubkey.extend_from_slice(&script_hash);

    return script_pubkey;
}

fn create_p2wpkh_scriptpubkey<N: BitcoinNetwork>(pubkey: &Vec<u8>) -> Vec<u8> {
    let script_hash = hash160(pubkey.as_slice());
    let mut script_pubkey = Vec::new();
    script_pubkey.extend(vec![0x00, 0x14]); // len of hash
    script_pubkey.extend_from_slice(&script_hash);

    return script_pubkey;
}

fn get_merch_close_timelocked_p2wsh_address(cust_pubkey: &Vec<u8>, merch_pubkey: &Vec<u8>, merch_close_pubkey: &Vec<u8>, to_self_delay: &[u8; 2]) -> Vec<u8> {
    // get the script
    let script = serialize_p2wsh_merch_close_redeem_script(merch_pubkey, cust_pubkey, merch_close_pubkey, to_self_delay);
    // compute SHA256 hash of script
    let script_hash = hash_to_slice(&script);
    let mut script_pubkey = Vec::new();
    script_pubkey.extend(vec![0x00, 0x20]); // len of hash
    script_pubkey.extend_from_slice(&script_hash);

    return script_pubkey;
}

fn get_cust_close_timelocked_p2wsh_address(rev_lock: &[u8; 20], merch_disp_pubkey: &Vec<u8>, cust_close_pubkey: &Vec<u8>, to_self_delay: &[u8; 2]) -> Vec<u8> {
//    # P2WSH cust-close scriptPubKey
//    # 0x63      OP_IF
//    # 0xa9      OP_HASH160
//    # 0x14      OP_DATA - len(revocation_lock {hash160[revocation-secret]})
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
    script.extend(vec![0x63, 0xa9, 0x14]);
    script.extend(rev_lock.iter());
    script.extend( vec![0x88, 0x21]);
    script.extend(merch_disp_pubkey.iter());
    script.push(0x67);
    script.push(0x02); // len for sequence
    script.extend(to_self_delay.iter()); // short sequence
    script.extend(vec![0xb2, 0x75, 0x21]);
    script.extend(cust_close_pubkey.iter());
    script.extend(vec![0x68, 0xac]);

    // compute SHA256 hash of script
    let script_hash = hash_to_slice(&script);
    let mut script_pubkey = Vec::new();
    script_pubkey.extend(vec![0x00, 0x20]); // len of hash
    script_pubkey.extend_from_slice(&script_hash);

    return script_pubkey;
}

fn create_opreturn_output(rev_lock: &[u8; 20], cust_close_pubkey: &Vec<u8>) -> Vec<u8> {
    let mut ret_val: Vec<u8> = Vec::new();
    let len = (rev_lock.len() + cust_close_pubkey.len()) as u8;
    ret_val.extend(vec![0x6a, len as u8]); // # OP_RETURN + OP_DATA
    ret_val.extend(rev_lock.iter());
    ret_val.extend(cust_close_pubkey.iter());
    return ret_val;
}

// creates a funding transaction with the following input/outputs
// input => p2pkh or p2sh_p2wpkh
// output1 => multi-sig addr via p2wsh
// output2 => change output to p2wpkh
pub fn create_bitcoin_escrow_tx<N: BitcoinNetwork>(config: &BitcoinTxConfig, input: &Input, output1: &MultiSigOutput, output2: &Output) -> (Vec<u8>, BitcoinTransaction<N>) {
    // retrieve signing key for funding input
    let private_key = BitcoinPrivateKey::<N>::from_str(input.private_key).unwrap();
    // types of UTXO inputs to support
    let address_format = match input.address_format {
        "p2pkh" => BitcoinFormat::P2PKH,
        "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
        "native_p2wsh" => BitcoinFormat::NATIVE_P2WSH,
        _ => panic!("do not currently support specified address format as funding input: {}", input.address_format)
    };
    let address = private_key.to_address(&address_format).unwrap();
    let transaction_id = hex::decode(input.transaction_id).unwrap();
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
            transaction_id,
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
    let output1_script_pubkey = create_p2wsh_scriptpubkey::<N>(&output1.pubkey1, &output1.pubkey2);
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

    let mut transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
    let hash_preimage = transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();
    // return hash preimage of transaction and the transaction itself (for later signing)
    return (hash_preimage, transaction);
}

// signs a given transaction using a specified private key
// assumes that transaction has already been loaded
pub fn sign_transaction<N: BitcoinNetwork>(unsigned_tx: BitcoinTransaction<N>, input: &Input) -> (String, BitcoinTransactionId) {
    let private_key = BitcoinPrivateKey::<N>::from_str(input.private_key).unwrap();

    let signed_tx = unsigned_tx.sign(&private_key).unwrap();
    let signed_tx_hex = hex::encode(signed_tx.to_transaction_bytes().unwrap());
    let tx_id_hex = signed_tx.to_transaction_id().unwrap();

    return (signed_tx_hex, tx_id_hex);
}

// creates a merch-close-tx that spends from a P2WSH to another
pub fn create_bitcoin_merch_close_tx<N: BitcoinNetwork>(config: &BitcoinTxConfig, input: &Input, merch_pubkey: &Vec<u8>, merch_close_pubkey: &Vec<u8>, self_delay: &[u8; 2]) -> (Vec<u8>, BitcoinTransaction<N>) {
    let private_key = BitcoinPrivateKey::<N>::from_str(input.private_key).unwrap();
    let cust_pubkey = private_key.to_public_key().to_secp256k1_public_key().serialize();

    let address_format = match input.address_format {
        "p2pkh" => BitcoinFormat::P2PKH,
        "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
        "native_p2wsh" => BitcoinFormat::NATIVE_P2WSH,
        _ => panic!("do not currently support specified address format: {}", input.address_format)
    };

    let transaction_id = hex::decode(input.transaction_id).unwrap();
    let redeem_script = match (input.redeem_script.as_ref(), address_format.clone()) {
        (Some(script), _) => Some(script.clone()),
        (None, BitcoinFormat::P2SH_P2WPKH) => {
            let mut redeem_script = serialize_p2wsh_escrow_redeem_script(merch_pubkey, &cust_pubkey.to_vec());
            // println!("redeem_script: {}", hex::encode(&redeem_script));
            Some(redeem_script)
        }
        (None, _) => None,
    };

    let mut address = match address_format {
        BitcoinFormat::NATIVE_P2WSH => BitcoinAddress::<N>::p2wsh(redeem_script.as_ref().unwrap()).unwrap(),
        _ => private_key.to_address(&address_format).unwrap()
    };
    // println!("address: {}", address);
    let sequence = input.sequence.map(|seq| seq.to_vec());
    // println!("redeem_script: {}", hex::encode(redeem_script.as_ref().unwrap()));

    let mut escrow_tx_input = BitcoinTransactionInput::<N>::new(
            transaction_id,
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

    let musig_script_pubkey = get_merch_close_timelocked_p2wsh_address(&cust_pubkey.to_vec(), merch_pubkey, merch_close_pubkey, self_delay);
    let musig_output = BitcoinTransactionOutput { amount: BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap(), script_pub_key: musig_script_pubkey };
    // println!("Multi-sig output script pubkey: {}", hex::encode(musig_output.serialize().unwrap()));

    let mut output_vec = vec![];
    output_vec.push(musig_output);

    let transaction_parameters = BitcoinTransactionParameters::<N> {
        version: config.version,
        inputs: input_vec,
        outputs: output_vec,
        lock_time: config.lock_time,
        segwit_flag: true,
    };

    let mut transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
    let hash_preimage= transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();

    return (hash_preimage, transaction);
}

pub struct ClosePublicKeys {
    pub cust_pk: Vec<u8>,
    pub cust_close_pk: Vec<u8>,
    pub merch_pk: Vec<u8>,
    pub merch_close_pk: Vec<u8>,
    pub merch_disp_pk: Vec<u8>,
    pub rev_lock: [u8; 20]
}

pub fn create_bitcoin_cust_close_transaction<N: BitcoinNetwork>(config: &BitcoinTxConfig, input: &Input, pubkeys: &ClosePublicKeys, self_delay: &[u8; 2],
                                                             cust_bal: i64, merch_bal: i64, from_escrow: bool) -> (Vec<u8>, BitcoinTransaction<N>){

    let private_key = BitcoinPrivateKey::<N>::from_str(input.private_key).unwrap();
    let cust_pubkey = private_key.to_public_key().to_secp256k1_public_key().serialize();
    // check that cust_pubkey == cust_pk

    let address_format = match input.address_format {
        "native_p2wsh" => BitcoinFormat::NATIVE_P2WSH,
        _ => panic!("do not currently support specified address format: {}", input.address_format)
    };

    let transaction_id = hex::decode(input.transaction_id).unwrap();
    let redeem_script = match from_escrow {
        true => {
            let redeem_script = serialize_p2wsh_escrow_redeem_script(&pubkeys.merch_pk, &pubkeys.cust_pk);
            // println!("escrow-tx redeem_script: {}", hex::encode(&redeem_script));
            Some(redeem_script)
        },
        false => {
            let redeem_script = serialize_p2wsh_merch_close_redeem_script(&pubkeys.merch_pk, &pubkeys.cust_pk, &pubkeys.merch_close_pk, self_delay);
            // println!("merch-close-tx redeem_script: {}", hex::encode(&redeem_script));
            Some(redeem_script)
        }
    };
    let mut address = match address_format {
        BitcoinFormat::NATIVE_P2WSH => BitcoinAddress::<N>::p2wsh(redeem_script.as_ref().unwrap()).unwrap(),
        _ => panic!("do not currently support specified address format")
    };
    // println!("address: {}", address);
    let sequence = input.sequence.map(|seq| seq.to_vec());

    let mut escrow_tx_input = BitcoinTransactionInput::<N>::new(
            transaction_id,
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
    let output1_script_pubkey = get_cust_close_timelocked_p2wsh_address(&pubkeys.rev_lock, &pubkeys.merch_disp_pk, &pubkeys.cust_close_pk, self_delay);
    // println!("(1) to_customer: {}", hex::encode(&output1_script_pubkey));
    let to_customer = BitcoinTransactionOutput { amount: BitcoinAmount::from_satoshi(cust_bal).unwrap(), script_pub_key: output1_script_pubkey };
    // println!("Multi-sig output script pubkey: {}", hex::encode(to_customer.serialize().unwrap()));

    // output 2: P2WPKH output to merchant
    let output2_script_pubkey = create_p2wpkh_scriptpubkey::<N>(&pubkeys.merch_close_pk);
    // println!("(2) to_merchant: {}", hex::encode(&output2_script_pubkey));
    let to_merchant = BitcoinTransactionOutput { amount: BitcoinAmount::from_satoshi(merch_bal).unwrap(), script_pub_key: output2_script_pubkey };

    // output 3: OP_RETURN output
    let output3_script_pubkey = create_opreturn_output(&pubkeys.rev_lock, &pubkeys.cust_close_pk);
    // println!("(3) OP_RETURN: {}", hex::encode(&output3_script_pubkey));
    let op_return_out = BitcoinTransactionOutput { amount: BitcoinAmount::from_satoshi(0).unwrap(), script_pub_key: output3_script_pubkey };

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

    let mut transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
    let hash_preimage= transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();

    return (hash_preimage, transaction);
}


#[cfg(test)]
mod tests {
    use super::*;
    use transactions::{Input, Output, BitcoinTxConfig};
    use std::intrinsics::transmute;
    use std::str::FromStr;
    use bitcoin::Testnet;
    use bitcoin::Denomination::Satoshi;

    #[test]
    fn test_bitcoin_p2sh_address() {
        let expected_scriptpubkey = hex::decode("0020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd").unwrap();
        let pubkey1 = hex::decode("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb").unwrap();
        let pubkey2 = hex::decode("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1").unwrap();
        let output_scriptpubkey = create_p2wsh_scriptpubkey::<Testnet>(&pubkey1, &pubkey2);
        
        
        println!("expected script_pubkey: {}", hex::encode(&output_scriptpubkey));

         assert_eq!(output_scriptpubkey, expected_scriptpubkey);
    }

    #[test]
    fn test_bitcoin_testnet_escrow_tx() {
        let input = Input {
            private_key: "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn", // testnet
            address_format: "p2sh_p2wpkh",
            transaction_id: "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
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

        let fee = 0; // 0.001
        let musig_output = MultiSigOutput {
            pubkey1: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            pubkey2: hex::decode("037bed6ab680a171ef2ab564af25eff15c0659313df0bbfb96414da7c7d1e65882").unwrap(),
            address_format: "native_p2wsh",
            amount: 39 * SATOSHI
        };

        // address => "n1Z8M5eoimzqvAmufqrSXFAGzKtJ8QoDnD"
        // private_key => "cVKYvWfApKiQJjLJhHokq7eEEFcx8Y1vsJYE9tVb5ccj3ZaCY82X" // testnet
        let change_output = Output { pubkey: hex::decode("021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67").unwrap(),
                                     amount: (1 * SATOSHI) };

        let (escrow_tx_preimage, full_escrow_tx) = transactions::create_bitcoin_escrow_tx::<Testnet>(&config, &input, &musig_output, &change_output);

        let expected_escrow_preimage = "020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4000000001976a914a496306b960746361e3528534d04b1ac4726655a88ac00286bee00000000ffffffff51bbd879074a16332d89cd524d8672b9cbe2096ed6825847141b9798cb915ad80000000001000000";

        // println!("escrow tx raw preimage: {}", hex::encode(&escrow_tx_preimage));
        // println!("escrow tx: {}", full_escrow_tx);
        assert_eq!(escrow_tx_preimage, hex::decode(expected_escrow_preimage).unwrap());

        // TODO: add step for signing each transaction and building witness
    }

    #[test]
    fn test_bitcoin_testnet_merch_close_tx() {
        //let raw_tx = "02000000000101d9827f206a476a0d61db36348599bc39a5ab39f384da7c50885b726f0ec5b05e0000000000ffffffff018060333c000000002200204de4a2361c5f251e23b9aa799012a9c94131ab51ec4be0e2a9857125c375e19d0400483045022100ccbbc1d45af69e5071d8e23bfce035a422925d44e3967cb6b618099a032d0f4502205573432be4b797123a2107b46189f4120b2a9a9a61a7978391abbe2abd8c74e601483045022100ff658f9b62b027dc7b6ebcad2d7bf62311f6805f5d75a5de08064686479de57602205c3a3fd6b81413b68de1d75240935b57f0df8d5b7c4929f7c870c2ba87157d2d01475221024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b1210253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7c52ae00000000";
        //let mut new_transaction = BitcoinTransaction::<Testnet>::from_str(&raw_tx).unwrap();
        //println!("new_tx txid: {}", new_transaction.to_transaction_id().unwrap());

        // construct redeem script for this transaction to be able to spend from escrow-tx
        let cust_pk = hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap();
        let merch_pk = hex::decode("024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b1").unwrap();
        let merch_close_pk = hex::decode("02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af").unwrap();

        let expected_redeem_script = hex::decode("5221024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b121027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae").unwrap();
        let redeem_script = serialize_p2wsh_escrow_redeem_script(&merch_pk, &cust_pk);

        assert_eq!(redeem_script, expected_redeem_script);

        let input = Input {
            private_key: "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn", // testnet
            address_format: "native_p2wsh",
            // outpoint + txid
            transaction_id: "5eb0c50e6f725b88507cda84f339aba539bc99853436db610d6a476a207f82d9",
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
        let (merch_tx_preimage, full_tx) = transactions::create_bitcoin_merch_close_tx::<Testnet>(&config, &input, &merch_pk, &merch_close_pk, &to_self_delay);

        println!("merch-close tx raw preimage: {}", hex::encode(&merch_tx_preimage));
        let expected_merch_tx_preimage = hex::decode("02000000fdd1def69203bbf96a6ebc56166716401302fcd06eadd147682e8898ba19bee43bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044d9827f206a476a0d61db36348599bc39a5ab39f384da7c50885b726f0ec5b05e00000000475221024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b121027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae00ca9a3b00000000ffffffff480dafb4ad69ea75b066cc3f5a869af9ab5d64b15ab6c627dce37286b32a4c070000000001000000").unwrap();
        assert_eq!(merch_tx_preimage, expected_merch_tx_preimage);

        // TODO: sign the transaction
    }

    #[test]
    fn test_bitcoin_testnet_cust_close_from_escrow_tx() {
        let spend_from_escrow = true;
        let input = Input {
            private_key: "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn", // testnet
            address_format: "native_p2wsh",
            // outpoint + txid
            transaction_id: "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(10 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let config = BitcoinTxConfig {
            version: 2,
            lock_time: 0
        };

        let mut pubkeys = ClosePublicKeys {
            cust_pk: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            cust_close_pk: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            merch_pk: hex::decode("024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b1").unwrap(),
            merch_close_pk: hex::decode("02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af").unwrap(),
            merch_disp_pk: hex::decode("021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67").unwrap(),
            rev_lock: [0u8; 20]
        };
        let rev_lock = hex::decode("3111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let _rev_lock = hash160(&rev_lock);
        pubkeys.rev_lock.copy_from_slice(&_rev_lock);

        let cust_bal = 8 * SATOSHI;
        let merch_bal = 2 * SATOSHI;
        let to_self_delay: [u8; 2] = [0xcf, 0x05]; // little-endian format
        let (tx_preimage, full_tx) = transactions::create_bitcoin_cust_close_transaction::<Testnet>(&config,
                                                                                                 &input,
                                                                                                 &pubkeys,
                                                                                                 &to_self_delay,
                                                                                                 cust_bal,
                                                                                                 merch_bal,spend_from_escrow);
        println!("cust-close from escrow tx raw preimage: {}", hex::encode(&tx_preimage));
        let expected_tx_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff400000000475221024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b121027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae00ca9a3b00000000ffffffffb48579580dc4e96cb32cd5aa91768d7e8baf3d1340127c19e7a646c97b644dfa0000000001000000").unwrap();
        assert_eq!(tx_preimage, expected_tx_preimage);

    }

    #[test]
    fn test_bitcoin_testnet_cust_close_from_merch_tx() {
        let spend_from_escrow = false;
        let input = Input {
            private_key: "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn", // testnet
            address_format: "native_p2wsh",
            // outpoint + txid
            transaction_id: "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(10 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let config = BitcoinTxConfig {
            version: 2,
            lock_time: 0
        };

        let mut pubkeys = ClosePublicKeys {
            cust_pk: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            cust_close_pk: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            merch_pk: hex::decode("024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b1").unwrap(),
            merch_close_pk: hex::decode("02ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5af").unwrap(),
            merch_disp_pk: hex::decode("021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67").unwrap(),
            rev_lock: [0u8; 20]
        };
        let rev_lock = hex::decode("3111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let _rev_lock = hash160(&rev_lock);
        pubkeys.rev_lock.copy_from_slice(&_rev_lock);

        let cust_bal = 8 * SATOSHI;
        let merch_bal = 2 * SATOSHI;
        let to_self_delay: [u8; 2] = [0xcf, 0x05]; // little-endian format
        let (tx_preimage, full_tx) = transactions::create_bitcoin_cust_close_transaction::<Testnet>(&config,
                                                                                                 &input,
                                                                                                 &pubkeys,
                                                                                                 &to_self_delay,
                                                                                                 cust_bal,
                                                                                                 merch_bal,
                                                                                                 spend_from_escrow);
        println!("cust-close from merch tx raw preimage: {}", hex::encode(&tx_preimage));
        let expected_tx_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff40000000072635221024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b121027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae6702cf05b2752102ab573100532827bd0e44b4353e4eaa9c79afbc93f69454a4a44d9fea8c45b5afac6800ca9a3b00000000ffffffffb48579580dc4e96cb32cd5aa91768d7e8baf3d1340127c19e7a646c97b644dfa0000000001000000").unwrap();
        assert_eq!(tx_preimage, expected_tx_preimage);
    }


}
