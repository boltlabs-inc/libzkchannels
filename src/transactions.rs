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
use bs58;

const SATOSHI: i64 = 100000000;

pub struct Input {
    pub private_key: &'static str,
    pub address_format: &'static str,
    pub transaction_id: &'static str,
    pub index: u32,
    pub redeem_script: Option<&'static str>,
    pub script_pub_key: Option<&'static str>,
    pub utxo_amount: Option<i64>,
    pub sequence: Option<[u8; 4]>
}

pub struct Output {
    pub private_key: &'static str,
    pub amount: i64
}

pub struct MultiSigOutput {
    pub pubkey1: Vec<u8>,
    pub pubkey2: Vec<u8>,
    pub address_format: &'static str,
    pub amount: i64
}

pub struct TxConfig {
    pub version: u32,
    pub lock_time: u32,
    pub expiry_height: u32
}

pub fn createP2PKHAddress<N: BitcoinNetwork>(private_key: &'static str) -> (BitcoinPrivateKey<N>, BitcoinPublicKey<N>, BitcoinAddress<N>) {
    let private_key = BitcoinPrivateKey::<N>::from_str(&private_key).unwrap();
    let public_key = private_key.to_public_key();
    let address = public_key.to_address(&BitcoinFormat::P2PKH).unwrap();

    return (private_key, public_key, address);
}

pub fn generateRedeemScript(pubkey1: Vec<u8>, pubkey2: Vec<u8>) -> Vec<u8> {
    let mut script: Vec<u8> = Vec::new();
    script.extend(vec![0x52, 0x21]); // OP_2 + OP_DATA (pk1 len)
    script.extend(pubkey1.iter());
    script.push(0x21); // OP_DATA (pk2 len)
    script.extend(pubkey2.iter());
    script.extend(vec![0x52, 0xae]); // OP_2 OP_CHECKMULTISIG

    return script;
}

// given two public keys, create a multi-sig address via P2SH script
pub fn createMultiSigAddress<N: BitcoinNetwork>(pubkey1: &Vec<u8>, pubkey2: &Vec<u8>) -> (Vec<u8>, String) {
    let mut script: Vec<u8> = Vec::new();
    script.extend(vec![0x52, 0x21]); // OP_2 + OP_DATA (pk1 len)
    script.extend(pubkey1.iter());
    script.push(0x21); // OP_DATA (pk2 len)
    script.extend(pubkey2.iter());
    script.extend(vec![0x52, 0xae]); // OP_2 OP_CHECKMULTISIG

    let mut redeem_script_hash = hash160(&script);
    let prefix_byte = N::to_address_prefix(&BitcoinFormat::P2SH_P2WPKH)[0];
    redeem_script_hash.insert(0, prefix_byte);

    // compute SHA256 hash of script
    let script_hash = hash_to_slice(&script);

    let mut output_hash = Vec::new();
    output_hash.extend(vec![0x00, 0x20]); // len of hash
    output_hash.extend_from_slice(&script_hash);

    let script_hash2 = hash_to_slice(&script_hash.to_vec());
    redeem_script_hash.extend(&script_hash2[0..4]);
    let address = bs58::encode(redeem_script_hash).into_string();

    return (output_hash, address);
}

// creates a funding transaction with the following input/outputs
// input => p2pkh or p2sh_p2wpkh
// output1 => multi-sig addr via p2wsh
// output2 => change output to p2pkh
pub fn createBitcoinEscrowTx<N: BitcoinNetwork>(config: &TxConfig, input: &Input, output1: &MultiSigOutput, output2: &Output) -> (Vec<u8>, String, BitcoinTransactionId) {
    // retrieve signing key for funding input
    let private_key = BitcoinPrivateKey::<N>::from_str(input.private_key).unwrap();
    // types of UTXO inputs to support
    let address_format = match input.address_format {
        "p2pkh" => BitcoinFormat::P2PKH,
        "p2sh_p2wpkh" => BitcoinFormat::P2SH_P2WPKH,
        _ => panic!("do not currently support specified address format as funding input")
    };
    let address = private_key.to_address(&address_format).unwrap();
    let transaction_id = hex::decode(input.transaction_id).unwrap();
    // TODO: add logic for generating P2PKH redeem script below
    let redeem_script = match (input.redeem_script, address_format.clone()) {
        (Some(script), _) => Some(hex::decode(script).unwrap()),
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

    // add multi-sig output as P2SH output
    let (output_hash, musig_address) = createMultiSigAddress::<N>(&output1.pubkey1, &output1.pubkey2);
    let address2 = BitcoinAddress::<N>::from_str(musig_address.as_str()).unwrap();
    let multisig_output = BitcoinTransactionOutput::new(&address2, BitcoinAmount(output1.amount)).unwrap();

    // add P2PKH output
    let (priv_key, pub_key, addr) = createP2PKHAddress::<N>(output2.private_key);
    let change_output = BitcoinTransactionOutput::new(&addr, BitcoinAmount(output2.amount)).unwrap();

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
    let raw_preimage = transaction.segwit_hash_preimage(0, SIGHASH_ALL).unwrap();

    transaction = transaction.sign(&private_key).unwrap();
    let signed_tx = hex::encode(transaction.to_transaction_bytes().unwrap());
    let tx_id = transaction.to_transaction_id().unwrap();

    return (raw_preimage, signed_tx, tx_id);
}

pub fn createBitcoinMerchCloseTx<N: BitcoinNetwork>(config: &TxConfig, input: &Input, output1: &MultiSigOutput, output2: &Output) { // -> (Vec<u8>, String, BitcoinTransactionId)

    let transaction_id = hex::decode(input.transaction_id).unwrap();
    let sequence = input.sequence.map(|seq| seq.to_vec());
    let address = None;
    let redeem_script = None;
    let script_pub_key = None;
    let escrow_tx_input = BitcoinTransactionInput::<N>::new(
            transaction_id,
            input.index,
            address,
            Some(BitcoinAmount::from_satoshi(input.utxo_amount.unwrap()).unwrap()),
            redeem_script,
            script_pub_key,
            sequence,
            SIGHASH_ALL,
        )
        .unwrap();

    let mut input_vec = vec![];
    input_vec.push(escrow_tx_input);

    // let mut output_vec = vec![];
    // outut_vec.push()

}

// pub fn createBitcoinCustCloseFromEscrowTx<N: BitcoinNetwork>(config: &TxConfig)
// pub fn createBitcoinCustCloseFromMerchTx<N: BitcoinNetwork>(config: &TxConfig)

#[cfg(test)]
mod tests {
    use super::*;
    use transactions::{Input, Output, TxConfig};
    use std::intrinsics::transmute;
    use std::str::FromStr;
    use bitcoin::Mainnet;
    use bitcoin::Testnet;
    use bitcoin::Denomination::Satoshi;

    #[test]
    fn test_bitcoin_p2sh_address() {
        let expected_address1 = "2Mv6apz67hPF9SiEQdG5SaxbcC4JnouBBhh";
        let expected_address2 = "34YNmFA65vjoEvbrx8TZy1cLyi6d2Am5Hq";
        let pubkey1 = hex::decode("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb").unwrap();
        let pubkey2 = hex::decode("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1").unwrap();
        let (output_hash1, address1) = createMultiSigAddress::<Testnet>(&pubkey1, &pubkey2);
        let (output_hash2, address2) = createMultiSigAddress::<Mainnet>(&pubkey1, &pubkey2);
        println!("testnet address: {}", address1);
        println!("mainnet address: {}", address2);

        assert_eq!(address1, expected_address1);
        assert_eq!(address2, expected_address2);
    }

    #[test]
    fn test_bitcoin_testnet_escrow_tx() {
        let input = Input {
            private_key: "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn", // testnet
            address_format: "p2sh_p2wpkh",
            transaction_id: "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
            index: 0,
            redeem_script: None, // Some("0014a496306b960746361e3528534d04b1ac4726655a"),
            script_pub_key: None,
            utxo_amount: Some(40 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let config = TxConfig {
            version: 2,
            lock_time: 0,
            expiry_height: 499999999
        };

        let fee = 0; // 0.001
        let musig_output = MultiSigOutput {
            pubkey1: hex::decode("037bed6ab680a171ef2ab564af25eff15c0659313df0bbfb96414da7c7d1e65882").unwrap(),
            pubkey2: hex::decode("027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb").unwrap(),
            address_format: "p2sh",
            amount: 39 * SATOSHI
        };

        // address => "n1Z8M5eoimzqvAmufqrSXFAGzKtJ8QoDnD"
        let change_output = Output { private_key: "cVKYvWfApKiQJjLJhHokq7eEEFcx8Y1vsJYE9tVb5ccj3ZaCY82X", // testnet
                                     amount: (1 * SATOSHI) };

        let (escrow_tx_preimage, escrow_tx, txid) = transactions::createBitcoinEscrowTx::<Testnet>(&config, &input, &musig_output, &change_output);

        let expected_escrow_preimage = "020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4000000001976a914a496306b960746361e3528534d04b1ac4726655a88ac00286bee00000000ffffffff371372a8e81a87ad9d45b865f8893a2e4449f966622f3e3f74ab9791f434d11b0000000001000000";

        println!("escrow tx raw preimage: {}", hex::encode(&escrow_tx_preimage));
        println!("escrow tx: {}", escrow_tx);
        println!("tx id: {}", txid.to_string());
        assert_eq!(escrow_tx_preimage, hex::decode(expected_escrow_preimage).unwrap());
    }

    #[test]
    fn test_bitcoin_testnet_merch_close_tx() {
        let raw_tx = "02000000000101d9827f206a476a0d61db36348599bc39a5ab39f384da7c50885b726f0ec5b05e0000000000ffffffff018060333c000000002200204de4a2361c5f251e23b9aa799012a9c94131ab51ec4be0e2a9857125c375e19d0400483045022100ccbbc1d45af69e5071d8e23bfce035a422925d44e3967cb6b618099a032d0f4502205573432be4b797123a2107b46189f4120b2a9a9a61a7978391abbe2abd8c74e601483045022100ff658f9b62b027dc7b6ebcad2d7bf62311f6805f5d75a5de08064686479de57602205c3a3fd6b81413b68de1d75240935b57f0df8d5b7c4929f7c870c2ba87157d2d01475221024596d7b33733c28101dbc6c85901dffaed0cdac63ab0b2ea141217d1990ad4b1210253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7c52ae00000000";
        let mut new_transaction = BitcoinTransaction::<Testnet>::from_str(&raw_tx).unwrap();
        println!("new_tx txid: {}", new_transaction.to_transaction_id().unwrap());

        let input = Input {
            private_key: "cPmiXrwUfViwwkvZ5NXySiHEudJdJ5aeXU4nx4vZuKWTUibpJdrn", // testnet
            address_format: "p2sh_p2wpkh",
            // outpoint + txid
            transaction_id: "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
            index: 0,
            //
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(39 * SATOSHI),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let config = TxConfig {
            version: 2,
            lock_time: 0,
            expiry_height: 499999999
        };

        // transactions::createBitcoinMerchCloseTx(&config);
    }

    #[test]
    fn test_bitcoin_testnet_cust_close_from_escrow() {
    }

    #[test]
    fn test_bitcoin_testnet_cust_close_from_merch() {
    }


}
