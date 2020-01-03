use super::*;
use bitcoin::network::BitcoinNetwork;
use bitcoin::{BitcoinFormat, BitcoinTransaction, BitcoinTransactionInput,
              BitcoinTransactionOutput, BitcoinTransactionParameters, BitcoinAmount, BitcoinPrivateKey};
use bitcoin::address::BitcoinAddress;
use bitcoin::SignatureHash::SIGHASH_ALL;
use wagyu_model::crypto::hash160;
use wagyu_model::Transaction;
use wagyu_model::PrivateKey;
use std::str::FromStr;

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
    pub address: &'static str,
    pub address_format: &'static str,
    pub amount: i64
}

pub struct TxConfig {
    pub version: u32,
    pub lock_time: u32,
    pub expiry_height: u32
}

pub fn createBitcoinEscrowTx<N: BitcoinNetwork>(config: &TxConfig, input: &Input, output: &Output) -> Vec<u8> {

    let private_key = BitcoinPrivateKey::<N>::from_str(input.private_key).unwrap();

    let address_format = match input.address_format {
        "P2PKH" => BitcoinFormat::P2PKH,
        _ => panic!("did not specify supported address format")
    };
    let address = private_key.to_address(&address_format).unwrap();
    let transaction_id = hex::decode(input.transaction_id).unwrap();
    //let redeem_script = input.redeem_script.map(|script| hex::decode(script).unwrap());
    // let address_format = BitcoinFormat::P2PKH;

    let redeem_script = match (input.redeem_script, address_format.clone()) {
        (Some(script), _) => Some(hex::decode(script).unwrap()),
        (None, BitcoinFormat::P2SH_P2WPKH) => {
            let mut redeem_script = vec![0x00, 0x14];
            redeem_script.extend(&hash160(
                &private_key.to_public_key().to_secp256k1_public_key().serialize(),
            ));
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

    let address = BitcoinAddress::<N>::from_str(output.address).unwrap();
    let tx_output = BitcoinTransactionOutput::new(&address, BitcoinAmount(output.amount)).unwrap();
    output_vec.push(tx_output);

    let transaction_parameters = BitcoinTransactionParameters::<N> {
        version: config.version,
        inputs: input_vec,
        outputs: output_vec,
        lock_time: config.lock_time,
        segwit_flag: false,
    };

    let transaction = BitcoinTransaction::<N>::new(&transaction_parameters).unwrap();
    let raw_preimage = transaction.p2pkh_hash_preimage(1, SIGHASH_ALL).unwrap();

    return raw_preimage;
}

#[cfg(test)]
mod tests {
    use super::*;
    use transactions::{Input, Output, TxConfig};
    use std::intrinsics::transmute;
    use std::str::FromStr;
    use bitcoin::Testnet as BitcoinTestnet;

    #[test]
    fn test_bitcoin_escrow_tx() {
        let input = Input {
            private_key: "cQryG5K8Kpw9dNWA8jgmiQAP2jrFhGL6SgdnVzt6VVbscCqhAcA2",
            address_format: "P2PKH",
            transaction_id: "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1",
            index: 0,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(10000000),
            sequence: Some([0xff, 0xff, 0xff, 0xff]) // 4294967295
        };

        let config = TxConfig {
            version: 2,
            lock_time: 0,
            expiry_height: 499999999
        };

        let fee = 0; // 0.001
        let output = Output { address: "n1Z8M5eoimzqvAmufqrSXFAGzKtJ8QoDnD", address_format: "P2PKH", amount: 199996600 - fee };

        let escrow_tx_preimage = transactions::createBitcoinEscrowTx::<BitcoinTestnet>(&config, &input, &output);

        println!("escrow tx raw preimage: {}", hex::encode(&escrow_tx_preimage));
    }
}
