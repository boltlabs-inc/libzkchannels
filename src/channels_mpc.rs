use super::*;
use rand::Rng;
use wallet::{State, NONCE_LEN};
use util::{hash_to_slice, hmac_sign, compute_hash160};

#[cfg(feature = "mpc-bitcoin")]
use mpcwrapper::{mpc_build_masked_tokens_cust, mpc_build_masked_tokens_merch};
use transactions::ClosePublicKeys;
use transactions::btc::{create_escrow_transaction, create_merch_close_transaction_params, create_merch_close_transaction_preimage, sign_escrow_transaction};
use transactions::btc::{create_input, get_var_length_int, create_cust_close_transaction, generate_signature_for_multi_sig_transaction, completely_sign_multi_sig_transaction};
use bitcoin::{Testnet, BitcoinTransactionParameters, BitcoinNetwork, BitcoinPrivateKey};
use sha2::{Sha256, Digest};

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub conn_type: ConnType,
    pub dest_ip: String,
    pub dest_port: u32,
    pub path: String
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelMPCToken {
    pub pk_c: Option<secp256k1::PublicKey>, // pk_c
    pub pk_m: secp256k1::PublicKey, // pk_m
    pub escrow_txid: [u8; 32],
    pub merch_txid: [u8; 32]
}

#[cfg(feature = "mpc-bitcoin")]
impl ChannelMPCToken {
    pub fn set_customer_pk(&mut self, pk_c: secp256k1::PublicKey) {
        self.pk_c = Some(pk_c);
    }

    pub fn is_init(&self) -> bool {
        return !self.pk_c.is_none();
    }

    pub fn compute_channel_id(&self) -> Result<[u8; 32], String> {
        if self.pk_c.is_none() {
            return Err(String::from("pk_c is not initialized yet"));
        }

        // check txids are set
        let input = serde_json::to_vec(&self).unwrap();

        return Ok(hash_to_slice(&input));
    }
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelMPCState {
    R: i32,
    tx_fee: i64,
    dust_limit: i64,
    pub key_com: [u8; 32],
    pub name: String,
    pub pay_init: bool,
    pub channel_established: bool,
    pub third_party: bool,
    pub merch_payout_pk: Option<secp256k1::PublicKey>,
    pub merch_dispute_pk: Option<secp256k1::PublicKey>
}

#[cfg(feature = "mpc-bitcoin")]
impl ChannelMPCState {
    pub fn new(name: String, third_party_support: bool) -> ChannelMPCState {
        ChannelMPCState {
            R: 0,
            tx_fee: 0,
            dust_limit: 0,
            key_com: [0u8; 32],
            name: name.to_string(),
            pay_init: false,
            channel_established: false,
            third_party: third_party_support,
            merch_payout_pk: None,
            merch_dispute_pk: None
        }
    }

    pub fn set_channel_fee(&mut self, fee: i64) {
        self.tx_fee = fee;
    }

    pub fn get_channel_fee(&self) -> i64 {
        return self.tx_fee as i64;
    }

    pub fn set_dust_limit(&mut self, dust_amount: i64) {
        assert!(dust_amount >= 0);
        self.dust_limit = dust_amount;
    }

    pub fn get_dust_limit(&self) -> i64 {
        return self.dust_limit;
    }

    pub fn set_key_com(&mut self, key_com: [u8; 32]) {
        self.key_com = key_com;
    }

    pub fn set_merchant_public_keys(&mut self, merch_payout_pk: secp256k1::PublicKey, merch_dispute_pk: secp256k1::PublicKey) {
        self.merch_payout_pk = Some(merch_payout_pk);
        self.merch_dispute_pk = Some(merch_dispute_pk);
    }
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct MaskedMPCInputs {
    pt_mask: [u8; 32],
    escrow_mask: [u8; 32],
    merch_mask: [u8; 32],
    r_escrow_sig: [u8; 32],
    r_merch_sig: [u8; 32],
}

#[cfg(feature = "mpc-bitcoin")]
impl MaskedMPCInputs {
    pub fn get_tx_masks(&self) -> MaskedTxMPCInputs {
        return MaskedTxMPCInputs {
            escrow_mask: self.escrow_mask,
            merch_mask: self.merch_mask,
            r_escrow_sig: self.r_escrow_sig,
            r_merch_sig: self.r_merch_sig,
        }
    }
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct MaskedTxMPCInputs {
    pub escrow_mask: [u8; 32],
    pub merch_mask: [u8; 32],
    pub r_escrow_sig: [u8; 32],
    pub r_merch_sig: [u8; 32],
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct MaskedMPCOutputs {
    pt_masked: [u8; 32],
    escrow_masked: [u8; 32],
    merch_masked: [u8; 32]
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Serialize, Deserialize)]
pub struct CustomerMPCState {
    pub name: String,
    pub pk_c: secp256k1::PublicKey,
    sk_c: secp256k1::SecretKey,
    pub cust_balance: i64,
    pub merch_balance: i64,
    rev_lock: [u8; 32],
    rev_secret: [u8; 32],
    // old_kp: Option<LockMap>, // old lock and preimage pair
    t: [u8; 32], // randomness used to form the commitment
    state: Option<State>, // vector of field elements that represent current state
    index: i32,
    masked_outputs: HashMap<i32, MaskedMPCOutputs>,
    pay_tokens: HashMap<i32, [u8; 32]>,
    pay_token_mask_com: [u8; 32],
    payout_sk: secp256k1::SecretKey,
    pub conn_type: u32,
    cust_close_escrow_tx: String,
    cust_close_merch_tx: String
}

#[cfg(feature = "mpc-bitcoin")]
impl CustomerMPCState {
    pub fn new<R: Rng>(csprng: &mut R, cust_bal: i64, merch_bal: i64, name: String) -> Self
    {
        let secp = secp256k1::Secp256k1::new();

        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        // generate the signing keypair for the channel
        let sk_c = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let pk_c = secp256k1::PublicKey::from_secret_key(&secp, &sk_c);

        // generate the keypair for the initial state of channel
        let mut rev_secret = [0u8; 32];
        csprng.fill_bytes(&mut rev_secret);

        // compute hash of the revocation secret
        let rev_lock = hash_to_slice(&rev_secret.to_vec());

        // pick random t
        let t: [u8; 32] = [0; 32];
        let mut _payout_sk: [u8; 32] = [0; 32];
        csprng.fill_bytes(&mut _payout_sk);
        let payout_sk = secp256k1::SecretKey::from_slice(&_payout_sk).unwrap();

        let mpc_outputs = HashMap::new();
        let pt_db = HashMap::new();

        return CustomerMPCState {
            name: name,
            pk_c: pk_c,
            sk_c: sk_c,
            cust_balance: cust_bal,
            merch_balance: merch_bal,
            rev_lock: rev_lock,
            rev_secret: rev_secret,
            t: t,
            state: None,
            index: 0,
            masked_outputs: mpc_outputs,
            pay_tokens: pt_db,
            pay_token_mask_com: [0u8; 32],
            payout_sk: payout_sk,
            conn_type: 0,
            cust_close_escrow_tx: String::new(),
            cust_close_merch_tx: String::new()
        };
    }

    pub fn set_mpc_connect_type(&mut self, conn_type: u32) {
        self.conn_type = conn_type;
    }

    pub fn update_pay_com(&mut self, pay_token_mask_com: [u8; 32]) {
        self.pay_token_mask_com.copy_from_slice(&pay_token_mask_com);
    }

    pub fn generate_init_state<R: Rng>(&mut self, csprng: &mut R, channel_token: &mut ChannelMPCToken,
                                       escrow_tx_prevout: [u8; 32], merch_tx_prevout: [u8; 32]) {
        assert!(self.state.is_none());

        let mut nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
        csprng.fill_bytes(&mut nonce);

        channel_token.set_customer_pk(self.pk_c.clone());

        let state = State { nonce: nonce, rev_lock: self.rev_lock, pk_c: self.pk_c, pk_m: channel_token.pk_m.clone(),
                            bc: self.cust_balance, bm: self.merch_balance, escrow_txid: channel_token.escrow_txid,
                            merch_txid: channel_token.merch_txid, escrow_prevout: escrow_tx_prevout, merch_prevout: merch_tx_prevout };

        assert!(channel_token.is_init());
        self.state = Some(state);
    }

    pub fn generate_rev_lock_commitment<R: Rng>(&mut self, csprng: &mut R) -> [u8; 32] {
        // assert!(!self.state.is_none());
        let mut t: [u8; 32] = [0; 32];
        csprng.fill_bytes(&mut t);
        self.t.copy_from_slice(&t);

        let mut input = Vec::new();
        input.extend_from_slice(&self.rev_lock);
        // input.extend_from_slice(&self.t);
        return hash_to_slice(&input);
    }

    pub fn get_randomness(&self) -> [u8; 32] {
        return self.t;
    }

    pub fn get_rev_pair(&self) -> ([u8; 32], [u8; 32]) {
        return (self.rev_lock, self.rev_secret);
    }

    pub fn get_current_state(&self) -> State {
        assert!(self.state.is_some());
        return self.state.unwrap();
    }

    pub fn store_initial_pay_token(&mut self, pay_token: [u8; 32]) {
        self.pay_tokens.insert(0, pay_token);
    }

    pub fn generate_new_state<R: Rng>(&mut self, csprng: &mut R, channel: &ChannelMPCState, amount: i64) {
        assert!(!self.state.is_none());

        let mut new_state = self.state.unwrap().clone();

        // generate a new nonce
        let mut new_nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
        csprng.fill_bytes(&mut new_nonce);

        // generate a new rev_lock/rev_secret pair
        // generate the keypair for the initial state of channel
        let mut new_rev_secret = [0u8; 32];
        csprng.fill_bytes(&mut new_rev_secret);

        // compute hash of the revocation secret
        let new_rev_lock = hash_to_slice(&new_rev_secret.to_vec());

        // update balances appropriately
        new_state.bc -= amount;
        new_state.bm += amount;

        new_state.nonce.copy_from_slice(&new_nonce);
        new_state.rev_lock.copy_from_slice(&new_rev_lock);

        self.rev_secret.copy_from_slice(&new_rev_secret);
        self.rev_lock.copy_from_slice(&new_rev_lock);
        self.cust_balance = new_state.bc;
        self.merch_balance = new_state.bm;

        self.state = Some(new_state);
    }

    pub fn generate_init_channel_token(&self, pk_m: &secp256k1::PublicKey, escrow_txid: [u8; 32], merch_txid: [u8; 32]) -> ChannelMPCToken {

        return ChannelMPCToken {
            pk_c: Some(self.pk_c.clone()),
            pk_m: pk_m.clone(),
            escrow_txid: escrow_txid,
            merch_txid: merch_txid
        };
    }

    pub fn has_tokens(&self) -> bool {
        let index = self.index;
        let is_pt = self.pay_tokens.get(&index).is_some();
        return is_pt;
    }

//    // update the internal state of the customer wallet
//    pub fn update(&mut self, new_state: CustomerMPCState) -> bool {
//        // update everything except for the wpk/wsk pair
//        assert!(self.name == new_state.name);
//        self.cust_balance = new_state.cust_balance;
//        self.merch_balance = new_state.merch_balance;
//        self.old_kp = new_state.old_kp;
//        self.index = new_state.index;
//        self.masked_outputs = new_state.masked_outputs;
//        self.pay_tokens = new_state.pay_tokens;
//
//        return true;
//    }

    // customer side of mpc
    pub fn execute_mpc_context(&mut self, channel: &ChannelMPCState, channel_token: &ChannelMPCToken,
                       old_state: State, new_state: State, paytoken_mask_com: [u8; 32], rev_lock_com: [u8;32], amount: i64) -> Result<bool, String> {

        let secp = secp256k1::Secp256k1::new();
        // load the key_com from channel state
        let key_com = channel.key_com.clone();

        // get cust pub keys
        let cust_escrow_pub_key = self.pk_c.clone();
        let cust_payout_pub_key = secp256k1::PublicKey::from_secret_key(&secp, &self.payout_sk);

        let merch_escrow_pub_key= channel_token.pk_m.clone();
        let merch_dispute_key= channel.merch_dispute_pk.unwrap();
        let merch_payout_pub_key = channel.merch_payout_pk.unwrap();
        let pk_input_buf = merch_payout_pub_key.serialize();
        let merch_public_key_hash = compute_hash160(&pk_input_buf.to_vec());

        let old_paytoken = match self.has_tokens() {
            true => self.pay_tokens.get(&self.index).unwrap(),
            false => return Err(String::from("you do not have a pay token for previous state"))
        };

        let (pt_masked_ar, ct_escrow_masked_ar, ct_merch_masked_ar) =
            mpc_build_masked_tokens_cust(self.conn_type, amount, &paytoken_mask_com, &rev_lock_com, &key_com,
                                     merch_escrow_pub_key, merch_dispute_key, merch_public_key_hash, merch_payout_pub_key,
                                     new_state, old_state,old_paytoken, cust_escrow_pub_key, cust_payout_pub_key);

        let masked_output = MaskedMPCOutputs {
            pt_masked: pt_masked_ar,
            escrow_masked: ct_escrow_masked_ar,
            merch_masked: ct_merch_masked_ar
        };

        println!("CUSTOMER");
        println!("pt_masked: {}", hex::encode(&pt_masked_ar));
        println!("escrow_masked: {}", hex::encode(&ct_escrow_masked_ar));
        println!("merch_masked: {}", hex::encode(&ct_merch_masked_ar));
        println!("CUSTOMER");

        // save the masked outputs (will unmask later)
        self.masked_outputs.insert(self.index, masked_output.clone());
        Ok(true)
    }

    pub fn construct_close_transaction_preimage<N: BitcoinNetwork>(&self, channel_state: &ChannelMPCState, channel_token: &ChannelMPCToken) -> (Vec<u8>, Vec<u8>, BitcoinTransactionParameters<N>, BitcoinTransactionParameters<N>) {
        let secp = secp256k1::Secp256k1::new();
        let cust_escrow_pub_key = self.pk_c.serialize();
        let cust_payout_pub_key = secp256k1::PublicKey::from_secret_key(&secp, &self.payout_sk).serialize();

        let merch_escrow_pub_key= channel_token.pk_m.serialize();
        let merch_dispute_key= channel_state.merch_dispute_pk.unwrap().serialize();
        let merch_payout_pub_key = channel_state.merch_payout_pk.unwrap().serialize();

        let init_balance = self.cust_balance + self.merch_balance; // is this right?
        // TODO: should be configurable via a tx_config
        let escrow_index = 0;
        let merch_index = 0;
        let to_self_delay: [u8; 2] = [0xcf, 0x05]; // little-endian format

        let mut pubkeys = ClosePublicKeys {
            cust_pk: cust_escrow_pub_key.to_vec(),
            cust_close_pk: cust_payout_pub_key.to_vec(),
            merch_pk: merch_escrow_pub_key.to_vec(),
            merch_close_pk: merch_payout_pub_key.to_vec(),
            merch_disp_pk: merch_dispute_key.to_vec(),
            rev_lock: [0u8; 32]
        };
        pubkeys.rev_lock.copy_from_slice(&self.state.unwrap().rev_lock);
        // println!("Escrow TXID: {}", hex::encode(channel_token.escrow_txid));
        let escrow_input = create_input(&channel_token.escrow_txid, escrow_index, init_balance);
        let merch_input = create_input(&channel_token.merch_txid, merch_index, init_balance);

        let (escrow_tx_preimage, escrow_tx_params, _) =
            create_cust_close_transaction::<N>(&escrow_input, &pubkeys, &to_self_delay,self.cust_balance,self.merch_balance, true);

        let (merch_tx_preimage, merch_tx_params, _) =
            create_cust_close_transaction::<N>(&merch_input, &pubkeys, &to_self_delay, self.cust_balance, self.merch_balance, false);

        return (escrow_tx_preimage, merch_tx_preimage, escrow_tx_params, merch_tx_params);
    }

    // TODO: add BoltResult type here
    pub fn unmask_and_verify_transactions(&mut self, channel_state: &ChannelMPCState, channel_token: &ChannelMPCToken, mask_bytes: MaskedTxMPCInputs) -> bool {
        let mut escrow_mask_bytes = mask_bytes.escrow_mask.clone();
        let mut merch_mask_bytes = mask_bytes.merch_mask.clone();

        if self.masked_outputs.get(&self.index).is_none() {
            println!("could not find masked output");
            return false;
        }

        let mpc_out = self.masked_outputs.get(&self.index).unwrap();
        xor_in_place(&mut escrow_mask_bytes, &mpc_out.escrow_masked[..]);
        xor_in_place(&mut merch_mask_bytes, &mpc_out.merch_masked[..]);

        // if valid, output (s_{i+1}, CT_{i+1}, pay-token-{i+1})
        let (escrow_tx_preimage, merch_tx_preimage, escrow_tx_params, merch_tx_params) =
            self.construct_close_transaction_preimage::<Testnet>(channel_state, channel_token);
        println!("Close-Escrow Tx preimage: {}", hex::encode(&escrow_tx_preimage));
        println!("Close-Merch Tx preimage: {}", hex::encode(&merch_tx_preimage));

        let mut escrow_sig_vec = mask_bytes.r_escrow_sig.to_vec();
        escrow_sig_vec.append(&mut escrow_mask_bytes.to_vec());
        let escrow_sig = secp256k1::Signature::from_compact(&escrow_sig_vec.as_slice()).unwrap();
        println!("Close from Escrow Signature: {}", &escrow_sig);

        let mut merch_sig_vec = mask_bytes.r_merch_sig.to_vec();
        merch_sig_vec.append(&mut merch_mask_bytes.to_vec());
        let merch_sig = secp256k1::Signature::from_compact(&merch_sig_vec.as_slice()).unwrap();
        println!("Close from Merch Signature: {}", &merch_sig);

        let escrow_tx_hash = Sha256::digest(&Sha256::digest(&escrow_tx_preimage));
        let merch_tx_hash = Sha256::digest(&Sha256::digest(&merch_tx_preimage));

        // println!("Tx hash: {}", hex::encode(&escrow_tx_hash));
        let msg1 = secp256k1::Message::from_slice(&escrow_tx_hash).unwrap();
        let msg2 = secp256k1::Message::from_slice(&merch_tx_hash).unwrap();
        let secp = secp256k1::Secp256k1::verification_only();
        let escrow_sig_valid = secp.verify(&msg1, &escrow_sig, &channel_token.pk_m).is_ok();
        let merch_sig_valid = secp.verify(&msg2, &merch_sig, &channel_token.pk_m).is_ok();

        // customer sign the transactions to complete multi-sig and store CT bytes locally
        let private_key = BitcoinPrivateKey::<Testnet>::from_secp256k1_secret_key(self.sk_c.clone(), false);
        println!("Signing with private key: {}", &private_key.to_string());
        let escrow_signature = escrow_sig.serialize_der().to_vec();
        let enc_escrow_signature = [get_var_length_int(escrow_signature.len() as u64).unwrap(), escrow_signature].concat();

        let merch_signature = merch_sig.serialize_der().to_vec();
        let enc_merch_signature = [get_var_length_int(merch_signature.len() as u64).unwrap(), merch_signature].concat();

        // sign the cust-close-from-escrow-tx
        let (signed_cust_close_escrow_tx, _, _) =
            transactions::btc::completely_sign_multi_sig_transaction::<Testnet>(&escrow_tx_params, &enc_escrow_signature, &private_key);
        self.cust_close_escrow_tx = hex::encode(&signed_cust_close_escrow_tx.to_transaction_bytes().unwrap());

        // sign the cust-close-from-merch-tx
        let (signed_cust_close_merch_tx, _, _) =
            transactions::btc::completely_sign_multi_sig_transaction::<Testnet>(&merch_tx_params, &enc_merch_signature, &private_key);
        self.cust_close_merch_tx = hex::encode(&signed_cust_close_merch_tx.to_transaction_bytes().unwrap());

        return escrow_sig_valid && merch_sig_valid;
    }

    pub fn unmask_and_verify_pay_token(&mut self, pt_mask_bytes_in: [u8; 32]) -> bool {
        let mut pt_mask_bytes = pt_mask_bytes_in.clone();

        if self.masked_outputs.get(&self.index).is_none() {
            println!("could not find masked output");
            return false;
        }

        // check the validity of the commitment opening to pay-mask(i+1)
        let rec_pay_mask_com = hash_to_slice(&pt_mask_bytes.to_vec());
        if self.pay_token_mask_com != rec_pay_mask_com {
            println!("could not validate commitment opening to pay-mask for next state");
            // if invalid, abort and output (s_{i+1}, CT_{i+1})
            return false;
        }

        let mpc_out = self.masked_outputs.get(&self.index).unwrap();
        xor_in_place(&mut pt_mask_bytes, &mpc_out.pt_masked[..]);

        self.pay_tokens.insert(self.index, pt_mask_bytes);
        // self.index += 1;
        return true;
    }

    pub fn get_cust_close_escrow_tx(&self) -> String {
        return self.cust_close_escrow_tx.clone();
    }

    pub fn get_cust_close_merch_tx(&self) -> String {
        return self.cust_close_merch_tx.clone();
    }
}

fn compute_rev_lock_commitment(input: &[u8; 32], _r: &[u8; 32]) -> [u8; 32] {
    let mut input_buf = Vec::new();
    input_buf.extend_from_slice(input);
    // input_buf.extend_from_slice(r);
    return hash_to_slice(&input_buf);
}

fn xor_in_place(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LockMap {
    pub lock: [u8; 32],
    pub secret: [u8; 32],
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Serialize, Deserialize)]
pub struct MerchantMPCState {
    id: String,
    pub pk_m: secp256k1::PublicKey, // pk_m
    sk_m: secp256k1::SecretKey, // sk_m - for escrow
    hmac_key: Vec<u8>, // hmac key => [u8; 64]
    payout_sk: secp256k1::SecretKey, // for payout pub key
    pub payout_pk: secp256k1::PublicKey,
    dispute_sk: secp256k1::SecretKey, // for dispute pub key
    pub dispute_pk: secp256k1::PublicKey,
    pub nonce_mask_map: HashMap<String, [u8; 32]>,
    pub activate_map: HashMap<String, State>,
    pub lock_map_state: HashMap<String, Option<LockMap>>,
    pub mask_mpc_bytes: HashMap<String, MaskedMPCInputs>,
    pub conn_type: u32
}

#[cfg(feature = "mpc-bitcoin")]
impl MerchantMPCState {
    pub fn new<R: Rng>(csprng: &mut R, channel: &mut ChannelMPCState, id: String) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        // generate the signing keypair for the channel
        let sk_m = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let pk_m = secp256k1::PublicKey::from_secret_key(&secp, &sk_m);

        let mut hmac_key_buf = [0u8; 64]; // 512 bits
        csprng.fill_bytes(&mut hmac_key_buf);
        let hmac_key = hmac_key_buf.to_vec();

        let key_com = hash_to_slice(&hmac_key);
        channel.set_key_com(key_com);

        let mut _payout_sk = [0u8; 32];
        let mut _dispute_sk = [0u8; 32];
        csprng.fill_bytes(&mut _payout_sk);
        csprng.fill_bytes(&mut _dispute_sk);

        let payout_sk = secp256k1::SecretKey::from_slice(&_payout_sk).unwrap();
        let dispute_sk = secp256k1::SecretKey::from_slice(&_dispute_sk).unwrap();

        let payout_pub_key = secp256k1::PublicKey::from_secret_key(&secp, &payout_sk);
        let dispute_pub_key = secp256k1::PublicKey::from_secret_key(&secp, &dispute_sk);

        channel.set_merchant_public_keys(payout_pub_key, dispute_pub_key);

        //let mut ch = channel.clone();

        MerchantMPCState {
            id: id.clone(),
            pk_m: pk_m,
            sk_m: sk_m,
            hmac_key: hmac_key,
            payout_sk: payout_sk,
            payout_pk: payout_pub_key,
            dispute_sk: dispute_sk,
            dispute_pk: dispute_pub_key,
            nonce_mask_map: HashMap::new(),
            activate_map: HashMap::new(),
            lock_map_state: HashMap::new(),
            mask_mpc_bytes: HashMap::new(),
            conn_type: 0
        }
    }

    pub fn activate_channel(&self, channel_token: &ChannelMPCToken, s_0: &State) -> [u8; 32] {
        // store the state inside the ActivateBucket
        let channel_id = channel_token.compute_channel_id().unwrap();
        let channel_id_str= hex::encode(channel_id.to_vec());

        let mut key = [0; 64];
        key.copy_from_slice(&self.hmac_key);
        let s_vec= s_0.serialize_compact();
        // println!("initial state: {}", hex::encode(&s_vec));
        let init_pay_token = hmac_sign(key, &s_vec);

        return init_pay_token;
    }

    pub fn store_initial_state(&mut self, channel_token: &ChannelMPCToken, s0: &State) -> bool {
        let channel_id = channel_token.compute_channel_id().unwrap();
        let channel_id_str= hex::encode(channel_id.to_vec());
        self.activate_map.insert(channel_id_str, s0.clone());

        return true;
    }

    pub fn generate_pay_mask_commitment<R: Rng>(&mut self, csprng: &mut R, nonce: [u8; NONCE_LEN]) -> Result<[u8; 32], String> {
        // check if n_i not in S
        // let nonce_hex = hex::encode(nonce.to_vec());
        let nonce_hex = hex::encode(nonce);
        if self.lock_map_state.get(&nonce_hex).is_some() {
            return Err(String::from("nonce has been used already."));
        }

        // pick mask_pay and form commitment to it
        let mut pay_mask = [0u8; 32];
        csprng.fill_bytes(&mut pay_mask);

        // generate commitment to new pay token mask
        let paytoken_mask_com = hash_to_slice( &pay_mask.to_vec());

        // store pay_mask for use in mpc protocol later
        self.nonce_mask_map.insert(nonce_hex, pay_mask);

        Ok(paytoken_mask_com)
    }

    pub fn set_mpc_connect_type(&mut self, conn_type: u32) {
        self.conn_type = conn_type;
    }

    // for merchant side
    pub fn execute_mpc_context<R: Rng>(&mut self, csprng: &mut R, channel: &ChannelMPCState, nonce: [u8; NONCE_LEN],
                               rev_lock_com: [u8; 32], paytoken_mask_com: [u8; 32], amount: i64) -> Result<bool, String> {
        let secp = secp256k1::Secp256k1::new();

        // if epsilon > 0, check if acceptable (above dust limit).
        if amount > 0 && amount < channel.get_dust_limit() {
            // if check fails, abort and output an error
            return Err(String::from("epsilon below dust limit!"));
        }

        // check if n_i not in S
        let nonce_hex = hex::encode(nonce);
        if self.lock_map_state.get(&nonce_hex).is_some() {
            return Err(String::from("nonce has been used already."));
        }

        // check the nonce & paytoken_mask (based on the nonce)
        let pay_mask_bytes = match self.nonce_mask_map.get(&nonce_hex) {
            Some(&n) => n,
            _ => return Err(String::from("could not find pay mask for specified nonce"))
        };

        let pay_mask_com = hash_to_slice(&pay_mask_bytes.to_vec());
        if pay_mask_com != paytoken_mask_com {
            return Err(String::from("specified invalid pay mask commitment"));
        }

        // generate masks for close-escrow and close-merch txs
        let mut merch_mask_bytes = [0u8; 32];
        csprng.fill_bytes(&mut merch_mask_bytes);

        let mut escrow_mask_bytes = [0u8; 32];
        csprng.fill_bytes(&mut escrow_mask_bytes);

        // load the key_com from the channelState
        let key_com = channel.key_com.clone();
        // load the hmac key
        let mut hmac_key = [0u8; 64];
        hmac_key.copy_from_slice(self.hmac_key.as_slice());

        // get the public keys
        let merch_escrow_pub_key = self.pk_m.clone(); // escrow key
        let pk_input_buf = self.payout_pk.serialize();
        let mut merch_public_key_hash= compute_hash160(&pk_input_buf.to_vec());

        let (r_merch, r_esc) = mpc_build_masked_tokens_merch(csprng, self.conn_type, amount, &paytoken_mask_com, &rev_lock_com, &key_com,
                                                  merch_escrow_pub_key, self.dispute_pk, merch_public_key_hash, self.payout_pk, nonce,
                                                  &hmac_key,
                                                  self.sk_m.clone(), &merch_mask_bytes, &pay_mask_bytes, &escrow_mask_bytes);

        // store the rev_lock_com => (pt_mask_bytes, escrow_mask_bytes, merch_mask_bytes)
        let mask_bytes = MaskedMPCInputs {
            pt_mask: pay_mask_bytes,
            escrow_mask: escrow_mask_bytes,
            merch_mask: merch_mask_bytes,
            r_escrow_sig: r_esc,
            r_merch_sig: r_merch,
        };
        let rev_lock_com_hex = hex::encode(rev_lock_com);
        self.mask_mpc_bytes.insert( rev_lock_com_hex, mask_bytes);

        Ok(true)
    }

    pub fn verify_revoked_state(&mut self, nonce: [u8; NONCE_LEN], rev_lock_com: [u8; 32], rev_lock: [u8; 32], rev_sec: [u8; 32], t: [u8; 32]) -> Option<[u8; 32]> {
        // check rev_lock_com opens to RL_i / t_i
        // check that RL_i is derived from RS_i
        if compute_rev_lock_commitment(&rev_lock, &t) != rev_lock_com ||
            hash_to_slice(&rev_sec.to_vec()) != rev_lock {
            let nonce_hex = hex::encode(nonce);
            self.lock_map_state.insert(nonce_hex, None);
            return None;
        }

        // retrieve masked bytes from rev_lock_com (output error, if not)
        let rev_lock_com_hex = hex::encode(rev_lock_com);
        let (is_ok, pt_mask) = match self.mask_mpc_bytes.get(&rev_lock_com_hex) {
            Some(&n) => (true, Some(n.pt_mask)),
            _ => (false, None)
        };


        let nonce_hex = hex::encode(nonce);
        if is_ok {
            // add (n_i, RS_i, RL_i) to state
            let revoked_lock_pair = LockMap {
                lock: rev_lock,
                secret: rev_sec
            };
            self.lock_map_state.insert(nonce_hex, Some(revoked_lock_pair));
        } else {
            self.lock_map_state.insert(nonce_hex, None);
        }

        return pt_mask;
    }

}

#[cfg(test)]
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use wagyu_model::AddressError::Message;
use bindings::ConnType;
use wagyu_model::Transaction;

#[cfg(feature = "mpc-bitcoin")]
#[cfg(test)]
mod tests {
    use super::*;
    use channels_mpc::{ChannelMPCState, MerchantMPCState, CustomerMPCState};
    use std::thread;
    use std::time::Duration;
    use sha2::Digest;
    use sha2::Sha256;

    fn generate_test_txs<R: Rng>(csprng: &mut R, b0_cust: i64, b0_merch: i64) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
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

        return (escrow_txid, merch_txid, escrow_prevout, merch_prevout)
    }

rusty_fork_test!
{
    #[test]
    fn mpc_channel_util_customer_works() {
        let mut channel_state = ChannelMPCState::new(String::from("Channel A <-> B"), false);
        // let rng = &mut rand::thread_rng();
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d76);

        let b0_cust = 100;
        let b0_merch = 20;
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let mut merch_state = MerchantMPCState::new(&mut rng, &mut channel_state, String::from("Merchant B"));

        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerMPCState::new(&mut rng, b0_cust, b0_merch, String::from("Customer"));

        // at this point, cust/merch have both exchanged initial sigs (escrow-tx + merch-close-tx)
        let (escrow_txid, merch_txid, escrow_prevout, merch_prevout) = generate_test_txs(&mut rng, b0_cust, b0_merch);

        // initialize the channel token on with pks
        let mut channel_token = cust_state.generate_init_channel_token(&merch_state.pk_m, escrow_txid, merch_txid);

        // generate and send initial state to the merchant
        cust_state.generate_init_state(&mut rng, &mut channel_token, escrow_prevout, merch_prevout);
        let s_0 = cust_state.get_current_state();

        println!("Begin activate phase for channel");

        let r_com = cust_state.generate_rev_lock_commitment(&mut rng);
        let t_0 = cust_state.get_randomness();
        println!("Initial state: {}", s_0);
        println!("Init rev_lock commitment => {:?}", r_com);

        // send the initial state s_0 to merchant
        merch_state.store_initial_state(&channel_token, &s_0);

        // activate channel - generate pay_token
        let pay_token_0 = merch_state.activate_channel(&channel_token, &s_0);

        println!("Pay Token on s_0 => {:?}", pay_token_0);

        cust_state.store_initial_pay_token(pay_token_0);

        let (rev_lock, rev_secret) = cust_state.get_rev_pair();
        let t = cust_state.get_randomness();

        let amount = 10;

        cust_state.generate_new_state(&mut rng, &channel_state, amount);
        let s_1 = cust_state.get_current_state();
        println!("Updated state: {}", s_1);

        let pay_token_mask_com = merch_state.generate_pay_mask_commitment(&mut rng, s_0.nonce).unwrap();
        cust_state.update_pay_com(pay_token_mask_com);

        cust_state.set_mpc_connect_type(2);

        // prepare the customer inputs
        let s0 = s_0.clone();
        let s1 = s_1.clone();

        println!("hello, customer!");
        let res = cust_state.execute_mpc_context(&channel_state, &channel_token, s0, s1, pay_token_mask_com, r_com, amount);

        println!("completed mpc execution!");

        // prepare the merchant inputs
        let rev_lock_com = r_com.clone();
        let nonce = s_0.nonce.clone();

        let mask_bytes = merch_state.verify_revoked_state(nonce, rev_lock_com, rev_lock, rev_secret, t);
        //assert!(!mask_bytes.is_none());

        let mut pt_mask = [0u8; 32];
        pt_mask.copy_from_slice(hex::decode("6a98d319e040ccb25fb2b7dce1e7b22df53a27a851a43c7843c4781962a54fa3").unwrap().as_slice());
        let mut escrow_mask = [0u8; 32];
        escrow_mask.copy_from_slice(hex::decode("4a682bd5d46e3b5c7c6c353636086ed7a943895982cb43deba0a8843459500e4").unwrap().as_slice());
        let mut merch_mask = [0u8; 32];
        merch_mask.copy_from_slice(hex::decode("6cd32e3254e7adaf3e742870ecab92aee1b863eabe75342a427d8e1954787822").unwrap().as_slice());
        let mut r_merch_sig = [0u8; 32];
        r_merch_sig.copy_from_slice(hex::decode("f7ca10b9563c6490200e77ed2b2bae74cdd2c82ef3e578b84ccdaf877036af6d").unwrap().as_slice());
        let mut r_escrow_sig = [0u8; 32];
        r_escrow_sig.copy_from_slice(hex::decode("6f1badfa1b06afb2129e36d331919d445c48698d6a838619aa3239075c21dd5c").unwrap().as_slice());

        let mask_bytes = Some(MaskedMPCInputs { pt_mask, escrow_mask, merch_mask, r_escrow_sig, r_merch_sig });

        if mask_bytes.is_some() {
            let mb = mask_bytes.unwrap();
            println!("pt_masked: {:?}", hex::encode(&mb.pt_mask));
            println!("escrow_masked: {:?}", hex::encode(&mb.escrow_mask));
            println!("merch_masked: {:?}", hex::encode(&mb.merch_mask));

            println!("now, unmask and verify...");
            let is_ok = cust_state.unmask_and_verify_transactions(&channel_state, &channel_token, mb.get_tx_masks());
            assert!(is_ok);

            cust_state.unmask_and_verify_pay_token(mb.pt_mask);

            // output most recent closing tx
            println!("------------------------------------");
            let close_escrow_tx = cust_state.get_cust_close_escrow_tx();
            println!("Cust-close from escrow tx: {}", close_escrow_tx);
            println!("------------------------------------");

            let close_merch_tx = cust_state.get_cust_close_merch_tx();
            println!("Cust-close from merch tx: {}", close_merch_tx);
            println!("------------------------------------");
        }
    }
}

    #[test]
    fn mpc_channel_util_merchant_works() {
        let mut channel = ChannelMPCState::new(String::from("Channel A <-> B"), false);
        // let rng = &mut rand::thread_rng();
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d76);

        let b0_cust = 100;
        let b0_merch = 20;
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let mut merch_state = MerchantMPCState::new(&mut rng, &mut channel, String::from("Merchant"));

        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerMPCState::new(&mut rng, b0_cust, b0_merch, String::from("Customer"));

        // at this point, cust/merch have both exchanged initial sigs (escrow-tx + merch-close-tx)
        let (escrow_txid, merch_txid, escrow_prevout, merch_prevout) = generate_test_txs(&mut rng, b0_cust, b0_merch);

        // initialize the channel token on with pks
        let mut channel_token = cust_state.generate_init_channel_token(&merch_state.pk_m, escrow_txid, merch_txid);

        // generate and send initial state to the merchant
        cust_state.generate_init_state(&mut rng, &mut channel_token, escrow_prevout, merch_prevout);
        let s_0 = cust_state.get_current_state();

        println!("Begin activate phase for channel");

        let r_com = cust_state.generate_rev_lock_commitment(&mut rng);
        let t_0 = cust_state.get_randomness();
        println!("Initial state: {}", s_0);
        println!("Init rev_lock commitment => {:?}", r_com);

        // send the initial state s_0 to merchant
        merch_state.store_initial_state(&channel_token, &s_0);

        // activate channel - generate pay_token
        let pay_token_0 = merch_state.activate_channel(&channel_token, &s_0);

        println!("Pay Token on s_0 => {:?}", pay_token_0);

        cust_state.store_initial_pay_token(pay_token_0);

        let (rev_lock, rev_secret) = cust_state.get_rev_pair();
        let t = cust_state.get_randomness();

        let amount = 10;

        cust_state.generate_new_state(&mut rng, &channel, amount);
        let s_1 = cust_state.get_current_state();
        println!("Updated state: {}", s_1);

        let pay_token_mask_com = merch_state.generate_pay_mask_commitment(&mut rng, s_0.nonce).unwrap();
        cust_state.update_pay_com(pay_token_mask_com);

        merch_state.set_mpc_connect_type(2);

        // prepare the merchant inputs
        let rev_lock_com = r_com.clone();
        let nonce = s_0.nonce.clone();

        println!("hello, merchant!");
        let res = merch_state.execute_mpc_context(&mut rng, &channel, nonce, rev_lock_com, pay_token_mask_com, amount).unwrap();

        println!("completed mpc execution!");

        let pt_mask_bytes = merch_state.verify_revoked_state(nonce, rev_lock_com, rev_lock, rev_secret, t);
        assert!(!pt_mask_bytes.is_none());

        if pt_mask_bytes.is_some() {
            let pt_mask = pt_mask_bytes.unwrap();
            println!("pt_masked: {:?}", pt_mask);
        }
    }
}
