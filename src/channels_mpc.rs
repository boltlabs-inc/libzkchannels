use super::*;
use util::{hash_to_slice, hmac_sign, compute_hash160};
use fixed_size_array::{FixedSizeArray16, FixedSizeArray32, FixedSizeArray64};

#[cfg(feature = "mpc-bitcoin")]
use rand::Rng;
use wallet::{State, NONCE_LEN};
use mpcwrapper::{mpc_build_masked_tokens_cust, mpc_build_masked_tokens_merch};
use transactions::ClosePublicKeys;
use bindings::ConnType;
use wagyu_model::Transaction;
use transactions::btc::{create_reverse_input, get_var_length_int, create_cust_close_transaction,
                        generate_signature_for_multi_sig_transaction, completely_sign_multi_sig_transaction};
use bitcoin::{BitcoinTransactionParameters, BitcoinNetwork, BitcoinPrivateKey};
use sha2::{Sha256, Digest};
use std::fmt::Debug;
use std::hash::Hash;
use bitcoin::SignatureHash::SIGHASH_ALL;

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub conn_type: ConnType,
    pub dest_ip: String,
    pub dest_port: u32,
    pub path: String
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelMPCToken {
    pub pk_c: Option<secp256k1::PublicKey>, // pk_c
    pub pk_m: secp256k1::PublicKey, // pk_m
    pub escrow_txid: FixedSizeArray32,
    pub merch_txid: FixedSizeArray32
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
impl fmt::Display for ChannelMPCToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let pkc_hex = match self.pk_c {
            Some(n) => hex::encode(n.serialize().to_vec()),
            None => "None".to_string()
        };
        let pkm_hex = hex::encode(self.pk_m.serialize().to_vec());
        let escrow_txid_hex = hex::encode(self.escrow_txid.0.to_vec());
        let merch_txid_hex = hex::encode(self.merch_txid.0.to_vec());

        write!(f, "ChannelMPCToken : (\npkc={}\npkm={}\nescrow_txid={:?}\nmerch_txid={:?}\n)",
               pkc_hex, pkm_hex, escrow_txid_hex, merch_txid_hex)
    }
}


#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelMPCState {
    tx_fee: i64,
    dust_limit: i64,
    key_com: FixedSizeArray32,
    pub name: String,
    pub third_party: bool,
    pub merch_payout_pk: Option<secp256k1::PublicKey>,
    pub merch_dispute_pk: Option<secp256k1::PublicKey>
}

#[cfg(feature = "mpc-bitcoin")]
impl ChannelMPCState {
    pub fn new(name: String, third_party_support: bool) -> ChannelMPCState {
        ChannelMPCState {
            tx_fee: 0,
            dust_limit: 0,
            key_com: FixedSizeArray32([0u8; 32]),
            name: name.to_string(),
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

    pub fn get_key_com(&self) -> [u8; 32] {
        self.key_com.0.clone()
    }

    pub fn set_key_com(&mut self, key_com: [u8; 32]) {
        self.key_com = FixedSizeArray32(key_com);
    }

    pub fn set_merchant_public_keys(&mut self, merch_payout_pk: secp256k1::PublicKey, merch_dispute_pk: secp256k1::PublicKey) {
        self.merch_payout_pk = Some(merch_payout_pk);
        self.merch_dispute_pk = Some(merch_dispute_pk);
    }
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MaskedMPCInputs {
    pt_mask: FixedSizeArray32,
    pt_mask_r: FixedSizeArray16,
    escrow_mask: FixedSizeArray32,
    merch_mask: FixedSizeArray32,
    r_escrow_sig: FixedSizeArray32,
    r_merch_sig: FixedSizeArray32,
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
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MaskedTxMPCInputs {
    pub escrow_mask: FixedSizeArray32,
    pub merch_mask: FixedSizeArray32,
    pub r_escrow_sig: FixedSizeArray32,
    pub r_merch_sig: FixedSizeArray32,
}

#[cfg(feature = "mpc-bitcoin")]
impl MaskedTxMPCInputs {
    pub fn new(escrow_mask: [u8; 32], merch_mask: [u8; 32], r_escrow_sig: [u8; 32], r_merch_sig: [u8; 32]) -> Self {
        MaskedTxMPCInputs {
            escrow_mask: FixedSizeArray32(escrow_mask),
            merch_mask: FixedSizeArray32(merch_mask),
            r_escrow_sig: FixedSizeArray32(r_escrow_sig),
            r_merch_sig: FixedSizeArray32(r_merch_sig)
        }
    }

    pub fn get_escrow_mask(&self) -> [u8; 32] {
        self.escrow_mask.0
    }

    pub fn get_merch_mask(&self) -> [u8; 32] {
        self.merch_mask.0
    }

    pub fn get_r_escrow_sig(&self) -> [u8; 32] {
        self.r_escrow_sig.0
    }

    pub fn get_r_merch_sig(&self) -> [u8; 32] {
        self.r_merch_sig.0
    }
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MaskedMPCOutputs {
    pt_masked: FixedSizeArray32, // [u8; 32]
    escrow_masked: FixedSizeArray32,
    merch_masked: FixedSizeArray32
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomerMPCState {
    pub name: String,
    pub pk_c: secp256k1::PublicKey,
    sk_c: secp256k1::SecretKey,
    pub cust_balance: i64,
    pub merch_balance: i64,
    rev_lock: FixedSizeArray32,
    rev_secret: FixedSizeArray32,
    t: FixedSizeArray16, // randomness used to form the commitment
    state: Option<State>, // vector of field elements that represent current state
    index: i32,
    masked_outputs: HashMap<i32, MaskedMPCOutputs>,
    pay_tokens: HashMap<i32, FixedSizeArray32>,
    pay_token_mask_com: FixedSizeArray32,
    payout_sk: secp256k1::SecretKey,
    payout_pk: secp256k1::PublicKey,
    pub conn_type: u32,
    close_escrow_txid: String,
    close_escrow_tx: String,
    close_merch_txid: String,
    close_merch_tx: String,
    channel_initialized: bool,
    net_config: Option<NetworkConfig>
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InitCustState {
    pub pk_c: secp256k1::PublicKey,
    pub close_pk: secp256k1::PublicKey,
    pub nonce: FixedSizeArray16,
    pub rev_lock: FixedSizeArray32,
    pub cust_bal: i64,
    pub merch_bal: i64
}

#[cfg(feature = "mpc-bitcoin")]
impl fmt::Display for InitCustState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let nonce_hex = hex::encode(self.nonce.0.to_vec());
        let rev_lock_hex = hex::encode(self.rev_lock.0.to_vec());

        write!(f, "InitCustState : (\npkc={:?}\nnonce={:?}\nrev_lock={:?}\n)",
               &self.pk_c, nonce_hex, rev_lock_hex)
    }
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

        let pay_mask_com = [0u8; 32];
        let t = [0u8; 16];
        let mut _payout_sk: [u8; 32] = [0; 32];
        csprng.fill_bytes(&mut _payout_sk);
        let payout_sk = secp256k1::SecretKey::from_slice(&_payout_sk).unwrap();
        let payout_pk = secp256k1::PublicKey::from_secret_key(&secp, &payout_sk);

        let mpc_outputs = HashMap::new();
        let pt_db = HashMap::new();

        return CustomerMPCState {
            name: name,
            pk_c: pk_c,
            sk_c: sk_c,
            cust_balance: cust_bal,
            merch_balance: merch_bal,
            rev_lock: FixedSizeArray32(rev_lock),
            rev_secret: FixedSizeArray32(rev_secret),
            t: FixedSizeArray16(t),
            state: None,
            index: 0,
            masked_outputs: mpc_outputs,
            pay_tokens: pt_db,
            pay_token_mask_com: FixedSizeArray32(pay_mask_com),
            payout_sk: payout_sk,
            payout_pk: payout_pk,
            conn_type: 0,
            close_escrow_txid: String::new(),
            close_escrow_tx: String::new(),
            close_merch_txid: String::new(),
            close_merch_tx: String::new(),
            channel_initialized: false,
            net_config: None
        };
    }

    pub fn get_secret_key(&self) -> secp256k1::SecretKey {
        return self.sk_c.clone();
    }

    pub fn set_mpc_connect_type(&mut self, conn_type: u32) {
        self.conn_type = conn_type;
    }

    pub fn update_pay_com(&mut self, pay_token_mask_com: [u8; 32]) {
        self.pay_token_mask_com.0.copy_from_slice(&pay_token_mask_com);
    }

    pub fn generate_init_state<R: Rng>(&mut self, csprng: &mut R, channel_token: &mut ChannelMPCToken) {
        assert!(self.state.is_none());

        let mut nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
        csprng.fill_bytes(&mut nonce);

        channel_token.set_customer_pk(self.pk_c.clone());

        let state = State { nonce: FixedSizeArray16(nonce), rev_lock: self.rev_lock, bc: self.cust_balance, bm: self.merch_balance,
                            escrow_txid: FixedSizeArray32([0u8; 32]), merch_txid: FixedSizeArray32([0u8; 32]),
                            escrow_prevout: FixedSizeArray32([0u8; 32]), merch_prevout: FixedSizeArray32([0u8; 32]) };

        // assert!(channel_token.is_init());
        self.state = Some(state);
    }

    pub fn generate_rev_lock_commitment<R: Rng>(&mut self, csprng: &mut R) -> [u8; 32] {
        let mut t: [u8; 16] = [0; 16];
        csprng.fill_bytes(&mut t);
        self.t.0.copy_from_slice(&t);

        let mut input = Vec::new();
        input.extend_from_slice(&self.rev_lock.0);
        input.extend_from_slice(&self.t.0);
        return hash_to_slice(&input);
    }

    pub fn get_randomness(&self) -> [u8; 16] {
        return self.t.0;
    }

    pub fn get_rev_pair(&self) -> ([u8; 32], [u8; 32]) {
        return (self.rev_lock.0, self.rev_secret.0);
    }

    pub fn get_current_state(&self) -> State {
        assert!(self.state.is_some());
        return self.state.unwrap();
    }

    pub fn store_initial_pay_token(&mut self, pay_token: [u8; 32]) {
        self.pay_tokens.insert(0, FixedSizeArray32(pay_token));
    }

    pub fn set_funding_tx_info(&mut self, channel_token: &mut ChannelMPCToken, tx: &FundingTxInfo) -> Result<(), String> {
        if self.state.is_none() {
            return Err(String::from("Customer initial state has not been created!"))
        }

        let mut s = self.state.unwrap();
        s.escrow_txid = tx.escrow_txid.clone();
        s.escrow_prevout = tx.escrow_prevout.clone();
        s.merch_txid = tx.merch_txid.clone();
        s.merch_prevout = tx.merch_prevout.clone();
        s.bc = tx.init_cust_bal;
        s.bm = tx.init_merch_bal;
        self.state = Some(s);

        channel_token.escrow_txid = tx.escrow_txid.clone();
        channel_token.merch_txid = tx.merch_txid.clone();

        Ok(())
    }

    pub fn get_initial_cust_state(&self) -> Result<InitCustState, String> {
        assert!(self.state.is_some());

        let s = self.state.unwrap();
        Ok(InitCustState {
            pk_c: self.pk_c.clone(),
            close_pk: self.payout_pk.clone(),
            nonce: FixedSizeArray16(s.get_nonce()),
            rev_lock: FixedSizeArray32(s.get_rev_lock()),
            cust_bal: self.cust_balance,
            merch_bal: self.merch_balance
        })
    }

    pub fn generate_new_state<R: Rng>(&mut self, csprng: &mut R, amount: i64) {
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

        new_state.nonce.0.copy_from_slice(&new_nonce);
        new_state.rev_lock.0.copy_from_slice(&new_rev_lock);

        // generate new rev_secret, rev_lock
        self.rev_secret.0.copy_from_slice(&new_rev_secret);
        self.rev_lock.0.copy_from_slice(&new_rev_lock);
        self.cust_balance = new_state.bc;
        self.merch_balance = new_state.bm;

        self.state = Some(new_state);
    }

    pub fn generate_init_channel_token(&self, pk_m: &secp256k1::PublicKey) -> ChannelMPCToken {

        return ChannelMPCToken {
            pk_c: Some(self.pk_c.clone()),
            pk_m: pk_m.clone(),
            escrow_txid: FixedSizeArray32([0u8; 32]),
            merch_txid: FixedSizeArray32([0u8; 32])
        };
    }

    pub fn has_tokens(&self) -> bool {
        let index = self.index;
        let is_pt = self.pay_tokens.get(&index).is_some();
        return is_pt;
    }

    pub fn set_network_config(&mut self, net_config: NetworkConfig)  {
        self.net_config = Some(net_config);
    }

    // customer side of mpc
    pub fn execute_mpc_context(&mut self, channel_state: &ChannelMPCState, channel_token: &ChannelMPCToken,
                               old_state: State, new_state: State, paytoken_mask_com: [u8; 32], rev_lock_com: [u8;32], amount: i64) -> Result<bool, String> {
        //assert!(self.channel_initialized);
        // load the key_com from channel state
        let key_com = channel_state.get_key_com();

        // get cust pub keys
        let cust_escrow_pub_key = self.pk_c.clone();
        let cust_payout_pub_key = self.payout_pk;

        let merch_escrow_pub_key= channel_token.pk_m.clone();
        let merch_dispute_key= channel_state.merch_dispute_pk.unwrap();
        let merch_payout_pub_key = channel_state.merch_payout_pk.unwrap();
        let pk_input_buf = merch_payout_pub_key.serialize();
        let merch_public_key_hash = compute_hash160(&pk_input_buf.to_vec());

        let old_paytoken = match self.has_tokens() {
            true => self.pay_tokens.get(&self.index).unwrap(),
            false => return Err(String::from("you do not have a pay token for previous state"))
        };

        let (pt_masked_ar, ct_escrow_masked_ar, ct_merch_masked_ar) =
            mpc_build_masked_tokens_cust(self.conn_type, amount, &paytoken_mask_com, &rev_lock_com, &self.t.0, &key_com,
                                     merch_escrow_pub_key, merch_dispute_key, merch_public_key_hash, merch_payout_pub_key,
                                     new_state, old_state,&old_paytoken.0, cust_escrow_pub_key, cust_payout_pub_key);

        let masked_output = MaskedMPCOutputs {
            pt_masked: FixedSizeArray32(pt_masked_ar),
            escrow_masked: FixedSizeArray32(ct_escrow_masked_ar),
            merch_masked: FixedSizeArray32(ct_merch_masked_ar)
        };

        // save the masked outputs (will unmask later)
        self.masked_outputs.insert(self.index, masked_output.clone());
        Ok(true)
    }

    pub fn get_pubkeys(&self, channel_state: &ChannelMPCState, channel_token: &ChannelMPCToken) -> ClosePublicKeys {
        let cust_escrow_pub_key = self.pk_c.serialize();
        let cust_payout_pub_key = self.payout_pk.serialize();
        let merch_escrow_pub_key= channel_token.pk_m.serialize();
        let merch_dispute_key= channel_state.merch_dispute_pk.unwrap().serialize();
        let merch_payout_pub_key = channel_state.merch_payout_pk.unwrap().serialize();

        let mut pubkeys = ClosePublicKeys {
            cust_pk: cust_escrow_pub_key.to_vec(),
            cust_close_pk: cust_payout_pub_key.to_vec(),
            merch_pk: merch_escrow_pub_key.to_vec(),
            merch_close_pk: merch_payout_pub_key.to_vec(),
            merch_disp_pk: merch_dispute_key.to_vec(),
            rev_lock: FixedSizeArray32([0u8; 32])
        };
        pubkeys.rev_lock.0.copy_from_slice(&self.state.unwrap().get_rev_lock());
        return pubkeys;
    }

    // Customer constructs initial tx preimage and transaction params
    pub fn construct_close_transaction_preimage<N: BitcoinNetwork>(&self, channel_state: &ChannelMPCState, channel_token: &ChannelMPCToken) -> (Vec<u8>, Vec<u8>, BitcoinTransactionParameters<N>, BitcoinTransactionParameters<N>) {
        let init_balance = self.cust_balance + self.merch_balance;
        // TODO: should be configurable via a tx_config
        let escrow_index = 0;
        let merch_index = 0;
        let to_self_delay: [u8; 2] = [0xcf, 0x05]; // little-endian format

        let pubkeys = self.get_pubkeys(channel_state, channel_token);
        let escrow_input = create_reverse_input(&channel_token.escrow_txid.0, escrow_index, init_balance);
        let merch_input = create_reverse_input(&channel_token.merch_txid.0, merch_index, init_balance);

        let (escrow_tx_preimage, escrow_tx_params, _) =
            create_cust_close_transaction::<N>(&escrow_input, &pubkeys, &to_self_delay,self.cust_balance,self.merch_balance, true);

        let (merch_tx_preimage, merch_tx_params, _) =
            create_cust_close_transaction::<N>(&merch_input, &pubkeys, &to_self_delay, self.cust_balance, self.merch_balance, false);

        return (escrow_tx_preimage, merch_tx_preimage, escrow_tx_params, merch_tx_params);
    }

    // Customer signs the initial closing transaction (in the clear)
    pub fn sign_initial_closing_transaction<N: BitcoinNetwork>(&mut self, channel_state: &ChannelMPCState, channel_token: &ChannelMPCToken, orig_escrow_sig: &Vec<u8>, orig_merch_sig: &Vec<u8>) -> Result<bool, String> {
        let (escrow_tx_preimage, merch_tx_preimage, escrow_tx_params, merch_tx_params) =
            self.construct_close_transaction_preimage::<N>(channel_state, channel_token);

        // now that we've got preimages
        let escrow_tx_hash = Sha256::digest(&Sha256::digest(&escrow_tx_preimage));
        let merch_tx_hash = Sha256::digest(&Sha256::digest(&merch_tx_preimage));

        // new escrow signature
        let sig_len = orig_escrow_sig[0] as usize;
        let mut new_escrow_sig = orig_escrow_sig[1..].to_vec();
        if sig_len != new_escrow_sig.len() {
            return Err(String::from("Invalid escrow_sig len!"));
        }
        new_escrow_sig.pop(); // remove last byte for sighash flag
        let escrow_sig = match secp256k1::Signature::from_der(&new_escrow_sig.as_slice()) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string())
        };
        // new merch signature
        let sig_len = orig_merch_sig[0] as usize;
        let mut new_merch_sig = orig_merch_sig[1..].to_vec();
        if sig_len != new_merch_sig.len() {
            return Err(String::from("Invalid merch_sig len!"));
        }
        new_merch_sig.pop(); // remove last byte for sighash flag
        let merch_sig = match secp256k1::Signature::from_der(&new_merch_sig.as_slice()) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string())
        };

        // println!("Tx hash: {}", hex::encode(&escrow_tx_hash));
        let msg1 = secp256k1::Message::from_slice(&escrow_tx_hash).unwrap();
        let msg2 = secp256k1::Message::from_slice(&merch_tx_hash).unwrap();
        let secp = secp256k1::Secp256k1::verification_only();
        let escrow_sig_valid = secp.verify(&msg1, &escrow_sig, &channel_token.pk_m).is_ok();
        let merch_sig_valid = secp.verify(&msg2, &merch_sig, &channel_token.pk_m).is_ok();

        if escrow_sig_valid && merch_sig_valid {
            // customer sign the transactions to complete multi-sig and store CT bytes locally
            let private_key = BitcoinPrivateKey::<N>::from_secp256k1_secret_key(self.sk_c.clone(), false);
            // sign the cust-close-from-escrow-tx
            let (signed_cust_close_escrow_tx, close_escrow_txid, _) =
                completely_sign_multi_sig_transaction::<N>(&escrow_tx_params, &orig_escrow_sig, true, None, &private_key);
            self.close_escrow_txid = hex::encode(&close_escrow_txid);
            self.close_escrow_tx = hex::encode(&signed_cust_close_escrow_tx.to_transaction_bytes().unwrap());

            // sign the cust-close-from-merch-tx
            let script_data: Vec<u8> = vec![0x01];
            let (signed_cust_close_merch_tx, close_merch_txid, _) =
                completely_sign_multi_sig_transaction::<N>(&merch_tx_params, &orig_merch_sig, true, Some(script_data), &private_key);
            self.close_merch_txid = hex::encode(&close_merch_txid);
            self.close_merch_tx = hex::encode(&signed_cust_close_merch_tx.to_transaction_bytes().unwrap());

            self.channel_initialized = true;
            Ok(true)
        } else {
            let s = String::from("Could not verify the merchant signature on the initial closing transactions!");
            Err(s)
        }
    }

    pub fn unmask_and_verify_transactions<N: BitcoinNetwork>(&mut self, channel_state: &ChannelMPCState, channel_token: &ChannelMPCToken, mask_bytes: MaskedTxMPCInputs) -> bool {
        let mut escrow_mask_bytes = mask_bytes.get_escrow_mask();
        let mut merch_mask_bytes = mask_bytes.get_merch_mask();

        if self.masked_outputs.get(&self.index).is_none() {
            println!("could not find masked output");
            return false;
        }

        let mpc_out = self.masked_outputs.get(&self.index).unwrap();
        xor_in_place(&mut escrow_mask_bytes, &mpc_out.escrow_masked.0[..]);
        xor_in_place(&mut merch_mask_bytes, &mpc_out.merch_masked.0[..]);

        // if valid, output (s_{i+1}, CT_{i+1}, pay-token-{i+1})
        let (escrow_tx_preimage, merch_tx_preimage, escrow_tx_params, merch_tx_params) =
            self.construct_close_transaction_preimage::<N>(channel_state, channel_token);
        // println!("Close-Escrow Tx preimage: {}", hex::encode(&escrow_tx_preimage));
        // println!("Close-Merch Tx preimage: {}", hex::encode(&merch_tx_preimage));

        let mut escrow_sig_vec = mask_bytes.r_escrow_sig.0.to_vec();
        escrow_sig_vec.append(&mut escrow_mask_bytes.to_vec());
        let escrow_sig = secp256k1::Signature::from_compact(&escrow_sig_vec.as_slice()).unwrap();
        // println!("Close from Escrow Signature: {}", &escrow_sig);

        let mut merch_sig_vec = mask_bytes.r_merch_sig.0.to_vec();
        merch_sig_vec.append(&mut merch_mask_bytes.to_vec());
        let merch_sig = secp256k1::Signature::from_compact(&merch_sig_vec.as_slice()).unwrap();
        // println!("Close from Merch Signature: {}", &merch_sig);

        let escrow_tx_hash = Sha256::digest(&Sha256::digest(&escrow_tx_preimage));
        let merch_tx_hash = Sha256::digest(&Sha256::digest(&merch_tx_preimage));

        // println!("Tx hash: {}", hex::encode(&escrow_tx_hash));
        let msg1 = secp256k1::Message::from_slice(&escrow_tx_hash).unwrap();
        let msg2 = secp256k1::Message::from_slice(&merch_tx_hash).unwrap();

        let secp = secp256k1::Secp256k1::verification_only();
        let escrow_sig_valid = secp.verify(&msg1, &escrow_sig, &channel_token.pk_m).is_ok();
        let merch_sig_valid = secp.verify(&msg2, &merch_sig, &channel_token.pk_m).is_ok();
        // println!("escrow_sig_valid: {}", escrow_sig_valid);
        // println!("merch_sig_valid: {}", merch_sig_valid);

        // customer sign the transactions to complete multi-sig and store CT bytes locally
        let private_key = BitcoinPrivateKey::<N>::from_secp256k1_secret_key(self.sk_c.clone(), false);
        let sighash_code = SIGHASH_ALL as u32;
        let mut escrow_signature = escrow_sig.serialize_der().to_vec();
        escrow_signature.push(sighash_code.to_le_bytes()[0]);
        let enc_escrow_signature = [get_var_length_int(escrow_signature.len() as u64).unwrap(), escrow_signature].concat();

        let mut merch_signature = merch_sig.serialize_der().to_vec();
        merch_signature.push(sighash_code.to_le_bytes()[0]);
        let enc_merch_signature = [get_var_length_int(merch_signature.len() as u64).unwrap(), merch_signature].concat();

        // sign the cust-close-from-escrow-tx
        let (signed_cust_close_escrow_tx, close_escrow_txid, _) =
            completely_sign_multi_sig_transaction::<N>(&escrow_tx_params, &enc_escrow_signature, true, None, &private_key);
        self.close_escrow_txid = hex::encode(&close_escrow_txid);
        self.close_escrow_tx = hex::encode(&signed_cust_close_escrow_tx.to_transaction_bytes().unwrap());

        // sign the cust-close-from-merch-tx
        let script_data: Vec<u8> = vec![0x01];
        let (signed_cust_close_merch_tx, close_merch_txid, _) =
            completely_sign_multi_sig_transaction::<N>(&merch_tx_params, &enc_merch_signature, true, Some(script_data), &private_key);
        self.close_merch_txid = hex::encode(&close_merch_txid);
        self.close_merch_tx = hex::encode(&signed_cust_close_merch_tx.to_transaction_bytes().unwrap());

        return escrow_sig_valid && merch_sig_valid;
    }

    pub fn unmask_and_verify_pay_token(&mut self, pt_mask_bytes_in: [u8; 32], pt_mask_r: [u8; 16]) -> bool {
        let mut pt_mask_bytes = pt_mask_bytes_in.clone();

        if self.masked_outputs.get(&self.index).is_none() {
            println!("could not find masked output");
            return false;
        }

        // check the validity of the commitment opening to pay-mask(i+1)
        let mut input_buf = pt_mask_bytes.to_vec();
        input_buf.extend_from_slice(&pt_mask_r);
        let rec_pay_mask_com = hash_to_slice(&input_buf);
        if self.pay_token_mask_com.0 != rec_pay_mask_com {
            println!("could not validate commitment opening to pay-mask for next state");
            // if invalid, abort and output (s_{i+1}, CT_{i+1})
            return false;
        }

        let mpc_out = self.masked_outputs.get(&self.index).unwrap();
        xor_in_place(&mut pt_mask_bytes, &mpc_out.pt_masked.0[..]);

        self.pay_tokens.insert(self.index, FixedSizeArray32(pt_mask_bytes));
        // self.index += 1;
        return true;
    }

    pub fn get_cust_close_escrow_tx(&self) -> String {
        return self.close_escrow_tx.clone();
    }

    pub fn get_cust_close_merch_tx(&self) -> String {
        return self.close_merch_tx.clone();
    }
}

#[cfg(feature = "mpc-bitcoin")]
fn compute_rev_lock_commitment(input: &[u8; 32], r: &[u8; 16]) -> [u8; 32] {
    let mut input_buf = Vec::new();
    input_buf.extend_from_slice(input);
    input_buf.extend_from_slice(r);
    return hash_to_slice(&input_buf);
}

#[cfg(feature = "mpc-bitcoin")]
fn xor_in_place(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RevokedState {
    pub nonce: FixedSizeArray16,
    pub rev_lock_com: FixedSizeArray32,
    pub rev_lock: FixedSizeArray32,
    pub rev_secret: FixedSizeArray32,
    pub t: FixedSizeArray16
}

#[cfg(feature = "mpc-bitcoin")]
impl RevokedState {
    pub fn new(nonce: [u8; NONCE_LEN], rev_lock_com: [u8; 32], rev_lock: [u8; 32], rev_secret: [u8; 32], t: [u8; 16]) -> Self {
        RevokedState {
            nonce: FixedSizeArray16(nonce),
            rev_lock_com: FixedSizeArray32(rev_lock_com),
            rev_lock: FixedSizeArray32(rev_lock),
            rev_secret: FixedSizeArray32(rev_secret),
            t: FixedSizeArray16(t)
        }
    }

    pub fn get_nonce(&self) -> [u8; NONCE_LEN] {
        self.nonce.0
    }

    pub fn get_rev_lock_com(&self) -> [u8; 32] {
        self.rev_lock_com.0
    }

    pub fn get_rev_lock(&self) -> [u8; 32] {
        self.rev_lock.0
    }

    pub fn get_rev_secret(&self) -> [u8; 32] {
        self.rev_secret.0
    }

    pub fn get_randomness(&self) -> [u8; 16] {
        self.t.0
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LockMap {
    pub lock: FixedSizeArray32,
    pub secret: FixedSizeArray32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PayMaskMap {
    pub mask: FixedSizeArray32,
    pub r: FixedSizeArray16
}

#[cfg(feature = "mpc-bitcoin")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MerchantMPCState {
    id: String,
    pub pk_m: secp256k1::PublicKey, // pk_m
    sk_m: secp256k1::SecretKey, // sk_m - for escrow
    hmac_key: FixedSizeArray64,
    hmac_key_r: FixedSizeArray16, // key_com_r
    payout_sk: secp256k1::SecretKey, // for payout pub key
    pub payout_pk: secp256k1::PublicKey,
    dispute_sk: secp256k1::SecretKey, // for dispute pub key
    pub dispute_pk: secp256k1::PublicKey,
    pub nonce_mask_map: HashMap<String, PayMaskMap>,
    pub activate_map: HashMap<String, State>,
    pub unlink_map: HashSet<String>,
    pub spent_lock_map: HashMap<String, Option<LockMap>>,
    pub mask_mpc_bytes: HashMap<String, MaskedMPCInputs>,
    pub conn_type: u32,
    net_config: Option<NetworkConfig>
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

        let mut key_com_r = [0u8; 16];
        csprng.fill_bytes(&mut key_com_r);

        let mut key_com_buf = hmac_key_buf.to_vec();
        key_com_buf.extend_from_slice(&key_com_r);
        let key_com = hash_to_slice(&key_com_buf.to_vec());
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

        MerchantMPCState {
            id: id.clone(),
            pk_m: pk_m,
            sk_m: sk_m,
            hmac_key: FixedSizeArray64::new(hmac_key_buf),
            hmac_key_r: FixedSizeArray16(key_com_r),
            payout_sk: payout_sk,
            payout_pk: payout_pub_key,
            dispute_sk: dispute_sk,
            dispute_pk: dispute_pub_key,
            nonce_mask_map: HashMap::new(),
            activate_map: HashMap::new(),
            unlink_map: HashSet::new(),
            spent_lock_map: HashMap::new(),
            mask_mpc_bytes: HashMap::new(),
            conn_type: 0,
            net_config: None
        }
    }

    pub fn get_secret_key(&self) -> secp256k1::SecretKey {
        return self.sk_m.clone();
    }

    pub fn activate_channel(&self, channel_token: &ChannelMPCToken, s0: &State) -> Result<[u8; 32], String> {
        // refer to the state stored inside ActivateBucket by the channel_id
        let channel_id = channel_token.compute_channel_id().unwrap();
        let channel_id_str = hex::encode(channel_id.to_vec());

        // check that s_0 is consistent with init phase before signing
        let s0_hash = s0.compute_hash();
        let init_state_hash = match self.activate_map.get(&channel_id_str) {
            Some(n) => n.compute_hash(),
            None => return Err(String::from("activate_channel: could not find initial state given channel token"))
        };

        if s0_hash != init_state_hash {
            return Err(String::from("activate_channel: initial state on activation does not match stored state"))
        }

        // proceed to sign the initial state
        let key = self.hmac_key.get_bytes();
        let s_vec= s0.serialize_compact();
        let init_pay_token = hmac_sign(key, &s_vec);

        Ok(init_pay_token)
    }

    pub fn validate_initial_state(&mut self, channel_token: &ChannelMPCToken, init_state: &InitCustState, init_state_hash: [u8; 32]) -> Result<bool, String> {
        let channel_id = channel_token.compute_channel_id().unwrap();
        let channel_id_str= hex::encode(channel_id.to_vec());

        // check if pk_c
        let pk_c = match channel_token.pk_c {
            Some(pk) => pk,
            None => return Err(String::from("cannot validate channel token: pk_c not set"))
        };

        if pk_c != init_state.pk_c {
            return Err(String::from("init state pk_c does not match channel token pk_c"));
        }

        if channel_token.pk_m != self.pk_m {
            return Err(String::from("channel token pk_m does not match merch state pk_m"));
        }

        // cache prevout from escrow_txid and escrow_prevout
        let mut escrow_prevout = [0u8; 32];
        let mut merch_prevout = [0u8; 32];

        let mut escrow_txid_be = channel_token.escrow_txid.0.clone();
        let mut merch_txid_be = channel_token.merch_txid.0.clone();

        let mut prevout_preimage1: Vec<u8> = Vec::new();
        prevout_preimage1.extend(escrow_txid_be.iter()); // txid1
        prevout_preimage1.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result1 = Sha256::digest(&Sha256::digest(&prevout_preimage1));
        escrow_prevout.copy_from_slice(&result1);

        let mut prevout_preimage2: Vec<u8> = Vec::new();
        prevout_preimage2.extend(merch_txid_be.iter()); // txid2
        prevout_preimage2.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result2 = Sha256::digest(&Sha256::digest(&prevout_preimage2));
        merch_prevout.copy_from_slice(&result2);

        let s0 = State {
            bc: init_state.cust_bal,
            bm: init_state.merch_bal,
            nonce: init_state.nonce.clone(),
            rev_lock: init_state.rev_lock.clone(),
            escrow_txid: channel_token.escrow_txid,
            escrow_prevout: FixedSizeArray32(escrow_prevout),
            merch_txid: channel_token.merch_txid,
            merch_prevout: FixedSizeArray32(merch_prevout),
        };

        if init_state_hash != s0.compute_hash() {
            println!("state: {}", s0);
            return Err(String::from("initial state not well-formed"));
        }

        let nonce_hex_str = hex::encode(s0.get_nonce());

        self.activate_map.insert(channel_id_str, s0);
        self.unlink_map.insert(nonce_hex_str);

        Ok(true)
    }

    pub fn generate_pay_mask_commitment<R: Rng>(&mut self, csprng: &mut R, channel_state: &ChannelMPCState, nonce: [u8; NONCE_LEN], rev_lock_com: [u8; 32], amount: i64) -> Result<[u8; 32], String> {

        let nonce_hex = hex::encode(nonce);

        // check if n_i in S_unlink and amount == 0. if so, proceed since this is the unlink protocol
        if amount == 0 && !self.unlink_map.contains(&nonce_hex) {
            return Err(String::from("can only run unlink with previously known nonce"));
        }

        // if epsilon > 0, check if acceptable (above dust limit).
        if amount > 0 && amount < channel_state.get_dust_limit() {
            // if check fails, abort and output an error
            return Err(String::from("epsilon below dust limit!"));
        }

        // check if n_i not in S_spent
        if self.spent_lock_map.get(&nonce_hex).is_some() {
            return Err(format!("nonce {} has been spent already.", &nonce_hex));
        }

        // pick mask_pay and form commitment to it
        let mut pay_mask = [0u8; 32];
        let mut pay_mask_r = [0u8; 16];
        csprng.fill_bytes(&mut pay_mask);
        csprng.fill_bytes(&mut pay_mask_r);

        // generate commitment to new pay token mask
        let mut pay_mask_buf = pay_mask.to_vec();
        pay_mask_buf.extend_from_slice(&pay_mask_r);
        let paytoken_mask_com = hash_to_slice( &pay_mask_buf);

        // store pay_mask for use in mpc protocol later
        let pay_mask_map = PayMaskMap { mask: FixedSizeArray32(pay_mask), r: FixedSizeArray16(pay_mask_r) };
        self.nonce_mask_map.insert(nonce_hex, pay_mask_map);

        Ok(paytoken_mask_com)
    }

    pub fn set_mpc_connect_type(&mut self, conn_type: u32) {
        self.conn_type = conn_type;
    }

    pub fn set_network_config(&mut self, net_config: NetworkConfig)  {
        self.net_config = Some(net_config);
    }

    fn recompute_commitmment(&self, buf: &[u8; 32], r: &[u8; 16]) -> [u8; 32] {
        let mut input_buf = buf.to_vec();
        input_buf.extend_from_slice(r);
        return hash_to_slice(&input_buf);
    }

    // Merchant sign's the initial closing transaction (in the clear)
    pub fn sign_initial_closing_transaction<N: BitcoinNetwork>(&self, funding_tx: FundingTxInfo, rev_lock: [u8; 32], cust_pk: Vec<u8>, cust_close_pk: Vec<u8>, to_self_delay: [u8; 2]) -> (Vec<u8>, Vec<u8>) {
        let init_balance = funding_tx.init_cust_bal + funding_tx.init_merch_bal;
        let escrow_index = 0;
        let merch_index = 0;

        let escrow_input = create_reverse_input(&funding_tx.escrow_txid.0, escrow_index, init_balance);
        let merch_input = create_reverse_input(&funding_tx.merch_txid.0, merch_index, init_balance);

        let pubkeys = ClosePublicKeys {
            cust_pk: cust_pk.clone(),
            merch_pk: self.pk_m.serialize().to_vec(),
            merch_close_pk: self.payout_pk.serialize().to_vec(),
            merch_disp_pk: self.dispute_pk.serialize().to_vec(),
            cust_close_pk: cust_close_pk.clone(),
            rev_lock: FixedSizeArray32(rev_lock)
        };

        let (escrow_tx_preimage, _, _) =
            create_cust_close_transaction::<N>(&escrow_input, &pubkeys, &to_self_delay, funding_tx.init_cust_bal, funding_tx.init_merch_bal, true);

        let (merch_tx_preimage, _, _) =
            create_cust_close_transaction::<N>(&merch_input, &pubkeys, &to_self_delay, funding_tx.init_cust_bal, funding_tx.init_merch_bal, false);

        // merchant generates signatures
        let m_private_key = BitcoinPrivateKey::<N>::from_secp256k1_secret_key(self.sk_m.clone(), false);
        let escrow_cust_sig = generate_signature_for_multi_sig_transaction::<N>(&escrow_tx_preimage, &m_private_key).unwrap();
        let merch_cust_sig = generate_signature_for_multi_sig_transaction::<N>(&merch_tx_preimage, &m_private_key).unwrap();

        return (escrow_cust_sig, merch_cust_sig);
    }

    fn print_map<K: Debug + Eq + Hash, V: Debug>(&self, map: &HashMap<K, V>) {
        for (k, v) in map.iter() {
            println!("{:?}: {:?}", k, v);
        }
    }

    // for merchant side
    pub fn execute_mpc_context<R: Rng>(&mut self, csprng: &mut R, channel_state: &ChannelMPCState, nonce: [u8; NONCE_LEN],
                               rev_lock_com: [u8; 32], paytoken_mask_com: [u8; 32], amount: i64) -> Result<bool, String> {
        // if epsilon > 0, check if acceptable (above dust limit).
        if amount > 0 && amount < channel_state.get_dust_limit() {
            // if check fails, abort and output an error
            return Err(String::from("epsilon below dust limit!"));
        }

        // check if n_i not in S_spent
        let nonce_hex = hex::encode(nonce);
        if self.spent_lock_map.get(&nonce_hex).is_some() {
            return Err(format!("nonce {} has been spent already.", &nonce_hex));
        }

        // check the nonce & paytoken_mask (based on the nonce)
        let (pay_mask_bytes, pay_mask_r) = match self.nonce_mask_map.get(&nonce_hex) {
            Some(n) => (n.mask.0, n.r.0),
            _ => return Err(String::from("could not find pay mask for specified nonce"))
        };

        let pay_mask_com = self.recompute_commitmment(&pay_mask_bytes, &pay_mask_r);
        if pay_mask_com != paytoken_mask_com {
            return Err(String::from("specified invalid pay mask commitment"));
        }

        // generate masks for close-escrow and close-merch txs
        let mut merch_mask_bytes = [0u8; 32];
        csprng.fill_bytes(&mut merch_mask_bytes);

        let mut escrow_mask_bytes = [0u8; 32];
        csprng.fill_bytes(&mut escrow_mask_bytes);

        // load the key_com from the channelState
        let hmac_key_com = channel_state.get_key_com();

        // load the hmac key
        let mut hmac_key = [0u8; 64];
        hmac_key.copy_from_slice(&self.hmac_key.get_bytes());

        // get the public keys
        let merch_escrow_pub_key = self.pk_m.clone(); // escrow key
        let pk_input_buf = self.payout_pk.serialize();
        let merch_public_key_hash= compute_hash160(&pk_input_buf.to_vec());

        let (r_merch, r_esc) = mpc_build_masked_tokens_merch(csprng, self.conn_type, amount, &paytoken_mask_com, &rev_lock_com, &hmac_key_com, &self.hmac_key_r.0,
                                                  merch_escrow_pub_key, self.dispute_pk, merch_public_key_hash, self.payout_pk, nonce,
                                                  &hmac_key, self.sk_m.clone(), &merch_mask_bytes,
                                                  &pay_mask_bytes, &pay_mask_r, &escrow_mask_bytes);

        // store the rev_lock_com => (pt_mask_bytes, escrow_mask_bytes, merch_mask_bytes)
//        println!("=================================================================");
//        println!("merchant pt_mask: {:?}", hex::encode(&pay_mask_bytes));
//        println!("merchant escrow_mask: {:?}", hex::encode(&escrow_mask_bytes));
//        println!("merchant merch_mask: {:?}", hex::encode(&merch_mask_bytes));
//        println!("merchant r_escrow_sig: {:?}", hex::encode(&r_esc));
//        println!("merchant r_merch_sig: {:?}", hex::encode(&r_merch));
//        println!("=================================================================");

        let mask_bytes = MaskedMPCInputs {
            pt_mask: FixedSizeArray32(pay_mask_bytes),
            pt_mask_r: FixedSizeArray16(pay_mask_r),
            escrow_mask: FixedSizeArray32(escrow_mask_bytes),
            merch_mask: FixedSizeArray32(merch_mask_bytes),
            r_escrow_sig: FixedSizeArray32(r_esc),
            r_merch_sig: FixedSizeArray32(r_merch),
        };

        let rev_lock_com_hex = hex::encode(rev_lock_com);
        self.mask_mpc_bytes.insert( rev_lock_com_hex, mask_bytes);

        Ok(true)
    }

    pub fn verify_revoked_state(&mut self, nonce: [u8; NONCE_LEN], rev_lock_com: [u8; 32], rev_lock: [u8; 32], rev_sec: [u8; 32], t: [u8; 16]) -> (Option<[u8; 32]>, Option<[u8; 16]>) {
        // check rev_lock_com opens to RL_i / t_i
        // check that RL_i is derived from RS_i
        if compute_rev_lock_commitment(&rev_lock, &t) != rev_lock_com ||
            hash_to_slice(&rev_sec.to_vec()) != rev_lock {
            let nonce_hex = hex::encode(nonce);
            self.spent_lock_map.insert(nonce_hex, None);
            return (None, None);
        }

        // retrieve masked bytes from rev_lock_com (output error, if not)
        let rev_lock_com_hex = hex::encode(rev_lock_com);
        let (is_ok, pt_mask, pt_mask_r) = match self.mask_mpc_bytes.get(&rev_lock_com_hex) {
            Some(&n) => (true, Some(n.pt_mask.0), Some(n.pt_mask_r.0)),
            _ => (false, None, None)
        };


        let nonce_hex = hex::encode(nonce);
        if is_ok {
            // add (n_i, RS_i, RL_i) to S_spent map
            let revoked_lock_pair = LockMap {
                lock: FixedSizeArray32(rev_lock),
                secret: FixedSizeArray32(rev_sec)
            };
            self.spent_lock_map.insert(nonce_hex.clone(), Some(revoked_lock_pair));
            // check if n_i in the unlink map. if so, remove it
            if self.unlink_map.contains(&nonce_hex) {
                self.unlink_map.remove(&nonce_hex);
            }

        } else {
            self.spent_lock_map.insert(nonce_hex, None);
        }

        return (pt_mask, pt_mask_r);
    }

}

#[cfg(feature = "mpc-bitcoin")]
#[cfg(test)]
mod tests {
    use super::*;
    use rand_xorshift::XorShiftRng;
    use channels_mpc::{ChannelMPCState, MerchantMPCState, CustomerMPCState};
    use std::thread;
    use std::time::Duration;
    use sha2::Digest;
    use sha2::Sha256;
    use serde::de::value::Error;
    use bitcoin::Testnet;
    use rand::SeedableRng;
    use wagyu_model::AddressError::Message;
    use bindings::ConnType;
    use wagyu_model::Transaction;

    fn generate_test_txs<R: Rng>(csprng: &mut R, b0_cust: i64, b0_merch: i64) -> FundingTxInfo {
        let mut escrow_txid = [0u8; 32];
        let mut merch_txid = [0u8; 32];

        csprng.fill_bytes(&mut escrow_txid);
        csprng.fill_bytes(&mut merch_txid);

        let mut escrow_prevout = [0u8; 32];
        let mut merch_prevout = [0u8; 32];

        let mut prevout_preimage1: Vec<u8> = Vec::new();
        prevout_preimage1.extend(escrow_txid.iter());
        prevout_preimage1.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result1 = Sha256::digest(&Sha256::digest(&prevout_preimage1));
        escrow_prevout.copy_from_slice(&result1);

        let mut prevout_preimage2: Vec<u8> = Vec::new();
        prevout_preimage2.extend(merch_txid.iter());
        prevout_preimage2.extend(vec![0x00, 0x00, 0x00, 0x00]); // index
        let result2 = Sha256::digest(&Sha256::digest(&prevout_preimage2));
        merch_prevout.copy_from_slice(&result2);

        return FundingTxInfo { init_cust_bal: b0_cust, init_merch_bal: b0_merch,
                        escrow_txid: FixedSizeArray32(escrow_txid), escrow_prevout: FixedSizeArray32(escrow_prevout),
                        merch_txid: FixedSizeArray32(merch_txid), merch_prevout: FixedSizeArray32(merch_prevout) };
    }

rusty_fork_test!
{
    #[test]
    fn mpc_channel_util_customer_works() {
        let mut channel_state = ChannelMPCState::new(String::from("Channel A <-> B"), false);
        // let rng = &mut rand::thread_rng();
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d86);

        let b0_cust = 100;
        let b0_merch = 20;
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let mut merch_state = MerchantMPCState::new(&mut rng, &mut channel_state, String::from("Merchant B"));

        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerMPCState::new(&mut rng, b0_cust, b0_merch, String::from("Customer"));

        // at this point, cust/merch have both exchanged initial sigs (escrow-tx + merch-close-tx)
        let funding_tx_info = generate_test_txs(&mut rng, b0_cust, b0_merch);

        // initialize the channel token on with pks
        let mut channel_token = cust_state.generate_init_channel_token(&merch_state.pk_m);

        // generate and send initial state to the merchant
        cust_state.generate_init_state(&mut rng, &mut channel_token);
        // set escrow-tx and merch-close-tx info
        cust_state.set_funding_tx_info(&mut channel_token, &funding_tx_info).unwrap();
        // get initial state
        let s_0 = cust_state.get_current_state();

        // retrieve the initial state from cust state
        let init_cust_state = cust_state.get_initial_cust_state().unwrap();

        // validate the initial state with merchant
        merch_state.validate_initial_state(&channel_token, &init_cust_state, s_0.compute_hash());

        println!("Begin activate phase for channel");
        println!("customer channel token: {}", &serde_json::to_string(&channel_token).unwrap());

        let r_com = cust_state.generate_rev_lock_commitment(&mut rng);
        let t_0 = cust_state.get_randomness();
        println!("Initial state: {}", s_0);
        println!("Init rev_lock commitment => {:?}", r_com);

        // activate channel - generate pay_token
        let pay_token_0 = match merch_state.activate_channel(&channel_token, &s_0) {
            Ok(p) => p,
            Err(e) => panic!(e)
        };

        println!("Pay Token on s_0 => {:?}", pay_token_0);

        cust_state.store_initial_pay_token(pay_token_0);

        let (rev_lock, rev_secret) = cust_state.get_rev_pair();
        let t = cust_state.get_randomness();

        let amount = 10;

        cust_state.generate_new_state(&mut rng, amount);
        let s_1 = cust_state.get_current_state();
        println!("Updated state: {}", s_1);

        let pay_token_mask_com = merch_state.generate_pay_mask_commitment(&mut rng, &channel_state, s_0.get_nonce(), r_com.clone(), amount).unwrap();
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
        let nonce = s_0.get_nonce().clone();

        let mask_bytes = merch_state.verify_revoked_state(nonce, rev_lock_com, rev_lock, rev_secret, t);
        //assert!(!mask_bytes.is_none());

        let mut pt_mask = [0u8; 32];
        pt_mask.copy_from_slice(hex::decode("142ce9bf56c107f0eb082c751e94c43f7e96bbc96ef378073ac8061200ca7909").unwrap().as_slice());
        let mut pt_mask_r = [0u8; 16];
        pt_mask_r.copy_from_slice(hex::decode("37a5641c56c647dcfc8224f8327eca3f").unwrap().as_slice());

        let mut escrow_mask = [0u8; 32];
        escrow_mask.copy_from_slice(hex::decode("8beda3c4cac531d6b33c746052f32c39498e38e251187fba093a2f7b5de0c725").unwrap().as_slice());
        let mut merch_mask = [0u8; 32];
        merch_mask.copy_from_slice(hex::decode("e129be06162a29e40d67c638c9b591549b6f97a36598430eaf68b6052daa50dc").unwrap().as_slice());
        let mut r_escrow_sig = [0u8; 32];
        r_escrow_sig.copy_from_slice(hex::decode("073ab5239d02e596408d9e025c5c586ed6cd4779a23ab41901317833d6d1aec2").unwrap().as_slice());
        let mut r_merch_sig = [0u8; 32];
        r_merch_sig.copy_from_slice(hex::decode("aac4f29a8a958f846509f07610030da10f5f46d791c8c90bfd8d17a88a7d5c48").unwrap().as_slice());

        let mask_bytes = Some(MaskedMPCInputs { pt_mask: FixedSizeArray32(pt_mask), escrow_mask: FixedSizeArray32(escrow_mask),
                                                pt_mask_r: FixedSizeArray16(pt_mask_r),
                                                merch_mask: FixedSizeArray32(merch_mask), r_escrow_sig: FixedSizeArray32(r_escrow_sig),
                                                r_merch_sig: FixedSizeArray32(r_merch_sig) });

        if mask_bytes.is_some() {
            let mb = mask_bytes.unwrap();
            let ser_mask_bytes = serde_json::to_string(&mb).unwrap();
            println!("ser mask bytes: {}", ser_mask_bytes);

            let orig_mask_bytes: MaskedMPCInputs = serde_json::from_str(&ser_mask_bytes).unwrap();
            assert_eq!(mb, orig_mask_bytes);

            println!("pt_masked: {:?}", hex::encode(&mb.pt_mask.0));
            println!("escrow_masked: {:?}", hex::encode(&mb.escrow_mask.0));
            println!("merch_masked: {:?}", hex::encode(&mb.merch_mask.0));

            println!("now, unmask and verify...");
            let is_ok = cust_state.unmask_and_verify_transactions::<Testnet>(&channel_state, &channel_token, mb.get_tx_masks());
            assert!(is_ok);

            cust_state.unmask_and_verify_pay_token(mb.pt_mask.0, mb.pt_mask_r.0);

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
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d86);

        let b0_cust = 100;
        let b0_merch = 20;
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let mut merch_state = MerchantMPCState::new(&mut rng, &mut channel, String::from("Merchant"));

        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerMPCState::new(&mut rng, b0_cust, b0_merch, String::from("Customer"));

        // at this point, cust/merch have both exchanged initial sigs (escrow-tx + merch-close-tx)
        let funding_tx_info = generate_test_txs(&mut rng, b0_cust, b0_merch);

        // initialize the channel token on with pks
        let mut channel_token = cust_state.generate_init_channel_token(&merch_state.pk_m);

        // generate and send initial state to the merchant
        cust_state.generate_init_state(&mut rng, &mut channel_token);
        // set escrow-tx and merch-close-tx info
        cust_state.set_funding_tx_info(&mut channel_token, &funding_tx_info).unwrap();
        // get initial state
        let s_0 = cust_state.get_current_state();

        // retrieve the initial state from cust state
        let init_cust_state = cust_state.get_initial_cust_state().unwrap();

        // validate the initial state with merchant
        merch_state.validate_initial_state(&channel_token, &init_cust_state, s_0.compute_hash());

        println!("Begin activate phase for channel");
        println!("merchant channel token: {}", &serde_json::to_string(&channel_token).unwrap());

        let r_com = cust_state.generate_rev_lock_commitment(&mut rng);
        let t_0 = cust_state.get_randomness();
        println!("Initial state: {}", s_0);
        println!("Init rev_lock commitment => {:?}", r_com);

        // activate channel - generate pay_token
        let pay_token_0 = match merch_state.activate_channel(&channel_token, &s_0) {
            Ok(p) => p,
            Err(e) => panic!(e)
        };

        println!("Pay Token on s_0 => {:?}", pay_token_0);

        cust_state.store_initial_pay_token(pay_token_0);

        let (rev_lock, rev_secret) = cust_state.get_rev_pair();
        let t = cust_state.get_randomness();

        let amount = 10;

        cust_state.generate_new_state(&mut rng, amount);
        let s_1 = cust_state.get_current_state();
        println!("Updated state: {}", s_1);
        let pay_token_mask_com = merch_state.generate_pay_mask_commitment(&mut rng, &channel, s_0.get_nonce(), r_com.clone(), amount).unwrap();
        cust_state.update_pay_com(pay_token_mask_com);

        merch_state.set_mpc_connect_type(2);

        // prepare the merchant inputs
        let rev_lock_com = r_com.clone();
        let nonce = s_0.get_nonce().clone();

        println!("hello, merchant!");
        let res = merch_state.execute_mpc_context(&mut rng, &channel, nonce, rev_lock_com, pay_token_mask_com, amount).unwrap();

        println!("completed mpc execution!");

        let (pt_mask_bytes, pt_mask_r) = merch_state.verify_revoked_state(nonce, rev_lock_com, rev_lock, rev_secret, t);
        assert!(!pt_mask_bytes.is_none());
        assert!(!pt_mask_r.is_none());

        if pt_mask_bytes.is_some() {
            let pt_mask = pt_mask_bytes.unwrap();
            println!("pt_masked: {:?}", hex::encode(&pt_mask));
        }

        if pt_mask_r.is_some() {
            let pt_mask_r = pt_mask_r.unwrap();
            println!("pt_mask_r: {:?}", hex::encode(&pt_mask_r));
        }

    }

    #[test]
    fn mpc_test_serialization() {
        let mut channel_state = ChannelMPCState::new(String::from("Channel A <-> B"), false);
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d863e54);

        let b0_cust = 1000;
        let b0_merch = 10;

        let merch_state = MerchantMPCState::new(&mut rng, &mut channel_state, String::from("Merchant"));

        let ser_merch_state = serde_json::to_string(&merch_state).unwrap();
        println!("Ser Merchant state: {}", ser_merch_state);
        let orig_merch_state: MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();
        assert_eq!(merch_state, orig_merch_state);

        let ser_channel_state = serde_json::to_string(&channel_state).unwrap();
        println!("Ser channel state: {}", ser_channel_state);

        let orig_channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();
        assert_eq!(channel_state, orig_channel_state);

        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerMPCState::new(&mut rng, b0_cust, b0_merch, String::from("Customer"));

        // at this point, cust/merch have both exchanged initial sigs (escrow-tx + merch-close-tx)
        let funding_tx_info = generate_test_txs(&mut rng, b0_cust, b0_merch);

        // initialize the channel token on with pks
        let mut channel_token = cust_state.generate_init_channel_token(&merch_state.pk_m);

        cust_state.set_funding_tx_info(&mut channel_token, &funding_tx_info);

        // generate and send initial state to the merchant
        cust_state.generate_init_state(&mut rng, &mut channel_token);
        let s_0 = cust_state.get_current_state();

        let ser_state = serde_json::to_string(&s_0).unwrap();
        println!("Ser state: {}", &ser_state);

        let orig_state: State = serde_json::from_str(&ser_state).unwrap();
        assert_eq!(s_0, orig_state);

        let ser_channel_token = serde_json::to_string(&channel_token).unwrap();
        println!("Ser channel token: {}", ser_channel_token);
        let orig_channel_token: ChannelMPCToken = serde_json::from_str(&ser_channel_token).unwrap();
        assert_eq!(channel_token, orig_channel_token);
    }
}
