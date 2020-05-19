use super::*;
use util::{compute_hash160, hash_to_slice, hmac_sign, VAL_CPFP};

use bindings::{load_circuit_file, ConnType};
use database::{MaskedMPCInputs, MaskedTxMPCInputs, StateDatabase};
use mpcwrapper::{mpc_build_masked_tokens_cust, mpc_build_masked_tokens_merch, CIRCUIT_FILE};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::ffi::{c_void, CString};
use std::fmt::Debug;
use std::os::unix::io::RawFd;
use std::{env, ptr};
use wallet::{State, NONCE_LEN};
use zkchan_tx::fixed_size_array::{FixedSizeArray16, FixedSizeArray32, FixedSizeArray64};
use zkchan_tx::transactions::btc::{
    completely_sign_multi_sig_transaction, create_cust_close_transaction, create_utxo_input,
    generate_customer_close_tx_helper, generate_signature_for_multi_sig_transaction,
    get_private_key, merchant_form_close_transaction,
};
use zkchan_tx::transactions::ClosePublicKeys;
use zkchan_tx::{BitcoinNetwork, BitcoinTransactionParameters, Transaction};
use std::fmt::Display;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub conn_type: ConnType,
    pub path: String,
    pub dest_ip: String,
    pub dest_port: i32,
    pub peer_raw_fd: RawFd,
}

// pub struct Circuit {
//     ptr: *mut c_void
// }

#[derive(Clone, Debug, PartialEq, Display, Serialize, Deserialize)]
pub enum ChannelStatus {
    Opened,
    Initialized,
    Activated,
    Established,
    MerchantInitClose,
    CustomerInitClose,
    Disputed,
    PendingClose,
    ConfirmedClose
}

pub enum PaymentStatus {
    Prepare,
    Update,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelMPCToken {
    pub pk_c: Option<secp256k1::PublicKey>,
    // pk_c
    pub pk_m: secp256k1::PublicKey,
    // pk_m
    pub escrow_txid: FixedSizeArray32,
    pub merch_txid: FixedSizeArray32,
}

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

impl fmt::Display for ChannelMPCToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let pkc_hex = match self.pk_c {
            Some(n) => hex::encode(n.serialize().to_vec()),
            None => "None".to_string(),
        };
        let pkm_hex = hex::encode(self.pk_m.serialize().to_vec());
        let escrow_txid_hex = hex::encode(self.escrow_txid.0.to_vec());
        let merch_txid_hex = hex::encode(self.merch_txid.0.to_vec());

        write!(
            f,
            "ChannelMPCToken : (\npkc={}\npkm={}\nescrow_txid={:?}\nmerch_txid={:?}\n)",
            pkc_hex, pkm_hex, escrow_txid_hex, merch_txid_hex
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelMPCState {
    min_threshold: i64,
    key_com: FixedSizeArray32,
    pub name: String,
    pub third_party: bool,
    pub merch_payout_pk: Option<secp256k1::PublicKey>,
    pub merch_dispute_pk: Option<secp256k1::PublicKey>,
    pub self_delay: u16,
}

impl ChannelMPCState {
    pub fn new(
        name: String,
        self_delay: u16,
        min_threshold: i64,
        third_party_support: bool,
    ) -> ChannelMPCState {
        ChannelMPCState {
            min_threshold: min_threshold, // dust limit (546)
            key_com: FixedSizeArray32([0u8; 32]),
            name: name.to_string(),
            third_party: third_party_support,
            merch_payout_pk: None,
            merch_dispute_pk: None,
            self_delay: self_delay,
        }
    }

    pub fn set_min_threshold(&mut self, dust_amount: i64) {
        assert!(dust_amount >= 0);
        self.min_threshold = dust_amount;
    }

    pub fn get_min_threshold(&self) -> i64 {
        return self.min_threshold;
    }

    pub fn get_key_com(&self) -> [u8; 32] {
        self.key_com.0.clone()
    }

    pub fn set_key_com(&mut self, key_com: [u8; 32]) {
        self.key_com = FixedSizeArray32(key_com);
    }

    pub fn set_merchant_public_keys(
        &mut self,
        merch_payout_pk: secp256k1::PublicKey,
        merch_dispute_pk: secp256k1::PublicKey,
    ) {
        self.merch_payout_pk = Some(merch_payout_pk);
        self.merch_dispute_pk = Some(merch_dispute_pk);
    }

    pub fn get_self_delay_be(&self) -> [u8; 2] {
        let b = self.self_delay.to_be_bytes();

        let mut self_delay_be = [0u8; 2];
        self_delay_be.copy_from_slice(&b);
        self_delay_be
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MaskedMPCOutputs {
    pt_masked: FixedSizeArray32,
    escrow_masked: FixedSizeArray32,
    merch_masked: FixedSizeArray32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomerMPCState {
    pub name: String,
    pub pk_c: secp256k1::PublicKey,
    sk_c: FixedSizeArray32,
    pub cust_balance: i64,
    pub merch_balance: i64,
    fee_cc: i64,
    rev_lock: FixedSizeArray32,
    rev_secret: FixedSizeArray32,
    t: FixedSizeArray16,
    // randomness used to form the commitment
    state: Option<State>,
    // vector of field elements that represent current state
    index: i32,
    masked_outputs: HashMap<i32, MaskedMPCOutputs>,
    pay_tokens: HashMap<i32, FixedSizeArray32>,
    pay_token_mask_com: FixedSizeArray32,
    payout_sk: FixedSizeArray32,
    payout_pk: secp256k1::PublicKey,
    close_escrow_signature: Option<String>,
    close_merch_signature: Option<String>,
    pub channel_status: ChannelStatus,
    pub net_config: Option<NetworkConfig>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InitCustState {
    pub pk_c: secp256k1::PublicKey,
    pub close_pk: secp256k1::PublicKey,
    pub nonce: FixedSizeArray16,
    pub rev_lock: FixedSizeArray32,
    pub cust_bal: i64,
    pub merch_bal: i64,
    pub min_fee: i64,
    pub max_fee: i64,
    pub fee_mc: i64,
}

impl fmt::Display for InitCustState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let nonce_hex = hex::encode(self.nonce.0.to_vec());
        let rev_lock_hex = hex::encode(self.rev_lock.0.to_vec());

        write!(
            f,
            "InitCustState : (\npkc={:?}\nnonce={:?}\nrev_lock={:?}\n)",
            &self.pk_c, nonce_hex, rev_lock_hex
        )
    }
}

fn convert_to_little_endian(be: &FixedSizeArray32) -> FixedSizeArray32 {
    let mut le = be.clone();
    le.0.reverse();
    return le;
}

impl CustomerMPCState {
    pub fn new<R: Rng>(
        csprng: &mut R,
        cust_bal: i64,
        merch_bal: i64,
        fee_cc: i64,
        name: String
    ) -> Self {
        let secp = secp256k1::Secp256k1::new();

        let mut _sk_c = [0u8; 32];
        let mut _payout_sk = [0u8; 32];
        csprng.fill_bytes(&mut _sk_c);
        csprng.fill_bytes(&mut _payout_sk);

        // generate the signing keypair for the channel
        let sk_c = secp256k1::SecretKey::from_slice(&_sk_c).unwrap();
        let pk_c = secp256k1::PublicKey::from_secret_key(&secp, &sk_c);

        // generate the keypair for the initial state of channel
        let mut rev_secret = [0u8; 32];
        csprng.fill_bytes(&mut rev_secret);

        // compute hash of the revocation secret
        let rev_lock = hash_to_slice(&rev_secret.to_vec());

        let pay_mask_com = [0u8; 32];
        let t = [0u8; 16];
        let payout_sk = secp256k1::SecretKey::from_slice(&_payout_sk).unwrap();
        let payout_pk = secp256k1::PublicKey::from_secret_key(&secp, &payout_sk);

        let mpc_outputs = HashMap::new();
        let pt_db = HashMap::new();

        return CustomerMPCState {
            name: name,
            pk_c: pk_c,
            sk_c: FixedSizeArray32(_sk_c),
            cust_balance: cust_bal,
            merch_balance: merch_bal,
            fee_cc: fee_cc,
            rev_lock: FixedSizeArray32(rev_lock),
            rev_secret: FixedSizeArray32(rev_secret),
            t: FixedSizeArray16(t),
            state: None,
            index: 0,
            masked_outputs: mpc_outputs,
            pay_tokens: pt_db,
            pay_token_mask_com: FixedSizeArray32(pay_mask_com),
            payout_sk: FixedSizeArray32(_payout_sk),
            payout_pk: payout_pk,
            close_escrow_signature: None,
            close_merch_signature: None,
            channel_status: ChannelStatus::Opened,
            net_config: None,
        };
    }

    pub fn load_external_wallet(&mut self, channel_token: &mut ChannelMPCToken, cust_sk: [u8; 32], pay_sk: [u8; 32]) -> Result<(), String> {
        let secp = secp256k1::Secp256k1::new();

        let sk_c = handle_error_util!(secp256k1::SecretKey::from_slice(&cust_sk));
        let payout_sk = handle_error_util!(secp256k1::SecretKey::from_slice(&pay_sk));

        let pk_c = secp256k1::PublicKey::from_secret_key(&secp, &sk_c);
        let payout_pk = secp256k1::PublicKey::from_secret_key(&secp, &payout_sk);
        
        channel_token.set_customer_pk(pk_c.clone());
        
        self.sk_c = FixedSizeArray32(cust_sk);
        self.pk_c = pk_c;

        self.payout_sk = FixedSizeArray32(pay_sk);
        self.payout_pk = payout_pk;

        Ok(())
    }

    pub fn get_secret_key(&self) -> Vec<u8> {
        // let sk_c = secp256k1::SecretKey::from_slice(&self.sk_c.0).unwrap();
        return self.sk_c.0.to_vec();
    }

    pub fn get_close_secret_key(&self) -> Vec<u8> {
        return self.payout_sk.0.to_vec();
    }

    pub fn update_pay_com(&mut self, pay_token_mask_com: [u8; 32]) {
        self.pay_token_mask_com
            .0
            .copy_from_slice(&pay_token_mask_com);
    }

    pub fn generate_init_state<R: Rng>(
        &mut self,
        csprng: &mut R,
        pk_m: &secp256k1::PublicKey,
        min_fee: i64,
        max_fee: i64,
        fee_mc: i64,
    ) -> ChannelMPCToken {
        assert!(self.state.is_none());

        let mut nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
        csprng.fill_bytes(&mut nonce);

        let state = State {
            nonce: FixedSizeArray16(nonce),
            rev_lock: self.rev_lock,
            bc: self.cust_balance,
            bm: self.merch_balance,
            escrow_txid: FixedSizeArray32([0u8; 32]),
            merch_txid: FixedSizeArray32([0u8; 32]),
            escrow_prevout: FixedSizeArray32([0u8; 32]),
            merch_prevout: FixedSizeArray32([0u8; 32]),
            min_fee,
            max_fee,
            fee_mc,
        };

        self.state = Some(state);
        return ChannelMPCToken {
            pk_c: Some(self.pk_c.clone()),
            pk_m: pk_m.clone(),
            escrow_txid: FixedSizeArray32([0u8; 32]),
            merch_txid: FixedSizeArray32([0u8; 32]),
        };
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

    pub fn store_initial_pay_token(&mut self, pay_token: [u8; 32]) -> Result<(), String> {
        if self.channel_status != ChannelStatus::Initialized {
            return Err(format!("Invalid channel status for store_initial_pay_token(): {}", self.channel_status));
        }

        self.pay_tokens.insert(0, FixedSizeArray32(pay_token));
        self.channel_status = ChannelStatus::Activated;
        Ok(())
    }

    pub fn set_funding_tx_info(
        &mut self,
        channel_token: &mut ChannelMPCToken,
        tx: &FundingTxInfo,
    ) -> Result<(), String> {
        if self.state.is_none() {
            return Err(String::from("Customer initial state has not been created!"));
        }

        let mut s = self.state.unwrap();
        s.escrow_txid = tx.escrow_txid.clone();
        s.escrow_prevout = tx.escrow_prevout.clone();
        s.merch_txid = tx.merch_txid.clone();
        s.merch_prevout = tx.merch_prevout.clone();
        s.bc = tx.init_cust_bal;
        s.bm = tx.init_merch_bal;
        s.min_fee = tx.min_fee;
        s.max_fee = tx.max_fee;
        s.fee_mc = tx.fee_mc;
        self.state = Some(s);

        channel_token.escrow_txid = convert_to_little_endian(&tx.escrow_txid);
        channel_token.merch_txid = convert_to_little_endian(&tx.merch_txid);

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
            merch_bal: self.merch_balance,
            min_fee: self.state.unwrap().min_fee,
            max_fee: self.state.unwrap().max_fee,
            fee_mc: self.state.unwrap().fee_mc,
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

    pub fn has_tokens(&self) -> bool {
        let index = self.index;
        let is_pt = self.pay_tokens.get(&index).is_some();
        return is_pt;
    }

    pub fn set_network_config(&mut self, net_config: NetworkConfig) {
        self.net_config = Some(net_config);
    }

    pub fn get_circuit_file(&self) -> *mut c_void {
        let using_ag2pc = match env::var("AG2PC") {
            Ok(_s) => true,
            Err(_e) => false,
        };

        let circuit_file = match using_ag2pc {
            true => match env::var("ZK_DEPS_INSTALL") {
                Ok(s) => format!("{}{}", s, CIRCUIT_FILE),
                Err(e) => panic!("ZK_DEPS_INSTALL env not set: {}", e),
            },
            false => String::new(),
        };

        let cf_ptr = match using_ag2pc {
            true => {
                let cf_ptr = unsafe {
                    let c_str = CString::new(circuit_file).unwrap();
                    load_circuit_file(c_str.as_ptr() as *const i8)
                };
                cf_ptr
            }
            false => ptr::null_mut(),
        };
        return cf_ptr;
    }

    pub fn get_fee_cc(&self) -> i64 {
        return self.fee_cc;
    }

    pub fn validate_state(
        &self,
        old_state: State,
        new_state: State,
        amount: i64,
        fee_cc: i64,
        min_threshold: i64,
    ) {
        assert_eq!(old_state.min_fee, new_state.min_fee);
        assert_eq!(old_state.max_fee, new_state.max_fee);
        assert_eq!(old_state.fee_mc, new_state.fee_mc);

        assert!(new_state.max_fee >= fee_cc);
        assert!(new_state.min_fee <= fee_cc);

        assert_eq!(new_state.bm, old_state.bm + amount);
        assert_eq!(new_state.bc, old_state.bc - amount);

        assert!(new_state.bm >= min_threshold + new_state.fee_mc + VAL_CPFP);
        assert!(new_state.bc >= min_threshold + fee_cc + VAL_CPFP);
    }

    // customer side of mpc
    pub fn execute_mpc_context(
        &mut self,
        channel_state: &ChannelMPCState,
        channel_token: &ChannelMPCToken,
        old_state: State,
        new_state: State,
        fee_cc: i64,
        paytoken_mask_com: [u8; 32],
        rev_lock_com: [u8; 32],
        amount: i64,
        circuit: *mut c_void
    ) -> Result<bool, String> {
        let min_cust_bal = channel_state.min_threshold + fee_cc + VAL_CPFP;
        if new_state.bc <= min_cust_bal {
            return Err(format!(
                "customer::execute_mpc_context - customer balance below min balance allowed after payment: {}", min_cust_bal
            ));
        }

        // TODO: add channel_status check: 

        // load the key_com from channel state
        let key_com = channel_state.get_key_com();

        // get cust pub keys
        let cust_escrow_pub_key = self.pk_c.clone();
        let cust_payout_pub_key = self.payout_pk;
        let cust_pk_input_buf = cust_payout_pub_key.serialize();
        let cust_public_key_hash = compute_hash160(&cust_pk_input_buf.to_vec());

        let merch_escrow_pub_key = channel_token.pk_m.clone();
        let merch_dispute_key = channel_state.merch_dispute_pk.unwrap();
        let merch_payout_pub_key = channel_state.merch_payout_pk.unwrap();
        let pk_input_buf = merch_payout_pub_key.serialize();
        let merch_public_key_hash = compute_hash160(&pk_input_buf.to_vec());

        let old_paytoken = match self.has_tokens() {
            true => self.pay_tokens.get(&self.index).unwrap(),
            false => {
                return Err(String::from(
                    "you do not have a pay token for previous state",
                ));
            }
        };

        // retrieve network config details
        let net_conn = match self.net_config.clone() {
            Some(nc) => nc,
            None => {
                return Err(String::from(
                    "customer::execute_mpc_context - net config not specified",
                ));
            }
        };

        // let cf_ptr = self.get_circuit_file();

        self.validate_state(
            old_state,
            new_state,
            amount,
            fee_cc,
            channel_state.min_threshold,
        );
        let (pt_masked_ar, ct_escrow_masked_ar, ct_merch_masked_ar) =
            match mpc_build_masked_tokens_cust(
                net_conn,
                circuit,
                amount,
                &paytoken_mask_com,
                &rev_lock_com,
                &self.t.0,
                &key_com,
                merch_escrow_pub_key,
                merch_dispute_key,
                merch_public_key_hash,
                merch_payout_pub_key,
                new_state,
                old_state,
                fee_cc,
                &old_paytoken.0,
                cust_escrow_pub_key,
                cust_payout_pub_key,
                cust_public_key_hash,
            ) {
                Ok(c) => (c.0, c.1, c.2),
                Err(e) => return Err(e.to_string()),
            };

        let masked_output = MaskedMPCOutputs {
            pt_masked: FixedSizeArray32(pt_masked_ar),
            escrow_masked: FixedSizeArray32(ct_escrow_masked_ar),
            merch_masked: FixedSizeArray32(ct_merch_masked_ar),
        };

        // save the masked outputs (will unmask later)
        self.masked_outputs
            .insert(self.index, masked_output.clone());
        Ok(true)
    }

    pub fn get_pubkeys(
        &self,
        channel_state: &ChannelMPCState,
        channel_token: &ChannelMPCToken,
    ) -> ClosePublicKeys {
        let cust_escrow_pub_key = self.pk_c.serialize();
        let cust_payout_pub_key = self.payout_pk.serialize();
        let merch_escrow_pub_key = channel_token.pk_m.serialize();
        let merch_dispute_key = channel_state.merch_dispute_pk.unwrap().serialize();
        let merch_payout_pub_key = channel_state.merch_payout_pk.unwrap().serialize();

        let mut pubkeys = ClosePublicKeys {
            cust_pk: cust_escrow_pub_key.to_vec(),
            cust_close_pk: cust_payout_pub_key.to_vec(),
            merch_pk: merch_escrow_pub_key.to_vec(),
            merch_close_pk: merch_payout_pub_key.to_vec(),
            merch_disp_pk: merch_dispute_key.to_vec(),
            rev_lock: FixedSizeArray32([0u8; 32]),
        };
        pubkeys
            .rev_lock
            .0
            .copy_from_slice(&self.state.unwrap().get_rev_lock());
        return pubkeys;
    }

    // Customer constructs initial tx preimage and transaction params
    pub fn construct_close_transaction_preimage<N: BitcoinNetwork>(
        &self,
        channel_state: &ChannelMPCState,
        channel_token: &ChannelMPCToken,
    ) -> (
        Vec<u8>,
        Vec<u8>,
        BitcoinTransactionParameters<N>,
        BitcoinTransactionParameters<N>,
    ) {
        let init_balance = self.cust_balance + self.merch_balance;
        // TODO: should be configurable via a tx_config
        let escrow_index = 0;
        let merch_index = 0;
        let to_self_delay_be: [u8; 2] = channel_state.get_self_delay_be(); // big-endian format

        let pubkeys = self.get_pubkeys(channel_state, channel_token);
        let escrow_input =
            create_utxo_input(&channel_token.escrow_txid.0, escrow_index, init_balance);
        let merch_input =
            create_utxo_input(&channel_token.merch_txid.0, merch_index, init_balance);

        let (escrow_tx_preimage, escrow_tx_params, _) = create_cust_close_transaction::<N>(
            &escrow_input,
            &pubkeys,
            &to_self_delay_be,
            self.cust_balance,
            self.merch_balance,
            self.fee_cc,
            self.get_current_state().fee_mc,
            util::VAL_CPFP,
            true,
        );

        let (merch_tx_preimage, merch_tx_params, _) = create_cust_close_transaction::<N>(
            &merch_input,
            &pubkeys,
            &to_self_delay_be,
            self.cust_balance,
            self.merch_balance,
            self.fee_cc,
            self.get_current_state().fee_mc,
            util::VAL_CPFP,
            false,
        );

        return (
            escrow_tx_preimage,
            merch_tx_preimage,
            escrow_tx_params,
            merch_tx_params,
        );
    }

    // Customer signs the initial closing transaction (in the clear)
    pub fn sign_initial_closing_transaction<N: BitcoinNetwork>(
        &mut self,
        channel_state: &ChannelMPCState,
        channel_token: &ChannelMPCToken,
        orig_escrow_sig: &Vec<u8>,
        orig_merch_sig: &Vec<u8>,
    ) -> Result<bool, String> {
        let (escrow_tx_preimage, merch_tx_preimage, _, _) =
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
            Err(e) => return Err(e.to_string()),
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
            Err(e) => return Err(e.to_string()),
        };

        // println!("Tx hash: {}", hex::encode(&escrow_tx_hash));
        let msg1 = secp256k1::Message::from_slice(&escrow_tx_hash).unwrap();
        let msg2 = secp256k1::Message::from_slice(&merch_tx_hash).unwrap();
        let secp = secp256k1::Secp256k1::verification_only();
        let escrow_sig_valid = secp.verify(&msg1, &escrow_sig, &channel_token.pk_m).is_ok();
        let merch_sig_valid = secp.verify(&msg2, &merch_sig, &channel_token.pk_m).is_ok();

        if escrow_sig_valid && merch_sig_valid {
            // store the merchant signatures
            let escrow_sig_hex = hex::encode(&escrow_sig.serialize_compact().to_vec());
            let merch_sig_hex = hex::encode(&merch_sig.serialize_compact().to_vec());
            self.close_escrow_signature = Some(escrow_sig_hex);
            self.close_merch_signature = Some(merch_sig_hex);
            self.channel_status = ChannelStatus::Initialized;
            Ok(true)
        } else {
            let s = String::from(
                "Could not verify the merchant signature on the initial closing transactions!",
            );
            Err(s)
        }
    }

    pub fn unmask_and_verify_transactions<N: BitcoinNetwork>(
        &mut self,
        channel_state: &ChannelMPCState,
        channel_token: &ChannelMPCToken,
        mask_bytes: MaskedTxMPCInputs,
    ) -> Result<bool, String> {
        let mut escrow_mask_bytes = mask_bytes.get_escrow_mask();
        let mut merch_mask_bytes = mask_bytes.get_merch_mask();

        if self.masked_outputs.get(&self.index).is_none() {
            return Err(String::from("could not find masked output"));
        }

        let mpc_out = self.masked_outputs.get(&self.index).unwrap();
        xor_in_place(&mut escrow_mask_bytes, &mpc_out.escrow_masked.0[..]);
        xor_in_place(&mut merch_mask_bytes, &mpc_out.merch_masked.0[..]);

        // if valid, output (s_{i+1}, CT_{i+1}, pay-token-{i+1})
        let (escrow_tx_preimage, merch_tx_preimage, _, _) =
            self.construct_close_transaction_preimage::<N>(channel_state, channel_token);
        // println!("Close-Escrow Tx preimage: {}", hex::encode(&escrow_tx_preimage));
        // println!("Close-Merch Tx preimage: {}", hex::encode(&merch_tx_preimage));

        let mut escrow_sig_vec = mask_bytes.r_escrow_sig.0.to_vec();
        escrow_sig_vec.append(&mut escrow_mask_bytes.to_vec());
        let escrow_sig_res = secp256k1::Signature::from_compact(&escrow_sig_vec.as_slice());
        if escrow_sig_res.is_err() {
            return Err(escrow_sig_res.err().unwrap().to_string());
        }
        let escrow_sig = escrow_sig_res.unwrap();
        // println!("Close from Escrow Signature: {}", &escrow_sig);

        let mut merch_sig_vec = mask_bytes.r_merch_sig.0.to_vec();
        merch_sig_vec.append(&mut merch_mask_bytes.to_vec());
        let merch_sig_res = secp256k1::Signature::from_compact(&merch_sig_vec.as_slice());
        if merch_sig_res.is_err() {
            return Err(merch_sig_res.err().unwrap().to_string());
        }
        let merch_sig = merch_sig_res.unwrap();
        // println!("Close from Merch Signature: {}", &merch_sig);

        let escrow_tx_hash = Sha256::digest(&Sha256::digest(&escrow_tx_preimage));
        let merch_tx_hash = Sha256::digest(&Sha256::digest(&merch_tx_preimage));

        // println!("Tx hash: {}", hex::encode(&escrow_tx_hash));
        let msg1 = secp256k1::Message::from_slice(&escrow_tx_hash).unwrap();
        let msg2 = secp256k1::Message::from_slice(&merch_tx_hash).unwrap();

        let secp = secp256k1::Secp256k1::verification_only();
        let ver_escrow = secp.verify(&msg1, &escrow_sig, &channel_token.pk_m);
        if ver_escrow.is_err() {
            return Err(format!(
                "Escrow tx signature failed: {}",
                ver_escrow.err().unwrap().to_string()
            ));
        }
        let ver_merch = secp.verify(&msg2, &merch_sig, &channel_token.pk_m);
        if ver_merch.is_err() {
            return Err(format!(
                "Merch tx signature failed: {}",
                ver_merch.err().unwrap().to_string()
            ));
        }
        let escrow_sig_hex = hex::encode(&escrow_sig.serialize_compact().to_vec());
        let merch_sig_hex = hex::encode(&merch_sig.serialize_compact().to_vec());
        self.close_escrow_signature = Some(escrow_sig_hex);
        self.close_merch_signature = Some(merch_sig_hex);
        Ok(true)
    }

    pub fn unmask_and_verify_pay_token(
        &mut self,
        pt_mask_bytes_in: [u8; 32],
        pt_mask_r: [u8; 16],
    ) -> bool {
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

        self.pay_tokens
            .insert(self.index, FixedSizeArray32(pt_mask_bytes));

        if self.channel_status == ChannelStatus::Activated {
            self.channel_status = ChannelStatus::Established;
        }
        return true;
    }

    pub fn customer_close<N: BitcoinNetwork>(
        &self,
        channel_state: &ChannelMPCState,
        channel_token: &ChannelMPCToken,
        from_escrow: bool,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let (escrow_tx_preimage, merch_tx_preimage, escrow_tx_params, merch_tx_params) =
            self.construct_close_transaction_preimage::<N>(channel_state, channel_token);
        let merch_pk = channel_token.pk_m.serialize().to_vec();
        let cust_sk = self.sk_c.0.to_vec();
        return generate_customer_close_tx_helper::<N>(
            &self.close_escrow_signature,
            &escrow_tx_preimage,
            &escrow_tx_params,
            &self.close_merch_signature,
            &merch_tx_preimage,
            &merch_tx_params,
            from_escrow,
            &merch_pk,
            &cust_sk,
        );
    }
}

fn compute_rev_lock_commitment(input: &[u8; 32], r: &[u8; 16]) -> [u8; 32] {
    let mut input_buf = Vec::new();
    input_buf.extend_from_slice(input);
    input_buf.extend_from_slice(r);
    return hash_to_slice(&input_buf);
}

fn xor_in_place(a: &mut [u8], b: &[u8]) {
    for (b1, b2) in a.iter_mut().zip(b.iter()) {
        *b1 ^= *b2;
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RevokedState {
    pub nonce: FixedSizeArray16,
    pub rev_lock_com: FixedSizeArray32,
    pub rev_lock: FixedSizeArray32,
    pub rev_secret: FixedSizeArray32,
    pub t: FixedSizeArray16,
}

impl RevokedState {
    pub fn new(
        nonce: [u8; NONCE_LEN],
        rev_lock_com: [u8; 32],
        rev_lock: [u8; 32],
        rev_secret: [u8; 32],
        t: [u8; 16],
    ) -> Self {
        RevokedState {
            nonce: FixedSizeArray16(nonce),
            rev_lock_com: FixedSizeArray32(rev_lock_com),
            rev_lock: FixedSizeArray32(rev_lock),
            rev_secret: FixedSizeArray32(rev_secret),
            t: FixedSizeArray16(t),
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
pub struct PayMaskMap {
    pub mask: FixedSizeArray32,
    pub r: FixedSizeArray16,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MerchCloseTx {
    cust_pk: String,
    bc: i64,
    bm: i64,
    fee_mc: i64,
    cust_sig: String,
    self_delay: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MerchantMPCState {
    id: String,
    pub pk_m: secp256k1::PublicKey,
    // pk_m
    sk_m: FixedSizeArray32,
    // sk_m - for escrow
    hmac_key: FixedSizeArray64,
    hmac_key_r: FixedSizeArray16,
    // key_com_r
    payout_sk: FixedSizeArray32,
    // for payout pub key
    pub payout_pk: secp256k1::PublicKey,
    dispute_sk: FixedSizeArray32,
    // for dispute pub key
    pub dispute_pk: secp256k1::PublicKey,
    // replace the following with a fast in-memory key-value DB
    pub activate_map: HashMap<String, State>,
    pub close_tx: HashMap<FixedSizeArray32, MerchCloseTx>,
    pub net_config: Option<NetworkConfig>,
    pub db_url: String,
}

impl MerchantMPCState {
    pub fn new<R: Rng>(
        csprng: &mut R,
        db_url: String,
        channel: &mut ChannelMPCState,
        id: String
    ) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let mut _sk_m = [0u8; 32];        
        csprng.fill_bytes(&mut _sk_m);

        // generate the signing keypair for the channel
        let sk_m = secp256k1::SecretKey::from_slice(&_sk_m).unwrap();
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
            sk_m: FixedSizeArray32(_sk_m),
            hmac_key: FixedSizeArray64::new(hmac_key_buf),
            hmac_key_r: FixedSizeArray16(key_com_r),
            payout_sk: FixedSizeArray32(_payout_sk),
            payout_pk: payout_pub_key,
            dispute_sk: FixedSizeArray32(_dispute_sk),
            dispute_pk: dispute_pub_key,
            activate_map: HashMap::new(),
            close_tx: HashMap::new(),
            net_config: None,
            db_url: db_url,
        }
    }

    pub fn load_external_wallet(&mut self, channel: &mut ChannelMPCState, merch_sk: [u8; 32], pay_sk: [u8; 32], disp_sk: [u8; 32]) -> Result<(), String> {
        let secp = secp256k1::Secp256k1::new();

        let sk_m = handle_error_util!(secp256k1::SecretKey::from_slice(&merch_sk));
        let payout_sk = handle_error_util!(secp256k1::SecretKey::from_slice(&pay_sk));
        let dispute_sk = handle_error_util!(secp256k1::SecretKey::from_slice(&disp_sk));

        let pk_m = secp256k1::PublicKey::from_secret_key(&secp, &sk_m);
        let payout_pk = secp256k1::PublicKey::from_secret_key(&secp, &payout_sk);
        let dispute_pk = secp256k1::PublicKey::from_secret_key(&secp, &dispute_sk);

        // update channel state accordingly
        channel.set_merchant_public_keys(payout_pk.clone(), dispute_pk.clone());

        // merch-pk
        self.sk_m = FixedSizeArray32(merch_sk);
        self.pk_m = pk_m;
        // closing pub key
        self.payout_sk = FixedSizeArray32(pay_sk);
        self.payout_pk = payout_pk;
        // dispute pub key
        self.dispute_sk = FixedSizeArray32(disp_sk);
        self.dispute_pk = dispute_pk;

        Ok(())
    }

    pub fn get_secret_key(&self) -> Vec<u8> {
        return self.sk_m.0.to_vec();
    }

    pub fn get_close_secret_key(&self) -> Vec<u8> {
        return self.payout_sk.0.to_vec();
    }

    pub fn get_dispute_secret_key(&self) -> Vec<u8> {
        return self.dispute_sk.0.to_vec();
    }

    pub fn activate_channel(
        &self,
        _db: &mut dyn StateDatabase,
        channel_token: &ChannelMPCToken,
        s0: &State,
    ) -> Result<[u8; 32], String> {

        // refer to the state stored inside ActivateBucket by the channel_id
        let channel_id = channel_token.compute_channel_id().unwrap();
        let channel_id_str = hex::encode(channel_id.to_vec());

        // check that s_0 is consistent with init phase before signing
        let s0_hash = s0.compute_hash();
        let init_state_hash = match self.activate_map.get(&channel_id_str) {
            Some(n) => n.compute_hash(),
            None => {
                return Err(String::from(
                    "activate_channel: could not find initial state given channel token",
                ));
            }
        };

        if s0_hash != init_state_hash {
            return Err(String::from(
                "activate_channel: initial state on activation does not match stored state",
            ));
        }

        // proceed to sign the initial state
        let key = self.hmac_key.get_bytes();
        let s_vec = s0.serialize_compact();
        let init_pay_token = hmac_sign(key, &s_vec);

        Ok(init_pay_token)
    }

    pub fn validate_channel_params(
        &mut self,
        db: &mut dyn StateDatabase,
        channel_token: &ChannelMPCToken,
        init_state: &InitCustState,
        init_state_hash: [u8; 32],
    ) -> Result<bool, String> {
        let channel_id = channel_token.compute_channel_id().unwrap();
        let channel_id_str = hex::encode(channel_id.to_vec());

        // check if pk_c
        let pk_c = match channel_token.pk_c {
            Some(pk) => pk,
            None => return Err(String::from("cannot validate channel token: pk_c not set")),
        };

        if pk_c != init_state.pk_c {
            return Err(String::from(
                "init state pk_c does not match channel token pk_c",
            ));
        }

        if channel_token.pk_m != self.pk_m {
            return Err(String::from(
                "channel token pk_m does not match merch state pk_m",
            ));
        }

        // cache prevout from escrow_txid and escrow_prevout
        let mut escrow_prevout = [0u8; 32];
        let mut merch_prevout = [0u8; 32];

        let mut escrow_txid_be = channel_token.escrow_txid.0.clone();
        escrow_txid_be.reverse();
        let mut merch_txid_be = channel_token.merch_txid.0.clone();
        merch_txid_be.reverse();

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
            escrow_txid: FixedSizeArray32(escrow_txid_be),
            escrow_prevout: FixedSizeArray32(escrow_prevout),
            merch_txid: FixedSizeArray32(merch_txid_be),
            merch_prevout: FixedSizeArray32(merch_prevout),
            min_fee: init_state.min_fee,
            max_fee: init_state.max_fee,
            fee_mc: init_state.fee_mc,
        };

        if init_state_hash != s0.compute_hash() {
            println!("state: {}", s0);
            return Err(String::from("initial state not well-formed"));
        }

        let nonce_hex_str = hex::encode(s0.get_nonce());

        self.activate_map.insert(channel_id_str, s0);
        db.update_unlink_set(&nonce_hex_str)?;

        Ok(true)
    }

    pub fn generate_pay_mask_commitment<R: Rng>(
        &mut self,
        csprng: &mut R,
        db: &mut dyn StateDatabase,
        _channel_state: &ChannelMPCState,
        nonce: [u8; NONCE_LEN],
        _rev_lock_com: [u8; 32],
        amount: i64,
    ) -> Result<[u8; 32], String> {
        let nonce_hex = hex::encode(nonce);

        // check if n_i in S_unlink and amount == 0. if so, proceed since this is the unlink protocol
        if amount == 0 && !db.is_member_unlink_set(&nonce_hex) {
            return Err(String::from(
                "can only run unlink with previously known nonce",
            ));
        }

        // if epsilon > 0, check if updated balance is above dust limit.
        // if amount > 0 && amount < channel_state.get_min_threshold() {
        //     // if check fails, abort and output an error
        //     return Err(String::from("epsilon below dust limit!"));
        // }

        // check if n_i not in S_spent
        if db.check_spent_map(&nonce_hex) {
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
        let paytoken_mask_com = hash_to_slice(&pay_mask_buf);

        // store pay_mask for use in mpc protocol later
        db.update_nonce_mask_map(&nonce_hex, pay_mask, pay_mask_r)?;

        Ok(paytoken_mask_com)
    }

    pub fn set_network_config(&mut self, net_config: NetworkConfig) {
        self.net_config = Some(net_config);
    }

    fn recompute_commitmment(&self, buf: &[u8; 32], r: &[u8; 16]) -> [u8; 32] {
        let mut input_buf = buf.to_vec();
        input_buf.extend_from_slice(r);
        return hash_to_slice(&input_buf);
    }

    // Merchant sign's the initial closing transaction (in the clear)
    pub fn sign_initial_closing_transaction<N: BitcoinNetwork>(
        &self,
        funding_tx: FundingTxInfo,
        rev_lock: [u8; 32],
        cust_pk: Vec<u8>,
        cust_close_pk: Vec<u8>,
        to_self_delay_be: [u8; 2],
        fee_cc: i64,
    ) -> (Vec<u8>, Vec<u8>) {
        let init_balance = funding_tx.init_cust_bal + funding_tx.init_merch_bal;
        let escrow_index = 0;
        let merch_index = 0;
        let mut escrow_txid_le = funding_tx.escrow_txid.0.clone();
        escrow_txid_le.reverse();
        let mut merch_txid_le = funding_tx.merch_txid.0.clone();
        merch_txid_le.reverse();

        let escrow_input =
            create_utxo_input(&escrow_txid_le, escrow_index, init_balance);
        let merch_input = create_utxo_input(&merch_txid_le, merch_index, init_balance);

        let pubkeys = ClosePublicKeys {
            cust_pk: cust_pk.clone(),
            merch_pk: self.pk_m.serialize().to_vec(),
            merch_close_pk: self.payout_pk.serialize().to_vec(),
            merch_disp_pk: self.dispute_pk.serialize().to_vec(),
            cust_close_pk: cust_close_pk.clone(),
            rev_lock: FixedSizeArray32(rev_lock),
        };

        let (escrow_tx_preimage, _, _) = create_cust_close_transaction::<N>(
            &escrow_input,
            &pubkeys,
            &to_self_delay_be,
            funding_tx.init_cust_bal,
            funding_tx.init_merch_bal,
            fee_cc,
            funding_tx.fee_mc,
            util::VAL_CPFP,
            true,
        );

        let (merch_tx_preimage, _, _) = create_cust_close_transaction::<N>(
            &merch_input,
            &pubkeys,
            &to_self_delay_be,
            funding_tx.init_cust_bal,
            funding_tx.init_merch_bal,
            fee_cc,
            funding_tx.fee_mc,
            util::VAL_CPFP,
            false,
        );

        // merchant generates signatures
        let sk_m = self.sk_m.0.to_vec();
        let m_private_key = get_private_key(&sk_m).unwrap();
        let escrow_cust_sig =
            generate_signature_for_multi_sig_transaction::<N>(&escrow_tx_preimage, &m_private_key)
                .unwrap();
        let merch_cust_sig =
            generate_signature_for_multi_sig_transaction::<N>(&merch_tx_preimage, &m_private_key)
                .unwrap();

        return (escrow_cust_sig, merch_cust_sig);
    }

    pub fn store_merch_close_tx(
        &mut self,
        escrow_txid_be: &Vec<u8>,
        cust_pk: &Vec<u8>,
        cust_bal_sats: i64,
        merch_bal_sats: i64,
        fee_mc: i64,
        to_self_delay_be: [u8; 2],
        cust_sig: &Vec<u8>,
    ) {
        let merch_close = MerchCloseTx {
            cust_pk: hex::encode(cust_pk),
            bc: cust_bal_sats,
            bm: merch_bal_sats,
            fee_mc,
            cust_sig: hex::encode(cust_sig),
            self_delay: hex::encode(to_self_delay_be),
        };

        let mut escrow_txid = [0u8; 32];
        escrow_txid.copy_from_slice(escrow_txid_be.as_slice());
        self.close_tx
            .insert(FixedSizeArray32(escrow_txid), merch_close);
    }

    pub fn get_closing_tx<N: BitcoinNetwork>(
        &self,
        escrow_txid: [u8; 32],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let escrow_txid = FixedSizeArray32(escrow_txid);
        let m = match self.close_tx.get(&escrow_txid) {
            Some(t) => t,
            None => {
                return Err(format!(
                    "could not find merch_close_tx for escrow_txid: {}",
                    hex::encode(escrow_txid.0)
                ));
            }
        };
        let cust_pk = handle_error_util!(hex::decode(&m.cust_pk));
        let merch_pk = self.pk_m.serialize().to_vec();
        let merch_close_pk = self.payout_pk.serialize().to_vec();
        let t = handle_error_util!(hex::decode(&m.self_delay));
        let mut to_self_delay = [0u8; 2];
        to_self_delay.copy_from_slice(t.as_slice());
        let cust_sig_and_len_byte = handle_error_util!(hex::decode(&m.cust_sig));

        // move forward to sign the transaction
        let (_, tx_params) = handle_error_util!(merchant_form_close_transaction(
            escrow_txid.0.to_vec(),
            cust_pk,
            merch_pk,
            merch_close_pk,
            m.bc,
            m.bm,
            m.fee_mc,
            util::VAL_CPFP,
            to_self_delay
        ));

        let sk = get_private_key(&self.sk_m.0.to_vec()).unwrap();
        let (signed_merch_close_tx, txid_be, _) = completely_sign_multi_sig_transaction::<N>(
            &tx_params,
            &cust_sig_and_len_byte,
            false,
            None,
            &sk,
        );
        let mut txid_le = txid_be.to_vec();
        txid_le.reverse();
        let signed_merch_close_tx = signed_merch_close_tx.to_transaction_bytes().unwrap();

        Ok((signed_merch_close_tx, txid_be.to_vec(), txid_le))
    }

    pub fn get_circuit_file(&self) -> *mut c_void {
        // Box<Circuit>
        let using_ag2pc = match env::var("AG2PC") {
            Ok(_s) => true,
            Err(_e) => false,
        };

        let circuit_file = match using_ag2pc {
            true => match env::var("ZK_DEPS_INSTALL") {
                Ok(s) => format!("{}{}", s, CIRCUIT_FILE),
                Err(e) => panic!("ZK_DEPS_INSTALL env not set: {}", e),
            },
            false => String::new(),
        };
        // println!("Circuit: {}", circuit_file);
        let cf_ptr = match using_ag2pc {
            true => {
                let cf_ptr = unsafe {
                    let c_str = CString::new(circuit_file).unwrap();
                    load_circuit_file(c_str.as_ptr() as *const i8)
                };
                cf_ptr
            }
            false => ptr::null_mut(),
        };
        return cf_ptr; // Box::new(Circuit { ptr: cf_ptr }
    }

    // for merchant side
    pub fn execute_mpc_context<R: Rng>(
        &mut self,
        csprng: &mut R,
        db: &mut dyn StateDatabase,
        channel_state: &ChannelMPCState,
        nonce: [u8; NONCE_LEN],
        rev_lock_com: [u8; 32],
        paytoken_mask_com: [u8; 32],
        amount: i64,
        circuit: *mut c_void
    ) -> Result<bool, String> {
        // // if epsilon > 0, check if acceptable (above dust limit).
        // if amount > 0 && amount < channel_state.get_min_threshold() {
        //     // if check fails, abort and output an error
        //     return Err(String::from("epsilon below dust limit!"));
        // }

        // check if n_i not in S_spent
        let nonce_hex = hex::encode(nonce);
        if db.check_spent_map(&nonce_hex) {
            return Err(format!("nonce {} has been spent already.", &nonce_hex));
        }

        // retrieve the paytoken_mask & randomness (based on the given nonce)
        let (pay_mask_bytes, pay_mask_r) = match db.get_mask_map_from_nonce(&nonce_hex) {
            Ok(n) => (n.0, n.1),
            Err(e) => return Err(e.to_string()),
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
        let merch_public_key_hash = compute_hash160(&pk_input_buf.to_vec());

        // retrieve network config details
        let net_conn = match self.net_config.clone() {
            Some(nc) => nc,
            None => {
                return Err(String::from(
                    "merchant::execute_mpc_context - net config not specified",
                ));
            }
        };

        // let cf_ptr = self.get_circuit_file();
        let sk_m = secp256k1::SecretKey::from_slice(&self.sk_m.0).unwrap();

        let (r_merch, r_esc) = mpc_build_masked_tokens_merch(
            csprng,
            net_conn,
            circuit,
            amount,
            &paytoken_mask_com,
            &rev_lock_com,
            &hmac_key_com,
            &self.hmac_key_r.0,
            merch_escrow_pub_key,
            self.dispute_pk,
            merch_public_key_hash,
            self.payout_pk,
            nonce,
            &hmac_key,
            sk_m,
            &merch_mask_bytes,
            &pay_mask_bytes,
            &pay_mask_r,
            &escrow_mask_bytes,
        );

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

        let nonce_hex = hex::encode(nonce);
        db.update_masked_mpc_inputs(&nonce_hex, mask_bytes);

        Ok(true)
    }

    pub fn verify_revoked_state(
        &mut self,
        db: &mut dyn StateDatabase,
        nonce: [u8; NONCE_LEN],
        rev_lock_com: [u8; 32],
        rev_lock: [u8; 32],
        rev_sec: [u8; 32],
        t: [u8; 16],
    ) -> Result<([u8; 32], [u8; 16]), String> {
        // check rev_lock_com opens to RL_i / t_i
        // check that RL_i is derived from RS_i
        if compute_rev_lock_commitment(&rev_lock, &t) != rev_lock_com
            || hash_to_slice(&rev_sec.to_vec()) != rev_lock
        {
            return Err(String::from(
                "rev_lock_com commitment did not open to specified rev_lock",
            ));
        }

        // retrieve masked bytes from rev_lock_com (output error, if not)
        let nonce_hex = hex::encode(nonce);
        let (pt_mask, pt_mask_r) = match db.get_masked_mpc_inputs(&nonce_hex) {
            Ok(n) => (n.pt_mask.0, n.pt_mask_r.0),
            _ => {
                return Err(String::from(
                    "could not retrieve pt_mask for specified rev_lock_com commitment",
                ));
            }
        };

        // verify that RL_i not in the S_spent
        let rev_lock_r = hex::encode(&rev_lock);
        if db.check_rev_lock_map(&rev_lock_r) {
            return Err(String::from(
                "attempting to revoke with a rev_lock that is already revoked",
            ));
        }

        let rev_sec_r = hex::encode(&rev_sec);
        // add (n_i, RL_i) to S_spent map
        db.update_spent_map(&nonce_hex, &rev_lock_r)?;
        // add (RL_i, RS_i) to RL map
        db.update_rev_lock_map(&rev_lock_r, &rev_sec_r)?;
        // check if n_i in the unlink map. if so, remove it
        if db.is_member_unlink_set(&nonce_hex) {
            // remove from unlink set
            assert!(db.remove_from_unlink_set(&nonce_hex));
        }

        Ok((pt_mask, pt_mask_r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use channels_mpc::{ChannelMPCState, CustomerMPCState, MerchantMPCState};
    use database::{MaskedMPCInputs, RedisDatabase};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use sha2::Digest;
    use sha2::Sha256;
    use zkchan_tx::Testnet;

    fn generate_test_txs<R: Rng>(
        csprng: &mut R,
        b0_cust: i64,
        b0_merch: i64,
        fee_mc: i64,
    ) -> FundingTxInfo {
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

        return FundingTxInfo {
            init_cust_bal: b0_cust,
            init_merch_bal: b0_merch,
            escrow_txid: FixedSizeArray32(escrow_txid),
            escrow_prevout: FixedSizeArray32(escrow_prevout),
            merch_txid: FixedSizeArray32(merch_txid),
            merch_prevout: FixedSizeArray32(merch_prevout),
            fee_mc: fee_mc,
            min_fee: 0,
            max_fee: 10000,
        };
    }

    rusty_fork_test! {
    #[test]
    fn mpc_channel_util_customer_works() {
        let mut channel_state = ChannelMPCState::new(String::from("Channel A <-> B"), 1487, 546, false);
        // let rng = &mut rand::thread_rng();
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d86);

        let b0_cust = 1000000;
        let b0_merch = 200000;
        let fee_cc = 1000;
        let fee_mc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let db_url = "redis://127.0.0.1/".to_string();
        let mut merch_state = MerchantMPCState::new(&mut rng, db_url, &mut channel_state, String::from("Merchant B"));
        let mut db = RedisDatabase::new("test1", merch_state.db_url.clone()).unwrap();
        db.clear_state();

        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerMPCState::new(&mut rng, b0_cust, b0_merch, fee_cc, String::from("Customer"));

        // // initialize the channel token on with pks
        // let mut channel_token = cust_state.generate_init_channel_token(&merch_state.pk_m);
        // generate and send initial state to the merchant
        // cust_state.generate_init_state(&mut rng, &mut channel_token, min_fee, max_fee, fee_mc);

        // initialize the channel token on with pks
        // generate and send initial state to the merchant
        let mut channel_token = cust_state.generate_init_state(&mut rng, &merch_state.pk_m, min_fee, max_fee, fee_mc);

        // at this point, cust/merch have both exchanged initial sigs (escrow-tx + merch-close-tx)
        let funding_tx_info = generate_test_txs(&mut rng, b0_cust, b0_merch, fee_mc);
        
        // set escrow-tx and merch-close-tx info
        cust_state.set_funding_tx_info(&mut channel_token, &funding_tx_info).unwrap();


        // activate - get initial state (which should include the funding tx info)
        let s_0 = cust_state.get_current_state();
        println!("s_0.Nonce => {}", hex::encode(&s_0.nonce.0));

        // retrieve the initial state from cust state
        let init_cust_state = cust_state.get_initial_cust_state().unwrap();

        // merchant validates the channel token and init cust state
        let v = merch_state.validate_channel_params(&mut db as &mut dyn StateDatabase, &channel_token, &init_cust_state, s_0.compute_hash());
        assert!(v.is_ok());

        println!("Begin activate phase for channel");
        println!("customer channel token: {}", &serde_json::to_string(&channel_token).unwrap());

        let r_com = cust_state.generate_rev_lock_commitment(&mut rng);
        println!("Initial state: {}", s_0);
        println!("Init rev_lock commitment => {:?}", r_com);

        // activate channel - generate pay_token
        let pay_token_0 = match merch_state.activate_channel(&mut db as &mut dyn StateDatabase, &channel_token, &s_0) {
            Ok(p) => p,
            Err(e) => panic!(e)
        };

        // at this point, should have the signed cust-close-txs
        // so can update channel status to Initialized
        cust_state.channel_status = ChannelStatus::Initialized;
        println!("Pay Token on s_0 => {:?}", pay_token_0);

        cust_state.store_initial_pay_token(pay_token_0).unwrap();

        // let (rev_lock, rev_secret) = cust_state.get_rev_pair();
        // let t = cust_state.get_randomness();

        let amount = 10000;

        cust_state.generate_new_state(&mut rng, amount);
        let s_1 = cust_state.get_current_state();
        println!("Updated state: {}", s_1);

        let pay_token_mask_com = merch_state.generate_pay_mask_commitment(&mut rng, &mut db as &mut dyn StateDatabase, &channel_state, s_0.get_nonce(), r_com.clone(), amount).unwrap();
        cust_state.update_pay_com(pay_token_mask_com);

        // cust_state.set_mpc_connect_type(2);
        cust_state.set_network_config(NetworkConfig { conn_type: 1, dest_ip: String::from("127.0.0.1"), dest_port: 12347, path: String::from("foobar"), peer_raw_fd: 0 });
        // prepare the customer inputs
        let s0 = s_0.clone();
        let s1 = s_1.clone();

        println!("hello, customer!");
        let circuit = cust_state.get_circuit_file();
        let res = cust_state.execute_mpc_context(&channel_state, &channel_token, s0, s1, fee_cc, pay_token_mask_com, r_com, amount, circuit);
        assert!(res.is_ok(), res.err().unwrap());

        println!("completed mpc execution!");

        // prepare the merchant inputs
        // let rev_lock_com = r_com.clone();
        // let nonce = s_0.get_nonce().clone();

        // let _mask_bytes = match merch_state.verify_revoked_state(&mut db as &mut dyn StateDatabase, nonce, rev_lock_com, rev_lock, rev_secret, t) {
        //     Ok(n) => Some(n),
        //     Err(e) => None
        // };
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

        let mask_bytes = Some(MaskedMPCInputs {
            pt_mask: FixedSizeArray32(pt_mask),
            escrow_mask: FixedSizeArray32(escrow_mask),
            pt_mask_r: FixedSizeArray16(pt_mask_r),
            merch_mask: FixedSizeArray32(merch_mask),
            r_escrow_sig: FixedSizeArray32(r_escrow_sig),
            r_merch_sig: FixedSizeArray32(r_merch_sig),
        });

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
            assert!(is_ok.is_ok(), is_ok.err().unwrap());

            let is_ok = cust_state.unmask_and_verify_pay_token(mb.pt_mask.0, mb.pt_mask_r.0);
            assert!(is_ok);

            let result = cust_state.customer_close::<Testnet>(&channel_state, &channel_token, true);
            assert!(result.is_ok(), result.err().unwrap());
            let (close_escrow_tx, close_escrow_txid_be, _) = result.unwrap();

            // output most recent closing tx
            println!("------------------------------------");
            println!("Cust-close from escrow tx ID: {}", hex::encode(close_escrow_txid_be));
            println!("Cust-close from escrow tx: {}", hex::encode(close_escrow_tx));
            let (close_merch_tx, close_merch_txid_be, _) = cust_state.customer_close::<Testnet>(&channel_state, &channel_token, false).unwrap();
            println!("------------------------------------");
            println!("Cust-close from merch tx ID: {}", hex::encode(close_merch_txid_be));
            println!("Cust-close from merch tx: {}", hex::encode(close_merch_tx));
            println!("------------------------------------");
        }
    }
    }

    rusty_fork_test! {
    #[test]
    fn mpc_channel_util_merchant_works() {
        let mut channel = ChannelMPCState::new(String::from("Channel A <-> B"), 1487, 546, false);
        // let rng = &mut rand::thread_rng();
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d86);
        let db_url = "redis://127.0.0.1/".to_string();

        let b0_cust = 1000000;
        let b0_merch = 200000;
        let fee_cc = 1000;
        let fee_mc = 1000;
        let min_fee = 0;
        let max_fee = 10000;

        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens

        // initialize on the merchant side with balance: b0_merch
        let mut merch_state =
            MerchantMPCState::new(&mut rng, db_url, &mut channel, String::from("Merchant"));
        let mut db = RedisDatabase::new("test1", merch_state.db_url.clone()).unwrap();
        db.clear_state();

        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerMPCState::new(
            &mut rng,
            b0_cust,
            b0_merch,
            fee_cc,
            String::from("Customer")
        );

        // initialize the channel token on with pks
        // generate and send initial state to the merchant
        let mut channel_token = cust_state.generate_init_state(&mut rng, &merch_state.pk_m, min_fee, max_fee, fee_mc);

        // at this point, cust/merch have both exchanged initial sigs (escrow-tx + merch-close-tx)
        let funding_tx_info = generate_test_txs(&mut rng, b0_cust, b0_merch, fee_mc);

        // set escrow-tx and merch-close-tx info
        cust_state
            .set_funding_tx_info(&mut channel_token, &funding_tx_info)
            .unwrap();
        // get initial state
        let s_0 = cust_state.get_current_state();

        // retrieve the initial state from cust state
        let init_cust_state = cust_state.get_initial_cust_state().unwrap();

        // validate the initial state with merchant
        let res = merch_state.validate_channel_params(
            &mut db as &mut dyn StateDatabase,
            &channel_token,
            &init_cust_state,
            s_0.compute_hash(),
        );
        assert!(res.is_ok(), res.err().unwrap());

        println!("Begin activate phase for channel");
        println!(
            "merchant channel token: {}",
            &serde_json::to_string(&channel_token).unwrap()
        );

        let r_com = cust_state.generate_rev_lock_commitment(&mut rng);

        println!("Initial state: {}", s_0);
        println!("Init rev_lock commitment => {:?}", hex::encode(&r_com));

        // activate channel - generate pay_token
        let pay_token_0 = match merch_state.activate_channel(
            &mut db as &mut dyn StateDatabase,
            &channel_token,
            &s_0,
        ) {
            Ok(p) => p,
            Err(e) => panic!(e),
        };

        // at this point, should have the signed cust-close-txs
        // so can update channel status to Initialized
        cust_state.channel_status = ChannelStatus::Initialized;
        println!("Pay Token on s_0 => {:?}", hex::encode(&pay_token_0));
        cust_state.store_initial_pay_token(pay_token_0).unwrap();

        let (rev_lock, rev_secret) = cust_state.get_rev_pair();
        let t = cust_state.get_randomness();

        let amount = 10000;

        cust_state.generate_new_state(&mut rng, amount);
        let s_1 = cust_state.get_current_state();
        println!("Updated state: {}", s_1);
        let pay_token_mask_com = merch_state
            .generate_pay_mask_commitment(
                &mut rng,
                &mut db as &mut dyn StateDatabase,
                &channel,
                s_0.get_nonce(),
                r_com.clone(),
                amount,
            )
            .unwrap();
        cust_state.update_pay_com(pay_token_mask_com);

        // merch_state.set_mpc_connect_type(2);
        merch_state.set_network_config(NetworkConfig {
            conn_type: 1,
            dest_ip: String::from("127.0.0.1"),
            dest_port: 12347,
            path: String::from("foobar"),
            peer_raw_fd: 0,
        });

        // prepare the merchant inputs
        let rev_lock_com = r_com.clone();
        let nonce = s_0.get_nonce().clone();

        println!("hello, merchant!");
        let circuit = merch_state.get_circuit_file(); // can be preloaded and cached
        let res = merch_state.execute_mpc_context(
            &mut rng,
            &mut db as &mut dyn StateDatabase,
            &channel,
            nonce,
            rev_lock_com,
            pay_token_mask_com,
            amount,
            circuit
        );
        assert!(res.is_ok(), res.err().unwrap());

        let (pt_mask, pt_mask_r) = merch_state
            .verify_revoked_state(
                &mut db as &mut dyn StateDatabase,
                nonce,
                rev_lock_com,
                rev_lock,
                rev_secret,
                t,
            )
            .unwrap();
        println!("pt_masked: {:?}", hex::encode(&pt_mask));
        println!("pt_mask_r: {:?}", hex::encode(&pt_mask_r));
    }
    }

    #[test]
    fn mpc_test_serialization() {
        let mut channel_state =
            ChannelMPCState::new(String::from("Channel A <-> B"), 1487, 546, false);
        let mut rng = XorShiftRng::seed_from_u64(0x8d863e545dbe6259);
        let db_url = "redis://127.0.0.1/".to_string();

        let b0_cust = 1000000;
        let b0_merch = 10000;
        let fee_cc = 1000;
        let fee_mc = 1000;

        let mut merch_state = MerchantMPCState::new(
            &mut rng,
            db_url,
            &mut channel_state,
            String::from("Merchant"),
        );

        let merch_sk = [1u8; 32];
        let pay_sk = [2u8; 32];
        let disp_sk = [3u8; 32];
        merch_state.load_external_wallet(&mut channel_state, merch_sk, pay_sk, disp_sk).unwrap();

        let mut db = RedisDatabase::new("test1", merch_state.db_url.clone()).unwrap();
        db.clear_state();

        let ser_merch_state = serde_json::to_string(&merch_state).unwrap();
        println!("Ser Merchant state: {}", ser_merch_state);
        let orig_merch_state: MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();
        assert_eq!(merch_state, orig_merch_state);

        let ser_channel_state = serde_json::to_string(&channel_state).unwrap();
        println!("Ser channel state: {}", ser_channel_state);

        let orig_channel_state: ChannelMPCState = serde_json::from_str(&ser_channel_state).unwrap();
        assert_eq!(channel_state, orig_channel_state);

        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerMPCState::new(
            &mut rng,
            b0_cust,
            b0_merch,
            fee_cc,
            String::from("Customer")
        );

        // initialize the channel token on with pks
        // generate and send initial state to the merchant
        let mut channel_token = cust_state.generate_init_state(&mut rng, &merch_state.pk_m, 0, 10000, fee_mc);

        let cust_sk = [4u8; 32];
        let pay_sk = [5u8; 32];
        cust_state.load_external_wallet(&mut channel_token, cust_sk, pay_sk).unwrap();
        // at this point, cust/merch have both exchanged initial sigs (escrow-tx + merch-close-tx)
        let funding_tx_info = generate_test_txs(&mut rng, b0_cust, b0_merch, fee_mc);

        // start activate phase
        let s_0 = cust_state.get_current_state();

        cust_state
            .set_funding_tx_info(&mut channel_token, &funding_tx_info)
            .unwrap();

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
