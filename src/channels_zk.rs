use super::*;
use channels_util::{ChannelStatus, ProtocolStatus};
use crypto::cl::{BlindKeyPair, Signature};
use crypto::nizk::{NIZKProof, NIZKPublicParams, NIZKSecretParams};
use pairing::Engine;
use crypto::ped92::{CSMultiParams, Commitment};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use util::{
    encode_short_bytes_to_fr, hash_pubkey_to_fr, hash_secret_to_fr, hash_to_fr, hash_to_slice,
};
use wallet::Wallet;
use zkchan_tx::fixed_size_array::FixedSizeArray16;
use extensions::extension::Extensions;

#[derive(Debug)]
pub struct BoltError {
    details: String,
}

pub type ResultBoltType<E> = Result<E, BoltError>;

impl BoltError {
    pub fn new(msg: &str) -> BoltError {
        BoltError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for BoltError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for BoltError {
    fn description(&self) -> &str {
        &self.details
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RevLockPair {
    pub rev_lock: FixedSizeArray32,
    pub rev_secret: FixedSizeArray32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct ChannelParams<E: Engine> {
    pub pub_params: NIZKPublicParams<E>,
    l: usize,
    // messages for commitment
    extra_verify: bool, // extra verification for certain points in the establish/pay protocol
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct ChannelState<E: Engine> {
    R: i32,
    tx_fee: i64,
    pub cp: Option<ChannelParams<E>>,
    pub name: String,
    pub pay_init: bool,
    // pub channel_status: ChannelStatus,
    pub third_party: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct ChannelToken<E: Engine> {
    pub pk_c: Option<secp256k1::PublicKey>,
    // pk_c
    pub pk_m: secp256k1::PublicKey,
    // pk_m
    pub cl_pk_m: crypto::cl::PublicKey<E>,
    // PK_m (used for verifying blind signatures)
    pub mpk: crypto::cl::PublicParams<E>,
    // mpk for PK_m
    pub comParams: CSMultiParams<E>,
}

impl<E: Engine> ChannelToken<E> {
    pub fn set_customer_pk(&mut self, pk_c: &secp256k1::PublicKey) {
        self.pk_c = Some(pk_c.clone());
    }

    pub fn is_init(&self) -> bool {
        return !self.pk_c.is_none();
    }

    pub fn compute_channel_id(&self) -> E::Fr
    where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as ff::ScalarEngine>::Fr: serde::Serialize,
    {
        if self.pk_c.is_none() {
            panic!("pk_c is not initialized yet");
        }
        let input = serde_json::to_vec(&self).unwrap();

        return hash_to_fr::<E>(input);
    }

    // add a method to compute hash on chain: SHA256 + RIPEMD160?
}

///
/// Channel state for generating/loading channel parameters and generating keypairs
///
impl<E: Engine> ChannelState<E> {
    pub fn new(name: String, third_party_support: bool) -> ChannelState<E> {
        ChannelState {
            R: 0,
            tx_fee: 0,
            cp: None,
            name: name.to_string(),
            pay_init: false,
            third_party: third_party_support,
        }
    }

    ///
    /// keygen - takes as input public parameters and generates a digital signature keypair
    ///
    pub fn keygen<R: Rng>(&mut self, csprng: &mut R, _id: String) -> crypto::cl::BlindKeyPair<E> {
        let cp = self.cp.as_ref();
        let keypair =
            BlindKeyPair::<E>::generate(csprng, &cp.unwrap().pub_params.mpk, cp.unwrap().l);
        // print the keypair as well
        return keypair;
    }

    pub fn load_params(&mut self, _cp: &ChannelParams<E>) {
        // load external params
    }

    pub fn set_channel_fee(&mut self, fee: i64) {
        self.tx_fee = fee;
    }

    pub fn get_channel_fee(&self) -> i64 {
        return self.tx_fee as i64;
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
struct WalletKeyPair {
    pub rev_lock: FixedSizeArray32,
    pub rev_secret: FixedSizeArray32,
}

///
/// Customer state
///
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct CustomerState<E: Engine> {
    pub name: String,
    pub pk_c: secp256k1::PublicKey,
    sk_c: secp256k1::SecretKey,
    pub cust_balance: i64,
    pub merch_balance: i64,
    pub nonce: FixedSizeArray16,
    pub rev_lock: FixedSizeArray32,
    rev_secret: FixedSizeArray32,
    // keypair bound to the wallet
    old_kp: Option<WalletKeyPair>,
    // old wallet key pair
    wallet: Wallet<E>,
    // vector of field elements that represent wallet
    pub coms: Option<Commitments<E>>,
    index: i32,
    close_tokens: HashMap<i32, Signature<E>>,
    pay_tokens: HashMap<i32, Signature<E>>,
    pub protocol_status: ProtocolStatus,
    channel_status: ChannelStatus,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct Commitments<E: Engine> {
    pub rl_com: Commitment<E>,
    rho: E::Fr,
    pub s_com: Commitment<E>,
    tau: E::Fr,
    pub s_bar_com: Commitment<E>,
    tau_bar: E::Fr,
}

impl<E: Engine> fmt::Display for Commitments<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut content = format!("rl_com = {}\n", &self.rl_com);
        content = format!("{}s_com = {}\n", content, &self.s_com);
        content = format!("{}s_bar_com = {}\n", content, &self.s_bar_com);

        write!(f, "Commitments : (\n{}\n)", &content)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct ClosedCommitments<E: Engine> {
    pub rl_com: Commitment<E>,
    pub s_com: Commitment<E>,
    pub s_bar_com: Commitment<E>,
}

impl<E: Engine> fmt::Display for ClosedCommitments<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut content = format!("rl_com = {}\n", &self.rl_com);
        content = format!("{}s_com = {}\n", content, &self.s_com);
        content = format!("{}s_bar_com = {}\n", content, &self.s_bar_com);

        write!(f, "Commitments : (\n{}\n)", &content)
    }
}

impl<E: Engine> CustomerState<E> {
    pub fn new<R: Rng>(
        csprng: &mut R,
        channel_token: &mut ChannelToken<E>,
        cust_bal: i64,
        merch_bal: i64,
        name: String,
    ) -> Self
    where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as ff::ScalarEngine>::Fr: serde::Serialize,
    {
        let secp = secp256k1::Secp256k1::new();

        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        // generate the signing keypair for the channel
        let sk_c = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let pk_c = secp256k1::PublicKey::from_secret_key(&secp, &sk_c);

        let mut seckey1 = [0u8; 32];
        csprng.fill_bytes(&mut seckey1);

        // generate the hash lock
        let mut rev_secret = [0u8; 32];
        csprng.fill_bytes(&mut rev_secret);

        // compute hash of the revocation secret
        let (rev_lock, rl) = hash_secret_to_fr::<E>(&rev_secret.to_vec());

        // generate the initial nonce
        let mut nonce_bytes = [0u8; 16];
        csprng.fill_bytes(&mut nonce_bytes);
        let nonce = encode_short_bytes_to_fr::<E>(nonce_bytes);

        // generate the keypair for the initial wallet
        // hash the wallet pub key
        channel_token.set_customer_pk(&pk_c);
        // compute the channel ID
        let channelId = channel_token.compute_channel_id();
        // initialize wallet vector
        let wallet = Wallet {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rl,
            bc: cust_bal,
            bm: merch_bal,
        };

        assert!(channel_token.is_init());

        let ct_db = HashMap::new();
        let pt_db = HashMap::new();

        return CustomerState {
            name: name,
            pk_c: pk_c,
            sk_c: sk_c,
            cust_balance: cust_bal,
            merch_balance: merch_bal,
            nonce: FixedSizeArray16(nonce_bytes),
            rev_lock: FixedSizeArray32(rev_lock),
            rev_secret: FixedSizeArray32(rev_secret),
            old_kp: None,
            wallet: wallet,
            coms: None,
            index: 0,
            close_tokens: ct_db,
            pay_tokens: pt_db,
            protocol_status: ProtocolStatus::New,
            channel_status: ChannelStatus::None,
        };
    }

    pub fn get_wallet(&self) -> Wallet<E> {
        return self.wallet.clone();
    }

    pub fn get_secret_key(&self) -> secp256k1::SecretKey {
        return self.sk_c.clone();
    }

    pub fn get_public_key(&self) -> E::Fr {
        // hash the channel pub key
        let pk_h = hash_pubkey_to_fr::<E>(&self.pk_c);
        return pk_h;
    }

    pub fn get_close_token(&self) -> crypto::cl::Signature<E> {
        let index = self.index;
        let close_token = self.close_tokens.get(&index).unwrap();
        // rerandomize first
        return close_token.clone();
    }

    pub fn verify_init_close_token(
        &mut self,
        channel: &ChannelState<E>,
        close_token: Signature<E>,
    ) -> bool {
        let close_wallet = self.wallet.as_fr_vec_bar();
        let cp = channel.cp.as_ref().unwrap();
        let mpk = cp.pub_params.mpk.clone();

        let is_close_valid =
            cp.pub_params
                .pk
                .get_pub_key()
                .verify(&mpk, &close_wallet, &close_token);
        if is_close_valid {
            self.close_tokens.insert(self.index, close_token);
            self.protocol_status = ProtocolStatus::Initialized;
            self.channel_status = ChannelStatus::PendingOpen;
        }

        return is_close_valid;
    }

    pub fn verify_close_token(
        &mut self,
        channel: &ChannelState<E>,
        close_token: &Signature<E>,
    ) -> bool {
        // add a prefix to the wallet for close-message
        let close_wallet = self.wallet.as_fr_vec_bar();
        let cp = channel.cp.as_ref().unwrap();
        let mpk = cp.pub_params.mpk.clone();
        //println!("verify_close_token - Wallet: {}", &self.wallet);

        let is_close_valid = cp.pub_params.pk.verify_blind(
            &mpk,
            &close_wallet,
            &self.coms.clone().unwrap().tau_bar,
            &close_token,
        );
        if is_close_valid {
            //println!("verify_close_token - Blinded close token is valid!!");
            let unblind_close_token = cp
                .pub_params
                .pk
                .unblind(&self.coms.clone().unwrap().tau_bar, &close_token);
            let pk = cp.pub_params.pk.get_pub_key();
            let is_valid = pk.verify(&mpk, &close_wallet, &unblind_close_token);
            if is_valid {
                // record the unblinded close token
                self.close_tokens.insert(self.index, unblind_close_token);
            }
            return is_valid;
        }

        //println!("Customer - Verification failed for close token!");
        return is_close_valid;
    }

    pub fn verify_init_pay_token(
        &mut self,
        channel: &ChannelState<E>,
        pay_token: Signature<E>,
    ) -> bool {
        // unblind and verify signature
        let cp = channel.cp.as_ref().unwrap();
        let mpk = cp.pub_params.mpk.clone();
        let wallet = self.wallet.as_fr_vec();

        let is_pay_valid = cp
            .pub_params
            .pk
            .get_pub_key()
            .verify(&mpk, &wallet, &pay_token);
        if is_pay_valid {
            self.pay_tokens.insert(self.index, pay_token);
        }

        return is_pay_valid;
    }

    pub fn unlink_verify_pay_token(
        &mut self,
        channel: &mut ChannelState<E>,
        pay_token: &Signature<E>,
    ) -> bool {
        let verified = self.pay_unmask_customer(channel, pay_token);
        if verified {
            // TODO:
            if self.protocol_status == ProtocolStatus::Activated {
                self.protocol_status = ProtocolStatus::Established;
            }
        }
        return verified;
    }

    pub fn pay_unmask_customer(
        &mut self,
        channel: &ChannelState<E>,
        pay_token: &Signature<E>,
    ) -> bool {
        // unblind and verify signature
        let cp = channel.cp.as_ref().unwrap();
        let mpk = cp.pub_params.mpk.clone();
        // we don't want to include "close" prefix here (even if it is set)
        let wallet = self.wallet.as_fr_vec();
        //println!("verify_pay_token - Wallet: {}", &self.wallet);

        let is_pay_valid = cp.pub_params.pk.verify_blind(
            &mpk,
            &wallet,
            &self.coms.clone().unwrap().tau,
            &pay_token,
        );
        if is_pay_valid {
            //println!("verify_pay_token - Blinded pay token is valid!!");
            let unblind_pay_token = cp
                .pub_params
                .pk
                .unblind(&self.coms.clone().unwrap().tau, &pay_token);
            let pk = cp.pub_params.pk.get_pub_key();
            let is_valid = pk.verify(&mpk, &wallet, &unblind_pay_token);
            if is_valid {
                self.pay_tokens.insert(self.index, unblind_pay_token);
            }
            return is_valid;
        }

        //println!("Customer - Verification failed for pay token!");
        return is_pay_valid;
    }

    pub fn has_tokens(&self) -> bool {
        let index = self.index;
        let is_pt = self.pay_tokens.get(&index).is_some();
        return self.has_init_close_token() && is_pt;
    }

    pub fn has_init_close_token(&self) -> bool {
        let index = self.index;
        return self.close_tokens.get(&index).is_some();
    }

    // for channel pay
    pub fn generate_payment<R: Rng>(
        &self,
        csprng: &mut R,
        channel: &ChannelState<E>,
        amount: i64,
    ) -> (
        NIZKProof<E>,
        ClosedCommitments<E>,
        FixedSizeArray16,
        FixedSizeArray32,
        CustomerState<E>,
    ) {
        // generate new hash lock
        let mut new_rev_secret = [0u8; 32];
        csprng.fill_bytes(&mut new_rev_secret);

        // compute hash of the revocation secret
        let (new_rev_lock, new_wallet_rl) = hash_secret_to_fr::<E>(&new_rev_secret.to_vec());

        // generate a new nonce
        let mut new_nonce = [0u8; 16];
        csprng.fill_bytes(&mut new_nonce);
        let new_wallet_nonce = encode_short_bytes_to_fr::<E>(new_nonce);

        // 2 - form new wallet and commitment
        let new_cust_bal = self.cust_balance - amount;
        let new_merch_bal = self.merch_balance + amount;
        let new_rho = E::Fr::rand(csprng);
        let new_tau = E::Fr::rand(csprng);
        let new_tau_bar = E::Fr::rand(csprng);

        let cp = channel.cp.as_ref().unwrap();
        let old_wallet = Wallet {
            channelId: self.wallet.channelId.clone(),
            nonce: self.wallet.nonce.clone(),
            rev_lock: self.wallet.rev_lock.clone(),
            bc: self.cust_balance,
            bm: self.merch_balance,
        };
        let new_wallet = Wallet {
            channelId: self.wallet.channelId.clone(),
            nonce: new_wallet_nonce,
            rev_lock: new_wallet_rl,
            bc: new_cust_bal,
            bm: new_merch_bal,
        };

        let new_rl_com = cp
            .pub_params
            .comParams
            .commit(&vec![self.wallet.rev_lock], &new_rho);
        let new_s_com = cp
            .pub_params
            .comParams
            .commit(&new_wallet.as_fr_vec(), &new_tau);
        let new_s_bar_com = cp
            .pub_params
            .comParams
            .commit(&new_wallet.as_fr_vec_bar(), &new_tau_bar);

        // 3 - generate new blinded and randomized pay token
        let i = self.index;
        let prev_pay_token = self.pay_tokens.get(&i).unwrap();
        //println!("Found prev pay token: {}", prev_pay_token);

        let pay_proof = cp.pub_params.prove(
            csprng,
            old_wallet,
            new_wallet.clone(),
            new_s_com.clone(),
            new_rho,
            new_tau,
            new_tau_bar,
            &prev_pay_token,
        );

        // update internal state after proof has been verified by remote
        let new_cw = CustomerState {
            name: self.name.clone(),
            pk_c: self.pk_c.clone(),
            sk_c: self.sk_c.clone(),
            cust_balance: new_cust_bal,
            merch_balance: new_merch_bal,
            nonce: FixedSizeArray16(new_nonce),
            rev_lock: FixedSizeArray32(new_rev_lock),
            rev_secret: FixedSizeArray32(new_rev_secret),
            old_kp: Some(WalletKeyPair {
                rev_lock: self.rev_lock.clone(),
                rev_secret: self.rev_secret.clone(),
            }),
            wallet: new_wallet.clone(),
            coms: Some(Commitments {
                rl_com: new_rl_com.clone(),
                rho: new_rho,
                s_com: new_s_com.clone(),
                tau: new_tau,
                s_bar_com: new_s_bar_com.clone(),
                tau_bar: new_tau_bar,
            }),
            index: self.index, // increment index here
            close_tokens: self.close_tokens.clone(),
            pay_tokens: self.pay_tokens.clone(),
            protocol_status: self.protocol_status.clone(),
            channel_status: self.channel_status.clone(),
        };

        let commitments = ClosedCommitments {
            rl_com: new_rl_com,
            s_com: new_s_com,
            s_bar_com: new_s_bar_com,
        };
        return (
            pay_proof,
            commitments,
            self.nonce.clone(),
            self.rev_lock.clone(),
            new_cw,
        );
    }

    // update the internal state of the customer wallet
    pub fn update(&mut self, new_wallet: CustomerState<E>) -> bool {
        // update everything except for the rev_lock/rev_secret pair
        assert!(self.name == new_wallet.name);
        self.cust_balance = new_wallet.cust_balance;
        self.merch_balance = new_wallet.merch_balance;
        self.old_kp = new_wallet.old_kp;
        self.nonce = new_wallet.nonce;
        self.rev_lock = new_wallet.rev_lock;
        self.rev_secret = new_wallet.rev_secret;
        self.coms = new_wallet.coms;
        self.wallet = new_wallet.wallet;
        self.index = new_wallet.index;
        self.close_tokens = new_wallet.close_tokens;
        self.pay_tokens = new_wallet.pay_tokens;

        return true;
    }

    pub fn get_old_rev_lock_pair(
        &mut self,
        channel: &ChannelState<E>,
        close_token: &Signature<E>,
    ) -> ResultBoltType<(FixedSizeArray32, FixedSizeArray32)> {
        if self.verify_close_token(channel, close_token) {
            let old_wallet = self.old_kp.unwrap();
            return Ok((old_wallet.rev_lock, old_wallet.rev_secret));
        }

        Err(BoltError::new(
            "get_old_rev_lock_pair - could not verify the close token.",
        ))
    }
}

impl<E: Engine> fmt::Display for CustomerState<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut content = format!("id = {}\n", &self.name);
        content = format!("{}pk = {}\n", content, &self.pk_c);
        content = format!("{}sk = {}\n", content, &self.sk_c);
        content = format!("{}cust-bal = {}\n", content, &self.cust_balance);
        content = format!("{}merch-bal = {}\n", content, &self.merch_balance);
        content = format!("{}nonce = {}\n", content, &self.nonce);
        content = format!(
            "{}rev_lock = {}\nrev_secret = {}\n",
            content, &self.rev_lock, &self.rev_secret
        );
        if self.old_kp.is_some() {
            let old_kp = self.old_kp.unwrap();
            content = format!(
                "{}revoked: rev_lock = {}\nrevoked: rev_secret = {}\n",
                content, &old_kp.rev_lock, &old_kp.rev_secret
            );
        }
        content = format!("{}wallet = {}\n", content, &self.wallet);
        if self.coms.is_some() {
            content = format!("{}coms = {}\n", content, &self.coms.clone().unwrap());
        }
        let close_token = self.close_tokens.get(&self.index);
        let pay_token = self.pay_tokens.get(&self.index);
        if close_token.is_some() {
            content = format!(
                "{}close_token = {}\n",
                content,
                &self.close_tokens.get(&self.index).unwrap()
            );
        }
        if pay_token.is_some() {
            content = format!(
                "{}pay_token = {}\n",
                content,
                &self.pay_tokens.get(&self.index).unwrap()
            );
        }
        write!(f, "CustomerState : (\n{}\n)", &content)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelcloseM {
    pub address: String,
    pub revoke: Option<secp256k1::Signature>,
    pub signature: secp256k1::Signature,
}

///
/// Merchant State
///
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct MerchantState<E: Engine> {
    id: String,
    keypair: crypto::cl::BlindKeyPair<E>,
    nizkParams: NIZKSecretParams<E>,
    pk: secp256k1::PublicKey,
    // pk_m
    sk: secp256k1::SecretKey,
    // sk_m
    comParams: CSMultiParams<E>,
    pub keys: HashMap<String, String>,
    pub unlink_nonces: HashSet<String>,
    pub spent_nonces: HashSet<String>,
    pub pay_tokens: HashMap<String, crypto::cl::Signature<E>>,
    extensions: HashMap<String, Extensions>,
}

impl<E: Engine> MerchantState<E> {
    pub fn new<R: Rng>(
        csprng: &mut R,
        channel: &mut ChannelState<E>,
        id: String,
    ) -> (Self, ChannelState<E>) {
        let l = 5;
        // generate keys
        let secp = secp256k1::Secp256k1::new();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);
        let rev_wsk = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let rev_wpk = secp256k1::PublicKey::from_secret_key(&secp, &rev_wsk);

        let mut ch = channel.clone();
        let nizkParams = NIZKSecretParams::<E>::setup(csprng, l);
        ch.cp = Some(ChannelParams::<E> {
            pub_params: nizkParams.pubParams.clone(),
            l,
            extra_verify: true,
        });

        (
            MerchantState {
                id: id.clone(),
                keypair: nizkParams.keypair.clone(),
                nizkParams: nizkParams.clone(),
                pk: rev_wpk,
                sk: rev_wsk,
                comParams: nizkParams.pubParams.comParams.clone(),
                keys: HashMap::new(), // store rev_locks/revoke_tokens
                unlink_nonces: HashSet::new(),
                spent_nonces: HashSet::new(),
                pay_tokens: HashMap::new(),
                extensions: HashMap::new(),
            },
            ch,
        )
    }

    pub fn init(&mut self, channel: &mut ChannelState<E>) -> ChannelToken<E> {
        let cp = channel.cp.as_ref().unwrap(); // if not set, then panic!
        let mpk = cp.pub_params.mpk.clone();
        let cl_pk = self.keypair.get_public_key(&mpk);

        return ChannelToken {
            pk_c: None,
            cl_pk_m: cl_pk.clone(), // extract the regular public key
            pk_m: self.pk.clone(),
            mpk: mpk,
            comParams: self.comParams.clone(),
        };
    }

    pub fn issue_close_token<R: Rng>(
        &self,
        csprng: &mut R,
        cp: &ChannelParams<E>,
        com: &Commitment<E>,
    ) -> Signature<E> {
        return self
            .keypair
            .sign_blind(csprng, &cp.pub_params.mpk, com.clone());
    }

    pub fn issue_pay_token<R: Rng>(
        &self,
        csprng: &mut R,
        cp: &ChannelParams<E>,
        com: &Commitment<E>,
    ) -> Signature<E> {
        //println!("com for pay-token: {}", &pay_com);
        return self
            .keypair
            .sign_blind(csprng, &cp.pub_params.mpk, com.clone());
    }

    pub fn issue_init_close_token<R: Rng>(
        &self,
        csprng: &mut R,
        init_state: &Wallet<E>,
    ) -> Signature<E> {
        self.keypair.sign(csprng, &init_state.as_fr_vec_bar())
    }

    pub fn issue_init_pay_token<R: Rng>(
        &self,
        csprng: &mut R,
        init_state: &Wallet<E>,
    ) -> Signature<E> {
        self.keypair.sign(csprng, &init_state.as_fr_vec())
    }

    fn store_rev_lock_with_token(&mut self, rev_lock: &FixedSizeArray32, pay_token: Signature<E>) {
        // convert rev_lock into hex string
        let rev_lock_str = hex::encode(rev_lock.0);
        self.pay_tokens.insert(rev_lock_str, pay_token);
    }

    fn get_pay_token(&self, rev_lock: &[u8; 32]) -> Signature<E> {
        let rev_lock_str = hex::encode(&rev_lock);
        return self.pay_tokens.get(&rev_lock_str).unwrap().clone();
    }

    pub fn verify_payment<R: Rng>(
        &mut self,
        csprng: &mut R,
        channel: &ChannelState<E>,
        proof: &NIZKProof<E>,
        coms: &ClosedCommitments<E>,
        nonce: &FixedSizeArray16,
        rev_lock: &FixedSizeArray32,
        amount: i64,
    ) -> ResultBoltType<Signature<E>> {
        let cp = channel.cp.as_ref().unwrap();
        let pay_proof = proof.clone();
        let prev_nonce = encode_short_bytes_to_fr::<E>(nonce.0);
        let epsilon = util::convert_int_to_fr::<E>(amount);

        if self.nizkParams.verify(pay_proof, epsilon, coms, prev_nonce) {
            // 1 - proceed with generating close and pay token
            let close_token = self.issue_close_token(csprng, cp, &coms.s_bar_com);
            let pay_token = self.issue_pay_token(csprng, cp, &coms.s_com);
            // let's store the pay token with the rev_lock for now
            self.store_rev_lock_with_token(rev_lock, pay_token);
            return Ok(close_token);
        }
        Err(BoltError::new(
            "verify_payment - Failed to validate NIZK PoK for payment.",
        ))
    }

    pub fn verify_revoke_message(
        &self,
        rev_lock: &FixedSizeArray32,
        rev_secret: &FixedSizeArray32,
    ) -> ResultBoltType<Signature<E>> {
        let rl = rev_lock.0;
        let rs = rev_secret.0.to_vec();
        if hash_to_slice(&rs) != rl {
            return Err(BoltError::new(
                // "rev_lock_com commitment did not open to specified rev_lock",
                "verify_revoke_message - Failed to verify the rev_lock/rev_secret pair!",
            ));
        }

        let new_pay_token = self.get_pay_token(&rl);
        return Ok(new_pay_token);
    }

    // pub fn sign_revoke_message(
    //     &self,
    //     address: String,
    //     revoke_token: &Option<secp256k1::Signature>,
    // ) -> ChannelcloseM {
    //     let secp = secp256k1::Secp256k1::signing_only();
    //     let mut msg = Vec::new();
    //     msg.extend(address.as_bytes());
    //     if !revoke_token.is_none() {
    //         let r = revoke_token.unwrap().serialize_der().to_vec();
    //         msg.extend(r);
    //     }
    //     let msg2 = secp256k1::Message::from_slice(&hash_to_slice(&msg)).unwrap();
    //     let merch_sig = secp.sign(&msg2, &self.sk);
    //     return ChannelcloseM {
    //         address: address.clone(),
    //         revoke: revoke_token.clone(),
    //         signature: merch_sig,
    //     };
    // }

    pub fn get_ext(&mut self, session_id: FixedSizeArray16) -> Option<&Extensions> {
        self.extensions.get(session_id.to_string().as_str())
    }

    pub fn store_ext(&mut self, session_id: FixedSizeArray16, ext: Extensions) {
        self.extensions.insert(session_id.to_string(), ext);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;
    use pairing::bn256::Bn256;

    #[test]
    fn channel_util_works_with_Bls12() {
        let mut channel = ChannelState::<Bls12>::new(String::from("Channel A <-> B"), false);
        let rng = &mut rand::thread_rng();

        let b0_cust = 100;
        let b0_merch = 20;
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let (mut merch_state, mut channel) =
            MerchantState::<Bls12>::new(rng, &mut channel, String::from("Merchant B"));

        // initialize the merchant wallet with the balance
        let mut channel_token = merch_state.init(&mut channel);

        // retrieve commitment setup params (using merchant long lived pk params)
        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerState::<Bls12>::new(
            rng,
            &mut channel_token,
            b0_cust,
            b0_merch,
            String::from("Alice"),
        );

        // first return the close token, then wait for escrow-tx confirmation
        // then send the pay-token after confirmation
        let channelId = channel_token.compute_channel_id();
        assert_eq!(channelId, cust_state.get_wallet().channelId);
        let close_token = merch_state.issue_init_close_token(rng, &cust_state.get_wallet());
        // unblind tokens and verify signatures
        assert!(cust_state.verify_init_close_token(&channel, close_token));

        let pay_token = merch_state.issue_init_pay_token(rng, &cust_state.get_wallet());
        assert!(cust_state.verify_init_pay_token(&channel, pay_token));

        println!("Done!");

        // pay protocol tests
        let amount = 10;
        let (pay_proof, new_com, old_nonce, old_rev_lock, new_cw) =
            cust_state.generate_payment(rng, &channel, amount);

        // new pay_token is not sent until revoke_token is obtained from the customer
        let new_close_token = merch_state
            .verify_payment(
                rng,
                &channel,
                &pay_proof,
                &new_com,
                &old_nonce,
                &old_rev_lock,
                amount,
            )
            .unwrap();

        //println!("1 -  Updated close Token : {}", new_close_token);
        // unblind tokens and verify signatures

        // assuming the pay_proof checks out, can go ahead and update internal state of cust_state
        assert!(cust_state.update(new_cw));
        //println!("2 - updated customer wallet!");

        assert!(cust_state.verify_close_token(&channel, &new_close_token));
        //println!("3 - verified the close token!");

        // invalidate the previous state only if close token checks out
        let (rev_lock, rev_secret) = cust_state
            .get_old_rev_lock_pair(&channel, &new_close_token)
            .unwrap();
        //println!("4 - Generated revoke token successfully.");

        //println!("5 - Revoke token => {}", revoke_token);

        let new_pay_token = merch_state
            .verify_revoke_message(&rev_lock, &rev_secret)
            .unwrap();
        assert!(cust_state.pay_unmask_customer(&channel, &new_pay_token));

        //println!("Validated revoke token!");
    }

    #[test]
    #[should_panic(expected = "pk_c is not initialized yet")]
    fn compute_channel_id_panics() {
        let mut channel = ChannelState::<Bls12>::new(String::from("Channel A <-> B"), false);
        let rng = &mut rand::thread_rng();

        // initialize on the merchant side with balance: b0_merch
        let (mut merch_state, mut channel) =
            MerchantState::<Bls12>::new(rng, &mut channel, String::from("Merchant B"));

        // initialize the merchant wallet with the balance
        let channel_token = merch_state.init(&mut channel);

        let _channelId = channel_token.compute_channel_id();
    }

    #[test]
    fn channel_util_works_with_Bn256() {
        let mut channel = ChannelState::<Bn256>::new(String::from("Channel A <-> B"), false);
        let rng = &mut rand::thread_rng();

        let b0_cust = 100;
        let b0_merch = 20;
        // each party executes the init algorithm on the agreed initial challenge balance
        // in order to derive the channel tokens
        // initialize on the merchant side with balance: b0_merch
        let (mut merch_state, mut channel) =
            MerchantState::<Bn256>::new(rng, &mut channel, String::from("Merchant B"));

        // initialize the merchant wallet with the balance
        let mut channel_token = merch_state.init(&mut channel);

        // retrieve commitment setup params (using merchant long lived pk params)
        // initialize on the customer side with balance: b0_cust
        let mut cust_state = CustomerState::<Bn256>::new(
            rng,
            &mut channel_token,
            b0_cust,
            b0_merch,
            String::from("Alice"),
        );

        // first return the close token, then wait for escrow-tx confirmation
        // then send the pay-token after confirmation
        let channelId = channel_token.compute_channel_id();
        assert_eq!(channelId, cust_state.get_wallet().channelId);
        let close_token = merch_state.issue_init_close_token(rng, &cust_state.get_wallet());
        // unblind tokens and verify signatures
        assert!(cust_state.verify_init_close_token(&channel, close_token));

        let pay_token = merch_state.issue_init_pay_token(rng, &cust_state.get_wallet());
        assert!(cust_state.verify_init_pay_token(&channel, pay_token));

        // pay protocol tests
        let amount = 10;
        let (pay_proof, new_com, old_nonce, old_rev_lock, new_cw) =
            cust_state.generate_payment(rng, &channel, amount);

        // new pay_token is not sent until revoke_token is obtained from the customer
        let new_close_token = merch_state
            .verify_payment(
                rng,
                &channel,
                &pay_proof,
                &new_com,
                &old_nonce,
                &old_rev_lock,
                amount,
            )
            .unwrap();

        //println!("1 -  Updated close Token : {}", new_close_token);
        // unblind tokens and verify signatures

        // assuming the pay_proof checks out, can go ahead and update internal state of cust_state
        assert!(cust_state.update(new_cw));
        //println!("2 - updated customer wallet!");

        assert!(cust_state.verify_close_token(&channel, &new_close_token));
        //println!("3 - verified the close token!");

        // invalidate the previous state only if close token checks out
        let (rev_lock, rev_secret) = cust_state
            .get_old_rev_lock_pair(&channel, &new_close_token)
            .unwrap();
        //println!("4 - Generated revoke token successfully.");

        //println!("5 - Revoke token => {}", revoke_token);

        let new_pay_token = merch_state
            .verify_revoke_message(&rev_lock, &rev_secret)
            .unwrap();
        assert!(cust_state.pay_unmask_customer(&channel, &new_pay_token));

        //println!("Validated revoke token!");
    }
}
