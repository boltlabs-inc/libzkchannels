use super::*;
use cl;
use pairing::Engine;
use rand::Rng;
use wallet;
// for blind signature
use secp256k1;
// for on-chain keys
use HashMap;

use channels_util::{ChannelStatus, PaymentStatus, ProtocolStatus};
use channels_zk::ClosedCommitments;
pub use channels_zk::{
    BoltError, ChannelParams, ChannelState, ChannelToken, ChannelcloseM, CustomerState,
    MerchantState, ResultBoltType, RevLockPair,
};
pub use cl::PublicParams;
pub use cl::{PublicKey, Signature};
pub use nizk::NIZKProof;
pub use ped92::Commitment;
pub use ped92::CommitmentProof;
use serde::{Deserialize, Serialize};
use util::{encode_short_bytes_to_fr, hash_to_slice};
pub use wallet::{serialize_compact, Wallet};
use zkchan_tx::fixed_size_array::{FixedSizeArray16, FixedSizeArray32};

////////////////////////////////// Utilities //////////////////////////////////

pub type BoltResult<T> = Result<Option<T>, String>;

#[macro_export]
macro_rules! handle_bolt_result {
    ($e:expr) => {
        match $e {
            Ok(val) => val,
            Err(_) => None,
        }
    };
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionFeeInfo {
    pub bal_min_cust: i64,
    pub bal_min_merch: i64,
    pub fee_cc: i64,
    pub fee_mc: i64,
}

impl fmt::Display for TransactionFeeInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TransactionFees : (\nbal_min_cust={}\nbal_min_merch={}\nfee_cc={}\nfee_mc={}\n)",
            self.bal_min_cust, self.bal_min_merch, self.fee_cc, self.fee_mc
        )
    }
}

////////////////////////////////// Utilities //////////////////////////////////

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                            <E as pairing::Engine>::G1: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                            <E as pairing::Engine>::G1: serde::Deserialize<'de>")
)]
pub struct ChannelcloseC<E: Engine> {
    pub rev_lock: FixedSizeArray32,
    pub message: wallet::Wallet<E>,
    pub merch_signature: cl::Signature<E>,
    pub cust_signature: secp256k1::Signature,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                            <E as pairing::Engine>::G1: serde::Serialize, \
                            <E as pairing::Engine>::G2: serde::Serialize, \
                            <E as pairing::Engine>::Fqk: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                            <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                            <E as pairing::Engine>::G2: serde::Deserialize<'de>,\
                            <E as pairing::Engine>::Fqk: serde::Deserialize<'de>")
)]
pub struct Payment<E: Engine> {
    proof: NIZKProof<E>,
    coms: ClosedCommitments<E>,
    nonce: FixedSizeArray16,
    rev_lock: FixedSizeArray32,
    amount: i64,
}

///
/// merchant_init - takes as input the public params, merchant balance and keypair.
/// Generates merchant data which consists of channel token and merchant state.
///
pub fn merchant_init<'a, R: Rng, E: Engine>(
    csprng: &mut R,
    channel_state: &mut ChannelState<E>,
    name: &'a str,
) -> (ChannelToken<E>, MerchantState<E>, ChannelState<E>) {
    // create new merchant state
    let merch_name = String::from(name);
    let (mut merch_state, mut channel_state) =
        MerchantState::<E>::new(csprng, channel_state, merch_name);
    // initialize the merchant state
    let channel_token = merch_state.init(&mut channel_state);

    return (channel_token, merch_state, channel_state.clone());
}

///
/// customer_init - takes as input the public params, channel state, commitment params, keypair,
/// and initial balance for customer and merchant. Generate initial customer channel token,
/// and wallet commitment.
///
pub fn customer_init<'a, R: Rng, E: Engine>(
    csprng: &mut R,
    channel_token: &mut ChannelToken<E>,
    b0_cust: i64,
    b0_merch: i64,
    name: &'a str,
) -> CustomerState<E>
where
    <E as pairing::Engine>::G1: serde::Serialize,
    <E as pairing::Engine>::G2: serde::Serialize,
    <E as ff::ScalarEngine>::Fr: serde::Serialize,
{
    assert!(b0_cust >= 0);
    assert!(b0_merch >= 0);

    let cust_name = String::from(name);
    return CustomerState::<E>::new(csprng, channel_token, b0_cust, b0_merch, cust_name);
}

///
/// get_initial_state() - takes as input the customer state.
/// Prepares to activate the channel for the customer (call activate_customer_finalize to finalize activation)
/// output: initial state
///
pub fn get_initial_state<E: Engine>(cust_state: &CustomerState<E>) -> Wallet<E> {
    return cust_state.get_wallet();
}

///
/// validate_channel_params (Phase 1) - takes as input the channel state,
/// the initial values from the customer. Generates close token (a
/// signature) over the contents of the customer's wallet.
///
pub fn validate_channel_params<R: Rng, E: Engine>(
    csprng: &mut R,
    init_state: &Wallet<E>,
    merch_state: &MerchantState<E>,
) -> cl::Signature<E> {
    merch_state.issue_init_close_token(csprng, init_state)
}

///
/// customer_mark_open_channel() - changes channel status in customer state
///
pub fn customer_mark_open_channel<E: Engine>(
    init_close_token: cl::Signature<E>,
    channel_state: &mut ChannelState<E>,
    cust_state: &mut CustomerState<E>,
) -> Result<bool, BoltError> {
    let is_init_ct_valid = cust_state.verify_init_close_token(&channel_state, init_close_token);
    return Ok(is_init_ct_valid);
}

///
/// merchant_mark_open_channel() - changes channel status for a given escrow-txid.
/// fails if not in pending open state and assumes escrow-txid has been broadcast on chain
///
pub fn merchant_mark_open_channel<E: Engine>(
    _escrow_txid_le: [u8; 32],
    _merch_state: &mut MerchantState<E>,
) -> Result<bool, BoltError> {
    // TODO: look up the channel state for specified escrow tx
    return Ok(true);
}

pub mod activate {
    use super::*;

    ///
    /// activate::customer_init() - takes as input the customer state and confirm that.
    /// Prepares to activate the channel for the customer (call activate_customer_finalize to finalize activation)
    /// output: initial state
    ///
    pub fn customer_init<E: Engine>(cust_state: &CustomerState<E>) -> Result<Wallet<E>, BoltError> {
        // verify channel can be activated first (e.g., if customer has init close token)
        let init_close_token = cust_state.has_init_close_token();
        if init_close_token && cust_state.protocol_status == ProtocolStatus::Initialized {
            return Ok(cust_state.get_wallet());
        }
        return Err(BoltError::new("activate::customer_init - failed either due to not having an initial close token or channel is not yet initialized."));
    }

    ///
    /// activate::merchant_init() - takes as input the channel state,
    /// the commitment from the customer. Generates close token (a blinded
    /// signature) over the contents of the customer's wallet.
    ///
    pub fn merchant_init<R: Rng, E: Engine>(
        csprng: &mut R,
        init_state: &Wallet<E>,
        merch_state: &mut MerchantState<E>,
    ) -> cl::Signature<E> {
        merch_state
            .unlink_nonces
            .insert(init_state.nonce.to_string());
        merch_state.issue_init_pay_token(csprng, init_state)
    }

    ///
    /// activate::customer_finalize() - takes as input the channel state, customer state,
    /// and pay token (blinded sig) obtained from merchant. Add the returned
    /// blinded signature to the wallet.
    ///
    pub fn customer_finalize<E: Engine>(
        channel_state: &mut ChannelState<E>,
        cust_state: &mut CustomerState<E>,
        pay_token: cl::Signature<E>,
    ) -> bool {
        // verify the pay-token first
        if !cust_state.verify_init_pay_token(&channel_state, pay_token) {
            println!("activate::customer_finalize - failed to verify the pay-token");
            return false;
        }

        // only if both tokens have been stored
        if cust_state.has_tokens() {
            // must be an old wallet
            cust_state.protocol_status = ProtocolStatus::Activated;
        }
        return cust_state.protocol_status == ProtocolStatus::Activated;
    }
}

pub mod unlink {
    pub use super::pay::customer_unmask;
    pub use super::pay::merchant_validate_rev_lock;
    use super::*;

    ///
    /// unlink::customer_update_state() - takes as input the public params, channel state, channel token,
    /// merchant public keys, current customer state.
    /// output: session id, payment proof and new customer state
    ///
    pub fn customer_update_state<R: Rng, E: Engine>(
        csprng: &mut R,
        channel_state: &ChannelState<E>,
        cust_state: &CustomerState<E>,
    ) -> ([u8; 16], Payment<E>, CustomerState<E>) {
        // unlink payment of amount 0 (to avoid tx fees on the channel we start with an amount of -tx_fee)
        let (payment, new_cust_state) = pay::customer_update_state(
            csprng,
            channel_state,
            cust_state,
            -channel_state.get_channel_fee(),
        );
        // pick new session ID
        let mut session_id = [0u8; 16];
        csprng.fill_bytes(&mut session_id);
        return (session_id, payment, new_cust_state);
    }

    ///
    /// pay::merchant_update_state() - takes as input the public params, channel state, payment proof
    /// and merchant keys. If proof is valid, then merchant returns the refund token
    /// (i.e., partially blind signature on IOU with updated balance)
    ///
    pub fn merchant_update_state<R: Rng, E: Engine>(
        csprng: &mut R,
        channel_state: &ChannelState<E>,
        session_id: &[u8; 16],
        payment: &Payment<E>,
        merch_state: &mut MerchantState<E>,
    ) -> BoltResult<cl::Signature<E>> {
        if merch_state
            .unlink_nonces
            .contains(&encode_short_bytes_to_fr::<E>(payment.nonce.0).to_string())
        {
            Ok(Some(pay::merchant_update_state(
                csprng,
                channel_state,
                session_id,
                payment,
                merch_state,
            )))
        } else {
            Err(String::from(
                "unlink::merchant_update_state - The nonce is not a valid unlink nonce.",
            ))
        }
    }

    pub fn customer_finalize<E: Engine>(
        channel_state: &mut ChannelState<E>,
        cust_state: &mut CustomerState<E>,
        pay_token: cl::Signature<E>,
    ) -> bool {
        // verify the pay-token
        if !cust_state.unlink_verify_pay_token(channel_state, &pay_token) {
            println!("unlink::customer_finalize - failed to verify the pay-token");
            return false;
        }

        return true;
    }
}

pub mod pay {
    use super::*;

    ///
    /// pay::customer_prepare() - takes as input an rng, the channel state, the payment amount, and the customer state.
    /// Prepare payment for customer
    /// output: nonce and generates a session id
    ///
    pub fn customer_prepare<R: Rng, E: Engine>(
        csprng: &mut R,
        channel_state: &ChannelState<E>,
        amount: i64,
        cust_state: &CustomerState<E>,
    ) -> Result<(FixedSizeArray16, [u8; 16]), String> {
        // verify that channel status is already activated or established
        if (cust_state.protocol_status == ProtocolStatus::Activated && amount == 0)
            || (cust_state.protocol_status == ProtocolStatus::Established && amount != 0)
        {
            // check if payment on current balance is greater than dust limit
            let new_balance = match amount > 0 {
                true => cust_state.cust_balance - amount,  // positive value
                false => cust_state.cust_balance + amount, // negative value
            };

            if new_balance < channel_state.get_channel_fee() {
                let max_payment = cust_state.cust_balance - channel_state.get_channel_fee();
                let s = format!(
                    "Balance after payment is below dust limit: {}. Max payment: {}",
                    channel_state.get_channel_fee(),
                    max_payment
                );
                return Err(s);
            }

            // pick new session ID
            let mut session_id = [0u8; 16];
            csprng.fill_bytes(&mut session_id);
            return Ok((cust_state.nonce, session_id));
        } else {
            return Err(format!(
                "Invalid protocol status for pay::customer_prepare(): {}",
                cust_state.protocol_status
            ));
        }
    }

    ///
    /// pay::merchant_prepare() - takes as input the session id, the nonce of the old state, amount and
    /// the merchant state
    /// output: true or false if the payment would be successful
    ///
    pub fn merchant_prepare<E: Engine>(
        _session_id: &[u8; 16],
        nonce: FixedSizeArray16,
        amount: i64,
        merch_state: &mut MerchantState<E>,
    ) -> bool {
        if !merch_state.spent_nonces.contains(&nonce.to_string()) && amount != 0 {
            merch_state.spent_nonces.insert(nonce.to_string());
            return true;
        }
        return false;
    }

    ///
    /// pay::customer_update_state() - takes as input the public params, channel state, channel token,
    /// merchant public keys, old wallet and balance increment. Generate a new wallet commitment
    /// PoK of the committed values in new wallet and PoK of old wallet. Return new channel token,
    /// new wallet (minus blind signature and refund token) and payment proof.
    ///
    pub fn customer_update_state<R: Rng, E: Engine>(
        csprng: &mut R,
        channel_state: &ChannelState<E>,
        cust_state: &CustomerState<E>,
        amount: i64,
    ) -> (Payment<E>, CustomerState<E>) {
        let tx_fee = channel_state.get_channel_fee();
        let payment_amount = match tx_fee > 0 {
            true => amount + tx_fee,
            false => amount,
        };
        let (proof, coms, nonce, rev_lock, new_cust_state) =
            cust_state.generate_payment(csprng, &channel_state, payment_amount);
        let payment = Payment {
            proof,
            coms,
            nonce,
            rev_lock,
            amount,
        };
        return (payment, new_cust_state);
    }

    ///
    /// pay::merchant_update_state() - takes as input the public params, channel state, payment proof
    /// and merchant keys. If proof is valid, then merchant returns the refund token
    /// (i.e., partially blind signature on IOU with updated balance)
    ///
    pub fn merchant_update_state<R: Rng, E: Engine>(
        csprng: &mut R,
        channel_state: &ChannelState<E>,
        _session_id: &[u8; 16],
        payment: &Payment<E>,
        merch_state: &mut MerchantState<E>,
    ) -> cl::Signature<E> {
        // if payment proof verifies, then returns close-token and records wpk => pay-token
        // if valid revoke_token is provided later for wpk, then release pay-token
        let tx_fee = channel_state.get_channel_fee();
        let payment_amount = match tx_fee > 0 {
            true => payment.amount + tx_fee,
            false => payment.amount,
        };
        let new_close_token = merch_state
            .verify_payment(
                csprng,
                &channel_state,
                &payment.proof,
                &payment.coms,
                &payment.nonce,
                &payment.rev_lock,
                payment_amount,
            )
            .unwrap();
        // store the rev_lock since it has been revealed
        update_merchant_state(&mut merch_state.keys, &payment.rev_lock, None);
        return new_close_token;
    }

    ///
    /// Verify third party payment proof from two bi-directional channel payments with intermediary (payment amount
    ///
    pub fn multi_customer_update_state<R: Rng, E: Engine>(
        csprng: &mut R,
        channel_state: &ChannelState<E>,
        sender_payment: &Payment<E>,
        receiver_payment: &Payment<E>,
        merch_state: &mut MerchantState<E>,
    ) -> BoltResult<(cl::Signature<E>, cl::Signature<E>)> {
        let tx_fee = channel_state.get_channel_fee();
        let amount = sender_payment.amount + receiver_payment.amount;
        if amount != 0 {
            // we want to check this relation in ZK without knowing the amount
            return Err(String::from("payments do not offset"));
        }

        let new_close_token = merch_state
            .verify_payment(
                csprng,
                &channel_state,
                &sender_payment.proof,
                &sender_payment.coms,
                &sender_payment.nonce,
                &sender_payment.rev_lock,
                sender_payment.amount + tx_fee,
            )
            .unwrap();

        let cond_close_token = merch_state
            .verify_payment(
                csprng,
                &channel_state,
                &receiver_payment.proof,
                &receiver_payment.coms,
                &receiver_payment.nonce,
                &receiver_payment.rev_lock,
                receiver_payment.amount + tx_fee,
            )
            .unwrap();

        // store the wpk since it has been revealed
        update_merchant_state(&mut merch_state.keys, &sender_payment.rev_lock, None);
        update_merchant_state(&mut merch_state.keys, &receiver_payment.rev_lock, None);

        return Ok(Some((new_close_token, cond_close_token)));
    }

    ///
    /// pay::customer_unmask() - takes as input the public params, old wallet, new wallet,
    /// merchant's verification key and refund token. If the refund token is valid, generate
    /// a revocation token for the old wallet public key.
    ///
    pub fn customer_unmask<E: Engine>(
        channel_state: &ChannelState<E>,
        old_cust_state: &mut CustomerState<E>,
        new_cust_state: CustomerState<E>,
        new_close_token: &cl::Signature<E>,
    ) -> ResultBoltType<RevLockPair> {
        // let's update the old wallet
        assert!(old_cust_state.update(new_cust_state));

        // generate the token after verifying that the close token is valid
        let (rev_lock, rev_secret) =
            old_cust_state.get_old_rev_lock_pair(channel_state, new_close_token)?;

        return Ok(RevLockPair {
            rev_lock: rev_lock,
            rev_secret: rev_secret,
        });
    }

    ///
    /// pay::merchant_validate_rev_lock() - takes as input revoke message and signature
    /// from the customer and the merchant state. If the revocation token is valid,
    /// generate a new signature for the new wallet (from the PoK of committed values in new wallet).
    ///
    pub fn merchant_validate_rev_lock<E: Engine>(
        _session_id: &[u8; 16],
        rt: &RevLockPair,
        merch_state: &mut MerchantState<E>,
    ) -> BoltResult<cl::Signature<E>> {
        if merch_state.keys.contains_key(&hex::encode(&rt.rev_lock))
            && merch_state.keys.get(&hex::encode(&rt.rev_lock)).unwrap() != ""
        {
            return Err(String::from(
                "pay::merchant_validate_rev_lock() - revocation lock is already known to merchant",
            ));
        }
        let pay_token_result = merch_state.verify_revoke_message(&rt.rev_lock, &rt.rev_secret);
        let new_pay_token = match pay_token_result {
            Ok(n) => n,
            Err(err) => return Err(String::from(err.to_string())),
        };
        update_merchant_state(
            &mut merch_state.keys,
            &rt.rev_lock,
            Some(rt.rev_secret.clone()),
        );
        Ok(Some(new_pay_token))
    }

    ///
    /// pay::customer_unmask_pay_token() - takes as input the pay token and the customer state.
    /// Verify the pay token and store if true
    /// output: success boolean
    ///
    pub fn customer_unmask_pay_token<E: Engine>(
        pay_token: cl::Signature<E>,
        channel_state: &ChannelState<E>,
        cust_state: &mut CustomerState<E>,
    ) -> Result<bool, String> {
        return Ok(cust_state.pay_unmask_customer(&channel_state, &pay_token));
    }

    ///
    /// pay::multi_merchant_unmask (phase 2) - takes as input revoke messages and signatures
    /// from the sender and receiver and the merchant state of the intermediary.
    /// If the revocation tokens are valid, generate new signatures for the new wallets of both
    /// sender and receiver (from the PoK of committed values in new wallet).
    ///
    pub fn multi_merchant_unmask<E: Engine>(
        rt_sender: &RevLockPair,
        rt_receiver: &RevLockPair,
        merch_state: &mut MerchantState<E>,
    ) -> BoltResult<(cl::Signature<E>, cl::Signature<E>)> {
        let pay_token_sender_result =
            merch_state.verify_revoke_message(&rt_sender.rev_lock, &rt_sender.rev_secret);
        let pay_token_receiver_result =
            merch_state.verify_revoke_message(&rt_receiver.rev_lock, &rt_receiver.rev_secret);
        let new_pay_token_sender = match pay_token_sender_result {
            Ok(n) => n,
            Err(err) => return Err(String::from(err.to_string())),
        };
        let new_pay_token_receiver = match pay_token_receiver_result {
            Ok(n) => n,
            Err(err) => return Err(String::from(err.to_string())),
        };

        update_merchant_state(
            &mut merch_state.keys,
            &rt_sender.rev_lock,
            Some(rt_sender.rev_secret.clone()),
        );
        update_merchant_state(
            &mut merch_state.keys,
            &rt_receiver.rev_lock,
            Some(rt_receiver.rev_secret.clone()),
        );

        Ok(Some((new_pay_token_sender, new_pay_token_receiver)))
    }
}

// for customer => on input a wallet w, it outputs a customer channel closure message
///
/// customer_close - takes as input the channel state, merchant's verification
/// key, and customer state. Generates a channel closure message for customer.
///
pub fn force_customer_close<E: Engine>(
    channel_state: &ChannelState<E>,
    cust_state: &CustomerState<E>,
) -> Result<ChannelcloseC<E>, BoltError>
where
    <E as pairing::Engine>::G1: serde::Serialize,
{
    if cust_state.protocol_status != ProtocolStatus::Established {
        // instead of Unlinked
        return Err(BoltError::new(
            "Cannot close a channel that has not been established!",
        ));
    }

    let wallet = cust_state.get_wallet();
    let close_token = cust_state.get_close_token();

    let cp = channel_state.cp.as_ref().unwrap();
    let pk = cp.pub_params.pk.get_pub_key();
    let close_wallet = wallet.as_fr_vec_bar();

    assert!(pk.verify(&cp.pub_params.mpk, &close_wallet, &close_token));

    // hash the closing wallet + close token (merch sig)
    let mut m1 = serialize_compact::<E>(&close_wallet);
    let m2 = close_token.serialize_compact();
    m1.extend_from_slice(&m2);
    let m = hash_to_slice(&m2);

    // compute secp256k1 signature on the hash
    let secp = secp256k1::Secp256k1::new();
    let msg = secp256k1::Message::from_slice(&m).unwrap();
    let seckey = cust_state.get_secret_key();
    let cust_sig = secp.sign(&msg, &seckey);

    Ok(ChannelcloseC {
        rev_lock: FixedSizeArray32(cust_state.rev_lock.0.clone()),
        message: wallet,
        merch_signature: close_token,
        cust_signature: cust_sig,
    })
}

fn update_merchant_state(
    db: &mut HashMap<String, String>,
    rev_lock: &FixedSizeArray32,
    rev_secret: Option<FixedSizeArray32>,
) {
    let rev_lock_str = hex::encode(&rev_lock);
    let rev_secret_str = match rev_secret {
        Some(s) => hex::encode(&s),
        None => String::from(""),
    };
    db.insert(rev_lock_str, rev_secret_str);
}

///
/// merchant_close - takes as input the channel state, channel token, customer close msg/sig,
/// Returns tokens for merchant close transaction (only if customer close message is found to be a
/// double spend). If not, then None is returned.
///
pub fn force_merchant_close<E: Engine>(
    channel_state: &ChannelState<E>,
    channel_token: &ChannelToken<E>,
    cust_close: &ChannelcloseC<E>,
    merch_state: &MerchantState<E>,
) -> Result<RevLockPair, BoltError> {
    // if channel_state.channel_status != UNLINKED {
    //     return Err(BoltError::new("force_merchant_close - Channel not established! Cannot generate channel closure message."));
    // }

    let cp = channel_state.cp.as_ref().unwrap();
    let pk = cp.pub_params.pk.get_pub_key();
    let wallet = cust_close.message.clone();
    let close_wallet = wallet.as_fr_vec_bar();
    let close_token = cust_close.merch_signature.clone();

    let is_valid = pk.verify(&channel_token.mpk, &close_wallet, &close_token);
    // check that cust_close.rev_lock == close_wallet.rev_lock

    if is_valid {
        let rev_lock = cust_close.rev_lock;
        // found the rev_lock, which means close token on old state
        let rev_lock_key = hex::encode(&rev_lock);
        if merch_state.keys.contains_key(&rev_lock_key) {
            let rev_secret_str = merch_state.keys.get(&rev_lock_key).unwrap();
            let rev_secret = hex::decode(&rev_secret_str).unwrap();
            let mut rs_buf = [0u8; 32];
            // TODO: check that rev_secret is 32 len
            rs_buf.copy_from_slice(&rev_secret);
            return Ok(RevLockPair {
                rev_lock: rev_lock,
                rev_secret: FixedSizeArray32(rs_buf),
            });
        }
        return Err(BoltError::new(
            "force_merchant_close() - Could not find entry for rev_lock/rev_secret pair. Valid close!",
        ));
    }
    Err(BoltError::new(
        "force_merchant_close() - Customer close message not valid!",
    ))
}

//
// Used in open-channel WTP for validating that a close_token is a valid signature under <
//
// pub fn tze_verify_cust_close_message<E: Engine>(
//     channel_token: &ChannelToken<E>,
//     wpk: &secp256k1::PublicKey,
//     close_msg: &wallet::Wallet<E>,
//     close_token: &Signature<E>,
// ) -> bool {
//     // close_msg => <pkc> || <wpk> || <balance-cust> || <balance-merch> || CLOSE
//     // close_token = regular CL signature on close_msg
//     // channel_token => <pk_c, CL_PK_m, pk_m, mpk, comParams>

//     // (1) check that channel token and close msg are consistent (e.g., close_msg.pk_c == H(channel_token.pk_c) &&
//     let pk_c = channel_token.pk_c.unwrap();
//     let chan_token_pk_c = util::hash_pubkey_to_fr::<E>(&pk_c);
//     let chan_token_wpk = util::hash_pubkey_to_fr::<E>(&wpk);

//     let pkc_thesame = (close_msg.channelId == chan_token_pk_c);
//     // (2) check that wpk matches what's in the close msg
//     let wpk_thesame = (close_msg.wpk == chan_token_wpk);
//     return pkc_thesame
//         && wpk_thesame
//         && channel_token.cl_pk_m.verify(
//             &channel_token.mpk,
//             &close_msg.as_fr_vec(),
//             &close_token,
//         );
// }

//
// Used in merch-close WTP for validating that revoke_token is a valid signature under <wpk> and the <revoked || wpk> message
//
// pub fn tze_verify_revoke_message(
//     wpk: &secp256k1::PublicKey,
//     revoke_token: &secp256k1::Signature,
// ) -> bool {
//     let secp = secp256k1::Secp256k1::verification_only();
//     let revoke_msg = RevokedMessage::new(String::from("revoked"), wpk.clone());
//     let msg = secp256k1::Message::from_slice(&revoke_msg.hash_to_slice()).unwrap();
//     // verify that the revocation token is valid with respect to revoked || wpk
//     return secp.verify(&msg, &revoke_token, &wpk).is_ok();
// }

//
// Used in merch-close WTP for validating that merch_sig is a valid signature under <merch_pk> on <dest_addr || revoke-token> message
//
// pub fn tze_verify_merch_close_message<E: Engine>(
//     channel_token: &ChannelToken<E>,
//     merch_close: &ChannelcloseM,
// ) -> bool {
//     let secp = secp256k1::Secp256k1::verification_only();
//     let mut msg = Vec::new();
//     msg.extend(merch_close.address.as_bytes());
//     if !merch_close.revoke.is_none() {
//         // serialize signature in DER format
//         let r = merch_close.revoke.unwrap().serialize_der().to_vec();
//         msg.extend(r);
//     }
//     let msg2 = secp256k1::Message::from_slice(&hash_to_slice(&msg)).unwrap();
//     // verify that merch sig is valid with respect to dest_address
//     return secp
//         .verify(&msg2, &merch_close.signature, &channel_token.pk_m)
//         .is_ok();
// }
