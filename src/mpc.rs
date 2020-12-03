use super::*;
use bindings::{cb_receive, cb_send, ConnType_LNDNETIO, ConnType_NETIO};
pub use channels_mpc::{
    ChannelMPCState, ChannelMPCToken, CustomerMPCState, MerchantMPCState, RevokedState,
    TransactionFeeInfo,
};
pub use channels_mpc::{InitCustState, NetworkConfig};
pub use channels_util::{ChannelStatus, PaymentStatus, ProtocolStatus};
use database::{MaskedTxMPCInputs, StateDatabase};
use libc::c_void;
use rand::Rng;
use secp256k1::PublicKey;
pub use wallet::{State, NONCE_LEN};
use zkchan_tx::fixed_size_array::{FixedSizeArray16, FixedSizeArray32};
use zkchan_tx::Testnet;

///
/// init_merchant() - takes as input the public params, merchant balance and keypair.
/// Generates merchant data which consists of channel token and merchant state.
/// output: merchant state
///
pub fn init_merchant<'a, R: Rng>(
    csprng: &mut R,
    db_url: String,
    channel_state: &mut ChannelMPCState,
    name: &'a str,
) -> MerchantMPCState {
    // create new merchant state
    let merch_name = String::from(name);
    let merch_state = MerchantMPCState::new(csprng, db_url, channel_state, merch_name);

    return merch_state;
}

///
/// init_customer() - takes as input the merchant's public key, and initial balance for customer and merchant.
/// Generate initial customer channel state and channel token.
/// output: a channel token and customer state
///
pub fn init_customer<'a, R: Rng>(
    csprng: &mut R,
    pk_m: &PublicKey,
    b0_cust: i64,
    b0_merch: i64,
    tx_fee_info: &TransactionFeeInfo,
    name: &str,
) -> (ChannelMPCToken, CustomerMPCState) {
    assert!(b0_cust > 0);
    assert!(b0_merch >= 0);
    let bal_min_cust = tx_fee_info.bal_min_cust;
    let bal_min_merch = tx_fee_info.bal_min_merch;
    let val_cpfp = tx_fee_info.val_cpfp;
    let fee_cc = tx_fee_info.fee_cc;
    let fee_mc = tx_fee_info.fee_mc;
    let min_fee = tx_fee_info.min_fee;
    let max_fee = tx_fee_info.max_fee;

    let b0_cust = match b0_merch {
        0 => b0_cust - bal_min_cust - fee_mc - val_cpfp,
        _ => b0_cust,
    };

    let b0_merch = match b0_merch {
        0 => bal_min_merch + fee_mc + val_cpfp,
        _ => b0_merch,
    };

    let cust_name = String::from(name);
    let mut cust_state = CustomerMPCState::new(csprng, b0_cust, b0_merch, fee_cc, cust_name);

    // generate the initial channel token and initial state
    let channel_token = cust_state.generate_init_state(csprng, &pk_m, min_fee, max_fee, fee_mc);

    (channel_token, cust_state)
}

///
/// get_initial_state() - takes as input the customer state
/// output: initial cust state and expected hash
///
pub fn get_initial_state(
    cust_state: &CustomerMPCState,
) -> Result<(InitCustState, [u8; 32]), String> {
    let init_state = match cust_state.get_initial_cust_state() {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };
    let init_state_hash = cust_state.get_current_state().compute_hash();
    Ok((init_state, init_state_hash))
}

///
/// validate_channel_params() - takes as input the channel token, initial state and verifies that they are well-formed
/// output: true or false
///
pub fn validate_channel_params(
    db: &mut dyn StateDatabase,
    channel_token: &ChannelMPCToken,
    init_state: &InitCustState,
    init_hash: [u8; 32],
    merch_state: &mut MerchantMPCState,
) -> Result<bool, String> {
    merch_state.validate_channel_params(db, channel_token, init_state, init_hash)
}

///
/// customer_mark_open_channel() - changes channel status in customer state
///
pub fn customer_mark_open_channel(cust_state: &mut CustomerMPCState) -> Result<(), String> {
    cust_state.change_channel_status(ChannelStatus::Open)
}

///
/// merchant_mark_open_channel() - changes channel status for a given escrow-txid.
/// fails if not in pending open state and assumes escrow-txid has been broadcast on chain
///
pub fn merchant_mark_open_channel(
    escrow_txid_le: [u8; 32],
    merch_state: &mut MerchantMPCState,
) -> Result<(), String> {
    let mut escrow_txid_be = escrow_txid_le.clone();
    escrow_txid_be.reverse();
    merch_state.change_channel_status(escrow_txid_be, ChannelStatus::Open)
}

///
/// activate_customer() - takes as input an rng and the customer state.
/// Prepare to activate the channel for the customer (call activate_customer_finalize to finalize activation)
/// output: initial state
///
pub fn activate_customer<R: Rng>(
    csprng: &mut R,
    cust_state: &mut CustomerMPCState,
) -> Result<State, String> {
    // check that customer already in the Initialized state
    if cust_state.protocol_status != ProtocolStatus::Initialized {
        return Err(format!(
            "invalid channel status for activate_customer(): {}",
            cust_state.protocol_status
        ));
    }

    let channel_status = cust_state.get_channel_status();
    if channel_status != ChannelStatus::Open {
        return Err(format!("channel is not open yet: {}", channel_status));
    }

    let _r_com = cust_state.generate_rev_lock_commitment(csprng);
    let _t0 = cust_state.get_randomness();

    Ok(cust_state.get_current_state())
}

///
/// activate_merchant() - takes as input a channel token, the intial state, and the merchant state.
/// Activate the channel for the merchant
/// output: intial pay token
///
pub fn activate_merchant(
    db: &mut dyn StateDatabase,
    channel_token: ChannelMPCToken,
    s0: &State,
    merch_state: &mut MerchantMPCState,
) -> Result<[u8; 32], String> {
    // TODO: implement ZKC-19
    // activate channel - generate pay_token
    let mut escrow_txid_be = channel_token.escrow_txid.0.clone();
    escrow_txid_be.reverse();
    let channel_status = match merch_state.get_channel_status(escrow_txid_be) {
        Ok(s) => s,
        Err(e) => return Err(e.to_string()),
    };
    if channel_status != ChannelStatus::Open {
        return Err(format!("channel is not open yet: {}", channel_status));
    }
    merch_state.activate_channel(db, &channel_token, s0)
}

///
/// activate_customer_finalize() - takes as input the initial pay token and the customer state.
/// Finalize activation of the channel for customer
/// no output
///
pub fn activate_customer_finalize(
    pay_token_0: [u8; 32],
    cust_state: &mut CustomerMPCState,
) -> Result<(), String> {
    cust_state.store_initial_pay_token(pay_token_0)
}

///
/// pay_prepare_customer() - takes as input an rng, the channel state, the payment amount, and the customer state.
/// Prepare payment for customer
/// output: new state (after payment), revocation lock commitment, revocation lock, revocation secret
/// (only send revocation lock commitment to merchant)
///
pub fn pay_prepare_customer<R: Rng>(
    csprng: &mut R,
    channel: &ChannelMPCState,
    amount: i64,
    cust_state: &mut CustomerMPCState,
) -> Result<(State, RevokedState, [u8; 32], [u8; 16]), String> {
    // verify that channel status is already activated or established
    if (cust_state.protocol_status == ProtocolStatus::Activated && amount >= 0)
        || (cust_state.protocol_status == ProtocolStatus::Established && amount > 0)
    {
        // check if payment on current balance is greater than dust limit
        let new_balance = match amount > 0 {
            true => cust_state.cust_balance - amount,  // positive value
            false => cust_state.cust_balance + amount, // negative value
        };
        if new_balance < channel.get_bal_min_cust() {
            let max_payment = cust_state.cust_balance - channel.get_bal_min_cust();
            let s = format!(
                "Balance after payment is below dust limit: {}. Max payment: {}",
                channel.get_bal_min_cust(),
                max_payment
            );
            return Err(s);
        }
        let (cur_rev_lock, cur_rev_secret) = cust_state.get_rev_pair();
        // get current rev lock commitment
        let cur_rev_lock_com = cust_state.generate_rev_lock_commitment(csprng);
        // randomness for old rev lock commitment
        let cur_t = cust_state.get_randomness();

        cust_state.generate_new_state(csprng, amount);
        let new_state = cust_state.get_current_state();
        // pick new session ID
        let mut session_id = [0u8; 16];
        csprng.fill_bytes(&mut session_id);
        Ok((
            new_state,
            RevokedState {
                rev_lock: FixedSizeArray32(cur_rev_lock),
                rev_secret: FixedSizeArray32(cur_rev_secret),
                t: FixedSizeArray16(cur_t),
            },
            cur_rev_lock_com,
            session_id,
        ))
    } else {
        return Err(format!(
            "Invalid channel status for pay_prepare_customer(): {}",
            cust_state.protocol_status
        ));
    }
}

///
/// pay_prepare_merchant() - takes as input an rng, the channel state, the nonce of the old state, rev lock commitment, amount and the merchant state.
/// Prepare payment for merchant
/// output: commitment of the payment token mask
///
pub fn pay_prepare_merchant<R: Rng>(
    csprng: &mut R,
    db: &mut dyn StateDatabase,
    channel_state: &ChannelMPCState,
    session_id: [u8; 16],
    nonce: [u8; NONCE_LEN],
    rev_lock_com: [u8; 32],
    amount: i64,
    justification: Option<String>,
    merch_state: &mut MerchantMPCState,
) -> Result<[u8; 32], String> {
    // checks that no existing session with the specified session_id/nonce combo
    merch_state.generate_pay_mask_commitment(
        csprng,
        db,
        channel_state,
        session_id,
        nonce,
        rev_lock_com,
        amount,
        justification,
    )
}

///
/// pay_update_customer() - takes as input the channel state, the channel token, the intial state, the final state, a commitment for the mask for the pay token,
/// the revocation lock commitment, the payment amount, and the customer state.
/// Start the MPC for a payment for the Customer
/// output: a success boolean, or error
///
pub fn pay_update_customer(
    channel_state: &ChannelMPCState,
    channel_token: &ChannelMPCToken,
    s0: State,
    s1: State,
    pay_token_mask_com: [u8; 32],
    rev_lock_com: [u8; 32],
    amount: i64,
    cust_state: &mut CustomerMPCState,
    p_ptr: *mut c_void,
    send_cb: cb_send,
    receive_cb: cb_receive,
) -> Result<String, String> {
    // verify that channel status is already activated or established (unlink)
    if (cust_state.protocol_status == ProtocolStatus::Activated && amount >= 0)
        || (cust_state.protocol_status == ProtocolStatus::Established && amount > 0)
    {
        cust_state.update_pay_com(pay_token_mask_com);
        if cust_state.net_config.is_none() {
            // use default
            let conn_type = match send_cb.is_some() && receive_cb.is_some() {
                true => ConnType_LNDNETIO,
                false => ConnType_NETIO,
            };
            cust_state.set_network_config(NetworkConfig {
                conn_type,
                dest_ip: String::from("127.0.0.1"),
                dest_port: 2424,
                path: String::new(),
            });
        }
        let circuit = cust_state.get_circuit_file();
        cust_state.execute_mpc_context(
            &channel_state,
            &channel_token,
            s0,
            s1,
            pay_token_mask_com,
            rev_lock_com,
            amount,
            circuit,
            p_ptr,
            send_cb,
            receive_cb,
        )
    } else {
        return Err(format!(
            "Invalid channel status for pay_update_customer(): {}",
            cust_state.protocol_status
        ));
    }
}

///
/// pay_update_merchant() - takes as input an rng, the channel state, the intial state, a commitment for the mask for the pay token,
/// the revocation lock commitment, the payment amount, and the merchant state.
/// Start the MPC for a payment for the Merchant
/// output: the transaction masks (escrow and merch tx), or error
///
pub fn pay_update_merchant<R: Rng>(
    csprng: &mut R,
    db: &mut dyn StateDatabase,
    channel: &ChannelMPCState,
    session_id: [u8; 16],
    pay_token_mask_com: [u8; 32],
    merch_state: &mut MerchantMPCState,
    p_ptr: *mut c_void,
    send_cb: cb_send,
    receive_cb: cb_receive,
) -> Result<bool, String> {
    if merch_state.net_config.is_none() {
        // use default ip/port
        let conn_type = match send_cb.is_some() && receive_cb.is_some() {
            true => ConnType_LNDNETIO,
            false => ConnType_NETIO,
        };
        merch_state.set_network_config(NetworkConfig {
            conn_type,
            dest_ip: String::from("127.0.0.1"),
            dest_port: 2424,
            path: String::new(),
        });
    }
    let circuit = merch_state.get_circuit_file();
    return merch_state.execute_mpc_context(
        csprng,
        db,
        &channel,
        session_id,
        pay_token_mask_com,
        circuit,
        p_ptr,
        send_cb,
        receive_cb,
    );
}

///
/// pay_confirm_mpc_result() - takes as input a db, session identifier, mpc result and merch state
/// output: masked input if the mpc result was successful and there is a masked input for a given session_id
///
pub fn pay_confirm_mpc_result(
    db: &mut dyn StateDatabase,
    session_id: [u8; 16],
    success: String,
    _merch_state: &mut MerchantMPCState,
) -> Result<MaskedTxMPCInputs, String> {
    // check db is connected
    db.is_connected()?;

    let session_id_hex = hex::encode(session_id);
    let mask_bytes = match db.get_masked_mpc_inputs(&session_id_hex) {
        Ok(n) => Some(n),
        Err(e) => return Err(e.to_string()),
    };
    let mask_bytes_unwrapped = mask_bytes.unwrap();
    if hex::encode(mask_bytes_unwrapped.verify_success.0) == success {
        return Ok(mask_bytes_unwrapped.get_tx_masks());
    } else {
        let mut session_state = match db.load_session_state(&session_id_hex) {
            Ok(s) => s,
            Err(e) => return Err(e.to_string()),
        };
        session_state.status = PaymentStatus::Error;
        db.update_session_state(&session_id_hex, &session_state);
        return Err(format!(
            "pay_confirm_mpc_result: will need to restart MPC session"
        ));
    }
}

///
/// pay_unmask_sigs_customer() - takes as input the transaction masks and the customer state.
/// Unmask the transactions received from the MPC
/// output: a success boolean
///
pub fn pay_unmask_sigs_customer(
    channel_state: &ChannelMPCState,
    channel_token: &ChannelMPCToken,
    mask_bytes: MaskedTxMPCInputs,
    cust_state: &mut CustomerMPCState,
) -> Result<bool, String> {
    if (cust_state.protocol_status == ProtocolStatus::Activated
        || cust_state.protocol_status == ProtocolStatus::Established)
    {
        cust_state.unmask_and_verify_transactions::<Testnet>(
            channel_state,
            channel_token,
            mask_bytes,
        )
    } else {
        return Err(format!(
            "Invalid channel status for pay_unmask_sigs_customer(): {}",
            cust_state.protocol_status
        ));
    }
}

///
/// pay_validate_rev_lock_merchant() - takes as input the nonce, the revocation lock commitment, the revocation lock,
/// the revocation secret and the merchant state.
/// Verify the revocation lock commitment
/// output: the pay token mask and randomness
///
pub fn pay_validate_rev_lock_merchant(
    db: &mut dyn StateDatabase,
    session_id: [u8; 16],
    rev_state: RevokedState,
    merch_state: &mut MerchantMPCState,
) -> Result<([u8; 32], [u8; 16]), String> {
    let (pt_mask, pt_mask_r) = match merch_state.verify_revoked_state(
        db,
        session_id,
        rev_state.get_rev_lock(),
        rev_state.get_rev_secret(),
        rev_state.get_randomness(),
    ) {
        Ok(n) => (n.0, n.1),
        Err(e) => return Err(e.to_string()),
    };
    Ok((pt_mask, pt_mask_r))
}

///
/// pay_unmask_pay_token_customer() - takes as input the paytoken mask and the customer state.
/// Verify the paytoken mask commitment and unmask paytoken
/// output: success boolean
///
pub fn pay_unmask_pay_token_customer(
    pt_mask_bytes: [u8; 32],
    pt_mask_r: [u8; 16],
    cust_state: &mut CustomerMPCState,
) -> Result<bool, String> {
    if (cust_state.protocol_status == ProtocolStatus::Activated
        || cust_state.protocol_status == ProtocolStatus::Established)
    {
        Ok(cust_state.unmask_and_verify_pay_token(pt_mask_bytes, pt_mask_r))
    } else {
        return Err(format!(
            "Invalid channel status for pay_unmask_pay_token_customer(): {}",
            cust_state.protocol_status
        ));
    }
}

///
/// force_customer_close() - takes as input the channel_state, channel_token, from_escrow and customer state.
/// signs the closing tx on the current state of the channel
/// output: cust-close-(signed_tx, txid) from escrow-tx or merch-close-tx
///
pub fn force_customer_close(
    channel_state: &ChannelMPCState,
    channel_token: &ChannelMPCToken,
    from_escrow: bool,
    cust_state: &mut CustomerMPCState,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    // (close_tx, close_txid_be, close_txid_le) that spends from escrow (if from_escrow = true)
    cust_state.customer_close::<Testnet>(&channel_state, &channel_token, from_escrow)
}

///
/// force_merchant_close() - takes as input the escrow txid and merchant state.
/// signs the merch-close-tx tx on the current state of the channel
/// output: merch-close-signed-tx on a given channel (identified by the escrow-txid)
///
pub fn force_merchant_close(
    escrow_txid: &Vec<u8>,
    val_cpfp: i64,
    merch_state: &mut MerchantMPCState,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    if escrow_txid.len() != 32 {
        return Err(format!(
            "escrow-txid does not have expected length: {}",
            escrow_txid.len()
        ));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(escrow_txid.as_slice());
    merch_state.get_closing_tx::<Testnet>(txid, val_cpfp)
}
