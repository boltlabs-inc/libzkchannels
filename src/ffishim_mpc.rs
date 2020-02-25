#[cfg(feature = "mpc-bitcoin")]
#[no_mangle]
pub mod ffishim_mpc {
    extern crate libc;

    use mpc;
    use txutil;
    use serde::Deserialize;
    use libc::c_char;
    use std::ffi::{CStr, CString};
    use std::str;
    use channels_mpc::{CustomerMPCState, MerchantMPCState, ChannelMPCToken, InitCustState,
                       ChannelMPCState, MaskedTxMPCInputs};
    use wallet::State;
    use hex::FromHexError;
    use mpc::RevokedState;
    use FundingTxInfo;
    use bitcoin::Testnet;

    fn error_message(s: String) -> *mut c_char {
        let ser = ["{\'error\':\'", &s, "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    macro_rules! handle_errors {
        ($e:expr) => (match $e {
            Ok(val) => val,
            Err(err) => return error_message(err.to_string()),
        });
    }

    pub type ResultSerdeType<T> = Result<T, serde_json::error::Error>;

    fn deserialize_result_object<'a, T>(serialized: *mut c_char) -> ResultSerdeType<T>
        where
            T: Deserialize<'a>,
    {
        let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
        let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
        serde_json::from_str(&string)
    }

    fn deserialize_hex_string(serialized: *mut c_char) -> Result<Vec<u8>, FromHexError>
    {
        let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
        let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
        hex::decode(&string)
    }

    #[no_mangle]
    pub extern fn mpc_free_string(pointer: *mut c_char) {
        unsafe {
            if pointer.is_null() { return; }
            CString::from_raw(pointer)
        };
    }

    #[no_mangle]
    pub extern fn mpc_channel_setup(channel_name: *const c_char, third_party_support: u32) -> *mut c_char {
        let bytes = unsafe { CStr::from_ptr(channel_name).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let mut tps = false;
        if third_party_support >= 1 {
            tps = true;
        }
        let channel_state = mpc::ChannelMPCState::new(name.to_string(), tps);

        let ser = ["{\'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // INIT

    #[no_mangle]
    pub extern fn mpc_init_merchant(ser_channel_state: *mut c_char, name_ptr: *const c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        let channel_state_result: ResultSerdeType<mpc::ChannelMPCState> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let merch_state = mpc::init_merchant(rng, &mut channel_state, name);

        let ser = ["{\'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\', \'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str(), "\'}"].concat();

        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_init_customer(ser_pk_m: *mut c_char, cust_bal: i64, merch_bal: i64, name_ptr: *const c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the pk_m
        let pk_m_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_pk_m);
        let pk_m = handle_errors!(pk_m_result);

        // Deserialize the name
        let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        // We change the channel state
        let (channel_token, cust_state) = mpc::init_customer(rng, &pk_m, cust_bal,merch_bal, name);
        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\', \'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // VALIDATE INITIAL STATE
    #[no_mangle]
    pub extern fn mpc_get_initial_state(ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> = deserialize_result_object(ser_cust_state);
        let cust_state = handle_errors!(cust_state_result);

        let (init_state, init_hash) = handle_errors!(mpc::get_initial_state(&cust_state));
        let ser = ["{\'init_state\':\'", serde_json::to_string(&init_state).unwrap().as_str(), "\', \'init_hash\':\'", &hex::encode(init_hash), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_validate_initial_state(ser_channel_token: *mut c_char, ser_init_state: *mut c_char, ser_init_hash: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the init state
        let init_state_result: ResultSerdeType<InitCustState> = deserialize_result_object(ser_init_state);
        let init_state = handle_errors!(init_state_result);

        // Deserialize init hash
        let init_hash_result = deserialize_hex_string(ser_init_hash);
        let hash_buf = handle_errors!(init_hash_result);
        let mut init_hash = [0u8; 32];
        init_hash.copy_from_slice(hash_buf.as_slice());

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let is_ok = handle_errors!(mpc::validate_initial_state(&channel_token, &init_state, init_hash, &mut merch_state));
        let ser = ["{\'is_ok\':", &is_ok.to_string(), ", \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_get_channel_id(ser_channel_token: *mut c_char) -> *mut c_char {
        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        let channel_id = handle_errors!(channel_token.compute_channel_id());
        let ser = ["{\'channel_id\':\'", &hex::encode(channel_id), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // ACTIVATE

    #[no_mangle]
    pub extern fn mpc_activate_customer(ser_cust_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let state = mpc::activate_customer(rng, &mut cust_state);
        let ser = ["{\'state\':\'", serde_json::to_string(&state).unwrap().as_str(), "\', \'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_activate_merchant(ser_channel_token: *mut c_char, ser_state: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the state
        let state_result: ResultSerdeType<State> = deserialize_result_object(ser_state);
        let state = handle_errors!(state_result);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // We change the channel state
        let pay_token = handle_errors!(mpc::activate_merchant(channel_token, &state, &mut merch_state));
        let ser = ["{\'pay_token\':\'", &hex::encode(pay_token), "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_activate_customer_finalize(ser_pay_token: *mut c_char, ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize pay token
        let pay_token_result = deserialize_hex_string(ser_pay_token);
        let pay_token = handle_errors!(pay_token_result);
        let mut pay_token_0 = [0u8; 32];
        pay_token_0.copy_from_slice(pay_token.as_slice());

        // We change the channel state
        mpc::activate_customer_finalize(pay_token_0, &mut cust_state);
        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // PAYMENT

    #[no_mangle]
    pub extern fn mpc_prepare_payment_customer(ser_channel_state: *mut c_char, amount: i64, ser_cust_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let (state, rev_state) = match mpc::pay_prepare_customer(rng, &channel_state, amount, &mut cust_state) {
            Ok(n) => n,
            Err(e) => return error_message(e)
        };
        let ser = ["{\'rev_state\':\'", serde_json::to_string(&rev_state).unwrap().as_str(), "\', \'state\':\'", serde_json::to_string(&state).unwrap().as_str(), "\', \'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_prepare_payment_merchant(ser_channel_state: *mut c_char, ser_rev_lock_com: *mut c_char, ser_nonce: *mut c_char, amount: i64, ser_merch_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize rev_lock_com
        let rev_lock_com_result = deserialize_hex_string(ser_rev_lock_com);
        let rev_lock_com = handle_errors!(rev_lock_com_result);
        let mut rev_lock_com_ar = [0u8; 32];
        rev_lock_com_ar.copy_from_slice(rev_lock_com.as_slice());

        // Deserialize nonce
        let nonce_result = deserialize_hex_string(ser_nonce);
        let nonce = handle_errors!(nonce_result);
        let mut nonce_ar = [0u8; 16];
        nonce_ar.copy_from_slice(nonce.as_slice());

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // We change the channel state
        let pay_token_mask_com = handle_errors!(mpc::pay_prepare_merchant(rng, &channel_state, rev_lock_com_ar, nonce_ar, amount, &mut merch_state));
        let ser = ["{\'pay_token_mask_com\':\'", &hex::encode(pay_token_mask_com), "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_pay_customer(ser_channel_state: *mut c_char, ser_channel_token: *mut c_char, ser_start_state: *mut c_char, ser_end_state: *mut c_char, ser_pay_token_mask_com: *mut c_char, ser_rev_lock_com: *mut c_char, amount: i64, ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the start_state
        let start_state_result: ResultSerdeType<State> = deserialize_result_object(ser_start_state);
        let start_state = handle_errors!(start_state_result);

        // Deserialize the end_state
        let end_state_result: ResultSerdeType<State> = deserialize_result_object(ser_end_state);
        let end_state = handle_errors!(end_state_result);

        // Deserialize pay_token_mask_com
        let pay_token_mask_com_result = deserialize_hex_string(ser_pay_token_mask_com);
        let pay_token_mask_com = handle_errors!(pay_token_mask_com_result);
        let mut pay_token_mask_com_ar = [0u8; 32];
        pay_token_mask_com_ar.copy_from_slice(pay_token_mask_com.as_slice());

        // Deserialize rev_lock_com
        let rev_lock_com_result = deserialize_hex_string(ser_rev_lock_com);
        let rev_lock_com = handle_errors!(rev_lock_com_result);
        let mut rev_lock_com_ar = [0u8; 32];
        rev_lock_com_ar.copy_from_slice(rev_lock_com.as_slice());

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let result = mpc::pay_customer(&mut channel_state, &channel_token, start_state, end_state, pay_token_mask_com_ar, rev_lock_com_ar, amount, &mut cust_state);
        let is_ok: bool = handle_errors!(result);
        let ser = ["{\'is_ok\':", &is_ok.to_string(), ", \'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_pay_merchant(ser_channel_state: *mut c_char, ser_nonce: *mut c_char, ser_pay_token_mask_com: *mut c_char, ser_rev_lock_com: *mut c_char, amount: i64, ser_merch_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize nonce
        let nonce_result = deserialize_hex_string(ser_nonce);
        let nonce = handle_errors!(nonce_result);
        let mut nonce_ar = [0u8; 16];
        nonce_ar.copy_from_slice(nonce.as_slice());

        // Deserialize pay_token_mask_com
        let pay_token_mask_com_result = deserialize_hex_string(ser_pay_token_mask_com);
        let pay_token_mask_com = handle_errors!(pay_token_mask_com_result);
        let mut pay_token_mask_com_ar = [0u8; 32];
        pay_token_mask_com_ar.copy_from_slice(pay_token_mask_com.as_slice());

        // Deserialize rev_lock_com
        let rev_lock_com_result = deserialize_hex_string(ser_rev_lock_com);
        let rev_lock_com = handle_errors!(rev_lock_com_result);
        let mut rev_lock_com_ar = [0u8; 32];
        rev_lock_com_ar.copy_from_slice(rev_lock_com.as_slice());

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // We change the channel state
        let result = mpc::pay_merchant(rng, &mut channel_state, nonce_ar, pay_token_mask_com_ar, rev_lock_com_ar, amount, &mut merch_state);
        let masked_tx_inputs = handle_errors!(result);
        let ser = ["{\'masked_tx_inputs\':\'", serde_json::to_string(&masked_tx_inputs).unwrap().as_str(), "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_pay_unmask_tx_customer(ser_channel_state: *mut c_char, ser_channel_token: *mut c_char, ser_masked_tx_inputs: *mut c_char, ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize masked_tx_inputs
        let masked_tx_inputs_result: ResultSerdeType<MaskedTxMPCInputs> = deserialize_result_object(ser_masked_tx_inputs);
        let masked_tx_inputs = handle_errors!(masked_tx_inputs_result);

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let is_ok = mpc::pay_unmask_tx_customer(&channel_state, &channel_token, masked_tx_inputs, &mut cust_state);
        let ser = ["{\'is_ok\':", &is_ok.to_string(), ", \'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_pay_validate_rev_lock_merchant(ser_revoked_state: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        // Deserialize masked_tx_inputs
        let revoked_state_result: ResultSerdeType<RevokedState> = deserialize_result_object(ser_revoked_state);
        let revoked_state = handle_errors!(revoked_state_result);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // We change the channel state
        let pay_token_mask_result = mpc::pay_validate_rev_lock_merchant(revoked_state, &mut merch_state);
        let pt = handle_errors!(pay_token_mask_result);
        let ser = ["{\'pay_token_mask\':\'", &hex::encode(pt.0), "\', \'pay_token_mask_r\':\'", &hex::encode(pt.1),
                          "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn mpc_pay_unmask_pay_token_customer(ser_pt_mask_bytes: *mut c_char, ser_pt_mask_r: *mut c_char, ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize pt_mask_bytes
        let pt_mask_bytes_result = deserialize_hex_string(ser_pt_mask_bytes);
        let pt_mask_bytes = handle_errors!(pt_mask_bytes_result);
        let mut pt_mask_bytes_ar = [0u8; 32];
        pt_mask_bytes_ar.copy_from_slice(pt_mask_bytes.as_slice());

        // Deserialize pt_mask_bytes
        let pt_mask_r_result = deserialize_hex_string(ser_pt_mask_r);
        let pt_mask_r = handle_errors!(pt_mask_r_result);
        let mut pt_mask_r_ar = [0u8; 16];
        pt_mask_r_ar.copy_from_slice(pt_mask_r.as_slice());

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let is_ok = mpc::pay_unmask_pay_token_customer(pt_mask_bytes_ar, pt_mask_r_ar, &mut cust_state);
        let ser = ["{\'is_ok\':", &is_ok.to_string(), ", \'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // TRANSACTION BUILDER FOR ESCROW, MERCH-CLOSE-TX and CUST-CLOSE-TXS

    #[no_mangle]
    pub extern fn cust_form_escrow_transaction(ser_txid: *mut c_char, index: u32, input_sats: i64, output_sats: i64,
                                          ser_cust_sk: *mut c_char, ser_cust_pk: *mut c_char, ser_merch_pk: *mut c_char, ser_change_pk: *mut c_char) -> *mut c_char {
        let txid_result = deserialize_hex_string(ser_txid);
        let txid = handle_errors!(txid_result);

        // Deserialize the sk_c
        let cust_sk_result: ResultSerdeType<secp256k1::SecretKey> = deserialize_result_object(ser_cust_sk);
        let cust_sk = handle_errors!(cust_sk_result);

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let merch_pk_result = deserialize_hex_string(ser_merch_pk);
        let merch_pk = handle_errors!(merch_pk_result);

        let change_pk_result = deserialize_hex_string(ser_change_pk);
        let change_pk = handle_errors!(change_pk_result);

        let (signed_tx, txid, prevout) = handle_errors!(txutil::customer_sign_escrow_transaction(txid, index, input_sats, output_sats, cust_sk, cust_pk, merch_pk, Some(change_pk)));
        let ser = ["{\'signed_tx\':\'", &hex::encode(signed_tx), "\', \'txid\':\'", &hex::encode(txid),
                          "\', \'hash_prevout\':\'", &hex::encode(prevout), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()

    }

    #[no_mangle]
    pub extern fn form_merch_close_transaction(ser_escrow_txid: *mut c_char, ser_cust_pk: *mut c_char, ser_merch_pk: *mut c_char, ser_merch_close_pk: *mut c_char, cust_bal_sats: i64, merch_bal_sats: i64, ser_self_delay: *mut c_char) -> *mut c_char {

        let escrow_txid_result = deserialize_hex_string(ser_escrow_txid);
        let escrow_txid = handle_errors!(escrow_txid_result);

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let merch_pk_result = deserialize_hex_string(ser_merch_pk);
        let merch_pk = handle_errors!(merch_pk_result);

        let merch_close_pk_result = deserialize_hex_string(ser_merch_close_pk);
        let merch_close_pk = handle_errors!(merch_close_pk_result);

        let self_delay_result = deserialize_hex_string(ser_self_delay);
        let self_delay = handle_errors!(self_delay_result);
        let mut to_self_delay = [0u8; 2];
        to_self_delay.copy_from_slice(&self_delay);

        let (merch_tx_preimage, _) = handle_errors!(txutil::merchant_form_close_transaction(escrow_txid, cust_pk, merch_pk, merch_close_pk, cust_bal_sats, merch_bal_sats, to_self_delay));

        let ser = ["{\'merch_tx_preimage\':\'", &hex::encode(merch_tx_preimage), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn customer_sign_merch_close_tx(ser_cust_sk: *mut c_char, ser_merch_tx_preimage: *mut c_char) -> *mut c_char {

//        let cust_sk_result = deserialize_hex_string(ser_cust_sk);
//        let cust_sk = handle_errors!(cust_sk_result);

        // Deserialize the sk_c
        let cust_sk_result: ResultSerdeType<secp256k1::SecretKey> = deserialize_result_object(ser_cust_sk);
        let cust_sk = handle_errors!(cust_sk_result);

        let tx_preimage_result = deserialize_hex_string(ser_merch_tx_preimage);
        let merch_tx_preimage = handle_errors!(tx_preimage_result);

        let cust_sig = handle_errors!(txutil::customer_sign_merch_close_transaction(cust_sk, merch_tx_preimage));
        let ser = ["{\'cust_sig\':\'", &hex::encode(cust_sig), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn merchant_sign_merch_close_tx(ser_escrow_txid: *mut c_char, ser_cust_pk: *mut c_char, ser_merch_pk: *mut c_char, ser_merch_close_pk: *mut c_char, cust_bal_sats: i64, merch_bal_sats: i64, ser_self_delay: *mut c_char, ser_cust_sig: *mut c_char, ser_merch_sk: *mut c_char) -> *mut c_char {

        let escrow_txid_result = deserialize_hex_string(ser_escrow_txid);
        let escrow_txid = handle_errors!(escrow_txid_result);

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let merch_pk_result = deserialize_hex_string(ser_merch_pk);
        let merch_pk = handle_errors!(merch_pk_result);

        let merch_close_pk_result = deserialize_hex_string(ser_merch_close_pk);
        let merch_close_pk = handle_errors!(merch_close_pk_result);

        let self_delay_result = deserialize_hex_string(ser_self_delay);
        let self_delay = handle_errors!(self_delay_result);
        let mut to_self_delay = [0u8; 2];
        to_self_delay.copy_from_slice(&self_delay);

        let cust_sig_result = deserialize_hex_string(ser_cust_sig);
        let cust_sig = handle_errors!(cust_sig_result);

        // Deserialize the sk_m
        let merch_sk_result: ResultSerdeType<secp256k1::SecretKey> = deserialize_result_object(ser_merch_sk);
        let merch_sk = handle_errors!(merch_sk_result);

        let (_, tx_params) = handle_errors!(txutil::merchant_form_close_transaction(escrow_txid, cust_pk, merch_pk, merch_close_pk, cust_bal_sats, merch_bal_sats, to_self_delay));

        let (signed_tx, txid, prevout) = handle_errors!(txutil::merchant_sign_merch_close_transaction(tx_params, cust_sig, merch_sk));

        let ser = ["{\'signed_tx\':\'", &hex::encode(signed_tx), "\', \'txid\':\'", &hex::encode(txid),
                          "\', \'hash_prevout\':\'", &hex::encode(prevout), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }


    #[no_mangle]
    pub extern fn merch_sign_init_cust_close_txs(ser_funding_tx: *mut c_char, ser_rev_lock: *mut c_char, ser_cust_pk: *mut c_char, ser_cust_close_pk: *mut c_char, ser_self_delay: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        // Deserialize the tx
        let tx_result: ResultSerdeType<FundingTxInfo> = deserialize_result_object(ser_funding_tx);
        let funding_tx = handle_errors!(tx_result);

        let rev_lock_result = deserialize_hex_string(ser_rev_lock);
        let _rev_lock = handle_errors!(rev_lock_result);
        let mut rl = [0u8; 32];
        rl.copy_from_slice(_rev_lock.as_slice());

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let cust_close_pk_result = deserialize_hex_string(ser_cust_close_pk);
        let cust_close_pk = handle_errors!(cust_close_pk_result);

        let self_delay_result = deserialize_hex_string(ser_self_delay);
        let self_delay = handle_errors!(self_delay_result);
        let mut to_self_delay = [0u8; 2];
        to_self_delay.copy_from_slice(&self_delay);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> = deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        let (escrow_sig, merch_sig) = merch_state.sign_initial_closing_transaction::<Testnet>(funding_tx, rl, cust_pk, cust_close_pk, to_self_delay);

        let ser = ["{\'escrow_sig\': \'", &hex::encode(escrow_sig), "\', \'merch_sig\':\'", &hex::encode(merch_sig), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn cust_sign_init_cust_close_txs(ser_funding_tx: *mut c_char, ser_channel_state: *mut c_char, ser_channel_token: *mut c_char, ser_escrow_sig: *mut c_char, ser_merch_sig: *mut c_char, ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the tx
        let tx_result: ResultSerdeType<FundingTxInfo> = deserialize_result_object(ser_funding_tx);
        let funding_tx = handle_errors!(tx_result);

        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> = deserialize_result_object(ser_channel_token);
        let mut channel_token = handle_errors!(channel_token_result);

        // Deserialize escrow-sig & merch-sig
        let escrow_sig_result = deserialize_hex_string(ser_escrow_sig);
        let escrow_sig = handle_errors!(escrow_sig_result);

        let merch_sig_result = deserialize_hex_string(ser_merch_sig);
        let merch_sig = handle_errors!(merch_sig_result);

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        handle_errors!(cust_state.set_funding_tx_info(&mut channel_token, &funding_tx));

        // now sign the customer's initial closing txs iff escrow-sig and merch-sig are valid
        let got_close_tx = handle_errors!(cust_state.sign_initial_closing_transaction::<Testnet>(&channel_state, &channel_token, &escrow_sig, &merch_sig));
        let ser = ["{\'is_ok\':", serde_json::to_string(&got_close_tx).unwrap().as_str(), ", \'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str(),
                          "\', \'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // #[no_mangle]
    // pub extern fn merch_sign_merch_dispute_tx(ser_input: *mut c_char, ser_rev_lock: *mut c_char, ser_cust_close_pk: *mut c_char, ser_self_delay: *mut c_char, ser_merch_state: *mut c_char) {
    //
    //     let rev_lock_result = deserialize_hex_string(ser_rev_lock);
    //     let _rev_lock = handle_errors!(rev_lock_result);
    //     let mut rl = [0u8; 32];
    //     rl.copy_from_slice(_rev_lock.as_slice());
    //
    //     let cust_close_pk_result = deserialize_hex_string(ser_cust_close_pk);
    //     let cust_close_pk = handle_errors!(cust_close_pk_result);
    //
    //     let self_delay_result = deserialize_hex_string(ser_self_delay);
    //     let self_delay = handle_errors!(self_delay_result);
    //     let mut to_self_delay = [0u8; 2];
    //     to_self_delay.copy_from_slice(&self_delay);
    //
    //     // Deserialize the merch_state
    //     let merch_state_result: ResultSerdeType<MerchantMPCState> = deserialize_result_object(ser_merch_state);
    //     let merch_state = handle_errors!(merch_state_result);
    //
    //
    //     // merchant_sign_merch_dispute_transaction(txid_le: Vec<u8>, index: u32, input_sats: i64, self_delay_le: [u8; 2], output_pk: Vec<u8>, rev_lock: Vec<u8>, rev_secret: Vec<u8>, cust_close_pk: Vec<u8>, merch_disp_pk: Vec<u8>, merch_sk: secp256k1::SecretKey)
    // }


}
