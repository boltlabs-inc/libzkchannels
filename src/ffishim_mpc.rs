//#[no_mangle]
pub mod ffishim_mpc {
    extern crate libc;

    use bindings::{cb_receive, cb_send};
    use channels_mpc::{
        ChannelMPCState, ChannelMPCToken, CustomerMPCState, InitCustState, MerchantMPCState,
        TransactionFeeInfo,
    };
    use channels_util::FundingTxInfo;
    use database::{MaskedTxMPCInputs, RedisDatabase, StateDatabase};
    use hex::FromHexError;
    use libc::{c_char, c_void};
    use mpc;
    use mpc::ChannelStatus;
    use mpc::RevokedState;
    use serde::Deserialize;
    use std::ffi::{CStr, CString};
    use std::str;
    use wallet::State;
    use zkchan_tx::Testnet;

    fn error_message(s: String) -> *mut c_char {
        let ser = ["{\'error\':\'", &s, "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    macro_rules! handle_errors {
        ($e:expr) => {
            match $e {
                Ok(val) => val,
                Err(err) => return error_message(err.to_string()),
            }
        };
    }

    macro_rules! check_vec_length {
        ($x: expr, $y: expr) => {
            if $x.len() != $y {
                return error_message(format!(
                    "{} does not have expected length: {}",
                    stringify!($x),
                    $y
                ));
            }
        };
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

    fn deserialize_hex_string(serialized: *mut c_char) -> Result<Vec<u8>, FromHexError> {
        let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
        let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
        hex::decode(&string)
    }

    fn deserialize_string(serialized: *mut c_char) -> Result<String, String> {
        let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
        match str::from_utf8(bytes) {
            Ok(n) => Ok(String::from(n)),
            Err(e) => Err(e.to_string()),
        }
    }

    #[no_mangle]
    pub extern "C" fn mpc_free_string(pointer: *mut c_char) {
        unsafe {
            if pointer.is_null() {
                return;
            }
            CString::from_raw(pointer)
        };
    }

    // UTILS

    #[no_mangle]
    pub extern "C" fn get_self_delay_be_hex(ser_channel_state: *mut c_char) -> *mut c_char {
        let channel_state_result: ResultSerdeType<mpc::ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        let ser = [
            "{\'self_delay_be\':\'",
            &hex::encode(channel_state.get_self_delay_be()),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // CHANNEL SETUP - define name, self-delay, third-party-support

    #[no_mangle]
    pub extern "C" fn mpc_channel_setup(
        channel_name: *const c_char,
        self_delay: u16,
        bal_min_cust: i64,
        bal_min_merch: i64,
        val_cpfp: i64,
        third_party_support: u32,
    ) -> *mut c_char {
        let bytes = unsafe { CStr::from_ptr(channel_name).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let mut tps = false;
        if third_party_support >= 1 {
            tps = true;
        }
        let channel_state = mpc::ChannelMPCState::new(
            name.to_string(),
            self_delay,
            bal_min_cust,
            bal_min_merch,
            val_cpfp,
            tps,
        );

        let ser = [
            "{\'channel_state\':\'",
            serde_json::to_string(&channel_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // INIT MERCHANT

    #[no_mangle]
    pub extern "C" fn mpc_init_merchant(
        db_url_str: *mut c_char,
        ser_channel_state: *mut c_char,
        name_ptr: *const c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        let channel_state_result: ResultSerdeType<mpc::ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
        let name: &str = handle_errors!(str::from_utf8(bytes));

        let db_url = handle_errors!(deserialize_string(db_url_str));

        let merch_state = mpc::init_merchant(rng, db_url, &mut channel_state, name);

        let ser = [
            "{\'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\', \'channel_state\':\'",
            serde_json::to_string(&channel_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // LOAD EXTERNAL WALLET

    #[no_mangle]
    pub extern "C" fn mpc_load_merchant_wallet(
        ser_merch_state: *mut c_char,
        ser_channel_state: *mut c_char,
        ser_sk_m: *mut c_char,
        ser_payout_sk: *mut c_char,
        ser_child_sk: *mut c_char,
        ser_dispute_sk: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        let sk = deserialize_hex_string(ser_sk_m);
        let sk_buf = handle_errors!(sk);
        check_vec_length!(sk_buf, 32);
        let mut merch_sk = [0u8; 32];
        merch_sk.copy_from_slice(sk_buf.as_slice());

        let psk = deserialize_hex_string(ser_payout_sk);
        let psk_buf = handle_errors!(psk);
        check_vec_length!(psk_buf, 32);
        let mut payout_sk = [0u8; 32];
        payout_sk.copy_from_slice(psk_buf.as_slice());

        let csk = deserialize_hex_string(ser_child_sk);
        let csk_buf = handle_errors!(csk);
        check_vec_length!(csk_buf, 32);
        let mut child_sk = [0u8; 32];
        child_sk.copy_from_slice(csk_buf.as_slice());

        let dsk = deserialize_hex_string(ser_dispute_sk);
        let dsk_buf = handle_errors!(dsk);
        check_vec_length!(dsk_buf, 32);
        let mut dispute_sk = [0u8; 32];
        dispute_sk.copy_from_slice(dsk_buf.as_slice());

        let _result = handle_errors!(merch_state.load_external_wallet(
            &mut channel_state,
            merch_sk,
            payout_sk,
            child_sk,
            dispute_sk
        ));
        let ser = [
            "{\'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\', \'channel_state\':\'",
            serde_json::to_string(&channel_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // INIT CUSTOMER

    #[no_mangle]
    pub extern "C" fn mpc_init_customer(
        ser_merch_pk: *mut c_char,
        cust_bal: i64,
        merch_bal: i64,
        ser_tx_fee_info: *mut c_char,
        name_ptr: *const c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the pk_m
        let merch_pk_result = deserialize_hex_string(ser_merch_pk);
        let merch_pk = handle_errors!(merch_pk_result);
        let pk_m = handle_errors!(secp256k1::PublicKey::from_slice(&merch_pk));

        // Deserialize the transaction fee info struct
        let tx_fee_info_result: ResultSerdeType<TransactionFeeInfo> =
            deserialize_result_object(ser_tx_fee_info);
        let tx_fee_info = handle_errors!(tx_fee_info_result);

        // Deserialize the name
        let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        // We change the channel state
        let (channel_token, cust_state) =
            mpc::init_customer(rng, &pk_m, cust_bal, merch_bal, &tx_fee_info, name);
        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'channel_token\':\'",
            serde_json::to_string(&channel_token).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_load_customer_wallet(
        ser_cust_state: *mut c_char,
        ser_channel_token: *mut c_char,
        ser_sk_c: *mut c_char,
        ser_payout_sk: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> =
            deserialize_result_object(ser_channel_token);
        let mut channel_token = handle_errors!(channel_token_result);

        let sk = deserialize_hex_string(ser_sk_c);
        let sk_buf = handle_errors!(sk);
        check_vec_length!(sk_buf, 32);
        let mut cust_sk = [0u8; 32];
        cust_sk.copy_from_slice(sk_buf.as_slice());

        let psk = deserialize_hex_string(ser_payout_sk);
        let psk_buf = handle_errors!(psk);
        check_vec_length!(psk_buf, 32);
        let mut payout_sk = [0u8; 32];
        payout_sk.copy_from_slice(psk_buf.as_slice());

        let _result =
            handle_errors!(cust_state.load_external_wallet(&mut channel_token, cust_sk, payout_sk));
        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'channel_token\':\'",
            serde_json::to_string(&channel_token).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // VALIDATE INITIAL STATE
    #[no_mangle]
    pub extern "C" fn mpc_get_initial_state(ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let cust_state = handle_errors!(cust_state_result);

        let (init_state, init_hash) = handle_errors!(mpc::get_initial_state(&cust_state));
        let ser = [
            "{\'init_state\':\'",
            serde_json::to_string(&init_state).unwrap().as_str(),
            "\', \'init_hash\':\'",
            &hex::encode(init_hash),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_validate_channel_params(
        ser_channel_token: *mut c_char,
        ser_init_state: *mut c_char,
        ser_init_hash: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> =
            deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the init state
        let init_state_result: ResultSerdeType<InitCustState> =
            deserialize_result_object(ser_init_state);
        let init_state = handle_errors!(init_state_result);

        // Deserialize init hash
        let init_hash_result = deserialize_hex_string(ser_init_hash);
        let hash_buf = handle_errors!(init_hash_result);
        check_vec_length!(hash_buf, 32);
        let mut init_hash = [0u8; 32];
        init_hash.copy_from_slice(hash_buf.as_slice());

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // get connection to the database
        let mut db: RedisDatabase =
            handle_errors!(RedisDatabase::new("mpc", merch_state.db_url.clone()));

        let is_ok = handle_errors!(mpc::validate_channel_params(
            &mut db as &mut dyn StateDatabase,
            &channel_token,
            &init_state,
            init_hash,
            &mut merch_state
        ));
        let ser = [
            "{\'is_ok\':",
            &is_ok.to_string(),
            ", \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_get_channel_id(ser_channel_token: *mut c_char) -> *mut c_char {
        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> =
            deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        let channel_id = handle_errors!(channel_token.compute_channel_id());
        let ser = ["{\'channel_id\':\'", &hex::encode(channel_id), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // ACTIVATE

    #[no_mangle]
    pub extern "C" fn mpc_activate_customer(ser_cust_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let state = handle_errors!(mpc::activate_customer(rng, &mut cust_state));
        let ser = [
            "{\'state\':\'",
            serde_json::to_string(&state).unwrap().as_str(),
            "\', \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_activate_merchant(
        ser_channel_token: *mut c_char,
        ser_state: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> =
            deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the state
        let state_result: ResultSerdeType<State> = deserialize_result_object(ser_state);
        let state = handle_errors!(state_result);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // get connection to the database
        let mut db: RedisDatabase =
            handle_errors!(RedisDatabase::new("mpc", merch_state.db_url.clone()));

        // We change the channel state
        let pay_token = handle_errors!(mpc::activate_merchant(
            &mut db as &mut dyn StateDatabase,
            channel_token,
            &state,
            &mut merch_state
        ));
        let ser = [
            "{\'pay_token\':\'",
            &hex::encode(pay_token),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_activate_customer_finalize(
        ser_pay_token: *mut c_char,
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize pay token
        let pay_token_result = deserialize_hex_string(ser_pay_token);
        let pay_token = handle_errors!(pay_token_result);
        check_vec_length!(pay_token, 32);
        let mut pay_token_0 = [0u8; 32];
        pay_token_0.copy_from_slice(pay_token.as_slice());

        // We change the channel state
        handle_errors!(mpc::activate_customer_finalize(
            pay_token_0,
            &mut cust_state
        ));
        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // PAYMENT

    #[no_mangle]
    pub extern "C" fn mpc_prepare_payment_customer(
        ser_channel_state: *mut c_char,
        amount: i64,
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let (state, rev_state, rev_lock_com, session_id) =
            match mpc::pay_prepare_customer(rng, &channel_state, amount, &mut cust_state) {
                Ok(n) => n,
                Err(e) => return error_message(e),
            };
        let ser = [
            "{\'rev_state\':\'",
            serde_json::to_string(&rev_state).unwrap().as_str(),
            "\', \'state\':\'",
            serde_json::to_string(&state).unwrap().as_str(),
            "\', \'rev_lock_com\':\'",
            &hex::encode(rev_lock_com),
            "\', \'session_id\':\'",
            &hex::encode(session_id),
            "\', \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_prepare_payment_merchant(
        ser_channel_state: *mut c_char,
        ser_session_id: *mut c_char,
        ser_nonce: *mut c_char,
        ser_rev_lock_com: *mut c_char,
        amount: i64,
        ser_justification: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize rev_lock_com
        let rev_lock_com_result = deserialize_hex_string(ser_rev_lock_com);
        let rev_lock_com = handle_errors!(rev_lock_com_result);
        check_vec_length!(rev_lock_com, 32);
        let mut rev_lock_com_ar = [0u8; 32];
        rev_lock_com_ar.copy_from_slice(rev_lock_com.as_slice());

        // Deserialize session_id
        let sess_id_result = deserialize_hex_string(ser_session_id);
        let session_id = handle_errors!(sess_id_result);
        check_vec_length!(session_id, 16);
        let mut session_id_ar = [0u8; 16];
        session_id_ar.copy_from_slice(session_id.as_slice());

        // Deserialize nonce
        let nonce_result = deserialize_hex_string(ser_nonce);
        let nonce = handle_errors!(nonce_result);
        check_vec_length!(nonce, 16);
        let mut nonce_ar = [0u8; 16];
        nonce_ar.copy_from_slice(nonce.as_slice());

        // Deserialize justification (if negative payment)
        let justification = handle_errors!(deserialize_string(ser_justification));

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // get connection to the database
        let mut db: RedisDatabase =
            handle_errors!(RedisDatabase::new("mpc", merch_state.db_url.clone()));

        // We change the channel state
        let pay_token_mask_com = handle_errors!(mpc::pay_prepare_merchant(
            rng,
            &mut db as &mut dyn StateDatabase,
            &channel_state,
            session_id_ar,
            nonce_ar,
            rev_lock_com_ar,
            amount,
            Some(justification),
            &mut merch_state
        ));
        let ser = [
            "{\'pay_token_mask_com\':\'",
            &hex::encode(pay_token_mask_com),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_pay_update_customer(
        ser_channel_state: *mut c_char,
        ser_channel_token: *mut c_char,
        ser_start_state: *mut c_char,
        ser_end_state: *mut c_char,
        ser_pay_token_mask_com: *mut c_char,
        ser_rev_lock_com: *mut c_char,
        amount: i64,
        ser_cust_state: *mut c_char,
        p_ptr: *mut c_void,
        send_cb: cb_send,
        receive_cb: cb_receive,
    ) -> *mut c_char {
        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> =
            deserialize_result_object(ser_channel_token);
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
        check_vec_length!(rev_lock_com, 32);
        let mut rev_lock_com_ar = [0u8; 32];
        rev_lock_com_ar.copy_from_slice(rev_lock_com.as_slice());

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let result = mpc::pay_update_customer(
            &mut channel_state,
            &channel_token,
            start_state,
            end_state,
            pay_token_mask_com_ar,
            rev_lock_com_ar,
            amount,
            &mut cust_state,
            p_ptr,
            send_cb,
            receive_cb,
        );
        let success = handle_errors!(result);
        let ser = [
            "{\'success\':\'",
            &success,
            "\', \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_pay_update_merchant(
        ser_channel_state: *mut c_char,
        ser_session_id: *mut c_char,
        ser_pay_token_mask_com: *mut c_char,
        ser_merch_state: *mut c_char,
        p_ptr: *mut c_void,
        send_cb: cb_send,
        receive_cb: cb_receive,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize session_id
        let sess_id_result = deserialize_hex_string(ser_session_id);
        let session_id = handle_errors!(sess_id_result);
        check_vec_length!(session_id, 16);
        let mut session_id_ar = [0u8; 16];
        session_id_ar.copy_from_slice(session_id.as_slice());

        // Deserialize pay_token_mask_com
        let pay_token_mask_com_result = deserialize_hex_string(ser_pay_token_mask_com);
        let pay_token_mask_com = handle_errors!(pay_token_mask_com_result);
        check_vec_length!(pay_token_mask_com, 32);
        let mut pay_token_mask_com_ar = [0u8; 32];
        pay_token_mask_com_ar.copy_from_slice(pay_token_mask_com.as_slice());

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // get connection to the database
        let mut db: RedisDatabase =
            handle_errors!(RedisDatabase::new("mpc", merch_state.db_url.clone()));

        // We change the channel state
        let result = mpc::pay_update_merchant(
            rng,
            &mut db as &mut dyn StateDatabase,
            &mut channel_state,
            session_id_ar,
            pay_token_mask_com_ar,
            &mut merch_state,
            p_ptr,
            send_cb,
            receive_cb,
        );
        let is_ok = handle_errors!(result);
        let ser = [
            "{\'is_ok\':",
            &is_ok.to_string(),
            ", \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_get_masked_tx_inputs(
        ser_session_id: *mut c_char,
        ser_success: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize session_id
        let sess_id_result = deserialize_hex_string(ser_session_id);
        let session_id = handle_errors!(sess_id_result);
        check_vec_length!(session_id, 16);
        let mut session_id_ar = [0u8; 16];
        session_id_ar.copy_from_slice(session_id.as_slice());

        // Deserialize success
        let success_result = deserialize_string(ser_success);
        let success = handle_errors!(success_result);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // get connection to the database
        let mut db: RedisDatabase =
            handle_errors!(RedisDatabase::new("mpc", merch_state.db_url.clone()));

        let result = mpc::pay_confirm_mpc_result(
            &mut db as &mut dyn StateDatabase,
            session_id_ar,
            success,
            &mut merch_state,
        );
        let masked_tx_inputs = handle_errors!(result);
        let ser = [
            "{\'masked_tx_inputs\':\'",
            serde_json::to_string(&masked_tx_inputs).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_pay_unmask_sigs_customer(
        ser_channel_state: *mut c_char,
        ser_channel_token: *mut c_char,
        ser_masked_tx_inputs: *mut c_char,
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> =
            deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize masked_tx_inputs
        let masked_tx_inputs_result: ResultSerdeType<MaskedTxMPCInputs> =
            deserialize_result_object(ser_masked_tx_inputs);
        let masked_tx_inputs = handle_errors!(masked_tx_inputs_result);

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let is_ok = handle_errors!(mpc::pay_unmask_sigs_customer(
            &channel_state,
            &channel_token,
            masked_tx_inputs,
            &mut cust_state
        ));
        let ser = [
            "{\'is_ok\':",
            &is_ok.to_string(),
            ", \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_pay_validate_rev_lock_merchant(
        ser_session_id: *mut c_char,
        ser_revoked_state: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize session_id
        let sess_id_result = deserialize_hex_string(ser_session_id);
        let session_id = handle_errors!(sess_id_result);
        check_vec_length!(session_id, 16);
        let mut session_id_ar = [0u8; 16];
        session_id_ar.copy_from_slice(session_id.as_slice());

        // Deserialize masked_tx_inputs
        let revoked_state_result: ResultSerdeType<RevokedState> =
            deserialize_result_object(ser_revoked_state);
        let revoked_state = handle_errors!(revoked_state_result);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // get connection to the database
        let mut db: RedisDatabase =
            handle_errors!(RedisDatabase::new("mpc", merch_state.db_url.clone()));

        // We change the channel state
        let pay_token_mask_result = mpc::pay_validate_rev_lock_merchant(
            &mut db as &mut dyn StateDatabase,
            session_id_ar,
            revoked_state,
            &mut merch_state,
        );
        let pt = handle_errors!(pay_token_mask_result);
        let ser = [
            "{\'pay_token_mask\':\'",
            &hex::encode(pt.0),
            "\', \'pay_token_mask_r\':\'",
            &hex::encode(pt.1),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn mpc_pay_unmask_pay_token_customer(
        ser_pt_mask_bytes: *mut c_char,
        ser_pt_mask_r: *mut c_char,
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize pt_mask_bytes
        let pt_mask_bytes_result = deserialize_hex_string(ser_pt_mask_bytes);
        let pt_mask_bytes = handle_errors!(pt_mask_bytes_result);
        check_vec_length!(pt_mask_bytes, 32);
        let mut pt_mask_bytes_ar = [0u8; 32];
        pt_mask_bytes_ar.copy_from_slice(pt_mask_bytes.as_slice());

        // Deserialize pt_mask_bytes
        let pt_mask_r_result = deserialize_hex_string(ser_pt_mask_r);
        let pt_mask_r = handle_errors!(pt_mask_r_result);
        check_vec_length!(pt_mask_r, 16);
        let mut pt_mask_r_ar = [0u8; 16];
        pt_mask_r_ar.copy_from_slice(pt_mask_r.as_slice());

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let is_ok = handle_errors!(mpc::pay_unmask_pay_token_customer(
            pt_mask_bytes_ar,
            pt_mask_r_ar,
            &mut cust_state
        ));
        let ser = [
            "{\'is_ok\':",
            &is_ok.to_string(),
            ", \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Change customer state to open (after escrow-tx confirmed on chain)
    #[no_mangle]
    pub extern "C" fn cust_change_channel_status_to_open(
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        handle_errors!(mpc::customer_mark_open_channel(&mut cust_state));

        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Change customer state to pending close (after close-tx detected on chain)
    #[no_mangle]
    pub extern "C" fn cust_change_channel_status_to_pending_close(
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        handle_errors!(cust_state.change_channel_status(ChannelStatus::PendingClose));

        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Change customer state to confirmed after
    #[no_mangle]
    pub extern "C" fn cust_change_channel_status_to_confirmed_close(
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        handle_errors!(cust_state.change_channel_status(ChannelStatus::ConfirmedClose));

        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn cust_clear_channel_status(ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        handle_errors!(cust_state.change_channel_status(ChannelStatus::None));

        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn merch_change_channel_status_to_open(
        ser_escrow_txid: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the escrow txid
        let escrow_txid_result = deserialize_hex_string(ser_escrow_txid);
        let escrow_txid_le_vec = handle_errors!(escrow_txid_result);
        check_vec_length!(escrow_txid_le_vec, 32);
        let mut escrow_txid_le = [0u8; 32];
        escrow_txid_le.copy_from_slice(escrow_txid_le_vec.as_slice());

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        handle_errors!(mpc::merchant_mark_open_channel(
            escrow_txid_le,
            &mut merch_state
        ));

        let ser = [
            "{\'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Change channel id'ed by escrow-txid => pending (in merchant state)
    #[no_mangle]
    pub extern "C" fn merch_change_channel_status_to_pending_close(
        ser_escrow_txid: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the escrow txid
        let escrow_txid_result = deserialize_hex_string(ser_escrow_txid);
        let escrow_txid_le = handle_errors!(escrow_txid_result);
        check_vec_length!(escrow_txid_le, 32);

        let mut escrow_txid_be = [0u8; 32];
        escrow_txid_be.copy_from_slice(escrow_txid_le.as_slice());
        escrow_txid_be.reverse();

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        handle_errors!(
            merch_state.change_channel_status(escrow_txid_be, ChannelStatus::PendingClose)
        );

        let ser = [
            "{\'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Change channel id'ed by escrow-txid => confirmed (in merchant state)
    #[no_mangle]
    pub extern "C" fn merch_change_channel_status_to_confirmed_close(
        ser_escrow_txid: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the escrow txid
        let escrow_txid_result = deserialize_hex_string(ser_escrow_txid);
        let escrow_txid_le = handle_errors!(escrow_txid_result);
        check_vec_length!(escrow_txid_le, 32);

        let mut escrow_txid_be = [0u8; 32];
        escrow_txid_be.copy_from_slice(escrow_txid_le.as_slice());
        escrow_txid_be.reverse();

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        handle_errors!(
            merch_state.change_channel_status(escrow_txid_be, ChannelStatus::ConfirmedClose)
        );

        let ser = [
            "{\'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn merch_clear_channel_status(
        ser_escrow_txid: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the escrow txid
        let escrow_txid_result = deserialize_hex_string(ser_escrow_txid);
        let escrow_txid_le = handle_errors!(escrow_txid_result);
        check_vec_length!(escrow_txid_le, 32);

        let mut escrow_txid_be = [0u8; 32];
        escrow_txid_be.copy_from_slice(escrow_txid_le.as_slice());
        escrow_txid_be.reverse();

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        handle_errors!(merch_state.change_channel_status(escrow_txid_be, ChannelStatus::None));

        let ser = [
            "{\'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // TRANSACTION BUILDER FOR ESCROW, MERCH-CLOSE-TX and CUST-CLOSE-TXS

    #[no_mangle]
    pub extern "C" fn force_customer_close_tx(
        ser_channel_state: *mut c_char,
        ser_channel_token: *mut c_char,
        ser_from_escrow: u32,
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> =
            deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        let mut from_escrow = false;
        // deserialize ser_from_escrow accordingly
        if ser_from_escrow >= 1 {
            from_escrow = true;
        }

        let (signed_tx, _, txid_le) = handle_errors!(mpc::force_customer_close(
            &channel_state,
            &channel_token,
            from_escrow,
            &mut cust_state
        ));
        let ser = [
            "{\'signed_tx\':\'",
            &hex::encode(signed_tx),
            "\', \'txid_le\':\'",
            &hex::encode(txid_le),
            "\', \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn force_merchant_close_tx(
        ser_escrow_txid: *mut c_char,
        ser_merch_state: *mut c_char,
        val_cpfp: i64,
    ) -> *mut c_char {
        // Deserialize the escrow-txid
        let escrow_txid_le_result = deserialize_hex_string(ser_escrow_txid);
        let mut escrow_txid_be = handle_errors!(escrow_txid_le_result);
        escrow_txid_be.reverse();

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // use channel token to retrieve initial channel params, then generate the merch-close-tx and sign it
        let (signed_tx, txid_be, txid_le) = handle_errors!(mpc::force_merchant_close(
            &escrow_txid_be,
            val_cpfp,
            &mut merch_state
        ));
        let ser = [
            "{\'signed_tx\':\'",
            &hex::encode(signed_tx),
            "\', \'txid_be\':\'",
            &hex::encode(txid_be),
            "\', \'txid_le\':\'",
            &hex::encode(txid_le),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn merchant_check_rev_lock(
        ser_rev_lock: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the rev_lock
        let rev_lock_result = deserialize_hex_string(ser_rev_lock);
        let _rev_lock = handle_errors!(rev_lock_result);

        let rev_lock_hex = hex::encode(&_rev_lock);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        // get connection to the database
        let mut db: RedisDatabase =
            handle_errors!(RedisDatabase::new("mpc", merch_state.db_url.clone()));

        let rs_result = db.get_rev_secret(&rev_lock_hex);
        let is_ok = rs_result.is_ok();
        let rev_secret = handle_errors!(rs_result);

        let ser = [
            "{\'is_ok\':",
            &is_ok.to_string(),
            ", \'found_rev_secret\':\'",
            &rev_secret,
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Form the escrow-tx
    #[no_mangle]
    pub extern "C" fn cust_create_escrow_transaction(
        ser_txid: *mut c_char,
        index: u32,
        ser_cust_sk: *mut c_char,
        input_sats: i64,
        output_sats: i64,
        ser_cust_pk: *mut c_char,
        ser_merch_pk: *mut c_char,
        ser_change_pk: *mut c_char,
        ser_change_pk_is_hash: u32,
        tx_fee: i64,
        ser_should_sign: u32,
    ) -> *mut c_char {
        let txid_result = deserialize_hex_string(ser_txid);
        let txid = handle_errors!(txid_result);

        // Deserialize the sk_c
        let cust_sk_result = deserialize_hex_string(ser_cust_sk);
        let cust_sk = handle_errors!(cust_sk_result);

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let merch_pk_result = deserialize_hex_string(ser_merch_pk);
        let merch_pk = handle_errors!(merch_pk_result);

        let change_pk_result = deserialize_hex_string(ser_change_pk);
        let change_pk = handle_errors!(change_pk_result);

        let mut change_pk_is_hash = false;
        // deserialize ser_from_escrow accordingly
        if ser_change_pk_is_hash >= 1 {
            change_pk_is_hash = true;
        }

        let mut should_sign = false;
        if ser_should_sign >= 1 {
            should_sign = true;
        }

        let ser = match should_sign {
            true => {
                // proceed to sign
                let (signed_tx, txid_be, txid_le, prevout) =
                    handle_errors!(zkchan_tx::txutil::customer_sign_escrow_transaction(
                        &txid,
                        index,
                        &cust_sk,
                        input_sats,
                        output_sats,
                        &cust_pk,
                        &merch_pk,
                        Some(&change_pk),
                        change_pk_is_hash,
                        tx_fee
                    ));
                let ser = [
                    "{\'signed_tx\':\'",
                    &hex::encode(signed_tx),
                    "\', \'txid_be\':\'",
                    &hex::encode(txid_be),
                    "\', \'txid_le\':\'",
                    &hex::encode(txid_le),
                    "\', \'hash_prevout\':\'",
                    &hex::encode(prevout),
                    "\'}",
                ]
                .concat();
                ser
            }
            false => {
                // proceed to form and return the txid/prevout
                let (txid_be, txid_le, prevout) =
                    handle_errors!(zkchan_tx::txutil::customer_form_escrow_transaction(
                        &txid,
                        index,
                        &cust_sk,
                        input_sats,
                        output_sats,
                        &cust_pk,
                        &merch_pk,
                        Some(&change_pk),
                        change_pk_is_hash,
                        tx_fee
                    ));
                let ser = [
                    "{\'txid_be\':\'",
                    &hex::encode(txid_be),
                    "\', \'txid_le\':\'",
                    &hex::encode(txid_le),
                    "\', \'hash_prevout\':\'",
                    &hex::encode(prevout),
                    "\'}",
                ]
                .concat();
                ser
            }
        };
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Form the merch-close-tx
    #[no_mangle]
    pub extern "C" fn form_merch_close_transaction(
        ser_escrow_txid: *mut c_char,
        ser_cust_pk: *mut c_char,
        ser_merch_pk: *mut c_char,
        ser_merch_close_pk: *mut c_char,
        ser_merch_child_pk: *mut c_char,
        cust_bal_sats: i64,
        merch_bal_sats: i64,
        fee_mc: i64,
        val_cpfp: i64,
        ser_self_delay: *mut c_char,
    ) -> *mut c_char {
        let escrow_txid_le_result = deserialize_hex_string(ser_escrow_txid);
        let mut escrow_txid_be = handle_errors!(escrow_txid_le_result);
        escrow_txid_be.reverse(); // now it's in big endian

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let merch_pk_result = deserialize_hex_string(ser_merch_pk);
        let merch_pk = handle_errors!(merch_pk_result);

        let merch_close_pk_result = deserialize_hex_string(ser_merch_close_pk);
        let merch_close_pk = handle_errors!(merch_close_pk_result);

        let merch_child_pk_result = deserialize_hex_string(ser_merch_child_pk);
        let merch_child_pk = handle_errors!(merch_child_pk_result);

        let self_delay_result = deserialize_hex_string(ser_self_delay);
        let self_delay = handle_errors!(self_delay_result);
        check_vec_length!(self_delay, 2);
        let mut self_delay_be = [0u8; 2];
        self_delay_be.copy_from_slice(&self_delay);

        let (merch_tx_preimage, _) = handle_errors!(
            zkchan_tx::transactions::btc::merchant_form_close_transaction::<Testnet>(
                escrow_txid_be,
                cust_pk,
                merch_pk,
                merch_close_pk,
                merch_child_pk,
                cust_bal_sats,
                merch_bal_sats,
                fee_mc,
                val_cpfp,
                self_delay_be
            )
        );

        let ser = [
            "{\'merch_tx_preimage\':\'",
            &hex::encode(merch_tx_preimage),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Customer - signs the initial merch-close-tx
    #[no_mangle]
    pub extern "C" fn customer_sign_merch_close_tx(
        ser_cust_sk: *mut c_char,
        ser_merch_tx_preimage: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the sk_c
        let cust_sk_result = deserialize_hex_string(ser_cust_sk);
        let cust_sk = handle_errors!(cust_sk_result);

        let tx_preimage_result = deserialize_hex_string(ser_merch_tx_preimage);
        let merch_tx_preimage = handle_errors!(tx_preimage_result);

        let cust_sig = handle_errors!(zkchan_tx::txutil::customer_sign_merch_close_transaction(
            &cust_sk,
            &merch_tx_preimage
        ));
        let ser = ["{\'cust_sig\':\'", &hex::encode(cust_sig), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Merchant - verify & store the initial merch-close-tx (w/ sig from Customer)
    #[no_mangle]
    pub extern "C" fn merchant_verify_merch_close_tx(
        ser_escrow_txid: *mut c_char,
        ser_cust_pk: *mut c_char,
        cust_bal_sats: i64,
        merch_bal_sats: i64,
        fee_mc: i64,
        val_cpfp: i64,
        ser_self_delay: *mut c_char,
        ser_cust_sig: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let escrow_txid_le_result = deserialize_hex_string(ser_escrow_txid);
        let mut escrow_txid_be = handle_errors!(escrow_txid_le_result);
        escrow_txid_be.reverse();

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let self_delay_result = deserialize_hex_string(ser_self_delay);
        let self_delay = handle_errors!(self_delay_result);
        check_vec_length!(self_delay, 2);
        let mut self_delay_be = [0u8; 2];
        self_delay_be.copy_from_slice(&self_delay);

        let cust_sig_result = deserialize_hex_string(ser_cust_sig);
        let cust_sig = handle_errors!(cust_sig_result);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let merch_pk = merch_state.pk_m.serialize().to_vec();
        let merch_child_pk = merch_state.child_pk.serialize().to_vec();
        let merch_close_pk = merch_state.payout_pk.serialize().to_vec();

        let (merch_tx_preimage, tx_params) = handle_errors!(
            zkchan_tx::transactions::btc::merchant_form_close_transaction::<Testnet>(
                escrow_txid_be.clone(),
                cust_pk.clone(),
                merch_pk,
                merch_close_pk,
                merch_child_pk,
                cust_bal_sats,
                merch_bal_sats,
                fee_mc,
                val_cpfp,
                self_delay_be
            )
        );

        let is_ok = handle_errors!(zkchan_tx::txutil::merchant_verify_merch_close_transaction(
            &merch_tx_preimage,
            &cust_sig,
            &cust_pk
        ));
        if is_ok {
            merch_state.store_merch_close_tx(
                &escrow_txid_be,
                &cust_pk,
                cust_bal_sats,
                merch_bal_sats,
                fee_mc,
                self_delay_be,
                &cust_sig,
            );
        } else {
            return error_message(
                "could not validate customer signature on the merch-close-tx".to_string(),
            );
        }

        let (txid_be, prevout) = handle_errors!(
            zkchan_tx::txutil::merchant_generate_transaction_id(tx_params)
        );
        let mut txid_le = txid_be.to_vec();
        txid_le.reverse();

        let ser = [
            "{\'is_ok\':",
            serde_json::to_string(&is_ok).unwrap().as_str(),
            ", \'txid_be\':\'",
            &hex::encode(txid_be),
            "\', \'txid_le\':\'",
            &hex::encode(txid_le),
            "\', \'hash_prevout\':\'",
            &hex::encode(prevout),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Merchant - sign the initial cust-close-*-tx for a channel
    #[no_mangle]
    pub extern "C" fn merch_sign_init_cust_close_txs(
        ser_funding_tx: *mut c_char,
        ser_rev_lock: *mut c_char,
        ser_cust_pk: *mut c_char,
        ser_cust_close_pk: *mut c_char,
        ser_self_delay: *mut c_char,
        ser_merch_state: *mut c_char,
        fee_cc: i64,
        fee_mc: i64,
        val_cpfp: i64,
    ) -> *mut c_char {
        // Deserialize the tx
        let tx_result: ResultSerdeType<FundingTxInfo> = deserialize_result_object(ser_funding_tx);
        let funding_tx = handle_errors!(tx_result);

        let rev_lock_result = deserialize_hex_string(ser_rev_lock);
        let rev_lock = handle_errors!(rev_lock_result);
        check_vec_length!(rev_lock, 32);
        let mut rl = [0u8; 32];
        rl.copy_from_slice(rev_lock.as_slice());

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let cust_close_pk_result = deserialize_hex_string(ser_cust_close_pk);
        let cust_close_pk = handle_errors!(cust_close_pk_result);

        let self_delay_result = deserialize_hex_string(ser_self_delay);
        let self_delay = handle_errors!(self_delay_result);
        check_vec_length!(self_delay, 2);
        let mut self_delay_be = [0u8; 2];
        self_delay_be.copy_from_slice(&self_delay);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        let (escrow_sig, merch_sig) = handle_errors!(merch_state
            .sign_initial_closing_transaction::<Testnet>(
                funding_tx,
                rl,
                cust_pk,
                cust_close_pk,
                self_delay_be,
                fee_cc,
                fee_mc,
                val_cpfp,
            ));

        let ser = [
            "{\'escrow_sig\': \'",
            &hex::encode(escrow_sig),
            "\', \'merch_sig\':\'",
            &hex::encode(merch_sig),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Customer - verify the initial cust-close-*-tx signatures (from Merchant)
    #[no_mangle]
    pub extern "C" fn cust_verify_init_cust_close_txs(
        ser_funding_tx: *mut c_char,
        ser_tx_fee_info: *mut c_char,
        ser_channel_state: *mut c_char,
        ser_channel_token: *mut c_char,
        ser_escrow_sig: *mut c_char,
        ser_merch_sig: *mut c_char,
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the tx
        let tx_result: ResultSerdeType<FundingTxInfo> = deserialize_result_object(ser_funding_tx);
        let funding_tx = handle_errors!(tx_result);

        // Deserialize the transaction fee info struct
        let tx_fee_info_result: ResultSerdeType<TransactionFeeInfo> =
            deserialize_result_object(ser_tx_fee_info);
        let tx_fee_info = handle_errors!(tx_fee_info_result);

        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the ChannelToken
        let channel_token_result: ResultSerdeType<ChannelMPCToken> =
            deserialize_result_object(ser_channel_token);
        let mut channel_token = handle_errors!(channel_token_result);

        // Deserialize escrow-sig & merch-sig
        let escrow_sig_result = deserialize_hex_string(ser_escrow_sig);
        let escrow_sig = handle_errors!(escrow_sig_result);

        let merch_sig_result = deserialize_hex_string(ser_merch_sig);
        let merch_sig = handle_errors!(merch_sig_result);

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        handle_errors!(cust_state.set_initial_cust_state(
            &mut channel_token,
            &funding_tx,
            &tx_fee_info
        ));

        // now sign the customer's initial closing txs iff escrow-sig and merch-sig are valid
        let got_close_tx = handle_errors!(cust_state.sign_initial_closing_transaction::<Testnet>(
            &channel_state,
            &channel_token,
            &escrow_sig,
            &merch_sig
        ));
        let ser = [
            "{\'is_ok\':",
            serde_json::to_string(&got_close_tx).unwrap().as_str(),
            ", \'channel_token\':\'",
            serde_json::to_string(&channel_token).unwrap().as_str(),
            "\', \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Merchant - form dispute tx given a revocation secret for an existing cust-close-*-tx
    #[no_mangle]
    pub extern "C" fn sign_merch_dispute_tx(
        ser_escrow_txid: *mut c_char,
        ser_tx_index: *mut c_char,
        index: u32,
        input_amount: i64,
        output_amount: i64,
        ser_self_delay: *mut c_char,
        ser_output_pk: *mut c_char,
        ser_rev_lock: *mut c_char,
        ser_rev_secret: *mut c_char,
        ser_cust_close_pk: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let escrow_txid_result = deserialize_hex_string(ser_escrow_txid);
        let escrow_txid_le = handle_errors!(escrow_txid_result);
        check_vec_length!(escrow_txid_le, 32);

        let txid_result = deserialize_hex_string(ser_tx_index);
        let txid_le = handle_errors!(txid_result);
        check_vec_length!(txid_le, 32);

        let rev_lock_result = deserialize_hex_string(ser_rev_lock);
        let rev_lock = handle_errors!(rev_lock_result);

        let rev_secret_result = deserialize_hex_string(ser_rev_secret);
        let rev_secret = handle_errors!(rev_secret_result);

        let cust_close_pk_result = deserialize_hex_string(ser_cust_close_pk);
        let cust_close_pk = handle_errors!(cust_close_pk_result);

        let output_pk_result = deserialize_hex_string(ser_output_pk);
        let output_pk = handle_errors!(output_pk_result);

        let self_delay_result = deserialize_hex_string(ser_self_delay);
        let self_delay = handle_errors!(self_delay_result);
        check_vec_length!(self_delay, 2);
        let mut self_delay_be = [0u8; 2];
        self_delay_be.copy_from_slice(&self_delay);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let merch_disp_pk = merch_state.dispute_pk.serialize().to_vec();
        let merch_disp_sk = merch_state.get_dispute_secret_key();

        let mut escrow_txid_be = [0u8; 32];
        escrow_txid_be.copy_from_slice(escrow_txid_le.as_slice());
        escrow_txid_be.reverse();

        let signed_tx = handle_errors!(zkchan_tx::txutil::merchant_sign_merch_dispute_transaction(
            txid_le,
            index,
            input_amount,
            output_amount,
            self_delay_be,
            output_pk,
            rev_lock,
            rev_secret,
            cust_close_pk,
            merch_disp_pk,
            merch_disp_sk
        ));

        // if signed_tx successfully created, then proceed with updating the channel status
        handle_errors!(
            merch_state.change_channel_status(escrow_txid_be, ChannelStatus::PendingClose)
        );

        let ser = [
            "{\'signed_tx\': \'",
            &hex::encode(signed_tx),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    /// Merchant - claim output from cust-close-tx which is spendable immediately
    #[no_mangle]
    pub extern "C" fn merch_claim_tx_from_cust_close(
        ser_tx_index: *mut c_char,
        index: u32,
        input_amount: i64,
        output_amount: i64,
        ser_output_pk: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let txid_result = deserialize_hex_string(ser_tx_index);
        let txid_le = handle_errors!(txid_result);

        let output_pk_result = deserialize_hex_string(ser_output_pk);
        let output_pk = handle_errors!(output_pk_result);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        let merch_close_sk = merch_state.get_close_secret_key();

        let signed_tx = handle_errors!(
            zkchan_tx::txutil::merchant_sign_cust_close_claim_transaction(
                txid_le,
                index,
                input_amount,
                output_amount,
                output_pk,
                merch_close_sk
            )
        );
        let ser = ["{\'signed_tx\': \'", &hex::encode(signed_tx), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    /// Merchant - claim output from merch-close-tx after timeout   
    #[no_mangle]
    pub extern "C" fn merch_claim_tx_from_merch_close(
        ser_tx_index: *mut c_char,
        index: u32,
        input_amount: i64,
        output_amount: i64,
        ser_self_delay: *mut c_char,
        ser_cust_pk: *mut c_char,
        ser_output_pk: *mut c_char,
        cpfp_index: u32,
        cpfp_amount: i64,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let txid_le_result = deserialize_hex_string(ser_tx_index);
        let txid_le = handle_errors!(txid_le_result);

        let self_delay_result = deserialize_hex_string(ser_self_delay);
        let self_delay = handle_errors!(self_delay_result);
        check_vec_length!(self_delay, 2);
        let mut self_delay_be = [0u8; 2];
        self_delay_be.copy_from_slice(&self_delay);

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let output_pk_result = deserialize_hex_string(ser_output_pk);
        let output_pk = handle_errors!(output_pk_result);

        // Deserialize the merch_state
        let merch_state_result: ResultSerdeType<MerchantMPCState> =
            deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        let merch_pk = merch_state.pk_m.serialize().to_vec();
        let merch_close_sk = merch_state.get_close_secret_key();
        let merch_child_sk = merch_state.get_cpfp_secret_key();
        let merch_close_pk = merch_state.payout_pk.serialize().to_vec();

        let signed_tx = handle_errors!(
            zkchan_tx::txutil::merchant_sign_merch_close_claim_transaction(
                txid_le,
                index,
                input_amount,
                output_amount,
                output_pk,
                self_delay_be,
                cust_pk,
                merch_pk,
                merch_close_pk,
                merch_close_sk,
                Some((cpfp_index, cpfp_amount)),
                Some(merch_child_sk)
            )
        );
        let ser = ["{\'signed_tx\': \'", &hex::encode(signed_tx), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Customer - claim tx from cust-close-*-tx after timeout
    #[no_mangle]
    pub extern "C" fn cust_claim_tx_from_cust_close(
        ser_channel_state: *mut c_char,
        ser_tx_index: *mut c_char,
        index: u32,
        input_amount: i64,
        output_amount: i64,
        ser_self_delay: *mut c_char,
        ser_output_pk: *mut c_char,
        ser_rev_lock: *mut c_char,
        ser_cust_close_pk: *mut c_char,
        cpfp_index: u32,
        cpfp_amount: i64,
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel_state
        let channel_state_result: ResultSerdeType<ChannelMPCState> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        let txid_result = deserialize_hex_string(ser_tx_index);
        let txid_le = handle_errors!(txid_result);

        let rev_lock_result = deserialize_hex_string(ser_rev_lock);
        let rev_lock = handle_errors!(rev_lock_result);

        let cust_close_pk_result = deserialize_hex_string(ser_cust_close_pk);
        let cust_close_pk = handle_errors!(cust_close_pk_result);

        let output_pk_result = deserialize_hex_string(ser_output_pk);
        let output_pk = handle_errors!(output_pk_result);

        let self_delay_result = deserialize_hex_string(ser_self_delay);
        let self_delay = handle_errors!(self_delay_result);
        check_vec_length!(self_delay, 2);
        let mut self_delay_be = [0u8; 2];
        self_delay_be.copy_from_slice(&self_delay);

        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<CustomerMPCState> =
            deserialize_result_object(ser_cust_state);
        let cust_state = handle_errors!(cust_state_result);

        let merch_disp_pk = match channel_state.merch_dispute_pk {
            Some(n) => n.serialize().to_vec(),
            None => {
                return error_message(String::from(
                    "channel state does not have merch_disp_pk set",
                ))
            }
        };

        let cust_sk = cust_state.get_close_secret_key();
        let mut cpfp_utxo = None;
        let mut cpfp_sk = None;
        if cpfp_index > 0 && cpfp_amount > 0 {
            cpfp_utxo = Some((cpfp_index, cpfp_amount));
            cpfp_sk = Some(cust_sk.clone());
        }

        let signed_tx = handle_errors!(
            zkchan_tx::txutil::customer_sign_cust_close_claim_transaction(
                txid_le,
                index,
                input_amount,
                cust_sk,
                output_amount,
                self_delay_be,
                output_pk,
                rev_lock,
                cust_close_pk,
                merch_disp_pk,
                cpfp_utxo,
                cpfp_sk
            )
        );
        let ser = ["{\'signed_tx\': \'", &hex::encode(signed_tx), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // Customer - sign the mutual close transaction
    #[no_mangle]
    pub extern "C" fn cust_sign_mutual_close_tx(
        ser_tx_index: *mut c_char,
        index: u32,
        input_amount: i64,
        cust_amount: i64,
        merch_amount: i64,
        ser_merch_close_pk: *mut c_char,
        ser_cust_close_pk: *mut c_char,
        ser_merch_pk: *mut c_char,
        ser_cust_pk: *mut c_char,
        ser_cust_sk: *mut c_char,
    ) -> *mut c_char {
        let txid_result = deserialize_hex_string(ser_tx_index);
        let txid_le = handle_errors!(txid_result);

        // Deserialize the sk_c
        let cust_sk_result = deserialize_hex_string(ser_cust_sk);
        let cust_escrow_sk = handle_errors!(cust_sk_result);

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let cust_close_pk_result = deserialize_hex_string(ser_cust_close_pk);
        let cust_close_pk = handle_errors!(cust_close_pk_result);

        let merch_pk_result = deserialize_hex_string(ser_merch_pk);
        let merch_pk = handle_errors!(merch_pk_result);

        let merch_close_pk_result = deserialize_hex_string(ser_merch_close_pk);
        let merch_close_pk = handle_errors!(merch_close_pk_result);

        let escrow_input = zkchan_tx::transactions::UtxoInput {
            address_format: String::from("p2wsh"),
            // outpoint + txid
            transaction_id: txid_le,
            index: index,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(input_amount),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let cust_signature =
            handle_errors!(zkchan_tx::txutil::customer_sign_mutual_close_transaction(
                &escrow_input,
                &cust_pk,
                &merch_pk,
                &cust_close_pk,
                &merch_close_pk,
                cust_amount,
                merch_amount,
                &cust_escrow_sk,
            ));

        let ser = ["{\'cust_sig\': \'", &hex::encode(cust_signature), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn merch_sign_mutual_close_tx(
        ser_tx_index: *mut c_char,
        index: u32,
        input_amount: i64,
        cust_amount: i64,
        merch_amount: i64,
        ser_merch_close_pk: *mut c_char,
        ser_cust_close_pk: *mut c_char,
        ser_merch_pk: *mut c_char,
        ser_cust_pk: *mut c_char,
        ser_cust_sig: *mut c_char,
        ser_merch_sk: *mut c_char,
    ) -> *mut c_char {
        let txid_result = deserialize_hex_string(ser_tx_index);
        let txid_le = handle_errors!(txid_result);

        // Deserialize the keys and signature
        let merch_sk_result = deserialize_hex_string(ser_merch_sk);
        let merch_escrow_sk = handle_errors!(merch_sk_result);

        let cust_pk_result = deserialize_hex_string(ser_cust_pk);
        let cust_pk = handle_errors!(cust_pk_result);

        let cust_close_pk_result = deserialize_hex_string(ser_cust_close_pk);
        let cust_close_pk = handle_errors!(cust_close_pk_result);

        let merch_pk_result = deserialize_hex_string(ser_merch_pk);
        let merch_pk = handle_errors!(merch_pk_result);

        let merch_close_pk_result = deserialize_hex_string(ser_merch_close_pk);
        let merch_close_pk = handle_errors!(merch_close_pk_result);

        let cust_sig_result = deserialize_hex_string(ser_cust_sig);
        let cust_sig = handle_errors!(cust_sig_result);

        let escrow_input = zkchan_tx::transactions::UtxoInput {
            address_format: String::from("p2wsh"),
            // outpoint + txid
            transaction_id: txid_le,
            index: index,
            redeem_script: None,
            script_pub_key: None,
            utxo_amount: Some(input_amount),
            sequence: Some([0xff, 0xff, 0xff, 0xff]), // 4294967295
        };

        let (signed_tx, txid) =
            handle_errors!(zkchan_tx::txutil::merchant_sign_mutual_close_transaction(
                &escrow_input,
                &cust_pk,
                &merch_pk,
                &cust_close_pk,
                &merch_close_pk,
                cust_amount,
                merch_amount,
                &cust_sig,
                &merch_escrow_sk,
            ));
        let ser = [
            "{\'signed_tx\': \'",
            &hex::encode(signed_tx),
            "\', \'txid_le\':\'",
            &hex::encode(txid),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn create_child_tx_to_bump_fee_via_p2wpkh_input(
        ser_tx_index1: *mut c_char,
        index1: u32,
        input_amount1: i64,
        ser_sk1: *mut c_char,
        ser_tx_index2: *mut c_char,
        index2: u32,
        input_amount2: i64,
        ser_sk2: *mut c_char,
        ser_redeem_script: *mut c_char,
        tx_fee: i64,
        ser_output_pk: *mut c_char,
    ) -> *mut c_char {
        let txid1_result = deserialize_hex_string(ser_tx_index1);
        let txid1_le = handle_errors!(txid1_result);

        let txid2_result = deserialize_hex_string(ser_tx_index2);
        let txid2_le = handle_errors!(txid2_result);

        let output_pk_result = deserialize_hex_string(ser_output_pk);
        let output_pk = handle_errors!(output_pk_result);

        let sk_result1 = deserialize_hex_string(ser_sk1);
        let utxo_input_sk1 = handle_errors!(sk_result1);

        let sk_result2 = deserialize_hex_string(ser_sk2);
        let utxo_input_sk2 = handle_errors!(sk_result2);

        let rscript = handle_errors!(deserialize_string(ser_redeem_script));
        let mut address_format2 = String::from("p2wpkh");
        let mut redeem_script = None;
        if rscript != "" {
            address_format2 = String::from("p2wsh");
            redeem_script = Some(handle_errors!(hex::decode(&rscript)));
        }

        let (signed_tx, txid) =
            handle_errors!(zkchan_tx::txutil::create_child_transaction_to_bump_fee(
                txid1_le,
                index1,
                input_amount1,
                &utxo_input_sk1,
                txid2_le,
                index2,
                address_format2,
                input_amount2,
                &utxo_input_sk2,
                redeem_script,
                tx_fee,
                &output_pk,
            ));
        let ser = [
            "{\'signed_tx\': \'",
            &hex::encode(signed_tx),
            "\', \'txid_le\':\'",
            &hex::encode(txid),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }
}
