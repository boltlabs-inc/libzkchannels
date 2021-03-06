//#[no_mangle]
pub mod ffishim {
    extern crate libc;

    use pairing::bls12_381::Bls12;
    use pairing::CurveProjective;
    use pairing::{
        bls12_381::{G1Uncompressed, G2Uncompressed},
        EncodedPoint,
    };
    use zkproofs;

    use serde::Deserialize;

    use libc::c_char;
    use std::collections::HashMap;
    use std::ffi::{CStr, CString};
    use std::str;
    use zkchan_tx::fixed_size_array::FixedSizeArray16;

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
    type CURVE = Bls12;

    fn deserialize_result_object<'a, T>(serialized: *mut c_char) -> ResultSerdeType<T>
    where
        T: Deserialize<'a>,
    {
        let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
        let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
        serde_json::from_str(&string)
    }

    // fn deserialize_hex_string(serialized: *mut c_char) -> Result<Vec<u8>, FromHexError> {
    //     let bytes = unsafe { CStr::from_ptr(serialized).to_bytes() };
    //     let string: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8
    //     hex::decode(&string)
    // }

    #[no_mangle]
    pub extern "C" fn ffishim_free_string(pointer: *mut c_char) {
        unsafe {
            if pointer.is_null() {
                return;
            }
            CString::from_raw(pointer)
        };
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_tze_check_wpk(ser_wpk: *mut c_char) -> *mut c_char {
        let wpk_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_wpk);
        let _wpk = handle_errors!(wpk_result);

        let res = true;
        let ser = [
            "{\'result\':\'",
            serde_json::to_string(&res).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_channel_setup(
        channel_name: *const c_char,
        third_party_support: u32,
    ) -> *mut c_char {
        let bytes = unsafe { CStr::from_ptr(channel_name).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let mut tps = false;
        if third_party_support > 1 {
            tps = true;
        }
        let channel_state = zkproofs::ChannelState::<CURVE>::new(name.to_string(), tps);

        let ser = [
            "{\'channel_state\':\'",
            serde_json::to_string(&channel_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // INIT

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_init_merchant_init(
        ser_channel_state: *mut c_char,
        name_ptr: *const c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let (channel_token, merch_state, channel_state) =
            zkproofs::merchant_init(rng, &mut channel_state, name);

        let ser = [
            "{\'channel_token\':\'",
            serde_json::to_string(&channel_token).unwrap().as_str(),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\', \'channel_state\':\'",
            serde_json::to_string(&channel_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();

        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_init_customer_init(
        ser_channel_token: *mut c_char,
        balance_customer: i64,
        balance_merchant: i64,
        name_ptr: *const c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<CURVE>> =
            deserialize_result_object(ser_channel_token);
        let mut channel_token = handle_errors!(channel_token_result);

        // Deserialize the name
        let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        // We change the channel state
        let cust_state = zkproofs::customer_init(
            rng,
            &mut channel_token,
            balance_customer,
            balance_merchant,
            name,
        );
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

    // ESTABLISH

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_generate_channel_id(
        ser_channel_token: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<CURVE>> =
            deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        let id = channel_token.compute_channel_id();
        let ser = [
            "{\'channel_id\':\'",
            serde_json::to_string(&id).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_validate_channel_params(
        ser_init_state: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let init_state_result: ResultSerdeType<zkproofs::Wallet<CURVE>> =
            deserialize_result_object(ser_init_state);
        let init_state = handle_errors!(init_state_result);

        // Deserialize the merchant state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        let close_token = zkproofs::validate_channel_params(rng, &init_state, &merch_state);

        let ser = [
            "{\'close_token\':\'",
            serde_json::to_string(&close_token).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_verify_init_close_token(
        ser_channel_state: *mut c_char,
        ser_customer_state: *mut c_char,
        ser_close_token: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_customer_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the close token
        let close_result: ResultSerdeType<zkproofs::Signature<CURVE>> =
            deserialize_result_object(ser_close_token);
        let close_token = handle_errors!(close_result);

        let is_close_token_valid =
            cust_state.verify_init_close_token(&mut channel_state, close_token);

        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'is_token_valid\':\'",
            serde_json::to_string(&is_close_token_valid)
                .unwrap()
                .as_str(),
            "\', \'channel_state\':\'",
            serde_json::to_string(&channel_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // ACTIVATE

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_activate_customer(ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the cust_state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // We change the channel state
        let init_state = handle_errors!(zkproofs::activate::customer_init(&mut cust_state));
        let ser = [
            "{\'state\':\'",
            serde_json::to_string(&init_state).unwrap().as_str(),
            "\', \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_activate_merchant(
        ser_init_state: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let init_state_result: ResultSerdeType<zkproofs::Wallet<CURVE>> =
            deserialize_result_object(ser_init_state);
        let init_state = handle_errors!(init_state_result);

        // Deserialize the merchant state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let pay_token = zkproofs::activate::merchant_init(rng, &init_state, &mut merch_state);

        let ser = [
            "{\'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\', \'pay_token\':\'",
            serde_json::to_string(&pay_token).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_verify_close_token(
        ser_channel_state: *mut c_char,
        ser_customer_state: *mut c_char,
        ser_close_token: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_customer_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the close token
        let close_result: ResultSerdeType<zkproofs::Signature<CURVE>> =
            deserialize_result_object(ser_close_token);
        let close_token = handle_errors!(close_result);

        let is_close_token_valid = cust_state.verify_close_token(&mut channel_state, &close_token);

        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'is_token_valid\':\'",
            serde_json::to_string(&is_close_token_valid)
                .unwrap()
                .as_str(),
            "\', \'channel_state\':\'",
            serde_json::to_string(&channel_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_activate_customer_finalize(
        ser_channel_state: *mut c_char,
        ser_customer_state: *mut c_char,
        ser_pay_token: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_customer_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the custdata
        let pay_token_result: ResultSerdeType<zkproofs::Signature<CURVE>> =
            deserialize_result_object(ser_pay_token);
        let pay_token = handle_errors!(pay_token_result);

        let is_channel_established =
            zkproofs::activate::customer_finalize(&mut channel_state, &mut cust_state, pay_token);

        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'is_established\':\'",
            serde_json::to_string(&is_channel_established)
                .unwrap()
                .as_str(),
            "\', \'channel_state\':\'",
            serde_json::to_string(&channel_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // UNLINK

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_unlink_customer_update_state(
        ser_channel_state: *mut c_char,
        ser_customer_state: *mut c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_customer_state);
        let cust_state = handle_errors!(cust_state_result);

        // Generate the payment proof
        let (session_id, payment, new_cust_state) =
            zkproofs::unlink::customer_update_state(rng, &channel_state, &cust_state);
        // Serialize the results and return to caller
        let ser = [
            "{\'session_id\':\'",
            &hex::encode(&session_id),
            "\', \'payment\':\'",
            serde_json::to_string(&payment).unwrap().as_str(),
            "\', \'cust_state\':\'",
            serde_json::to_string(&new_cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_unlink_merchant_update_state(
        ser_channel_state: *mut c_char,
        ser_session_id: *mut c_char,
        ser_pay_proof: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize session id
        let session_id_buf = unsafe { CStr::from_ptr(ser_session_id).to_bytes() };
        check_vec_length!(session_id_buf, 16);
        let mut session_id: [u8; 16] = [0u8; 16];
        session_id.copy_from_slice(session_id_buf);

        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the payment proof
        let payment_result: ResultSerdeType<zkproofs::Payment<CURVE>> =
            deserialize_result_object(ser_pay_proof);
        let payment = handle_errors!(payment_result);

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let close_token = zkproofs::unlink::merchant_update_state(
            rng,
            &channel_state,
            &session_id,
            &payment,
            &mut merch_state,
        );
        let ser = [
            "{\'close_token\':\'",
            serde_json::to_string(&close_token).unwrap().as_str(),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_unlink_customer_unmask(
        ser_channel_state: *mut c_char,
        ser_cust_state: *mut c_char,
        ser_new_cust_state: *mut c_char,
        ser_new_close_token: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the cust state
        let new_cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_new_cust_state);
        let new_cust_state = handle_errors!(new_cust_state_result);

        // Deserialize the close token
        let close_token_result: ResultSerdeType<zkproofs::Signature<CURVE>> =
            deserialize_result_object(ser_new_close_token);
        let new_close_token = handle_errors!(close_token_result);

        let revoke_token_result = zkproofs::pay::customer_unmask(
            &channel_state,
            &mut cust_state,
            new_cust_state,
            &new_close_token,
        );
        let rev_lock_pair = handle_errors!(revoke_token_result);
        let ser = [
            "{\'rev_lock_pair\':\'",
            serde_json::to_string(&rev_lock_pair).unwrap().as_str(),
            "\', \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_unlink_merchant_validate_rev_lock(
        ser_session_id: *mut c_char,
        ser_revoked_state: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize session id
        let session_id_buf = unsafe { CStr::from_ptr(ser_session_id).to_bytes() };
        check_vec_length!(session_id_buf, 16);
        let mut session_id: [u8; 16] = [0u8; 16];
        session_id.copy_from_slice(session_id_buf);

        // Deserialize the revoke token
        let revoked_state_result: ResultSerdeType<zkproofs::RevLockPair> =
            deserialize_result_object(ser_revoked_state);
        let revoked_state = handle_errors!(revoked_state_result);

        // Deserialize the cust state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // send revoke token and get pay-token in response
        let pay_token_result = zkproofs::unlink::merchant_validate_rev_lock(
            &session_id,
            &revoked_state,
            &mut merch_state,
        );
        let pay_token = handle_errors!(pay_token_result);

        let ser = [
            "{\'pay_token\':\'",
            serde_json::to_string(&pay_token.unwrap()).unwrap().as_str(),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_unlink_customer_finalize(
        ser_channel_state: *mut c_char,
        ser_cust_state: *mut c_char,
        ser_pay_token: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the pay token
        let pay_token_result: ResultSerdeType<zkproofs::Signature<CURVE>> =
            deserialize_result_object(ser_pay_token);
        let pay_token = handle_errors!(pay_token_result);

        // verify the pay token and update internal state
        // let is_pay_valid = cust_state.unlink_verify_pay_token(&mut channel_state, &pay_token);
        let is_pay_valid =
            zkproofs::unlink::customer_finalize(&mut channel_state, &mut cust_state, pay_token);
        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'channel_state\':\'",
            serde_json::to_string(&channel_state).unwrap().as_str(),
            "\', \'is_pay_valid\':\'",
            serde_json::to_string(&is_pay_valid).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // PAY

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_pay_customer_prepare(
        ser_channel_state: *mut c_char,
        amount: i64,
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_cust_state);
        let cust_state = handle_errors!(cust_state_result);

        // Generate the payment proof
        let (nonce, session_id) = handle_errors!(zkproofs::pay::customer_prepare(
            rng,
            &channel_state,
            amount,
            &cust_state,
        ));
        // Serialize the results and return to caller
        let ser = [
            "{\'nonce\':\'",
            &hex::encode(nonce),
            "\', \'session_id\':\'",
            &hex::encode(session_id),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_pay_merchant_prepare(
        ser_session_id: *mut c_char,
        ser_nonce: *mut c_char,
        amount: i64,
        ser_merchant_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize nonce
        let nonce = unsafe { CStr::from_ptr(ser_nonce).to_bytes() };
        let mut nonce_fixed: [u8; 16] = [0u8; 16];
        nonce_fixed.copy_from_slice(nonce);

        // Deserialize session id
        let session_id_buf = unsafe { CStr::from_ptr(ser_session_id).to_bytes() };
        check_vec_length!(session_id_buf, 16);
        let mut session_id: [u8; 16] = [0u8; 16];
        session_id.copy_from_slice(session_id_buf);

        // Deserialize the cust state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merchant_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // Generate the payment proof
        let accepted = zkproofs::pay::merchant_prepare(
            &session_id,
            FixedSizeArray16(nonce_fixed),
            amount,
            &mut merch_state,
        );
        // Serialize the results and return to caller
        let ser = [
            "{\'accepted\':\'",
            serde_json::to_string(&accepted).unwrap().as_str(),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_pay_customer_update_state(
        ser_channel_state: *mut c_char,
        ser_customer_state: *mut c_char,
        amount: i64,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_customer_state);
        let cust_state = handle_errors!(cust_state_result);

        // Generate the payment proof
        let (payment, new_cust_state) =
            zkproofs::pay::customer_update_state(rng, &channel_state, &cust_state, amount);
        // Serialize the results and return to caller
        let ser = [
            "{\'payment\':\'",
            serde_json::to_string(&payment).unwrap().as_str(),
            "\', \'cust_state\':\'",
            serde_json::to_string(&new_cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_pay_merchant_update_state(
        ser_channel_state: *mut c_char,
        ser_session_id: *mut c_char,
        ser_pay_proof: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();

        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize session id
        let session_id_buf = unsafe { CStr::from_ptr(ser_session_id).to_bytes() };
        check_vec_length!(session_id_buf, 16);
        let mut session_id: [u8; 16] = [0u8; 16];
        session_id.copy_from_slice(session_id_buf);

        // Deserialize the payment proof
        let payment_result: ResultSerdeType<zkproofs::Payment<CURVE>> =
            deserialize_result_object(ser_pay_proof);
        let payment = handle_errors!(payment_result);

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let close_token = zkproofs::pay::merchant_update_state(
            rng,
            &channel_state,
            &session_id,
            &payment,
            &mut merch_state,
        );
        let ser = [
            "{\'close_token\':\'",
            serde_json::to_string(&close_token).unwrap().as_str(),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_pay_verify_multiple_payment_proofs(
        ser_channel_state: *mut c_char,
        ser_sender_pay_proof: *mut c_char,
        ser_receiver_pay_proof: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the payment proofs
        let sender_payment_result: ResultSerdeType<zkproofs::Payment<CURVE>> =
            deserialize_result_object(ser_sender_pay_proof);
        let sender_payment = handle_errors!(sender_payment_result);

        let receiver_payment_result: ResultSerdeType<zkproofs::Payment<CURVE>> =
            deserialize_result_object(ser_receiver_pay_proof);
        let receiver_payment = handle_errors!(receiver_payment_result);

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let close_token_result = zkproofs::pay::multi_customer_update_state(
            rng,
            &channel_state,
            &sender_payment,
            &receiver_payment,
            &mut merch_state,
        );
        let (sender_close_token, receiver_cond_close_token) =
            handle_errors!(close_token_result).unwrap();
        let ser = [
            "{\'sender_close_token\':\'",
            serde_json::to_string(&sender_close_token).unwrap().as_str(),
            "\', \'receiver_cond_close_token\':\'",
            serde_json::to_string(&receiver_cond_close_token)
                .unwrap()
                .as_str(),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_pay_customer_unmask(
        ser_channel_state: *mut c_char,
        ser_cust_state: *mut c_char,
        ser_new_cust_state: *mut c_char,
        ser_close_token: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the cust state
        let new_cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_new_cust_state);
        let new_cust_state = handle_errors!(new_cust_state_result);

        // Deserialize the close token
        let close_token_result: ResultSerdeType<zkproofs::Signature<CURVE>> =
            deserialize_result_object(ser_close_token);
        let close_token = handle_errors!(close_token_result);

        let revoke_token_result = zkproofs::pay::customer_unmask(
            &channel_state,
            &mut cust_state,
            new_cust_state,
            &close_token,
        );
        let rev_lock_pair = handle_errors!(revoke_token_result);
        let ser = [
            "{\'rev_lock_pair\':\'",
            serde_json::to_string(&rev_lock_pair).unwrap().as_str(),
            "\', \'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_pay_merchant_validate_rev_lock(
        ser_session_id: *mut c_char,
        ser_revoke_token: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize session id
        let session_id_buf = unsafe { CStr::from_ptr(ser_session_id).to_bytes() };
        check_vec_length!(session_id_buf, 16);
        let mut session_id: [u8; 16] = [0u8; 16];
        session_id.copy_from_slice(session_id_buf);

        // Deserialize the revoke token
        let revoke_token_result: ResultSerdeType<zkproofs::RevLockPair> =
            deserialize_result_object(ser_revoke_token);
        let revoke_token = handle_errors!(revoke_token_result);

        // Deserialize the cust state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // send revoke token and get pay-token in response
        let pay_token_result =
            zkproofs::pay::merchant_validate_rev_lock(&session_id, &revoke_token, &mut merch_state);
        let pay_token = handle_errors!(pay_token_result);

        let ser = [
            "{\'pay_token\':\'",
            serde_json::to_string(&pay_token.unwrap()).unwrap().as_str(),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_pay_customer_unmask_pay_token(
        ser_channel_state: *mut c_char,
        ser_cust_state: *mut c_char,
        ser_pay_token: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the pay token
        let pay_token_result: ResultSerdeType<zkproofs::Signature<CURVE>> =
            deserialize_result_object(ser_pay_token);
        let pay_token = handle_errors!(pay_token_result);

        // verify the pay token and update internal state
        let is_pay_valid = handle_errors!(zkproofs::pay::customer_unmask_pay_token(
            pay_token,
            &channel_state,
            &mut cust_state
        ));
        let ser = [
            "{\'cust_state\':\'",
            serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'is_pay_valid\':\'",
            serde_json::to_string(&is_pay_valid).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_multi_pay_merchant_unmask(
        ser_sender_revoke_token: *mut c_char,
        ser_receiver_revoke_token: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the revoke tokens
        let sender_revoke_token_result: ResultSerdeType<zkproofs::RevLockPair> =
            deserialize_result_object(ser_sender_revoke_token);
        let sender_revoke_token = handle_errors!(sender_revoke_token_result);

        let receiver_revoke_token_result: ResultSerdeType<zkproofs::RevLockPair> =
            deserialize_result_object(ser_receiver_revoke_token);
        let receiver_revoke_token = handle_errors!(receiver_revoke_token_result);

        // Deserialize the cust state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // send revoke token and get pay-token in response
        let pay_token_result = zkproofs::pay::multi_merchant_unmask(
            &sender_revoke_token,
            &receiver_revoke_token,
            &mut merch_state,
        );
        let (sender_pay_token, receiver_pay_token) = handle_errors!(pay_token_result).unwrap();

        let ser = [
            "{\'sender_pay_token\':\'",
            serde_json::to_string(&sender_pay_token).unwrap().as_str(),
            "\', \'receiver_pay_token\':\'",
            serde_json::to_string(&receiver_pay_token).unwrap().as_str(),
            "\', \'merch_state\':\'",
            serde_json::to_string(&merch_state).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // CLOSE

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_customer_close(
        ser_channel_state: *mut c_char,
        ser_cust_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<CURVE>> =
            deserialize_result_object(ser_cust_state);
        let cust_state = handle_errors!(cust_state_result);

        let cust_close =
            handle_errors!(zkproofs::force_customer_close(&channel_state, &cust_state));
        let ser = [
            "{\'cust_close\':\'",
            serde_json::to_string(&cust_close).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_decompress_cust_close_message(
        ser_channel_state: *mut c_char,
        ser_cust_close: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the customer close structure
        let cust_close_result: ResultSerdeType<zkproofs::ChannelcloseC<CURVE>> =
            deserialize_result_object(ser_cust_close);
        let cust_close = handle_errors!(cust_close_result);

        let cp = channel_state.cp.unwrap();
        let mut merch_pk_map = HashMap::new();
        let mut signature_map = HashMap::new();

        // encode the merch public key
        let g2 = G2Uncompressed::from_affine(cp.pub_params.mpk.g2.into_affine());
        let X2 = G2Uncompressed::from_affine(cp.pub_params.pk.X2.into_affine());

        // encode the signature
        let h1 = G1Uncompressed::from_affine(cust_close.merch_signature.h.into_affine());
        let h2 = G1Uncompressed::from_affine(cust_close.merch_signature.H.into_affine());

        merch_pk_map.insert("g2".to_string(), hex::encode(&g2));
        merch_pk_map.insert("X".to_string(), hex::encode(&X2));
        let l = cp.pub_params.pk.Y2.len();
        for i in 0..l {
            let key = format!("Y{}", i);
            let y = G2Uncompressed::from_affine(cp.pub_params.pk.Y2[i].into_affine());
            merch_pk_map.insert(key, hex::encode(&y));
        }

        signature_map.insert("h1".to_string(), hex::encode(&h1));
        signature_map.insert("h2".to_string(), hex::encode(&h2));

        let ser = [
            "{\'merch_pk\':\'",
            serde_json::to_string(&merch_pk_map).unwrap().as_str(),
            "\', \'signature\':\'",
            serde_json::to_string(&signature_map).unwrap().as_str(),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern "C" fn ffishim_bls12_merchant_close(
        ser_channel_state: *mut c_char,
        ser_channel_token: *mut c_char,
        _ser_address: *const c_char,
        ser_cust_close: *mut c_char,
        ser_merch_state: *mut c_char,
    ) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<CURVE>> =
            deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<CURVE>> =
            deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the customer close structure
        let cust_close_result: ResultSerdeType<zkproofs::ChannelcloseC<CURVE>> =
            deserialize_result_object(ser_cust_close);
        let cust_close = handle_errors!(cust_close_result);

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<CURVE>> =
            deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        // // Deserialize the destination address as a string
        // let ser_addr_bytes = unsafe { CStr::from_ptr(ser_address).to_bytes() };
        // let address: &str = str::from_utf8(ser_addr_bytes).unwrap(); // make sure the bytes are UTF-8

        let keys = handle_errors!(zkproofs::force_merchant_close(
            &channel_state,
            &channel_token,
            &cust_close,
            &merch_state,
        ));

        // let merch_close: zkproofs::ChannelcloseM =
        //     merch_state.sign_revoke_message(address.to_string(), &keys.revoke_token);

        let ser = [
            "{\'rev_lock\':\'",
            &hex::encode(&keys.rev_lock),
            "\', \'rev_secret\':\'",
            &hex::encode(&keys.rev_secret),
            "\'}",
        ]
        .concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // #[no_mangle]
    // pub extern "C" fn ffishim_bls12_tze_verify_cust_close_message(
    //     ser_channel_token: *mut c_char,
    //     ser_wpk: *mut c_char,
    //     ser_close_msg: *mut c_char,
    //     ser_close_token: *mut c_char,
    // ) -> *mut c_char {
    //     // Deserialize the channel token
    //     let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<CURVE>> =
    //         deserialize_result_object(ser_channel_token);
    //     let channel_token = handle_errors!(channel_token_result);

    //     // Deserialize the wpk
    //     let wpk_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_wpk);
    //     let wpk = handle_errors!(wpk_result);

    //     // Deserialize the close wallet
    //     let close_msg_result: ResultSerdeType<zkproofs::Wallet<CURVE>> =
    //         deserialize_result_object(ser_close_msg);
    //     let close_msg = handle_errors!(close_msg_result);

    //     // Deserialize the close token
    //     let close_token_result: ResultSerdeType<zkproofs::Signature<CURVE>> =
    //         deserialize_result_object(ser_close_token);
    //     let close_token = handle_errors!(close_token_result);

    //     // check the signatures
    //     let token_valid =
    //         zkproofs::tze_verify_cust_close_message(&channel_token, &wpk, &close_msg, &close_token);
    //     let ser = [
    //         "{\"result\":\"",
    //         serde_json::to_string(&token_valid).unwrap().as_str(),
    //         "\"}",
    //     ]
    //     .concat();
    //     let cser = CString::new(ser).unwrap();
    //     cser.into_raw()
    // }

    // #[no_mangle]
    // pub extern "C" fn ffishim_bls12_tze_verify_merch_close_message(
    //     ser_channel_token: *mut c_char,
    //     ser_wpk: *mut c_char,
    //     ser_merch_close: *mut c_char,
    // ) -> *mut c_char {
    //     // Deserialize the channel token
    //     let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<CURVE>> =
    //         deserialize_result_object(ser_channel_token);
    //     let channel_token = handle_errors!(channel_token_result);

    //     // Deserialize the wpk
    //     let wpk_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_wpk);
    //     let wpk = handle_errors!(wpk_result);

    //     // Deserialize the merch close
    //     //let revoke_token: secp256k1::Signature = deserialize_object(ser_revoke_token);
    //     let merch_close_result: ResultSerdeType<zkproofs::ChannelcloseM> =
    //         deserialize_result_object(ser_merch_close);
    //     let merch_close = handle_errors!(merch_close_result);

    //     let revoke_token_valid =
    //         zkproofs::tze_verify_revoke_message(&wpk, &merch_close.revoke.unwrap());
    //     let merch_close_valid =
    //         zkproofs::tze_verify_merch_close_message(&channel_token, &merch_close);
    //     let token_valid = revoke_token_valid && merch_close_valid;

    //     let ser = [
    //         "{\'result\':\'",
    //         serde_json::to_string(&token_valid).unwrap().as_str(),
    //         "\'}",
    //     ]
    //     .concat();
    //     let cser = CString::new(ser).unwrap();
    //     cser.into_raw()
    // }
}
