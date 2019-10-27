#[no_mangle]
pub mod ffishim {
    extern crate libc;

    use zkproofs;
    use ff::ScalarEngine;
    use pairing::bls12_381::Bls12;

    use serde::Deserialize;

    use libc::c_char;
    use std::ffi::{CStr, CString};
    use std::str;

    fn error_message(s: String) -> *mut c_char {
        let ser = ["{\'error\':\'", &s, "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    macro_rules! bolt_try {
        ($e:expr) => (match $e {
            Ok(val) => val.unwrap(),
            Err(err) => return error_message(err),
        });
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

    #[no_mangle]
    pub extern fn ffishim_free_string(pointer: *mut c_char) {
        unsafe {
            if pointer.is_null() { return; }
            CString::from_raw(pointer)
        };
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_wtp_check_wpk(ser_wpk: *mut c_char) -> *mut c_char {
        let wpk_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_wpk);
        let _wpk = handle_errors!(wpk_result);

        let res = true;
        let ser = ["{\'result\':\'", serde_json::to_string(&res).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_channel_setup(channel_name: *const c_char, third_party_support: u32) -> *mut c_char {
        let bytes = unsafe { CStr::from_ptr(channel_name).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let mut tps = false;
        if third_party_support > 1 {
            tps = true;
        }
        let channel_state = zkproofs::ChannelState::<Bls12>::new(name.to_string(), tps);

        let ser = ["{\'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // INIT

    #[no_mangle]
    pub extern fn ffishim_zkproofs_init_merchant(ser_channel_state: *mut c_char, name_ptr: *const c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        let (channel_token, merch_state, channel_state) = zkproofs::init_merchant(rng, &mut channel_state, name);

        let ser = ["{\'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str(), "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\', \'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str(), "\'}"].concat();

        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_init_customer(ser_channel_token: *mut c_char, balance_customer: i64, balance_merchant: i64, name_ptr: *const c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let mut channel_token = handle_errors!(channel_token_result);

        // Deserialize the name
        let bytes = unsafe { CStr::from_ptr(name_ptr).to_bytes() };
        let name: &str = str::from_utf8(bytes).unwrap(); // make sure the bytes are UTF-8

        // We change the channel state
        let cust_state = zkproofs::init_customer(rng, &mut channel_token, balance_customer, balance_merchant, name);
        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\', \'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // ESTABLISH

    #[no_mangle]
    pub extern fn ffishim_zkproofs_establish_customer_generate_proof(ser_channel_token: *mut c_char, ser_customer_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let mut channel_token = handle_errors!(channel_token_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<Bls12>> = deserialize_result_object(ser_customer_state);
        let mut cust_state = handle_errors!(cust_state_result);

        let (com, com_proof) = zkproofs::establish_customer_generate_proof(rng, &mut channel_token, &mut cust_state);

        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'channel_token\':\'", serde_json::to_string(&channel_token).unwrap().as_str(),
            "\', \'com\':\'", serde_json::to_string(&com).unwrap().as_str(),
            "\', \'com_proof\':\'", serde_json::to_string(&com_proof).unwrap().as_str(),
            "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_generate_channel_id(ser_channel_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        let id = channel_token.compute_channel_id();
        let ser = ["{\'channel_id\':\'", serde_json::to_string(&id).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_establish_merchant_issue_close_token(ser_channel_state: *mut c_char, ser_com: *mut c_char, ser_com_proof: *mut c_char, ser_channel_id: *mut c_char, init_cust_bal: i64, init_merch_bal: i64, ser_merch_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the com proof
        let com_result: ResultSerdeType<zkproofs::Commitment<Bls12>> = deserialize_result_object(ser_com);
        let com = handle_errors!(com_result);

        // Deserialize the com proof
        let com_proof_result: ResultSerdeType<zkproofs::CommitmentProof<Bls12>> = deserialize_result_object(ser_com_proof);
        let com_proof = handle_errors!(com_proof_result);

        // Deserialize the merchant state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        // Deserialize the pk_c
        let channel_id_result: ResultSerdeType<<Bls12 as ScalarEngine>::Fr> = deserialize_result_object(ser_channel_id);
        let channel_id_fr = handle_errors!(channel_id_result);

        let close_token = bolt_try!(zkproofs::establish_merchant_issue_close_token(rng, &channel_state, &com, &com_proof, &channel_id_fr, init_cust_bal, init_merch_bal, &merch_state));

        let ser = ["{\'close_token\':\'", serde_json::to_string(&close_token).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_establish_merchant_issue_pay_token(ser_channel_state: *mut c_char, ser_com: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the commitment
        let com_result: ResultSerdeType<zkproofs::Commitment<Bls12>> = deserialize_result_object(ser_com);
        let com = handle_errors!(com_result);

        // Deserialize the merchant state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        let pay_token = zkproofs::establish_merchant_issue_pay_token(rng, &channel_state, &com, &merch_state);

        let ser = ["{\'pay_token\':\'", serde_json::to_string(&pay_token).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_verify_close_token(ser_channel_state: *mut c_char, ser_customer_state: *mut c_char, ser_close_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<Bls12>> = deserialize_result_object(ser_customer_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the close token
        let close_result: ResultSerdeType<zkproofs::Signature<Bls12>> = deserialize_result_object(ser_close_token);
        let close_token = handle_errors!(close_result);

        let is_close_token_valid = cust_state.verify_close_token(&mut channel_state, &close_token);

        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'is_token_valid\':\'", serde_json::to_string(&is_close_token_valid).unwrap().as_str(),
            "\', \'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }


    #[no_mangle]
    pub extern fn ffishim_zkproofs_establish_customer_final(ser_channel_state: *mut c_char, ser_customer_state: *mut c_char, ser_pay_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let mut channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<Bls12>> = deserialize_result_object(ser_customer_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the custdata
        let pay_token_result: ResultSerdeType<zkproofs::Signature<Bls12>> = deserialize_result_object(ser_pay_token);
        let pay_token = handle_errors!(pay_token_result);

        let is_channel_established = zkproofs::establish_customer_final(&mut channel_state, &mut cust_state, &pay_token);

        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'is_established\':\'", serde_json::to_string(&is_channel_established).unwrap().as_str(),
            "\', \'channel_state\':\'", serde_json::to_string(&channel_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // PAY

    #[no_mangle]
    pub extern fn ffishim_zkproofs_pay_generate_payment_proof(ser_channel_state: *mut c_char, ser_customer_state: *mut c_char, amount: i64) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<Bls12>> = deserialize_result_object(ser_customer_state);
        let cust_state = handle_errors!(cust_state_result);

        // Generate the payment proof
        let (payment, new_cust_state) = zkproofs::generate_payment_proof(rng, &channel_state, &cust_state, amount);
        // Serialize the results and return to caller
        let ser = ["{\'payment\':\'", serde_json::to_string(&payment).unwrap().as_str(),
            "\', \'cust_state\':\'", serde_json::to_string(&new_cust_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_pay_verify_payment_proof(ser_channel_state: *mut c_char, ser_pay_proof: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the payment proof
        let payment_result: ResultSerdeType<zkproofs::Payment<Bls12>> = deserialize_result_object(ser_pay_proof);
        let payment = handle_errors!(payment_result);

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let close_token = zkproofs::verify_payment_proof(rng, &channel_state, &payment, &mut merch_state);
        let ser = ["{\'close_token\':\'", serde_json::to_string(&close_token).unwrap().as_str(),
            "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_pay_verify_multiple_payment_proofs(ser_channel_state: *mut c_char, ser_sender_pay_proof: *mut c_char, ser_receiver_pay_proof: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        let rng = &mut rand::thread_rng();
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the payment proofs
        let sender_payment_result: ResultSerdeType<zkproofs::Payment<Bls12>> = deserialize_result_object(ser_sender_pay_proof);
        let sender_payment = handle_errors!(sender_payment_result);

        let receiver_payment_result: ResultSerdeType<zkproofs::Payment<Bls12>> = deserialize_result_object(ser_receiver_pay_proof);
        let receiver_payment = handle_errors!(receiver_payment_result);

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        let close_token_result = zkproofs::verify_multiple_payment_proofs(rng, &channel_state, &sender_payment, &receiver_payment, &mut merch_state);
        let (sender_close_token, receiver_cond_close_token) = handle_errors!(close_token_result).unwrap();
        let ser = ["{\'sender_close_token\':\'", serde_json::to_string(&sender_close_token).unwrap().as_str(),
            "\', \'receiver_cond_close_token\':\'", serde_json::to_string(&receiver_cond_close_token).unwrap().as_str(),
            "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_pay_generate_revoke_token(ser_channel_state: *mut c_char, ser_cust_state: *mut c_char, ser_new_cust_state: *mut c_char, ser_close_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<Bls12>> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the cust state
        let new_cust_state_result: ResultSerdeType<zkproofs::CustomerState<Bls12>> = deserialize_result_object(ser_new_cust_state);
        let new_cust_state = handle_errors!(new_cust_state_result);

        // Deserialize the close token
        let close_token_result: ResultSerdeType<zkproofs::Signature<Bls12>> = deserialize_result_object(ser_close_token);
        let close_token = handle_errors!(close_token_result);

        let revoke_token = zkproofs::generate_revoke_token(&channel_state, &mut cust_state, new_cust_state, &close_token);
        let ser = ["{\'revoke_token\':\'", serde_json::to_string(&revoke_token).unwrap().as_str(),
            "\', \'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_pay_verify_revoke_token(ser_revoke_token: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        // Deserialize the revoke token
        let revoke_token_result: ResultSerdeType<zkproofs::RevokeToken> = deserialize_result_object(ser_revoke_token);
        let revoke_token = handle_errors!(revoke_token_result);

        // Deserialize the cust state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // send revoke token and get pay-token in response
        let pay_token_result = zkproofs::verify_revoke_token(&revoke_token, &mut merch_state);
        let pay_token = handle_errors!(pay_token_result);

        let ser = ["{\'pay_token\':\'", serde_json::to_string(&pay_token.unwrap()).unwrap().as_str(),
            "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_pay_verify_multiple_revoke_tokens(ser_sender_revoke_token: *mut c_char, ser_receiver_revoke_token: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        // Deserialize the revoke tokens
        let sender_revoke_token_result: ResultSerdeType<zkproofs::RevokeToken> = deserialize_result_object(ser_sender_revoke_token);
        let sender_revoke_token = handle_errors!(sender_revoke_token_result);

        let receiver_revoke_token_result: ResultSerdeType<zkproofs::RevokeToken> = deserialize_result_object(ser_receiver_revoke_token);
        let receiver_revoke_token = handle_errors!(receiver_revoke_token_result);

        // Deserialize the cust state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let mut merch_state = handle_errors!(merch_state_result);

        // send revoke token and get pay-token in response
        let pay_token_result = zkproofs::verify_multiple_revoke_tokens(&sender_revoke_token, &receiver_revoke_token, &mut merch_state);
        let (sender_pay_token, receiver_pay_token) = handle_errors!(pay_token_result).unwrap();

        let ser = ["{\'sender_pay_token\':\'", serde_json::to_string(&sender_pay_token).unwrap().as_str(),
            "\', \'receiver_pay_token\':\'", serde_json::to_string(&receiver_pay_token).unwrap().as_str(),
            "\', \'merch_state\':\'", serde_json::to_string(&merch_state).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }


    #[no_mangle]
    pub extern fn ffishim_zkproofs_pay_verify_payment_token(ser_channel_state: *mut c_char, ser_cust_state: *mut c_char, ser_pay_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<Bls12>> = deserialize_result_object(ser_cust_state);
        let mut cust_state = handle_errors!(cust_state_result);

        // Deserialize the pay token
        let pay_token_result: ResultSerdeType<zkproofs::Signature<Bls12>> = deserialize_result_object(ser_pay_token);
        let pay_token = handle_errors!(pay_token_result);

        // verify the pay token and update internal state
        let is_pay_valid = cust_state.verify_pay_token(&channel_state, &pay_token);
        let ser = ["{\'cust_state\':\'", serde_json::to_string(&cust_state).unwrap().as_str(),
            "\', \'is_pay_valid\':\'", serde_json::to_string(&is_pay_valid).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    // CLOSE

    #[no_mangle]
    pub extern fn ffishim_zkproofs_customer_close(ser_channel_state: *mut c_char, ser_cust_state: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the cust state
        let cust_state_result: ResultSerdeType<zkproofs::CustomerState<Bls12>> = deserialize_result_object(ser_cust_state);
        let cust_state = handle_errors!(cust_state_result);

        let cust_close = zkproofs::customer_close(&channel_state, &cust_state);
        let ser = ["{\'cust_close\':\'", serde_json::to_string(&cust_close).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_merchant_close(ser_channel_state: *mut c_char, ser_channel_token: *mut c_char, ser_address: *const c_char, ser_cust_close: *mut c_char, ser_merch_state: *mut c_char) -> *mut c_char {
        // Deserialize the channel state
        let channel_state_result: ResultSerdeType<zkproofs::ChannelState<Bls12>> = deserialize_result_object(ser_channel_state);
        let channel_state = handle_errors!(channel_state_result);

        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the customer close structure
        let cust_close_result: ResultSerdeType<zkproofs::ChannelcloseC<Bls12>> = deserialize_result_object(ser_cust_close);
        let cust_close = handle_errors!(cust_close_result);

        // Deserialize the merch state
        let merch_state_result: ResultSerdeType<zkproofs::MerchantState<Bls12>> = deserialize_result_object(ser_merch_state);
        let merch_state = handle_errors!(merch_state_result);

        // Deserialize the destination address as a string
        let ser_addr_bytes = unsafe { CStr::from_ptr(ser_address).to_bytes() };
        let address: &str = str::from_utf8(ser_addr_bytes).unwrap(); // make sure the bytes are UTF-8

        let option = zkproofs::merchant_close(&channel_state, &channel_token, &cust_close, &merch_state);
        let keys = match option {
            Ok(n) => n.unwrap(),
            Err(err) => return error_message(err),
        };

        let merch_close: zkproofs::ChannelcloseM = merch_state.sign_revoke_message(address.to_string(), &keys.revoke_token);

        let ser = ["{\'wpk\':\'", serde_json::to_string(&keys.wpk).unwrap().as_str(),
            "\', \'merch_close\':\'", serde_json::to_string(&merch_close).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_wtp_verify_cust_close_message(ser_channel_token: *mut c_char, ser_wpk: *mut c_char, ser_close_msg: *mut c_char, ser_close_token: *mut c_char) -> *mut c_char {
        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the wpk
        let wpk_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_wpk);
        let wpk = handle_errors!(wpk_result);

        // Deserialize the close wallet
        let close_msg_result: ResultSerdeType<zkproofs::Wallet<Bls12>> = deserialize_result_object(ser_close_msg);
        let close_msg = handle_errors!(close_msg_result);

        // Deserialize the close token
        let close_token_result: ResultSerdeType<zkproofs::Signature<Bls12>> = deserialize_result_object(ser_close_token);
        let close_token = handle_errors!(close_token_result);

        // check the signatures
        let token_valid = zkproofs::wtp_verify_cust_close_message(&channel_token, &wpk, &close_msg, &close_token);
        let ser = ["{\"result\":\"", serde_json::to_string(&token_valid).unwrap().as_str(), "\"}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }

    #[no_mangle]
    pub extern fn ffishim_zkproofs_wtp_verify_merch_close_message(ser_channel_token: *mut c_char, ser_wpk: *mut c_char, ser_merch_close: *mut c_char) -> *mut c_char {
        // Deserialize the channel token
        let channel_token_result: ResultSerdeType<zkproofs::ChannelToken<Bls12>> = deserialize_result_object(ser_channel_token);
        let channel_token = handle_errors!(channel_token_result);

        // Deserialize the wpk
        let wpk_result: ResultSerdeType<secp256k1::PublicKey> = deserialize_result_object(ser_wpk);
        let wpk = handle_errors!(wpk_result);

        // Deserialize the merch close
        //let revoke_token: secp256k1::Signature = deserialize_object(ser_revoke_token);
        let merch_close_result: ResultSerdeType<zkproofs::ChannelcloseM> = deserialize_result_object(ser_merch_close);
        let merch_close = handle_errors!(merch_close_result);

        let revoke_token_valid = zkproofs::wtp_verify_revoke_message(&wpk, &merch_close.revoke.unwrap());
        let merch_close_valid = zkproofs::wtp_verify_merch_close_message(&channel_token, &merch_close);
        let token_valid = revoke_token_valid && merch_close_valid;

        let ser = ["{\'result\':\'", serde_json::to_string(&token_valid).unwrap().as_str(), "\'}"].concat();
        let cser = CString::new(ser).unwrap();
        cser.into_raw()
    }
}
