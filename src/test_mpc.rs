#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use sha2::{Digest, Sha256};

    use bindings::ConnType_NETIO;
    use channels_mpc;
    use channels_util::{ChannelStatus, PaymentStatus, ProtocolStatus};
    use database::{
        get_file_from_db, store_file_in_db, HashMapDatabase, MaskedTxMPCInputs, RedisDatabase,
        StateDatabase,
    };
    use mpc;
    use std::process::Command;
    use std::{env, ptr};
    use zkchan_tx::fixed_size_array::FixedSizeArray32;
    use zkchan_tx::Testnet;
    use FundingTxInfo;

    #[test]
    fn test_establish_mpc_channel() {
        let mut rng = &mut rand::thread_rng();
        // let mut db = RedisDatabase::new("lib", "redis://127.0.0.1/").unwrap();
        let mut db = HashMapDatabase::new("", "".to_string()).unwrap();

        let min_threshold = 546;
        let val_cpfp = 1000;
        let mut channel_state = mpc::ChannelMPCState::new(
            String::from("Channel A -> B"),
            1487,
            min_threshold,
            min_threshold,
            val_cpfp,
            false,
        );
        // init merchant
        let mut merch_state = mpc::init_merchant(rng, "".to_string(), &mut channel_state, "Bob");

        let fee_cc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let fee_mc = 1000;
        let b0_cust = 10000;
        let b0_merch = 10000;

        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        // init customer
        let (mut channel_token, mut cust_state) = mpc::init_customer(
            rng,
            &merch_state.pk_m,
            b0_cust,
            b0_merch,
            &tx_fee_info,
            "Alice",
        );

        // form all of the escrow and merch-close-tx transactions
        let funding_tx_info = generate_funding_tx(&mut rng, b0_cust, b0_merch);

        // form and sign the cust-close-from-escrow-tx and from-merch-close-tx
        let pubkeys = cust_state.get_pubkeys(&channel_state, &channel_token);

        // merchant signs the customer's closing transactions and sends signatures back to customer
        let to_self_delay_be = channel_state.get_self_delay_be(); // [0x05, 0xcf]; // big-endian format
        let (escrow_sig, merch_sig) = merch_state
            .sign_initial_closing_transaction::<Testnet>(
                funding_tx_info.clone(),
                pubkeys.rev_lock.0,
                pubkeys.cust_pk,
                pubkeys.cust_close_pk,
                to_self_delay_be,
                fee_cc,
                fee_mc,
                channel_state.get_val_cpfp(),
            )
            .unwrap();

        let res1 =
            cust_state.set_initial_cust_state(&mut channel_token, &funding_tx_info, &tx_fee_info);
        assert!(res1.is_ok(), res1.err().unwrap());

        let got_close_tx = cust_state.sign_initial_closing_transaction::<Testnet>(
            &channel_state,
            &channel_token,
            &escrow_sig,
            &merch_sig,
        );
        assert!(got_close_tx.is_ok(), got_close_tx.err().unwrap());
        // customer can proceed to sign the escrow-tx and merch-close-tx and sends resulting signatures to merchant
        let (init_cust_state, init_hash) = mpc::get_initial_state(&cust_state).unwrap();

        // at this point, the escrow-tx can be broadcast and confirmed
        let res2 = mpc::validate_channel_params(
            &mut db as &mut dyn StateDatabase,
            &channel_token,
            &init_cust_state,
            init_hash,
            &mut merch_state,
        );
        assert!(res2.is_ok(), res2.err().unwrap());
        let _rc = mpc::customer_mark_open_channel(&mut cust_state).unwrap();
        let _rc =
            mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state)
                .unwrap();

        let s0 = mpc::activate_customer(rng, &mut cust_state).unwrap();

        let pay_token = mpc::activate_merchant(
            &mut db as &mut dyn StateDatabase,
            channel_token,
            &s0,
            &mut merch_state,
        );
        assert!(pay_token.is_ok(), pay_token.err().unwrap());

        mpc::activate_customer_finalize(pay_token.unwrap(), &mut cust_state).unwrap();

        //TODO: test unlinking with a 0-payment of pay protocol
    }

    fn generate_funding_tx<R: Rng>(csprng: &mut R, b0_cust: i64, b0_merch: i64) -> FundingTxInfo {
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

        return FundingTxInfo {
            init_cust_bal: b0_cust,
            init_merch_bal: b0_merch,
            escrow_txid: FixedSizeArray32(escrow_txid),
            merch_txid: FixedSizeArray32(merch_txid),
            escrow_prevout: FixedSizeArray32(escrow_prevout),
            merch_prevout: FixedSizeArray32(merch_prevout),
        };
    }

    fn setup_new_zkchannel_helper<R: Rng>(
        rng: &mut R,
        cust_bal: i64,
        merch_bal: i64,
        tx_fee_info: &mpc::TransactionFeeInfo,
    ) -> (
        mpc::ChannelMPCState,
        mpc::ChannelMPCToken,
        mpc::CustomerMPCState,
        mpc::MerchantMPCState,
    ) {
        // init channel state
        let mut channel_state = mpc::ChannelMPCState::new(
            String::from("Channel A -> B"),
            1487,
            tx_fee_info.bal_min_cust,
            tx_fee_info.bal_min_merch,
            tx_fee_info.val_cpfp,
            false,
        );
        // init merchant
        let merch_state = mpc::init_merchant(rng, "".to_string(), &mut channel_state, "Bob");

        let b0_cust = cust_bal;
        let b0_merch = merch_bal;
        // init customer
        let (channel_token, cust_state) = mpc::init_customer(
            rng,
            &merch_state.pk_m,
            b0_cust,
            b0_merch,
            tx_fee_info,
            "Alice",
        );

        return (channel_state, channel_token, cust_state, merch_state);
    }

    #[test]
    fn test_payment_mpc_channel_merch() {
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d76);
        let mut db = RedisDatabase::new("merch.lib", "redis://127.0.0.1/".to_string()).unwrap();

        let min_threshold = 546;
        let val_cpfp = 1000;
        let mut channel_state = mpc::ChannelMPCState::new(
            String::from("Channel A -> B"),
            1487,
            min_threshold,
            min_threshold,
            val_cpfp,
            false,
        );

        let mut merch_state =
            mpc::init_merchant(&mut rng, "".to_string(), &mut channel_state, "Bob");

        let b0_cust = 100000;
        let b0_merch = 100000;
        let fee_cc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let fee_mc = 1000;
        let amount = 1000;
        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        let (mut channel_token, mut cust_state) = mpc::init_customer(
            &mut rng,
            &merch_state.pk_m,
            b0_cust,
            b0_merch,
            &tx_fee_info,
            "Alice",
        );

        let funding_tx_info = generate_funding_tx(&mut rng, b0_cust, b0_merch);

        cust_state
            .set_initial_cust_state(&mut channel_token, &funding_tx_info, &tx_fee_info)
            .unwrap();

        let (init_cust_state, init_hash) = mpc::get_initial_state(&cust_state).unwrap();

        let res2 = mpc::validate_channel_params(
            &mut db as &mut dyn StateDatabase,
            &channel_token,
            &init_cust_state,
            init_hash,
            &mut merch_state,
        );
        println!("mpc::validate_channel_params: {}", res2.is_ok());

        // TODO: add cust-close tx signing API
        // transition state manually
        cust_state.protocol_status = ProtocolStatus::Initialized;
        let mut escrow_txid_be = channel_token.escrow_txid.0.clone();
        escrow_txid_be.reverse();
        let rc = cust_state.change_channel_status(ChannelStatus::PendingOpen);
        assert!(rc.is_ok());
        let rc = merch_state.change_channel_status(escrow_txid_be, ChannelStatus::PendingOpen);
        assert!(rc.is_ok());

        let _rc = mpc::customer_mark_open_channel(&mut cust_state).unwrap();
        let _rc =
            mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state)
                .unwrap();

        let s0 = mpc::activate_customer(&mut rng, &mut cust_state).unwrap();

        let pay_token = mpc::activate_merchant(
            &mut db as &mut dyn StateDatabase,
            channel_token.clone(),
            &s0,
            &mut merch_state,
        )
        .unwrap();

        mpc::activate_customer_finalize(pay_token, &mut cust_state).unwrap();

        let (_new_state, revoked_state, rev_lock_com, session_id) =
            mpc::pay_prepare_customer(&mut rng, &channel_state, amount, &mut cust_state).unwrap();

        let pay_mask_com = mpc::pay_prepare_merchant(
            &mut rng,
            &mut db as &mut dyn StateDatabase,
            &channel_state,
            session_id,
            s0.get_nonce(),
            rev_lock_com.clone(),
            amount,
            None,
            &mut merch_state,
        )
        .unwrap();

        let res_merch = mpc::pay_update_merchant(
            &mut rng,
            &mut db as &mut dyn StateDatabase,
            &channel_state,
            session_id,
            pay_mask_com,
            &mut merch_state,
            ptr::null_mut(),
            None,
            None,
        );
        assert!(res_merch.is_ok(), res_merch.err().unwrap());

        let masked_inputs = mpc::pay_confirm_mpc_result(
            &mut db as &mut dyn StateDatabase,
            session_id.clone(),
            "6ae9c1ec9fe899664f2a35badbbcada8".to_string(),
            &mut merch_state,
        );
        assert!(masked_inputs.is_ok(), masked_inputs.err().unwrap());
        // println!("Masked Tx Inputs: {:#?}", masked_inputs.unwrap());
        let mask_in = masked_inputs.unwrap();
        println!("escrow_mask: {}", hex::encode(mask_in.escrow_mask.0));
        println!("merch_mask: {}", hex::encode(mask_in.merch_mask.0));
        println!("r_escrow_sig: {}", hex::encode(mask_in.r_escrow_sig.0));
        println!("r_merch_sig: {}", hex::encode(mask_in.r_merch_sig.0));

        let (pay_token_mask, pay_token_mask_r) = match mpc::pay_validate_rev_lock_merchant(
            &mut db as &mut dyn StateDatabase,
            session_id,
            revoked_state,
            &mut merch_state,
        ) {
            Ok(n) => (n.0, n.1),
            Err(e) => panic!("Could not get pay token mask and randomness: {}", e),
        };
        println!("pt_mask_r => {}", hex::encode(&pay_token_mask_r));
        assert_eq!(
            hex::encode(pay_token_mask),
            "4a682bd5d46e3b5c7c6c353636086ed7a943895982cb43deba0a8843459500e4"
        );
        assert_eq!(
            hex::encode(pay_token_mask_r),
            "671687f7cecc583745cd86342ddcccd4"
        );
        // db.clear_state();
    }

    rusty_fork_test! {
        #[test]
        fn test_payment_mpc_channel_cust() {
            let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d76);
            let mut db = RedisDatabase::new("cust.lib", "redis://127.0.0.1/".to_string()).unwrap();

            let min_threshold = 546;
            let val_cpfp = 1000;
            let mut channel_state = mpc::ChannelMPCState::new(String::from("Channel A -> B"), 1487, min_threshold, min_threshold, val_cpfp, false);
            let mut merch_state = mpc::init_merchant(&mut rng, "".to_string(), &mut channel_state, "Bob");

            let b0_cust = 100000;
            let b0_merch = 100000;
            let fee_cc = 1000;
            let min_fee = 0;
            let max_fee = 10000;
            let fee_mc = 1000;
            let amount = 1000;
            let tx_fee_info = mpc::TransactionFeeInfo {
                bal_min_cust: min_threshold,
                bal_min_merch: min_threshold,
                val_cpfp: val_cpfp,
                fee_cc: fee_cc,
                fee_mc: fee_mc,
                min_fee: min_fee,
                max_fee: max_fee
            };

            let (mut channel_token, mut cust_state) = mpc::init_customer(&mut rng, &merch_state.pk_m, b0_cust, b0_merch, &tx_fee_info, "Alice");

            let funding_tx_info = generate_funding_tx(&mut rng, b0_cust, b0_merch);

            cust_state.set_initial_cust_state(&mut channel_token, &funding_tx_info, &tx_fee_info).unwrap();

            let (init_cust_state, init_hash) = match mpc::get_initial_state(&cust_state) {
                Ok(n) => (n.0, n.1),
                Err(e) => panic!(e)
            };

            let res2 = mpc::validate_channel_params(&mut db as &mut dyn StateDatabase, &channel_token, &init_cust_state, init_hash, &mut merch_state);
            println!("mpc::validate_channel_params: {}", res2.is_ok());

            // transition state manually
            cust_state.protocol_status = ProtocolStatus::Initialized;
            let mut escrow_txid_be = channel_token.escrow_txid.0.clone();
            escrow_txid_be.reverse();
            let rc = cust_state.change_channel_status(ChannelStatus::PendingOpen);
            assert!(rc.is_ok());
            let rc = merch_state.change_channel_status(escrow_txid_be, ChannelStatus::PendingOpen);
            assert!(rc.is_ok());

            let rc = mpc::customer_mark_open_channel(&mut cust_state);
            assert!(rc.is_ok());
            let rc = mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state);
            assert!(rc.is_ok());

            let s0 = mpc::activate_customer(&mut rng, &mut cust_state).unwrap();

            let pay_token = mpc::activate_merchant(&mut db as &mut dyn StateDatabase, channel_token.clone(), &s0, &mut merch_state).unwrap();

            mpc::activate_customer_finalize(pay_token, &mut cust_state).unwrap();

            let ser_tx_info = serde_json::to_string(&funding_tx_info).unwrap();
            println!("Ser Funding Tx Info: {}", ser_tx_info);
            let orig_funding_tx_info: FundingTxInfo = serde_json::from_str(&ser_tx_info).unwrap();
            assert_eq!(funding_tx_info, orig_funding_tx_info);

            let (state, _rev_state, rev_lock_com, session_id) = mpc::pay_prepare_customer(&mut rng, &mut channel_state, amount, &mut cust_state).unwrap();

            let pay_mask_com = mpc::pay_prepare_merchant(&mut rng, &mut db as &mut dyn StateDatabase, &channel_state, session_id, state.get_nonce(), rev_lock_com.clone(), amount, None, &mut merch_state).unwrap();

            let res_cust = mpc::pay_update_customer(&channel_state, &channel_token, s0, state, pay_mask_com, rev_lock_com, amount, &mut cust_state,
            ptr::null_mut(),
            None,
            None,);
            assert!(res_cust.is_ok());

            let mut escrow_mask = [0u8; 32];
            escrow_mask.copy_from_slice(hex::decode("28a6c48749023149e45657f824b8d2d710b18575a3d667b4bd56c5f6d9c394b4").unwrap().as_slice());
            let mut merch_mask = [0u8; 32];
            merch_mask.copy_from_slice(hex::decode("fddc371be95df8ea164916e88dcd895a1522fcff163fc3d70182c78d91d33699").unwrap().as_slice());
            let mut r_escrow_sig = [0u8; 32];
            r_escrow_sig.copy_from_slice(hex::decode("f3c4bc971aaa9bba404dfb4ef79da1dfdfda7db2bc8678a64fc4e766aeec59d5").unwrap().as_slice());
            let mut r_merch_sig = [0u8; 32];
            r_merch_sig.copy_from_slice(hex::decode("e8c38fa6d975568b6a60269098bdf3a2d5eb896a06d47ff9733772ffb2fe7e27").unwrap().as_slice());

            let masks = MaskedTxMPCInputs::new(
                escrow_mask,
                merch_mask,
                r_escrow_sig,
                r_merch_sig
            );

            let is_ok = mpc::pay_unmask_sigs_customer(&channel_state, &channel_token, masks, &mut cust_state);
            assert!(is_ok.is_ok(), is_ok.err().unwrap());

            let mut pt_mask = [0u8; 32];
            pt_mask.copy_from_slice(hex::decode("4a682bd5d46e3b5c7c6c353636086ed7a943895982cb43deba0a8843459500e4").unwrap().as_slice());
            let mut pt_mask_r = [0u8; 16];
            pt_mask_r.copy_from_slice(hex::decode("671687f7cecc583745cd86342ddcccd4").unwrap().as_slice());

            let is_ok = mpc::pay_unmask_pay_token_customer(pt_mask, pt_mask_r, &mut cust_state).unwrap();
            assert!(is_ok);
        }
    }

    // establish the funding tx and sign initial closing tx
    fn establish_init_cust_close_tx_helper(
        funding_tx: &FundingTxInfo,
        tx_fee_info: &mpc::TransactionFeeInfo,
        channel_state: &mpc::ChannelMPCState,
        channel_token: &mut mpc::ChannelMPCToken,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
    ) {
        cust_state
            .set_initial_cust_state(channel_token, funding_tx, tx_fee_info)
            .unwrap();
        let pubkeys = cust_state.get_pubkeys(&channel_state, &channel_token);

        let to_self_delay_be = channel_state.get_self_delay_be();
        // merchant signs and returns initial close sigs to customer
        let (escrow_sig, merch_sig) = merch_state
            .sign_initial_closing_transaction::<Testnet>(
                funding_tx.clone(),
                pubkeys.rev_lock.0,
                pubkeys.cust_pk,
                pubkeys.cust_close_pk,
                to_self_delay_be.clone(),
                tx_fee_info.fee_cc,
                tx_fee_info.fee_mc,
                tx_fee_info.val_cpfp,
            )
            .unwrap();

        assert!(cust_state.protocol_status == ProtocolStatus::New);

        // customer verifies the close signatures
        let got_close_tx = cust_state.sign_initial_closing_transaction::<Testnet>(
            &channel_state,
            &channel_token,
            &escrow_sig,
            &merch_sig,
        );
        assert!(got_close_tx.is_ok(), got_close_tx.err().unwrap());

        // at this point, we should be pending open since we've got the initial close tx signed
        // just need to broadcast the escrow tx
        assert!(cust_state.get_channel_status() == ChannelStatus::PendingOpen);
    }

    // establish the init merch-close-tx
    fn establish_merch_close_tx_helper(
        funding_tx_info: &mut FundingTxInfo,
        channel_state: &mpc::ChannelMPCState,
        channel_token: &mpc::ChannelMPCToken,
        cust_bal: i64,
        merch_bal: i64,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
        fee_mc: i64,
    ) {
        let escrow_txid_be = funding_tx_info.escrow_txid.0.clone();
        let to_self_delay_be = channel_state.get_self_delay_be();
        let pubkeys = cust_state.get_pubkeys(&channel_state, &channel_token);
        let cust_sk = cust_state.get_close_secret_key();

        let (merch_tx_preimage, tx_params) =
            zkchan_tx::transactions::btc::merchant_form_close_transaction::<Testnet>(
                escrow_txid_be.to_vec(),
                pubkeys.cust_pk.clone(),
                pubkeys.merch_pk.clone(),
                pubkeys.merch_close_pk.clone(),
                pubkeys.merch_child_pk.clone(),
                cust_bal,
                merch_bal,
                fee_mc,
                channel_state.get_val_cpfp(),
                to_self_delay_be.clone(),
            )
            .unwrap();

        // set the funding_tx_info structure
        let (merch_txid_be, prevout) =
            zkchan_tx::txutil::merchant_generate_transaction_id(tx_params).unwrap();
        funding_tx_info.merch_txid = FixedSizeArray32(merch_txid_be);
        funding_tx_info.merch_prevout = FixedSizeArray32(prevout);

        // generate merch-close tx
        let cust_sig =
            zkchan_tx::txutil::customer_sign_merch_close_transaction(&cust_sk, &merch_tx_preimage)
                .unwrap();

        let _is_ok = zkchan_tx::txutil::merchant_verify_merch_close_transaction(
            &merch_tx_preimage,
            &cust_sig,
            &pubkeys.cust_pk,
        )
        .unwrap();

        // store the signature for merch-close-tx
        merch_state.store_merch_close_tx(
            &escrow_txid_be.to_vec(),
            &pubkeys.cust_pk,
            cust_bal,
            merch_bal,
            fee_mc,
            to_self_delay_be,
            &cust_sig,
        );
    }

    // validate the initial state of the channel
    fn validate_initial_channel_state_helper(
        db: &mut RedisDatabase,
        channel_token: &mpc::ChannelMPCToken,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
    ) {
        let (init_state, init_hash) = mpc::get_initial_state(&cust_state).unwrap();

        assert!(mpc::validate_channel_params(
            db as &mut dyn StateDatabase,
            &channel_token,
            &init_state,
            init_hash,
            merch_state
        )
        .unwrap());
    }

    // run activate sub protocol between customer/merchant
    fn activate_channel_helper<R: Rng>(
        rng: &mut R,
        db: &mut RedisDatabase,
        channel_token: &mpc::ChannelMPCToken,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
    ) {
        let s0_result = mpc::activate_customer(rng, cust_state);
        assert!(s0_result.is_ok());
        let s0 = s0_result.unwrap();

        let pay_token_result = mpc::activate_merchant(
            db as &mut dyn StateDatabase,
            channel_token.clone(),
            &s0,
            merch_state,
        );
        assert!(pay_token_result.is_ok());
        let pay_token = pay_token_result.unwrap();

        let res = mpc::activate_customer_finalize(pay_token, cust_state);
        assert!(res.is_ok());
    }

    // run pay prepare between customer and merchant
    fn pay_prepare_helper<R: Rng>(
        rng: &mut R,
        db: &mut RedisDatabase,
        channel_state: &mpc::ChannelMPCState,
        cust_state: &mut mpc::CustomerMPCState,
        amount: i64,
        merch_state: &mut mpc::MerchantMPCState,
    ) -> (
        [u8; 16],
        mpc::State,
        mpc::State,
        mpc::RevokedState,
        [u8; 32],
        [u8; 32],
    ) {
        // get the old state
        let cur_state = cust_state.get_current_state();
        // let's prepare a new payment
        let (new_state, rev_state, rev_lock_com, session_id) =
            mpc::pay_prepare_customer(rng, channel_state, amount, cust_state).unwrap();

        // println!("Old Nonce: {}", hex::encode(&cur_state.get_nonce()));
        let justification = match amount < 0 {
            true => Some(format!("empty-sig")),
            false => None,
        };
        let pay_mask_com = mpc::pay_prepare_merchant(
            rng,
            db as &mut dyn StateDatabase,
            channel_state,
            session_id,
            cur_state.get_nonce(),
            rev_lock_com.clone(),
            amount,
            justification,
            merch_state,
        )
        .unwrap();

        return (
            session_id,
            cur_state,
            new_state,
            rev_state,
            rev_lock_com,
            pay_mask_com,
        );
    }

    #[test]
    #[ignore]
    fn test_channel_activated_correctly() {
        let mut rng = XorShiftRng::seed_from_u64(0xc7175992415de87a);
        let mut db = RedisDatabase::new("mpclib", "redis://127.0.0.1/".to_string()).unwrap();
        db.clear_state();

        let b0_cust = 10000;
        let b0_merch = 10000;
        let fee_cc = 1000;
        let fee_mc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let min_threshold = 546; // dust limit
        let val_cpfp = 1000;

        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        let (channel_state, mut channel_token, mut cust_state, mut merch_state) =
            setup_new_zkchannel_helper(&mut rng, b0_cust, b0_merch, &tx_fee_info);

        // create funding txs
        let funding_tx_info = generate_funding_tx(&mut rng, b0_cust, b0_merch);

        // customer obtains signatures on initial closing tx
        establish_init_cust_close_tx_helper(
            &funding_tx_info,
            &tx_fee_info,
            &channel_state,
            &mut channel_token,
            &mut cust_state,
            &mut merch_state,
        );

        assert!(cust_state.protocol_status == ProtocolStatus::Initialized);

        // merchant validates the initial state
        validate_initial_channel_state_helper(
            &mut db,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );
        println!("initial channel state validated!");
        // println!("cust_state channel status: {}", cust_state.protocol_status);

        let rc = mpc::customer_mark_open_channel(&mut cust_state);
        assert!(rc.is_ok());
        let rc =
            mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state);
        assert!(rc.is_ok());

        activate_channel_helper(
            &mut rng,
            &mut db,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );
        assert!(cust_state.protocol_status == ProtocolStatus::Activated);
        println!("cust_state channel status: {}", cust_state.protocol_status);
    }

    fn zkchannel_full_establish_setup_helper<R: Rng>(
        rng: &mut R,
        db: &mut RedisDatabase,
        tx_fee_info: &mpc::TransactionFeeInfo,
    ) -> (
        mpc::ChannelMPCState,
        mpc::ChannelMPCToken,
        mpc::CustomerMPCState,
        mpc::MerchantMPCState,
    ) {
        let b0_cust = 10000;
        let b0_merch = 10000;

        let (channel_state, mut channel_token, mut cust_state, mut merch_state) =
            setup_new_zkchannel_helper(rng, b0_cust, b0_merch, &tx_fee_info);

        // generate random funding tx for testing
        let mut funding_tx_info = generate_funding_tx(rng, b0_cust, b0_merch);

        // customer and merchant jointly sign merch-close-tx
        establish_merch_close_tx_helper(
            &mut funding_tx_info,
            &channel_state,
            &channel_token,
            b0_cust,
            b0_merch,
            &mut cust_state,
            &mut merch_state,
            tx_fee_info.fee_mc,
        );

        // customer obtains signatures on initial closing tx
        establish_init_cust_close_tx_helper(
            &funding_tx_info,
            tx_fee_info,
            &channel_state,
            &mut channel_token,
            &mut cust_state,
            &mut merch_state,
        );
        assert!(cust_state.protocol_status == ProtocolStatus::Initialized);

        //println!("channel_token: {:?}", cust_state);

        // merchant validates the initial state
        validate_initial_channel_state_helper(
            db,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );

        // if escrow-tx confirmed on chain, can proceed to change status for both customer/merchant
        let rc = mpc::customer_mark_open_channel(&mut cust_state);
        assert!(rc.is_ok());
        let rc =
            mpc::merchant_mark_open_channel(channel_token.escrow_txid.0.clone(), &mut merch_state);
        assert!(rc.is_ok());

        // customer/merchant activate the channel
        activate_channel_helper(rng, db, &channel_token, &mut cust_state, &mut merch_state);
        assert!(cust_state.protocol_status == ProtocolStatus::Activated);
        println!("cust_state channel status: {}", cust_state.protocol_status);

        return (channel_state, channel_token, cust_state, merch_state);
    }

    fn complete_pay_helper(
        merch_db: &mut RedisDatabase,
        session_id: [u8; 16],
        success: String,
        rev_state: mpc::RevokedState,
        channel_state: &mpc::ChannelMPCState,
        channel_token: &mpc::ChannelMPCToken,
        cust_state: &mut mpc::CustomerMPCState,
        merch_state: &mut mpc::MerchantMPCState,
    ) {
        let mask_bytes = mpc::pay_confirm_mpc_result(
            merch_db as &mut dyn StateDatabase,
            session_id.clone(),
            success,
            merch_state,
        )
        .unwrap();

        println!("complete_pay_helper - got the mask bytes: {:?}", mask_bytes);

        // unmask the closing tx
        let is_sigs_ok =
            mpc::pay_unmask_sigs_customer(&channel_state, &channel_token, mask_bytes, cust_state)
                .unwrap();
        assert!(is_sigs_ok);

        // merchant validates the old state
        let (pt_mask, pt_mask_r) = match mpc::pay_validate_rev_lock_merchant(
            merch_db as &mut dyn StateDatabase,
            session_id,
            rev_state,
            merch_state,
        ) {
            Ok(n) => (n.0, n.1),
            Err(e) => {
                println!("Could not get pay token mask and randomness: {}", e);
                return;
            }
        };

        println!(
            "complete_pay_helper - new pay token: {}",
            hex::encode(&pt_mask)
        );

        // unmask pay_token
        let is_ok = mpc::pay_unmask_pay_token_customer(pt_mask, pt_mask_r, cust_state).unwrap();
        assert!(is_ok);
    }

    fn load_merchant_state_info(
        db_conn: &mut redis::Connection,
        db_key: &String,
        merch_state_key: &String,
    ) -> Result<mpc::MerchantMPCState, String> {
        // load the merchant state from DB
        let ser_merch_state = get_file_from_db(db_conn, &db_key, &merch_state_key).unwrap();
        let merch_state: mpc::MerchantMPCState = serde_json::from_str(&ser_merch_state).unwrap();
        Ok(merch_state)
    }

    fn save_merchant_state_info(
        db_conn: &mut redis::Connection,
        db_key: &String,
        channel_state_key: &String,
        channel_state: Option<&mpc::ChannelMPCState>,
        merch_state_key: &String,
        merch_state: &mpc::MerchantMPCState,
    ) -> Result<(), String> {
        // let key = String::from("cli:merch_db");
        match channel_state {
            Some(n) => {
                let channel_state_json_str = serde_json::to_string(n).unwrap();
                store_file_in_db(
                    db_conn,
                    &db_key,
                    &channel_state_key,
                    &channel_state_json_str,
                )?
            }
            None => false, // do nothing
        };

        let merch_state_json_str = serde_json::to_string(merch_state).unwrap();
        store_file_in_db(db_conn, &db_key, &merch_state_key, &merch_state_json_str)?;
        Ok(())
    }

    fn run_mpchelpers_as_merchant(
        db: &mut RedisDatabase,
        db_key: &String,
        session_id: [u8; 16],
        pay_mask_com: [u8; 32],
        channel_state: &mpc::ChannelMPCState,
        merch_state_key: &String,
        merch_state: &mpc::MerchantMPCState,
    ) -> std::process::Child {
        let cur_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let mut profile = "release";
        if cfg!(debug_assertions) {
            profile = "debug";
        }
        let mpc_test_bin = format!("{}/target/{}/mpchelpers", cur_dir, profile);
        println!("mpchelpers path: {}", mpc_test_bin);

        let session_id_arg = format!("{}", hex::encode(session_id));
        let pay_mask_com_arg = format!("{}", hex::encode(pay_mask_com));

        // let's start a thread but block until we get to pay_update_customer()
        let channel_state_key = "channel_state".to_string();
        save_merchant_state_info(
            &mut db.conn,
            db_key,
            &channel_state_key,
            Some(&channel_state),
            &merch_state_key,
            &merch_state,
        )
        .unwrap();

        let child = Command::new(mpc_test_bin)
            .arg("--db-key")
            .arg(db_key.clone())
            .arg("--pay-mask-com")
            .arg(pay_mask_com_arg)
            .arg("--session-id")
            .arg(session_id_arg)
            .spawn()
            .expect("failed to execute mpchelpers");

        return child;
    }

    #[test]
    #[ignore]
    fn test_unlink_and_pay_is_correct() {
        let mut rng = &mut rand::thread_rng();
        let mut db = RedisDatabase::new("mpchelpers", "redis://127.0.0.1/".to_string()).unwrap();
        db.clear_state();

        // full channel setup
        let fee_cc = 1000;
        let fee_mc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let min_threshold = 546; // dust limit
        let val_cpfp = 1000;

        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        let (channel_state, channel_token, mut cust_state, mut merch_state) =
            zkchannel_full_establish_setup_helper(&mut rng, &mut db, &tx_fee_info);

        // UNLINK PROTOCOL
        let (session_id, cur_state, new_state, rev_state, rev_lock_com, pay_mask_com) =
            pay_prepare_helper(
                &mut rng,
                &mut db,
                &channel_state,
                &mut cust_state,
                0,
                &mut merch_state,
            );

        let nc = channels_mpc::NetworkConfig {
            conn_type: ConnType_NETIO,
            path: String::from("tmpsock"),
            dest_ip: String::from("127.0.0.1"),
            dest_port: 5002,
        };
        cust_state.set_network_config(nc.clone());
        merch_state.set_network_config(nc.clone());

        let db_key = "mpchelpers:merch_db".to_string();
        let merch_state_key = "merch_state".to_string();
        let mut mpc_child = run_mpchelpers_as_merchant(
            &mut db,
            &db_key,
            session_id.clone(),
            pay_mask_com,
            &channel_state,
            &merch_state_key,
            &merch_state,
        );

        // pay update for customer
        let res_cust = mpc::pay_update_customer(
            &channel_state,
            &channel_token,
            cur_state,
            new_state,
            pay_mask_com,
            rev_lock_com,
            0,
            &mut cust_state,
            ptr::null_mut(),
            None,
            None,
        );
        assert!(res_cust.is_ok());

        // wait for mpchelpers to complete execution
        let ecode = mpc_child.wait().expect("failed to wait on mpchelpers");
        assert!(ecode.success());

        // load the updated merchant state
        let mut merch_state =
            load_merchant_state_info(&mut db.conn, &db_key, &merch_state_key).unwrap();

        // complete the rest of unlink
        complete_pay_helper(
            &mut db,
            session_id,
            res_cust.unwrap(),
            rev_state,
            &channel_state,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );

        println!("cust state: {:?}", cust_state.get_current_state());
        println!("customer's channel status: {}", cust_state.protocol_status);

        assert!(cust_state.protocol_status == ProtocolStatus::Established);

        // PAY PROTOCOL
        let (session_id1, cur_state1, new_state1, rev_state1, rev_lock_com1, pay_mask_com1) =
            pay_prepare_helper(
                &mut rng,
                &mut db,
                &channel_state,
                &mut cust_state,
                200,
                &mut merch_state,
            );

        let mut mpc_child = run_mpchelpers_as_merchant(
            &mut db,
            &db_key,
            session_id1.clone(),
            pay_mask_com1,
            &channel_state,
            &merch_state_key,
            &merch_state,
        );

        // pay update for customer
        let res_cust = mpc::pay_update_customer(
            &channel_state,
            &channel_token,
            cur_state1,
            new_state1,
            pay_mask_com1,
            rev_lock_com1,
            200,
            &mut cust_state,
            ptr::null_mut(),
            None,
            None,
        );
        assert!(res_cust.is_ok());

        let ecode = mpc_child.wait().expect("failed to wait on mpchelpers");
        assert!(ecode.success());

        // load the updated merchant state
        let merch_state_key = "merch_state".to_string();
        let mut merch_state =
            load_merchant_state_info(&mut db.conn, &db_key, &merch_state_key).unwrap();

        // complete the rest of unlink
        complete_pay_helper(
            &mut db,
            session_id1,
            res_cust.unwrap(),
            rev_state1,
            &channel_state,
            &channel_token,
            &mut cust_state,
            &mut merch_state,
        );

        // channel status should be Open at this point. Open -> ConfirmedClose should fail
        let res = cust_state.change_channel_status(ChannelStatus::ConfirmedClose);
        assert!(res.is_err());

        // customer initiates close tx
        let (_cust_close_signed_tx, _close_txid_be, _close_txid_le) =
            mpc::force_customer_close(&channel_state, &channel_token, true, &mut cust_state)
                .unwrap();

        assert_eq!(
            cust_state.get_channel_status(),
            ChannelStatus::CustomerInitClose
        );

        let mut escrow_txid_be = channel_token.escrow_txid.0.clone(); // originally in LE
        escrow_txid_be.reverse();
        let (_merch_close_signed_tx, _merch_txid_be, _merch_txid_le) = mpc::force_merchant_close(
            &escrow_txid_be.to_vec(),
            channel_state.get_val_cpfp(),
            &mut merch_state,
        )
        .unwrap();
        assert!(
            merch_state.get_channel_status(escrow_txid_be).unwrap()
                == ChannelStatus::MerchantInitClose
        );

        // change close status after closing transaction is detected on-chain
        let res = cust_state.change_channel_status(ChannelStatus::PendingClose);
        assert!(res.is_ok());
        assert_eq!(cust_state.get_channel_status(), ChannelStatus::PendingClose);

        // assume that timelock has passed and there was no dispute
        let res = cust_state.change_channel_status(ChannelStatus::ConfirmedClose);
        assert!(res.is_ok());
        assert_eq!(
            cust_state.get_channel_status(),
            ChannelStatus::ConfirmedClose
        );
    }

    #[test]
    #[ignore]
    //#[should_panic(expected = "Failed to get valid output from MPC!")]
    fn test_unlink_fail_as_expected() {
        let mut rng = &mut rand::thread_rng();
        let mut db = RedisDatabase::new("mpchelpers", "redis://127.0.0.1/".to_string()).unwrap();
        db.clear_state();

        // full channel setup
        let fee_cc = 1000;
        let fee_mc = 1000;
        let min_fee = 0;
        let max_fee = 10000;
        let min_threshold = 546; // dust limit
        let val_cpfp = 1000;
        let tx_fee_info = mpc::TransactionFeeInfo {
            bal_min_cust: min_threshold,
            bal_min_merch: min_threshold,
            val_cpfp: val_cpfp,
            fee_cc: fee_cc,
            fee_mc: fee_mc,
            min_fee: min_fee,
            max_fee: max_fee,
        };

        let (channel_state, channel_token, mut cust_state, mut merch_state) =
            zkchannel_full_establish_setup_helper(&mut rng, &mut db, &tx_fee_info);

        // UNLINK PROTOCOL
        let (session_id, cur_state, new_state, _rev_state, rev_lock_com, pay_mask_com) =
            pay_prepare_helper(
                &mut rng,
                &mut db,
                &channel_state,
                &mut cust_state,
                0,
                &mut merch_state,
            );

        let nc = channels_mpc::NetworkConfig {
            conn_type: ConnType_NETIO,
            path: String::from("tmpsock"),
            dest_ip: String::from("127.0.0.1"),
            dest_port: 5003,
        };
        cust_state.set_network_config(nc.clone());
        merch_state.set_network_config(nc.clone());

        let db_key = "mpchelpers:merch_db".to_string();
        let merch_state_key = "merch_state".to_string();
        let mut mpc_child = run_mpchelpers_as_merchant(
            &mut db,
            &db_key,
            session_id,
            pay_mask_com,
            &channel_state,
            &merch_state_key,
            &merch_state,
        );

        // pay update for customer
        let res_cust = mpc::pay_update_customer(
            &channel_state,
            &channel_token,
            cur_state,
            new_state,
            [11u8; 32], // bad pay-token-mask commitment
            rev_lock_com,
            0,
            &mut cust_state,
            ptr::null_mut(),
            None,
            None,
        );
        assert!(res_cust.is_err());

        // wait for mpchelpers to complete execution
        let ecode = mpc_child.wait().expect("failed to wait on mpchelpers");
        assert!(ecode.success());

        // load the updated merchant state
        let mut merch_state =
            load_merchant_state_info(&mut db.conn, &db_key, &merch_state_key).unwrap();
        let mask = mpc::pay_confirm_mpc_result(
            &mut db as &mut dyn StateDatabase,
            session_id.clone(),
            "False".to_string(),
            &mut merch_state,
        );
        assert!(mask.is_err());

        let session_id_hex = hex::encode(session_id);
        let session_state = db.load_session_state(&session_id_hex).unwrap();
        print!("Session State: {:?}\n", session_state);
        assert!(session_state.status == PaymentStatus::Error);
    }
}
