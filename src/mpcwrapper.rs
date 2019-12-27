use libc::{c_int, c_char};
use secp256k1::{Signature, Message, PublicKey, Secp256k1};
use std::ffi::{CString, CStr};
use rand::{RngCore, Rng};
use bit_array::BitArray;
use typenum::{U264, U64};
use num::BigInt;
use num::bigint::Sign;
use bindings::{build_masked_tokens_cust, build_masked_tokens_merch, EcdsaPartialSig_l, State_l, RevLock_l, RevLockCommitment_l, Nonce_l, Balance_l, PayToken_l, Txid_l, Mask_l, HMACKeyCommitment_l, MaskCommitment_l, HMACKey_l, BitcoinPublicKey_l, PublicKeyHash_l, EcdsaSig_l};
use std::slice;
use wallet::State;

pub fn mpc_build_masked_tokens_cust(amount: i64, pay_mask_com: &[u8], hmac_key_com: &[u8],
                                    merch_escrow_pub_key: secp256k1::PublicKey, merch_dispute_key: secp256k1::PublicKey,
                                    merch_pub_key_hash: [u8; 20], merch_payout_pub_key: secp256k1::PublicKey,
                                    new_state: State, old_state: State, t: &[u8; 32], pt_old: &[u8],
                                    cust_escrow_pub_key: secp256k1::PublicKey, cust_payout_pub_key: secp256k1::PublicKey,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    // translate wpk
    let mut rl_c = translate_revlock_com(&new_state.rev_lock[..]);

    // translate new_wallet
    let mut new_state_c = translate_state(&new_state);
    // translate old_wallet
    let mut old_state_c = translate_state(&old_state);
    // translate blinding factor
    let t_str = translate_string(&t[..]);
    // translate payment_token
    let pt_old_c = translate_paytoken(&pt_old);
    //paymask_com
    let paymask_com = MaskCommitment_l {
        commitment: translate_256_string(pay_mask_com),
    };

    //key_com
    let key_com = HMACKeyCommitment_l {
        commitment: translate_256_string(hmac_key_com),
    };

    //translate bitcoin keys
    let merch_escrow_pub_key_c = translate_bitcoin_key(&merch_escrow_pub_key);
    let merch_dispute_key_c = translate_bitcoin_key(&merch_dispute_key);
    let merch_public_key_hash_c = translate_pub_key_hash(&merch_pub_key_hash);
    let merch_payout_pub_key_c = translate_bitcoin_key(&merch_payout_pub_key);

    let cust_escrow_pub_key_c = translate_bitcoin_key(&cust_escrow_pub_key);
    let cust_payout_pub_key_c = translate_bitcoin_key(&cust_payout_pub_key);

    let nonce = translate_nonce(&old_state.nonce);

// create pointers the output variables
    let mut pt_return_ar = [0u32; 8];
    let mut pt_return = PayToken_l { paytoken: pt_return_ar };
    let mut sig1_ar = [0u32; 8];
    let mut ct_escrow = EcdsaSig_l { sig: sig1_ar };
    let mut sig2_ar = [0u32; 8];
    let mut ct_merch = EcdsaSig_l { sig: sig2_ar };

    unsafe {
        build_masked_tokens_cust(translate_balance(amount), rl_c,
                                 12345, CString::new("127.0.0.1").unwrap().into_raw(),
                                 paymask_com, key_com,
                                 merch_escrow_pub_key_c, merch_dispute_key_c,
                                 merch_public_key_hash_c, merch_payout_pub_key_c,
                                 nonce,
                                 new_state_c, old_state_c, t_str, pt_old_c,
                                 cust_escrow_pub_key_c, cust_payout_pub_key_c,
                                 &mut pt_return, &mut ct_escrow, &mut ct_merch);
    };

    //TODO: update with values
    let mut pt_masked_ar = [0u8; 32];
    pt_masked_ar.copy_from_slice(u32_to_bytes(&pt_return.paytoken[..]).as_slice());
    let mut ct_escrow_masked_ar = [0u8; 32];
    ct_escrow_masked_ar.copy_from_slice(u32_to_bytes(&ct_escrow.sig[..]).as_slice());
    let mut ct_merch_masked_ar = [0u8; 32];
    ct_merch_masked_ar.copy_from_slice(u32_to_bytes(&ct_merch.sig[..]).as_slice());

    (pt_masked_ar, ct_escrow_masked_ar, ct_merch_masked_ar)
}

fn translate_bitcoin_key(pub_key: &secp256k1::PublicKey) -> BitcoinPublicKey_l {
    let mut pub_key_ar = [0u32; 9];
    let pk_comp = pub_key.serialize();
    let mut pub_key_vec_padded = pk_comp.to_vec();
    pub_key_vec_padded.extend_from_slice(&[0, 0, 0]);
    let pub_key_vec = bytes_to_u32(pub_key_vec_padded.as_slice(), 36);
    pub_key_ar.copy_from_slice(pub_key_vec.as_slice());
    BitcoinPublicKey_l { key: pub_key_ar }
}

fn translate_pub_key_hash(pub_key_hash: &[u8; 20]) -> PublicKeyHash_l {
    let mut hash_ar = [0u32; 5];
    let hash_vec = bytes_to_u32(&pub_key_hash[..], 20);
    hash_ar.copy_from_slice(hash_vec.as_slice());
    PublicKeyHash_l { hash: hash_ar }
}

fn translate_nonce(nonce: &[u8; 16]) -> Nonce_l {
    let nonce_vec = bytes_to_u32(&nonce[..], 16);
    let mut nonce_ar = [0u32; 4];
    nonce_ar.copy_from_slice(nonce_vec.as_slice());
    Nonce_l { nonce: nonce_ar }
}

fn translate_paytoken(pt: &[u8]) -> PayToken_l {
    let mut pt_ar = [0u32; 8];
    let pt_vec = bytes_to_u32(pt.as_ref(), pt.len());
    pt_ar.copy_from_slice(&pt_vec.as_slice());
    let pt = PayToken_l {
        paytoken: pt_ar
    };
    pt
}

fn translate_state(state: &State) -> State_l {
    let txid_merch = translate_256_string(&state.merch_txid[..]);
    let txid_escrow = translate_256_string(&state.escrow_txid[..]);
    let prevout_escrow = translate_256_string(&state.escrow_prevout[..]);
    let prevout_merch = translate_256_string(&state.merch_prevout[..]);

    let nonce = translate_nonce(&state.nonce);
    let rev_lock = translate_revlock(&state.rev_lock[..]);

    let bc = translate_balance(state.bc);
    let bm = translate_balance(state.bm);

    let mut new_state = State_l {
        nonce,
        rl: rev_lock,
        balance_cust: bc,
        balance_merch: bm,
        txid_merch: Txid_l { txid: txid_merch },
        txid_escrow: Txid_l { txid: txid_escrow },
        HashPrevOuts_escrow: Txid_l { txid: prevout_escrow },
        HashPrevOuts_merch: Txid_l { txid: prevout_merch },
    };
    new_state
}

fn translate_balance(amount: i64) -> Balance_l {
    let mut balance = [0u32; 2];
    let balance_vec = bytes_to_u32(&amount.to_be_bytes(), 8);
    balance.copy_from_slice(balance_vec.as_slice());
    Balance_l { balance }
}

fn translate_256_string(input: &[u8]) -> [u32; 8] {
    let str_vec = bytes_to_u32(input, 32);
    let txid = str_vec.as_slice();
    let mut txid_ar = [0u32; 8];
    txid_ar.copy_from_slice(txid);
    txid_ar
}

fn translate_512_string(input: &[u8]) -> [u32; 16] {
    let str_vec = bytes_to_u32(input, 64);
    let txid = str_vec.as_slice();
    let mut txid_ar = [0u32; 16];
    txid_ar.copy_from_slice(txid);
    txid_ar
}

fn translate_string(in_str: &[u8]) -> *mut c_char {
    CString::new(in_str).unwrap().into_raw()
}

fn translate_revlock(rl: &[u8]) -> RevLock_l {
    let mut res = RevLock_l { revlock: translate_256_string(rl) };
    res
}

fn translate_revlock_com(rl: &[u8]) -> RevLockCommitment_l {
    let mut res = RevLockCommitment_l { commitment: translate_256_string(rl) };
    res
}

fn bytes_to_u32(input: &[u8], size: usize) -> Vec<u32> {
    let out_l = size / 4;
    let mut out = Vec::new();
    for i in 0..out_l {
        let start = i * 4;
        let end = i * 4 + 4;
        let mut byte4 = [0u8; 4];
        byte4.copy_from_slice(&input[start..end]);
        out.push(u32::from_be_bytes(byte4));
    }
    out
}

fn u32_to_bytes(input: &[u32]) -> Vec<u8> {
    let mut out = Vec::<u8>::new();
    for part in input.iter() {
        out.extend_from_slice(&part.to_be_bytes()[..]);
    }
    out
}

pub fn mpc_build_masked_tokens_merch<R: Rng>(rng: &mut R, amount: i64, com_new: &[u8], rl: &[u8],
                                             key_com: &[u8], merch_escrow_pub_key: secp256k1::PublicKey, merch_dispute_key: secp256k1::PublicKey,
                                             merch_pub_key_hash: [u8; 20], merch_payout_pub_key: secp256k1::PublicKey,
                                             nonce: [u8; 16],
                                             hmac_key: &[u8], sk_m: secp256k1::SecretKey, merch_mask: &[u8; 32], pay_mask: &[u8; 32], escrow_mask: &[u8; 32]) {
    // translate revlock commitment
    let mut rl_c = translate_revlock_com(rl);

    //translate bitcoin keys
    let merch_escrow_pub_key_c = translate_bitcoin_key(&merch_escrow_pub_key);
    let merch_dispute_key_c = translate_bitcoin_key(&merch_dispute_key);
    let merch_public_key_hash_c = translate_pub_key_hash(&merch_pub_key_hash);
    let merch_payout_pub_key_c = translate_bitcoin_key(&merch_payout_pub_key);

    let nonce_c = translate_nonce(&nonce);

    // Create ECDSA_params
    let mut params1 = createEcdsaParams(rng, &sk_m.clone());
    let mut params2 = createEcdsaParams(rng, &sk_m.clone());
    let mut params3 = createEcdsaParams(rng, &sk_m.clone());

    // Create close_mask
    let merch_mask = Mask_l { mask: translate_256_string(merch_mask) };

    // Create pay_mask
    let paytoken_mask_c = Mask_l { mask: translate_256_string(pay_mask) };

    //Create escrow_mask
    let escrow_mask = Mask_l { mask: translate_256_string(escrow_mask) };

    //paymask_com
    let paymask_com = MaskCommitment_l {
        commitment: translate_256_string(com_new),
    };

    //key_com
    let key_com = HMACKeyCommitment_l {
        commitment: translate_256_string(key_com),
    };

    //hmac key
    let hmac_key = HMACKey_l {
        key: translate_512_string(hmac_key),
    };

    unsafe {
        build_masked_tokens_merch(translate_balance(amount), rl_c,
                                  12345, CString::new("127.0.0.1").unwrap().into_raw(),
                                  paymask_com, key_com,
                                  merch_escrow_pub_key_c, merch_dispute_key_c,
                                  merch_public_key_hash_c, merch_payout_pub_key_c,
                                  nonce_c, hmac_key, merch_mask, escrow_mask,
                                  paytoken_mask_c, params1, params2, params3);
    };
}

fn createEcdsaParams<R: Rng>(rng: &mut R, sk: &secp256k1::SecretKey) -> EcdsaPartialSig_l {
    let secp = secp256k1::Secp256k1::new();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let nonce_message = Message::from_slice(&nonce);
    let partial_signature = secp.partial_sign(&nonce_message.unwrap(), &sk);
    let par_sig_compact = partial_signature.0.serialize_compact();
    let r_arr = translate_int_256_chars(&par_sig_compact[32..64]);
    let inv = translate_int_256_chars(&par_sig_compact[64..]);

    EcdsaPartialSig_l {
        r: r_arr,
        k_inv: inv,
    }
}

fn translate_int_256_chars(rx: &[u8]) -> [i8; 256] {
    let big_int = BigInt::from_bytes_be(Sign::Plus, rx).to_string();
    let big_int_str = CString::new(big_int).unwrap();
    let mut slice = big_int_str.into_bytes();
    let pad = 256 - slice.len();
    let mut padded_slice = Vec::new();
    for i in 0..pad {
        padded_slice.push(0x0);
    }
    padded_slice.append(&mut slice);
    let mut r_arr = [0i8; 256];
    r_arr.copy_from_slice(unsafe { slice::from_raw_parts(padded_slice.as_ptr() as *const i8, padded_slice.len()) });
    r_arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use typenum::U32;
    use std::{str, thread};
    use num::BigInt;
    use std::time::Duration;

    rusty_fork_test! {
    #[test]
    fn mpc_build_masked_tokens_merch_works() {
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        //TODO: this becomes merch_escrow_pub_key (and corresponding secret key)
        let sk_m = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let pk_m = PublicKey::from_secret_key(&Secp256k1::new(), &sk_m);

        /* MERCHANT INPUTS */
        /*  HMAC Key, Pt_Mask, Merch_Mask, Escrow_ Mask, 2x Partial Sigs*/
        let mut hmac_key = [0u8; 64];
        hmac_key.copy_from_slice(hex::decode("439452e56db2398e05396328c5e037086c5167565736ce7041356f12d161821715656a1a16eeff47615e0494d7b3757d730517f1beebc45575beb1644ba48a1a").unwrap().as_slice());
        let mut paytoken_mask_bytes = [0u8; 32];
        paytoken_mask_bytes.copy_from_slice(hex::decode("0c8dda801001c9a55f720c5f379ce09e42416780f98fef7900bd26b372b81850").unwrap().as_slice());
        let mut merch_mask_bytes = [0u8; 32];
        merch_mask_bytes.copy_from_slice(hex::decode("1c92f6e3dfb5f805a436b727a340fd08d41e4de53b7f6dd5865b5f30fcf80709").unwrap().as_slice());
        let mut escrow_mask_bytes = [0u8; 32];
        escrow_mask_bytes.copy_from_slice(hex::decode("2670345a391379cd02514a35ee4fb3f1f0c14b5fb75381b7e797b5dd26ee057d").unwrap().as_slice());
   
        /* PULBIC MPC INPUTS */
        /* Balance amount, HMACKeyCommit, PT_MaskCommit, RevLockCommit, Nonce, 3x Public Key, 1x PK_Hash*/

        let mut amount_ar = [0u8; 8];
        amount_ar.copy_from_slice(hex::decode("0000000000000010").unwrap().as_slice());
        let amount = i64::from_be_bytes(amount_ar);

        let mut key_com = [0u8; 32];
        key_com.copy_from_slice(hex::decode("e0e14aeda7bcf9bbbf4744ecd03fcdcef0bbc83e0d9fe55c1fb372799e3a0698").unwrap().as_slice());

        let mut paytoken_mask_com = [0u8; 32];
        paytoken_mask_com.copy_from_slice(hex::decode("d31e6fea41aa7080a7d2b34357591bab1f295b178c85572f6a5ecc8af3a93ba8").unwrap().as_slice());

        let mut rev_lock_com = [0u8; 32];
        rev_lock_com.copy_from_slice(hex::decode("1caa135b24792810dcab8dffbb5157972e38dff248f0d43f5ea453111ca25852").unwrap().as_slice());

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(hex::decode("18670766caf2e5fec5f909d04acd5e86").unwrap().as_slice());

        let merch_escrow_pub_key = secp256k1::PublicKey::from_slice(hex::decode("0342da23a1de903cd7a141a99b5e8051abfcd4d2d1b3c2112bac5c8997d9f12a00").unwrap().as_slice()).unwrap();
        let merch_dispute_key = secp256k1::PublicKey::from_slice(hex::decode("0253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7c").unwrap().as_slice()).unwrap();
        let mut merch_public_key_hash = [0u8; 20];
        merch_public_key_hash.copy_from_slice(hex::decode("43e9e81bc632ad9cad48fc23f800021c5769a063").unwrap().as_slice());
        let merch_payout_pub_key = secp256k1::PublicKey::from_slice(hex::decode("02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90").unwrap().as_slice()).unwrap();


        mpc_build_masked_tokens_merch(csprng, amount, &paytoken_mask_com, &rev_lock_com,
                                      &key_com,
                                      merch_escrow_pub_key, merch_dispute_key, merch_public_key_hash, merch_payout_pub_key, nonce,
                                      &hmac_key,
                                      sk_m, &merch_mask_bytes, &paytoken_mask_bytes, &escrow_mask_bytes);
    }
    }

    rusty_fork_test! {
    #[test]
    fn mpc_build_masked_tokens_cust_works() {
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        let sk_m = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let pk_m = PublicKey::from_secret_key(&Secp256k1::new(), &sk_m);

        let sk_c = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let pk_c = PublicKey::from_secret_key(&Secp256k1::new(), &sk_c);

        let mut t =  [0u8; 32];
        t.copy_from_slice(hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice());

        /*   CUSTOMER SECRET INPUTS */
        /*   old_state, new_state, old_paytoken, 2x public_keys */

        let mut nonce1 = [0u8; 16];
        nonce1.copy_from_slice(hex::decode("18670766caf2e5fec5f909d04acd5e86").unwrap().as_slice());
        let mut nonce2 = [0u8; 16];
        nonce2.copy_from_slice(hex::decode("b2f9b5a508cf8609f040641892824a61").unwrap().as_slice());

        let mut rl_ar1 = [0u8; 32];
        rl_ar1.copy_from_slice(hex::decode("0b744cf3475f300fe77d2e85c3a5911e603e725b17932ee90f99fc7a869b8307").unwrap().as_slice());

        let mut rl_ar2 = [0u8; 32];
        rl_ar2.copy_from_slice(hex::decode("ca54e2bc080dc33895f8fadb72902337e3ee171dd57e1dcf12e8d0d9abae3b6c").unwrap().as_slice());

        let mut tx_id_merch = [0u8; 32];
        tx_id_merch.copy_from_slice(hex::decode("e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4").unwrap().as_slice());

        let mut tx_id_esc = [0u8; 32];
        tx_id_esc.copy_from_slice(hex::decode("e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4").unwrap().as_slice());

        let mut hashouts_merch = [0u8; 32];
        hashouts_merch.copy_from_slice(hex::decode("7d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d738").unwrap().as_slice());

        let mut hashouts_escrow = [0u8; 32];
        hashouts_escrow.copy_from_slice(hex::decode("7d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d738").unwrap().as_slice());

        let new_state = State {
            nonce: nonce1,
            rev_lock: rl_ar1,
            pk_c,
            pk_m,
            bc: 80,
            bm: 48,
            escrow_txid: tx_id_esc,
            merch_txid: tx_id_merch,
            escrow_prevout: hashouts_escrow,
            merch_prevout: hashouts_merch,
        };
        let old_state = State {
            nonce: nonce2,
            rev_lock: rl_ar2,
            pk_c,
            pk_m,
            bc: 64,
            bm: 64,
            escrow_txid: tx_id_esc,
            merch_txid: tx_id_merch,
            escrow_prevout: hashouts_escrow,
            merch_prevout: hashouts_merch,
        };

        let mut old_paytoken = [0u8; 32];
        old_paytoken.copy_from_slice(hex::decode("1851d287d04a784fe30726d58e458ba87412e4c0ba5b6bfa68e2515365c01679").unwrap().as_slice());

        let cust_escrow_pub_key = secp256k1::PublicKey::from_slice(hex::decode("03fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d7").unwrap().as_slice()).unwrap();
        let cust_payout_pub_key = secp256k1::PublicKey::from_slice(hex::decode("03195e272df2310ded35f9958fd0c2847bf73b5b429a716c005d465009bd768641").unwrap().as_slice()).unwrap();

        /* END CUSTOMER INPUTS */

        /* PULBIC MPC INPUTS */
        /* Balance amount, HMACKeyCommit, PT_MaskCommit, RevLockCommit, Nonce, 3x Public Key, 1x PK_Hash*/

        let mut amount_ar = [0u8; 8];
        amount_ar.copy_from_slice(hex::decode("0000000000000010").unwrap().as_slice());
        let amount = i64::from_be_bytes(amount_ar);

        let mut key_com = [0u8; 32];
        key_com.copy_from_slice(hex::decode("e0e14aeda7bcf9bbbf4744ecd03fcdcef0bbc83e0d9fe55c1fb372799e3a0698").unwrap().as_slice());

        let mut paytoken_mask_com = [0u8; 32];
        paytoken_mask_com.copy_from_slice(hex::decode("d31e6fea41aa7080a7d2b34357591bab1f295b178c85572f6a5ecc8af3a93ba8").unwrap().as_slice());

        let mut rev_lock_com = [0u8; 32];
        rev_lock_com.copy_from_slice(hex::decode("1caa135b24792810dcab8dffbb5157972e38dff248f0d43f5ea453111ca25852").unwrap().as_slice());

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(hex::decode("18670766caf2e5fec5f909d04acd5e86").unwrap().as_slice());

        let merch_escrow_pub_key = secp256k1::PublicKey::from_slice(hex::decode("0342da23a1de903cd7a141a99b5e8051abfcd4d2d1b3c2112bac5c8997d9f12a00").unwrap().as_slice()).unwrap();
        let merch_dispute_key = secp256k1::PublicKey::from_slice(hex::decode("0253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7c").unwrap().as_slice()).unwrap();
        let mut merch_public_key_hash = [0u8; 20];
        merch_public_key_hash.copy_from_slice(hex::decode("43e9e81bc632ad9cad48fc23f800021c5769a063").unwrap().as_slice());
        let merch_payout_pub_key = secp256k1::PublicKey::from_slice(hex::decode("02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90").unwrap().as_slice()).unwrap();


        mpc_build_masked_tokens_cust(amount, &paytoken_mask_com, &key_com,
                                     merch_escrow_pub_key, merch_dispute_key, merch_public_key_hash, merch_payout_pub_key,
                                     new_state, old_state, &t,
                                     &old_paytoken, cust_escrow_pub_key, cust_payout_pub_key);

        // pt unmasked               "8162c3044e8802d456b7355c5c101078953dbec160e2d83194952613deb19134"
        // pt mask                   "0c8dda801001c9a55f720c5f379ce09e42416780f98fef7900bd26b372b81850"
        // Masked PayToken Should be "8def19845e89cb7109c539036b8cf0e6d77cd941996d3748942800a0ac098964"
    }
    }

    #[test]
    fn createEcdsaParamsWorks() {
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        let sk = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        println!("secret key: {}", sk.to_string());
        let params = createEcdsaParams(csprng, &sk);
        let rx = unsafe { str::from_utf8(CStr::from_ptr(params.r.as_ptr()).to_bytes()).unwrap() };
        let k_inv = unsafe { str::from_utf8(CStr::from_ptr(params.k_inv.as_ptr()).to_bytes()).unwrap() };
        print!("r: {}\n", rx);
        print!("k^-1: {}\n", k_inv);
    }

    #[test]
    fn signature() {
        let secp = Secp256k1::new();
        let sig = hex::decode("96fec178aea8d00c83f36b3424dd56762a5440547938ecc82b5c204435418fd968bafe1af248ec2c9ff9aba262cfcf801b486c685467ebc567b9b4e5e5674135").unwrap();
        let mut signature = secp256k1::Signature::from_compact(&sig).unwrap();
        let par_sig_ser = hex::decode("96fec178aea8d00c83f36b3424dd56762a5440547938ecc82b5c204435418fd99eedce5c89bba8897758b7d7454eb5300657f6da1132d3a930fd9721c352b6e6ce6f2c740f993c6c60931ee965241e5a0527e4ab466d97dcc3436860370700d1").unwrap();
        let par_sig = secp256k1::PartialSignature::from_compact(&par_sig_ser).unwrap();
        let sk_ser = hex::decode("c71ffda863b14b3a9434a8799561cb15ac082cba2ad16bebae89a507cda267a2").unwrap();
        let sk = secp256k1::SecretKey::from_slice(&sk_ser).unwrap();
        let msg = hex::decode("063157f426b2123c72182ed5e3f418ff26b13de970ec9c0a625a16f31ae0ce64").unwrap();
        println!("message: {}", BigInt::from_bytes_be(Sign::Plus, &msg).to_string());
        println!("{}", BigInt::from_bytes_be(Sign::Plus, &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap()).to_string());
        let mes = secp256k1::Message::from_slice(&msg).unwrap();
        println!("{:?}", mes);
        let sign = secp.compute_sign(&mes, &par_sig);
        println!("{}", hex::encode(&sign.serialize_compact()[..]));
        assert!(secp.verify(&mes, &signature, &secp256k1::PublicKey::from_secret_key(&secp, &sk)).is_ok());
        assert!(secp.verify(&mes, &sign, &secp256k1::PublicKey::from_secret_key(&secp, &sk)).is_ok());
    }
}
