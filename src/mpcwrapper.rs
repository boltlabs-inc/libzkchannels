use libc::{c_int, c_char};
use secp256k1::{Signature, Message, PublicKey, Secp256k1};
use std::ffi::{CString, CStr};
use rand::{RngCore, Rng};
use bit_array::BitArray;
use typenum::{U264, U64};
use num::BigInt;
use num::bigint::Sign;
use bindings::{PubKey, build_masked_tokens_cust, build_masked_tokens_merch, EcdsaPartialSig_l, State_l, RevLock_l, Nonce_l, Balance_l, PayToken_l, Txid_l, Mask_l, HMACKeyCommitment_l, MaskCommitment_l, HMACKey_l};
use std::slice;
use wallet::State;

pub fn mpc_build_masked_tokens_cust(pk_m: secp256k1::PublicKey, amount: i64, com_new: &[u8], key_com: &[u8],
                                    new_state: State, old_state: State, t: &[u8; 32], pt_old: &[u8],
                                    close_tx_e: &[u8], close_tx_m: &[u8]) -> ([u8; 32], [u8; 32]) {
    // translate pk_m
    let mut pk = translate_pub_key(&pk_m);

    // translate wpk
    let mut rl = translate_revlock(&new_state.rev_lock[..]);

    // translate new_wallet
    let mut new_state_c = translate_state(&new_state);
    // translate old_wallet
    let mut old_state_c = translate_state(&old_state);
    // translate blinding factor
    let t_str = translate_string(&t[..]);
    // translate payment_token
    let pt_old_c = translate_paytoken(&pt_old);
    // translate close_tx (e and m)
    let close_tx_e_bits = translate_string(close_tx_e);
    let close_tx_m_bits = translate_string(close_tx_m);
    //paymask_com
    let paymask_com = MaskCommitment_l {
        commitment: translate_256_string(com_new),
    };

    //key_com
    let key_com = HMACKeyCommitment_l {
        commitment: translate_256_string(key_com),
    };

// create pointers for closing token and payment token
    let mut ct_masked = [0i8; 256].as_mut_ptr();
    let mut pt_masked = [0i8; 256].as_mut_ptr();

    unsafe {
        build_masked_tokens_cust(pk, amount as u64, rl,
                                 12345, CString::new("127.0.0.1").unwrap().into_raw(),
                                 paymask_com, key_com,
                                 new_state_c, old_state_c, t_str, pt_old_c, close_tx_e_bits, close_tx_m_bits,
                                 ct_masked, pt_masked)
    };

    let mut ct_masked_ar = [0u8; 32];
//    let ct_masked_bytes = unsafe { CStr::from_ptr(ct_masked).to_bytes() };
//    ct_mask_ar.copy_from_slice(ct_masked_bytes);
    let mut pt_masked_ar = [0u8; 32];
//    let pt_masked_bytes = unsafe { CStr::from_ptr(pt_masked).to_bytes() };
//    pt_mask_ar.copy_from_slice(pt_masked_bytes);

    (ct_masked_ar, pt_masked_ar)
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

    let vec = bytes_to_u32(&state.nonce[..], 12);
    let mut nonce = [0u32; 4];
    nonce.copy_from_slice(vec.as_slice());

    let mut bc = [0u32; 2];
    let bc_vec = bytes_to_u32(&state.bc.to_le_bytes(), 8);
    bc.copy_from_slice(bc_vec.as_slice());
    let bm_vec = bytes_to_u32(&state.bm.to_le_bytes(), 8);
    let mut bm = [0u32; 2];
    bm.copy_from_slice(bm_vec.as_slice());

    let mut new_state = State_l {
        nonce: Nonce_l { nonce },
        rl: translate_revlock(&state.rev_lock[..]),
        balance_cust: Balance_l { balance: bc },
        balance_merch: Balance_l { balance: bm },
        txid_merch: Txid_l { txid: txid_merch },
        txid_escrow: Txid_l { txid: txid_escrow },
        HashPrevOuts_escrow: Txid_l { txid: prevout_escrow },
        HashPrevOuts_merch: Txid_l { txid: prevout_merch }
    };
    new_state
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

fn translate_pub_key(pk: &PublicKey) -> PubKey {
    let mut pk_ar = [0i8; 33];
    let pk_comp = pk.serialize();
    let pk_slice = unsafe {
        slice::from_raw_parts(pk_comp.as_ptr() as *const i8, pk_comp.len())
    };
    pk_ar.copy_from_slice(pk_slice);
    let mut res = PubKey { pubkey: pk_ar };
    res
}

fn translate_revlock(rl: &[u8]) -> RevLock_l {
    let mut res = RevLock_l { revlock: translate_256_string(rl) };
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

pub fn mpc_build_masked_tokens_merch<R: Rng>(rng: &mut R, pk_m: secp256k1::PublicKey, amount: i64, com_new: &[u8], rl: &[u8],
                                             key_com: &[u8], hmac_key: &[u8], sk_m: secp256k1::SecretKey, close_mask: &[u8; 32], pay_mask: &[u8; 32]) {
    // translate pk_m
    let mut pk = translate_pub_key(&pk_m);

    // translate wpk
    let mut rl_c = translate_revlock(rl);

    // Create ECDSA_params
    let mut params1 = createEcdsaParams(rng, &sk_m.clone());
    let mut params2 = createEcdsaParams(rng, &sk_m.clone());
    let mut params3 = createEcdsaParams(rng, &sk_m.clone());

    // Create close_mask
    let close_mask_c = Mask_l { mask: translate_256_string(close_mask) };

    // Create pay_mask
    let pay_mask_c = Mask_l { mask: translate_256_string(pay_mask) };

    let amount_bits = BitArray::<u8, U64>::from_bytes(amount.to_string().as_ref());
    let amount_vec: Vec<bool> = amount_bits.iter().map(|e| e.clone()).collect();

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
        build_masked_tokens_merch(pk, amount as u64, rl_c,
                                  12345, CString::new("127.0.0.1").unwrap().into_raw(),
                                  paymask_com, key_com, hmac_key,
                                  close_mask_c, pay_mask_c, params1, params2, params3)
    };
}

fn createEcdsaParams<R: Rng>(rng: &mut R, sk: &secp256k1::SecretKey) -> EcdsaPartialSig_l {
    let secp = secp256k1::Secp256k1::new();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let nonce_message = Message::from_slice(&nonce);
    let partial_signature = secp.partial_sign(&nonce_message.unwrap(), &sk);
    let par_sig_compact = partial_signature.0.serialize_compact();
    let r_arr = translate_256_chars(&par_sig_compact[32..64]);
    let inv = translate_256_chars(&par_sig_compact[64..]);

    EcdsaPartialSig_l {
        r: r_arr,
        k_inv: inv,
    }
}

fn translate_256_chars(rx: &[u8]) -> [i8; 256] {
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

        let sk_m = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let pk_m = PublicKey::from_secret_key(&Secp256k1::new(), &sk_m);

        let mut secwsk = [0u8; 32];
        csprng.fill_bytes(&mut secwsk);
        let wsk = secp256k1::SecretKey::from_slice(&secwsk).unwrap();
        let rl = hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap();

        let mut close_mask_bytes = [0u8; 32];
        csprng.fill_bytes(&mut close_mask_bytes);
        let mut pay_mask_bytes = [0u8; 32];
        csprng.fill_bytes(&mut pay_mask_bytes);

        mpc_build_masked_tokens_merch(csprng, pk_m, 6, hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice(), rl.as_slice(),
                                      hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice(),
                                      hex::decode("11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice(),
                                      sk_m, &close_mask_bytes, &pay_mask_bytes);
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

        let mut secwsk = [0u8; 32];
        csprng.fill_bytes(&mut secwsk);
        let wsk = secp256k1::SecretKey::from_slice(&secwsk).unwrap();
        let wpk = PublicKey::from_secret_key(&Secp256k1::new(), &wsk);

        let mut nonce1 = [0u8; 16];
        let mut nonce2 = [0u8; 16];
        csprng.fill_bytes(&mut nonce1);
        csprng.fill_bytes(&mut nonce2);

        let mut rl_ar = [0u8; 32];
        rl_ar.copy_from_slice(hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice());

        let mut tx_id_merch = [0u8; 32];
        tx_id_merch.copy_from_slice(hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice());

        let mut tx_id_esc = [0u8; 32];
        tx_id_esc.copy_from_slice(hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice());
        let new_state = State {
            nonce: nonce1,
            rev_lock: rl_ar,
            pk_c,
            pk_m,
            bc: 0,
            bm: 0,
            escrow_txid: tx_id_esc,
            merch_txid: tx_id_merch,
            escrow_prevout: [0u8; 32],
            merch_prevout: [1u8; 32]
        };
        let old_state = State {
            nonce: nonce2,
            rev_lock: rl_ar,
            pk_c,
            pk_m,
            bc: 0,
            bm: 0,
            escrow_txid: tx_id_esc,
            merch_txid: tx_id_merch,
            escrow_prevout: [0u8; 32],
            merch_prevout: [1u8; 32]
        };

        let mut t = [0u8; 32];
        t.copy_from_slice(hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice());

        mpc_build_masked_tokens_cust(pk_m, 6, hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice(),
                                     hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice(), new_state, old_state,
                                     &t,
                                     hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap().as_slice(),
                                     &[1u8; 1024][..],
                                     &[1u8; 1024][..]);
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
