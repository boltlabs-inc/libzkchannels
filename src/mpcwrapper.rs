use libc::{c_int, c_char};
use secp256k1::{Signature, Message, PublicKey, Secp256k1};
use std::ffi::{CString, CStr};
use rand::{RngCore, Rng};
use bit_array::BitArray;
use typenum::{U264, U64};
use num::BigInt;
use num::bigint::Sign;
use bindings::{PubKey, build_masked_tokens_cust, build_masked_tokens_merch, EcdsaPartialSig_l, RevLock, State};

pub fn mpc_build_masked_tokens_cust(pk_m: secp256k1::PublicKey, amount: i64, com_new: String, wpk_old: secp256k1::PublicKey,
                                    w_new: State, w_old: State, t: secp256k1::SecretKey, pt_old: Signature,
                                    close_tx_e: String, close_tx_m: String) -> (String, String) {
    // translate pk_m
    let mut pk = translate_pub_key(&pk_m);

    // translate commitment
    let com_bit_vec = translate_string(com_new);

    // translate wpk
    let mut wpk = translate_revlock(&wpk_old);

    // translate new_wallet
    let mut new_wallet = w_new.clone();
    // translate old_wallet
    let mut old_wallet = w_old.clone();
    // translate blinding factor
    let t_str = CString::new(t.to_string()).unwrap().into_raw();
    // translate payment_token
    let pt_old_str = CString::new(BigInt::from_bytes_be(Sign::Plus, &pt_old.serialize_compact()).to_string()).unwrap().into_raw();
    // translate close_tx (e and m)
    let close_tx_e_bits = translate_string(close_tx_e);
    let close_tx_m_bits = translate_string(close_tx_m);
// create pointers for closing token and payment token
    let mut ct_masked = CString::new("").unwrap().into_raw();
    let mut pt_masked = CString::new("").unwrap().into_raw();

    unsafe {
        build_masked_tokens_cust(&mut pk, CString::new(amount.to_string()).unwrap().into_raw(), com_bit_vec,
                                 &mut wpk, 8181, CString::new("127.0.0.1").unwrap().into_raw(),
                                 &mut new_wallet, &mut old_wallet, t_str, pt_old_str, close_tx_e_bits, close_tx_m_bits,
                                 ct_masked, pt_masked)
    };

    let ct_masked_bytes = unsafe { CStr::from_ptr(ct_masked).to_bytes() };
    let ct_masked_str: &str = std::str::from_utf8(ct_masked_bytes).unwrap();
    let pt_masked_bytes = unsafe { CStr::from_ptr(pt_masked).to_bytes() };
    let pt_masked_str: &str = std::str::from_utf8(pt_masked_bytes).unwrap();

    (ct_masked_str.to_string(), pt_masked_str.to_string())
}

//fn translate_wallet(wallet: &wallet) -> c_wallet {
//    let mut new_wallet = c_wallet {
//        channelId: &mut translate_pub_key(&wallet.channelId.clone()),
//        wpk: &mut translate_pub_key(&wallet.wpk.clone()),
//        bc: CString::new(wallet.bc.to_string()).unwrap().into_raw(),
//        bm: CString::new(wallet.bm.to_string()).unwrap().into_raw(),
//        txidM: translate_string(wallet.txidM.clone()),
//        txidE: translate_string(wallet.txidE.clone()),
//    };
//    new_wallet
//}

fn translate_string(in_str: String) -> *mut c_char {
    CString::new(in_str).unwrap().into_raw()
}

fn translate_pub_key(pk: &PublicKey) -> PubKey {
    let pk_bits = BitArray::<u8, U264>::from_bytes(&pk.serialize());
    let mut res = PubKey { pubkey: CString::new(format!("{:?}", pk_bits)).unwrap().into_raw() };
    res
}

fn translate_revlock(pk: &PublicKey) -> RevLock {
    let pk_bits = BitArray::<u8, U264>::from_bytes(&pk.serialize());
    let mut res = RevLock { revlock: CString::new(format!("{:?}", pk_bits)).unwrap().into_raw() };
    res
}

pub fn mpc_build_masked_tokens_merch<R: Rng>(rng: &mut R, pk_m: secp256k1::PublicKey, amount: i64, com_new: String, wpk_old: secp256k1::PublicKey,
                                             sk_m: secp256k1::SecretKey) {
    // translate pk_m
    let mut pk = translate_pub_key(&pk_m);

    // translate commitment
    let com_bit_vec = translate_string(com_new);

    // translate wpk
    let mut wpk = translate_revlock(&wpk_old);

    // Create ECDSA_params
    let mut params1 = createEcdsaParams(&sk_m.clone());
    let mut params2 = createEcdsaParams(&sk_m.clone());
    let mut params3 = createEcdsaParams(&sk_m.clone());

    // Create close_mask
    let mut close_mask_bytes = [0u8; 32];
    rng.fill_bytes(&mut close_mask_bytes);
    let close_mask = CString::new(hex::encode(close_mask_bytes)).unwrap().into_raw();

    // Create pay_mask
    let mut pay_mask_bytes = [0u8; 32];
    rng.fill_bytes(&mut pay_mask_bytes);
    let pay_mask = CString::new(hex::encode(pay_mask_bytes)).unwrap().into_raw();

    let amount_bits = BitArray::<u8, U64>::from_bytes(amount.to_string().as_ref());
    let amount_vec: Vec<bool> = amount_bits.iter().map(|e| e.clone()).collect();

    unsafe {
        build_masked_tokens_merch(&mut pk, CString::new(amount.to_string()).unwrap().into_raw(), com_bit_vec,
                                  &mut wpk, 8181, CString::new("127.0.0.1").unwrap().into_raw(),
                                  close_mask, pay_mask, &mut params1, &mut params2, &mut params3)
    };
}

fn createEcdsaParams(sk: &secp256k1::SecretKey) -> EcdsaPartialSig_l {
    let rng = &mut rand::thread_rng();
    let secp = secp256k1::Secp256k1::new();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let nonce_message = Message::from_slice(&nonce);
    let partial_signature = secp.partial_sign(&nonce_message.unwrap(), &sk);
    let par_sig_compact = partial_signature.0.serialize_compact();
    let rx = &par_sig_compact[32..64];
    let k_inv = &par_sig_compact[64..];

    EcdsaPartialSig_l {
        r: CString::new(hex::encode(rx)).unwrap().into_raw(),
        k_inv: CString::new(hex::encode(k_inv)).unwrap().into_raw(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use typenum::U32;
    use std::str;
    use num::BigInt;

    #[test]
    #[ignore]
    fn mpc_build_masked_tokens_merch_works() {
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        let sk_m = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let pk_m = PublicKey::from_secret_key(&Secp256k1::new(), &sk_m);

        let mut secwsk = [0u8; 32];
        csprng.fill_bytes(&mut secwsk);
        let wsk = secp256k1::SecretKey::from_slice(&secwsk).unwrap();
        let wpk = PublicKey::from_secret_key(&Secp256k1::new(), &wsk);

        mpc_build_masked_tokens_merch(csprng, pk_m, 6, "test_commitment".parse().unwrap(), wpk, sk_m);
    }

    #[test]
    #[ignore]
    fn mpc_build_masked_tokens_cust_works() {
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        let sk_m = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let pk_m = PublicKey::from_secret_key(&Secp256k1::new(), &sk_m);

        let mut secwsk = [0u8; 32];
        csprng.fill_bytes(&mut secwsk);
        let wsk = secp256k1::SecretKey::from_slice(&secwsk).unwrap();
        let wpk = PublicKey::from_secret_key(&Secp256k1::new(), &wsk);
        let secp = secp256k1::Secp256k1::new();
        let signature = secp.sign(&Message::from_slice(&secwsk).unwrap(), &wsk);

        mpc_build_masked_tokens_cust(pk_m, 6, "test_commitment".parse().unwrap(), wpk, State{
            pkC: &mut PubKey{ pubkey: &mut 0i8 },
            rl: &mut RevLock{ revlock: &mut 0i8 },
            balance_cust: 0,
            balance_merch: 0,
            txid_merch: [&mut 0i8; 256],
            txid_escrow: [&mut 0i8; 256]
        }, State{
            pkC: &mut PubKey{ pubkey: &mut 0i8 },
            rl: &mut RevLock{ revlock: &mut 0i8 },
            balance_cust: 0,
            balance_merch: 0,
            txid_merch: [&mut 0i8; 256],
            txid_escrow: [&mut 0i8; 256]
        }, wsk, signature, "test_tx1".parse().unwrap(), "test_tx2".parse().unwrap());
    }

    #[test]
    fn createEcdsaParamsWorks() {
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        let sk = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        println!("secret key: {}", sk.to_string());
        let params = createEcdsaParams(&sk);
        let rx = unsafe { str::from_utf8(CStr::from_ptr(params.r).to_bytes()).unwrap() };
        let k_inv = unsafe { str::from_utf8(CStr::from_ptr(params.k_inv).to_bytes()).unwrap() };
        print!("r: {}\n", rx);
        print!("k^-1: {}\n", k_inv);
    }

    #[test]
    fn testConvertToBitArray_works() {
        let input: &[u8] = &[165, 125, 255, 153];
        let array = BitArray::<u8, U32>::from_bytes(input);
        assert_eq!("10100101011111011111111110011001", format!("{:?}", array));
        let x: Vec<bool> = array.iter().map(|e| e.clone()).collect();
        assert_eq!(vec!(true, false, true, false, false, true, false, true, false, true, true, true, true, true, false, true, true, true, true, true, true, true, true, true, true, false, false, true, true, false, false, true), x);
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