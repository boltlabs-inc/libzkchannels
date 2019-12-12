use libc::{c_int, c_char};
use secp256k1::{Signature, Message, PublicKey, SecretKey, Secp256k1};
use std::ffi::{CString, CStr};
use rand::{RngCore, Rng};
use bit_array::BitArray;
use typenum::U256;
use num::{BigUint, BigInt};
use num::bigint::Sign;
use sha2::{Sha256, Digest};

#[repr(C)]
struct c_wallet {
    channelId: *mut c_pubkey,
    wpk: *mut c_pubkey,
    bc: *mut c_char,
    bm: *mut c_char,
    txidM: *const bool,
    txidE: *const bool,
}

pub struct wallet {
    channelId: secp256k1::PublicKey,
    wpk: secp256k1::PublicKey,
    bc: i64,
    bm: i64,
    txidM: String,
    txidE: String,
}

#[repr(C)]
struct c_pubkey {
    pk: *const bool,
}

#[repr(C)]
struct c_ecdsa_params {
    rx: *mut c_char,
    k_inv: *mut c_char,
}

#[link(name = "token-utils")]
extern {
    fn build_masked_tokens_cust(pkM: *mut c_pubkey, amount: *mut c_char, com_new: *const bool, wpk_old: *mut c_pubkey, port: c_int,
                                ip_addr: *mut c_char, w_new: *mut c_wallet, w_old: *mut c_wallet, t: *mut c_char, pt_old: *mut c_char,
                                close_tx_escrow: *const bool, //[bool; 1024]
                                close_tx_merch: *const bool, //[bool; 1024]
                                ct_masked: *mut c_char, pt_masked: *mut c_char);
    fn build_masked_tokens_merch(pkM: *mut c_pubkey, amount: *mut c_char, com_new: *const bool, wpk_old: *mut c_pubkey,
                                 port: c_int, ip_addr: *mut c_char, close_mask: *const bool, pay_mask: *const bool,
                                 params1: *mut c_ecdsa_params, params2: *mut c_ecdsa_params, params3: *mut c_ecdsa_params);
}

pub fn mpc_build_masked_tokens_cust(pk_m: secp256k1::PublicKey, amount: i64, com_new: String, wpk_old: secp256k1::PublicKey,
                                    w_new: wallet, w_old: wallet, t: secp256k1::SecretKey, pt_old: Signature,
                                    close_tx_e: String, close_tx_m: String) -> (String, String) {
    // translate pk_m
    let mut pk = translate_pub_key(&pk_m);

    // translate commitment
    let com_bit_vec = translate_string(com_new);

    // translate wpk
    let mut wpk = translate_pub_key(&wpk_old);

    // translate new_wallet
    let mut new_wallet = translate_wallet(&w_new);
    // translate old_wallet
    let mut old_wallet = translate_wallet(&w_old);
    // translate blinding factor
    let t_str = CString::new(t.to_string()).unwrap().into_raw();
    // translate payment_token
    let pt_old_str = CString::new(BigUint::from_bytes_be(&pt_old.serialize_compact()).to_string()).unwrap().into_raw();
    // translate close_tx (e and m)
    let close_tx_e_bits = translate_string(close_tx_e);
    let close_tx_m_bits = translate_string(close_tx_m);
// create pointers for closing token and payment token
    let mut ct_masked = CString::new("").unwrap().into_raw();
    let mut pt_masked = CString::new("").unwrap().into_raw();

//    unsafe { build_masked_tokens_cust(&mut pk, CString::new(amount.to_string()).unwrap().into_raw(),com_bit_vec,
//                                      &mut wpk, 8181, CString::new("127.0.0.1").unwrap().into_raw(),
//                                      &mut new_wallet, &mut old_wallet, t_str, pt_old_str, close_tx_e_bits, close_tx_m_bits,
//                                      ct_masked, pt_masked) };

    let ct_masked_bytes = unsafe { CStr::from_ptr(ct_masked).to_bytes() };
    let ct_masked_str: &str = std::str::from_utf8(ct_masked_bytes).unwrap();
    let pt_masked_bytes = unsafe { CStr::from_ptr(pt_masked).to_bytes() };
    let pt_masked_str: &str = std::str::from_utf8(pt_masked_bytes).unwrap();

    (ct_masked_str.to_string(), pt_masked_str.to_string())
}

fn translate_wallet(wallet: &wallet) -> c_wallet {
    let mut new_wallet = c_wallet {
        channelId: &mut translate_pub_key(&wallet.channelId.clone()),
        wpk: &mut translate_pub_key(&wallet.wpk.clone()),
        bc: CString::new(wallet.bc.to_string()).unwrap().into_raw(),
        bm: CString::new(wallet.bm.to_string()).unwrap().into_raw(),
        txidM: translate_string(wallet.txidM.clone()),
        txidE: translate_string(wallet.txidE.clone()),
    };
    new_wallet
}

fn translate_string(in_str: String) -> *const bool {
    let str_bits = BitArray::<u8, U256>::from_bytes(in_str.as_bytes());
    let res_vec: Vec<bool> = str_bits.iter().map(|e| e.clone()).collect();
    res_vec.as_ptr()
}

fn translate_pub_key(pk: &PublicKey) -> c_pubkey {
    let pk_bits = BitArray::<u8, U256>::from_bytes(&pk.serialize());
    let pk_bit_vec: Vec<bool> = pk_bits.iter().map(|e| e.clone()).collect();
    let mut res = c_pubkey { pk: pk_bit_vec.as_ptr() };
    res
}

pub fn mpc_build_masked_tokens_merch<R: Rng>(rng: &mut R, pk_m: secp256k1::PublicKey, amount: i64, com_new: String, wpk_old: secp256k1::PublicKey,
                                     sk_m: secp256k1::SecretKey) {
    // translate pk_m
    let mut pk = translate_pub_key(&pk_m);

    // translate commitment
    let com_bit_vec = translate_string(com_new);

    // translate wpk
    let mut wpk = translate_pub_key(&wpk_old);

    // Create ECDSA_params
    let mut params1 = createEcdsaParams(sk_m.clone());
    let mut params2 = createEcdsaParams(sk_m.clone());
    let mut params3 = createEcdsaParams(sk_m.clone());

    // Create close_mask
    let mut close_mask_bytes = [0u8; 32];
    rng.fill_bytes(&mut close_mask_bytes);
    let close_mask_bits = BitArray::<u8, U256>::from_bytes(&close_mask_bytes);
    let close_mask: Vec<bool> = close_mask_bits.iter().map(|e| e.clone()).collect();

    // Create pay_mask
    let mut pay_mask_bytes = [0u8; 32];
    rng.fill_bytes(&mut pay_mask_bytes);
    let pay_mask_bits = BitArray::<u8, U256>::from_bytes(&pay_mask_bytes);
    let pay_mask: Vec<bool> = pay_mask_bits.iter().map(|e| e.clone()).collect();

//    unsafe { build_masked_tokens_merch(&mut pk, CString::new(amount.to_string()).unwrap().into_raw(),
//                                       com_bit_vec, &mut wpk, 8181, CString::new("127.0.0.1").unwrap().into_raw(),
//                                       close_mask.as_ptr(), pay_mask.as_ptr(),
//                                       &mut params1, &mut params2, &mut params3) };
}

fn createEcdsaParams(sk: secp256k1::SecretKey) -> c_ecdsa_params {
    let rng = &mut rand::thread_rng();
    let secp = secp256k1::Secp256k1::new();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let nonce_message = Message::from_slice(&nonce);
    let partial_signature = secp.partial_sign(&nonce_message.unwrap(), &sk);
    let mut msg = [0u8; 27];
    rng.fill_bytes(&mut msg);
    println!("message: {:?}", hex::encode(&msg[..]));
    let mut hasher = Sha256::new();
    hasher.input(msg);
    let msg2 = hasher.result();
    let mes = Message::from_slice(msg2.as_slice());
    println!("message hash: {:?}", mes.unwrap());
    let signature = secp.compute_sign(&mes.unwrap(), &partial_signature);
    let serialized_signature = signature.serialize_compact();
    println!("Signature: {:?}", hex::encode(serialized_signature.to_vec()));
    assert!(secp.verify(&mes.unwrap(), &signature, &secp256k1::PublicKey::from_secret_key(&secp, &sk)).is_ok());
    let par_sig_compact = partial_signature.serialize_compact();
    let rx = &par_sig_compact[32..64];
    println!("parsig: {:?}", hex::encode(&par_sig_compact[..]));
    let k_inv = &par_sig_compact[64..];

    c_ecdsa_params {
        rx: CString::new(BigInt::from_bytes_be(Sign::Plus,rx).to_string()).unwrap().into_raw(),
        k_inv: CString::new(BigInt::from_bytes_be(Sign::Plus,k_inv).to_string()).unwrap().into_raw(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use typenum::U32;
    use std::str;
    use num::BigInt;

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
        let wpk = PublicKey::from_secret_key(&Secp256k1::new(), &wsk);

        mpc_build_masked_tokens_merch(csprng, pk_m, 6, "test_commitment".parse().unwrap(), wpk, sk_m);
    }

    #[test]
    fn createEcdsaParamsWorks() {
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        let sk = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        println!("secret key: {}", sk.to_string());
        let params = createEcdsaParams(sk);
        let rx = unsafe { str::from_utf8(CStr::from_ptr(params.rx).to_bytes()).unwrap() };
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
        println!("{}", BigInt::from_bytes_be(Sign::Plus,&hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap()).to_string());
        let mes = secp256k1::Message::from_slice(&msg).unwrap();
        println!("{:?}", mes);
        let sign = secp.compute_sign(&mes, &par_sig);
        println!("{}", hex::encode(&sign.serialize_compact()[..]));
        assert!(secp.verify(&mes, &signature, &secp256k1::PublicKey::from_secret_key(&secp, &sk)).is_ok());
        assert!(secp.verify(&mes, &sign, &secp256k1::PublicKey::from_secret_key(&secp, &sk)).is_ok());
    }


}