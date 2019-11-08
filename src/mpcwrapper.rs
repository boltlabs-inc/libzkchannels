use libc::{c_int, c_uchar};
use wallet::Wallet;
use secp256k1::{Signature, All};
use secp256k1::ffi::secp256k1_context_no_precomp;
use std::ffi::{CString, CStr};

#[repr(C)]
struct c_wallet {
    channelId: *mut c_pubkey,
    wpk: *mut c_pubkey,
    bc: c_int,
    bm: c_int,
    txidM: *const bool,
    txidE: *const bool,
}

#[repr(C)]
struct c_commit {
    c: *const bool,
    params: *const *const bool,
}

#[repr(C)]
struct c_pubkey {
    pk: *const bool,
}

#[repr(C)]
struct c_privkey {
    sk: *const bool,
}

#[repr(C)]
struct c_ecdsa_params {
    rx: *const bool,
    k_inv: *const bool,
}

#[link(name = "token")]
extern {
    fn build_masked_tokens_cust(pkM: *mut c_pubkey, amount: c_int, com_new: *mut c_commit, wpk_old: *mut c_pubkey, port: c_int,
                                ip_addr: c_int, w_new: *mut c_wallet, w_old: *mut c_wallet, t: c_int, pt_old: c_int,
                                close_tx_escrow: *const bool, //[bool; 1024]
                                close_tx_merch: *const bool, //[bool; 1024]
                                ecdse_params: *const c_ecdsa_params, //[c_ecdsa_params; 3]
                                ct_masked: *mut c_char, pt_masked: *mut c_char);
    fn build_masked_tokens_merch(pkM: *mut c_pubkey, amount: c_int, com_new: *mut c_commit, wpk_old: *mut c_pubkey,
                                 port: c_int, ip_addr: c_int, skM: *mut c_privkey);
}

pub fn mpc_build_masked_tokens_cust(pk_m: secp256k1::PublicKey, amount: i64, com_new: String, wpk_old: secp256k1::PublicKey,
                                    w_new: Wallet<secp256k1::Secp256k1>, w_old: Wallet<secp256k1::Secp256k1>, t: secp256k1::SecretKey, pt_old: Signature,
                                    close_tx_e: String, close_tx_m: String) -> (String, String) {
    // translate pk_m
    let ser_pk_m = pk_m.serialize();
    // translate amount
    // translate commitment
    // translate wpk
    // translate new_wallet
    // translate old_wallet
    // translate blinding factor
    // translate payment_token
    // translate close_tx (e and m)
    // create pointers for closing token and payment token
    let mut ct_masked = CString::new("").unwrap().into_raw();
    let mut pt_masked = CString::new("").unwrap().into_raw();

    unsafe { build_masked_tokens_cust(ct_masked, pt_masked) };

    let ct_masked_bytes = unsafe { CStr::from_ptr(ct_masked).to_bytes() };
    let ct_masked_str: &str = str::from_utf8(bytes).unwrap();
    let pt_masked_bytes = unsafe { CStr::from_ptr(pt_masked).to_bytes() };
    let pt_masked_str: &str = str::from_utf8(bytes).unwrap();

    (ct_masked_str.into_string(), pt_masked_str.into_string())
}

pub fn mpc_build_masked_tokens_merch(pk_m: secp256k1::PublicKey, amount: i64, com_new: String, wpk_old: secp256k1::PublicKey,
                                     sk_m: secp256k1::SecretKey) {
    // translate pk_m
    // translate amount
    // translate commitment
    // translate wpk
    // translate sk_m
    // Create ECDSA_params
    let params = createEcdsaParams(3, sk_m);


    unsafe { build_masked_tokens_merch() };
}

fn createEcdsaParams(l: usize, sk: secp256k1::SecretKey) -> *mut c_ecdsa_params {
    let mut params = vec! {};
    for i in 0..l {
        // generate random k
        let rng = &mut rand::thread_rng();
        let k = secp256k1::SecretKey::new(rng);
        // compute k^-1

        // compute (r_x, r_y) = kG
        let secp = secp256k1::Secp256k1::new();
        let r_x = secp256k1::PublicKey::from_secret_key(secp, &k);
        // compute r_x * sk mod q

        params.append(c_ecdsa_params {
            rx: &true,
            k_inv: &false,
        });
    }
    params.as_ptr();
}

#[cfg(test)]
mod tests {}