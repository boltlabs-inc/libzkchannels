// include standard libraries
use num::BigInt;
use num::bigint::Sign;
use rand::{RngCore, Rng};
use std::slice;
use std::ffi::{CString, CStr};
use super::*;

// include our libraries
use bindings::{EcdsaPartialSig_l};
use secp256k1::{Signature, Message, PublicKey, Secp256k1};

#[derive(Copy, Clone)] //, Serialize, Deserialize)]
pub struct EcdsaPartialSig {
    pub partial: secp256k1::PartialSignature
}

/* This module deals with ECDSA partial signatures
 * It returns different representations compatible with various libraries
 * including the bolt fork of secp256k1 and our EMP-toolkit-compatible tokenutils 
 */
impl EcdsaPartialSig {
    pub fn New<R:Rng>(rng: &mut R, sk: &secp256k1::SecretKey) -> EcdsaPartialSig {
        let secp = secp256k1::Secp256k1::new();
        // generate random nonce
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let nonce_message = Message::from_slice(&nonce);
 
        // compute partial signature
        let partial_signature = secp.partial_sign(&nonce_message.unwrap(), &sk);
        EcdsaPartialSig {partial: partial_signature.0 }

    }

    pub fn getSecpRepr(&self) -> secp256k1::PartialSignature {
        return self.partial
    }

    pub fn getMpcRepr(&self) -> EcdsaPartialSig_l {
        let partial_compact = self.partial.serialize_compact();
        let r_arr = translate_rx(&partial_compact[32..64]);
        let inv = translate_rx(&partial_compact[64..]);
        EcdsaPartialSig_l {
            r: r_arr,
            k_inv: inv,
        }
    }

    pub fn getK(&self) -> [u8;32] {
        let partial_compact = self.partial.serialize_compact();
        let mut k = [0u8; 32];
        k.copy_from_slice(&partial_compact[0..32]);
        k
    }
}

// local functions
// adds padding and messes around with types?
fn translate_rx(rx: &[u8]) -> [i8; 256] {
    //println!("translating in ecdsa_partial");
    let int = BigInt::from_bytes_be(Sign::Plus, rx);
    let out = CString::new(int.to_string()).unwrap();
    let out_ptr = out.as_ptr();
    let out_slice = unsafe { slice::from_raw_parts(out_ptr, int.to_string().len()) };
    let mut out_vec = out_slice.to_vec();
    let pad = 256 - out_vec.len();
    let mut padding_vec = Vec::new();
    for i in 0..pad {
        padding_vec.push(0x0 as i8);
    }
    out_vec.append(&mut padding_vec);
    let mut out_ar = [0i8; 256];
    out_ar.copy_from_slice(out_vec.as_slice());
    out_ar
}
