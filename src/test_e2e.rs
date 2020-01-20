use libc::{c_int, c_uint, c_void};
use secp256k1::{Signature, Message, PublicKey, Secp256k1};
use std::ffi::{CString, CStr};
use rand::{RngCore, Rng};
use num::BigInt;
use num::bigint::Sign;
use util::hmac_sign;
use std::slice;
use wallet::State;
use ecdsa_partial::EcdsaPartialSig;
use std::ptr;
use std::str;

extern "C" {
    pub fn build_test();
}

pub fn call_ecdsa() -> () {
    println!("calling ecdsa!");
    /*
    unsafe {
        build_test();
    };
    */
}

#[cfg(test)]
mod tests {
    use super::*;
    use typenum::U32;
    use std::{str, thread};
    use num::BigInt;
    use std::time::Duration;
    use sha2::{Sha256, Digest};
    use secp256k1::PartialSignature;
    use std::str::FromStr;
    use rand::rngs::mock::StepRng;

    #[test]
    fn test_mpc_ecdsa() {
        println!("testing ... testing ...");
        call_ecdsa();
        /*
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);
        let sk = secp256k1::SecretKey::from_slice(&seckey).unwrap();

        //let (eps,sps) = createEcdsaParamsPair(csprng,&sk);


        // compute signature locally
        let mut msg = [0u8; 32];
        csprng.fill_bytes(&mut msg);
        let mut hasher = Sha256::new();
        hasher.input(msg);
        let hash = hasher.result();
        //println!("{:x} --> {:x}", BigInt::from_bytes_be(Sign::Plus,&msg), hash);

        let secp = secp256k1::Secp256k1::new();
        let signature = secp.compute_sign(&Message::from_slice(&hash).unwrap(), &sps);
        println!("{}", hex::encode(signature.serialize_compact()));
        */

        // compute signature under mpc

        // compare
    }
}
