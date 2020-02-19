use secp256k1;
use bindings::{EcdsaPartialSig_l};
use std::convert::TryInto;
use std::ffi::CString;
use std::os::raw::c_char;


extern "C" {
    pub fn test_ecdsa_e2e(
        partial: EcdsaPartialSig_l, 
        hashedmsg: *const c_char,
        party: u32,
        digest: &[u32; 8],
        ) -> ();
}

fn call_ecdsa(psl: EcdsaPartialSig_l, hashedmsg: [u8; 32], party: u32) -> [u8; 32] {
    let return_digest = [0u32; 8];
    let hmsg = CString::new(hex::encode(hashedmsg)).unwrap();

    unsafe {
        test_ecdsa_e2e(psl, hmsg.as_ptr(), party, &return_digest);
    };

    let mut out = Vec::<u8>::new();
    for part in return_digest.iter() {
        out.extend_from_slice(&part.to_be_bytes()[..]);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(out.as_slice());
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};
    const NUM_TESTS: i32 = 50;
    use ecdsa_partial::{EcdsaPartialSig, translate_rx};
    use rand::RngCore;

    // rusty fork tests call the two parties separately.
    rusty_fork_test! {
    #[test]
    
    // tests MPC ecdsa implementation
    // variable ownership is not accurately reflected here
    // VARS party
    // - generates random ecdsa key
    // - generates ecdsa partial signature
    // - generates random message
    // - signs message with partial signature
    // - compares to MPC signature result
    fn test_mpc_ecdsa_VARS() {
        let csprng = &mut rand::thread_rng();

        for _ in 0..NUM_TESTS {
            let mut seckey = [0u8; 32];
            csprng.fill_bytes(&mut seckey);
            let sk = secp256k1::SecretKey::from_slice(&seckey).unwrap();
            let partial = EcdsaPartialSig::New(csprng,&sk);

            // compute signature locally
            let mut msg = [0u8; 32];
            csprng.fill_bytes(&mut msg);
            let mut hasher = Sha256::new();
            hasher.input(msg);

            let hash = hasher.result();

            let secp = secp256k1::Secp256k1::new();
            let signature = secp.compute_sign(&secp256k1::Message::from_slice(&hash).unwrap(), &(partial.getSecpRepr()));

            // compute signature under mpc as merch=1
            let hmsg: [u8; 32] = hash.as_slice().try_into().expect("Wrong length");
            let digest = call_ecdsa(partial.getMpcRepr(), hmsg, 1);

            // compare
            assert_eq!(hex::encode(digest),
                    hex::encode(&signature.serialize_compact()[32..]));
        }
        println!("Passed {} ECDSA end-to-end tests", NUM_TESTS);
    }}

    rusty_fork_test! {
    #[test]
    fn test_mpc_ecdsa_NOVARS() {
        let csprng = &mut rand::thread_rng();

        for _ in 0..NUM_TESTS {
            /* this will all be ignored when we share the object */
            let mut seckey = [0u8; 32];
            csprng.fill_bytes(&mut seckey);
            let sk = secp256k1::SecretKey::from_slice(&seckey).unwrap();
            let partial = EcdsaPartialSig::New(csprng,&sk);

            let hmsg = [1u8; 32];

            // compute signature under mpc as cust=2
            call_ecdsa(partial.getMpcRepr(), hmsg, 2);
        }
        println!("Passed {} ECDSA end-to-end tests", NUM_TESTS);
    }}
}
