use secp256k1::{Signature, Message, PublicKey, Secp256k1};
use ecdsa_partial::EcdsaPartialSig;
use bindings::{EcdsaPartialSig_l};

extern "C" {
    pub fn test_ecdsa_e2e(
        partial: EcdsaPartialSig_l, 
        // hashedmsg: [u8; 32],
        party: u32,
        digest: &[u32; 8],
        ) -> ();
}

fn call_ecdsa(psl: EcdsaPartialSig_l, hashedmsg: [u8; 32], party: u32) -> () {
    println!("calling ecdsa!");
    let return_digest = [0u32; 8];

    unsafe {
        // TODO: pass hashed message
        test_ecdsa_e2e(psl, party, &return_digest)
    };

    let mut out = Vec::<u8>::new();
    for part in return_digest.iter() {
        out.extend_from_slice(&part.to_be_bytes()[..]);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(out.as_slice());
    println!("rsig: {}", hex::encode(digest));
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};
    use rand::{RngCore};

    // rusty fork tests call the two parties separately.
    rusty_fork_test! {
    #[test]
    fn test_mpc_ecdsa_MERCH() {
        println!("testing merch ... testing ...");

        let csprng = &mut rand::thread_rng();
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
        let signature = secp.compute_sign(&Message::from_slice(&hash).unwrap(), &(partial.getSecpRepr()));
        // println!("{}", hex::encode(signature.serialize_compact()));

        // compute signature under mpc as merch=1
        // TODO pass hashed message, not original
        call_ecdsa(partial.getMpcRepr(), msg, 1);

        // compare
    }}

    rusty_fork_test! {
    #[test]
    fn test_mpc_ecdsa_CUST() {
        println!("testing cust ... testing ...");

        /* this will all be ignored when we share the object */
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);
        let sk = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let partial = EcdsaPartialSig::New(csprng,&sk);

        let msg = [0u8; 32];

        // compute signature under mpc as cust=2
        call_ecdsa(partial.getMpcRepr(), msg, 2);

        // compare
    }}
}
