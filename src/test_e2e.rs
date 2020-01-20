use secp256k1::{Signature, Message, PublicKey, Secp256k1};
use rand::{RngCore};
use ecdsa_partial::EcdsaPartialSig;
use bindings::{EcdsaPartialSig_l};

extern "C" {
    pub fn test_ecdsa_e2e(partial: EcdsaPartialSig_l, digest: &[u32; 8]) -> ();
}

pub fn call_ecdsa(psl: EcdsaPartialSig_l) -> () {
    println!("calling ecdsa!");
    let return_digest = [0u32; 8];

    unsafe {
        test_ecdsa_e2e(psl, &return_digest);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    #[test]
    fn test_mpc_ecdsa() {
        println!("testing ... testing ...");

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

        // compute signature under mpc
        call_ecdsa(partial.getMpcRepr());

        // compare
    }
}
