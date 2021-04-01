use super::*;
use ff::PrimeField;
use hmac::{Hmac, Mac};
use num::BigUint;
use pairing::Engine;
use ripemd160::Ripemd160;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[macro_export]
macro_rules! handle_error_util {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => return Err(err.to_string()),
        }
    };
}

pub fn is_vec_fr_equal<E: Engine>(a: &Vec<E::Fr>, b: &Vec<E::Fr>) -> bool {
    (a.len() == b.len()) && a.iter().zip(b).all(|(a, b)| a == b)
}

pub fn is_vec_g1_equal<E: Engine>(a: &Vec<E::G1>, b: &Vec<E::G1>) -> bool {
    (a.len() == b.len()) && a.iter().zip(b).all(|(a, b)| a == b)
}

pub fn is_vec_g2_equal<E: Engine>(a: &Vec<E::G2>, b: &Vec<E::G2>) -> bool {
    (a.len() == b.len()) && a.iter().zip(b).all(|(a, b)| a == b)
}

pub fn encode_as_hexstring(bytes: &Vec<u8>) -> String {
    let mut ser_hex = hex::encode(bytes);
    ser_hex.insert(0, '"');
    ser_hex.push('"');
    return ser_hex;
}

pub fn hash_g1_to_fr<E: Engine>(x: &Vec<E::G1>) -> E::Fr {
    let mut x_vec: Vec<u8> = Vec::new();
    for i in x.iter() {
        x_vec.extend(format!("{}", i).bytes());
    }
    hash_to_fr::<E>(x_vec)
}

pub fn hash_g2_to_fr<E: Engine>(x: &E::G2) -> E::Fr {
    let mut x_vec: Vec<u8> = Vec::new();
    x_vec.extend(format!("{}", x).bytes());
    hash_to_fr::<E>(x_vec)
}

pub fn fmt_bytes_to_int(bytearray: [u8; 32]) -> String {
    let mut result: String = "".to_string();
    for byte in bytearray.iter() {
        // Decide if you want upper- or lowercase results,
        // padding the values to two characters, spaces
        // between bytes, etc.
        let s = format!("{}", *byte as u8);
        result = result + &s;
    }
    let s = match result.starts_with('0') {
        true => result[1..].to_string(),
        false => result.to_string(),
    };
    return s;
}

pub fn compute_the_hash<E: Engine>(bytes: &Vec<u8>) -> E::Fr {
    let mut hasher = sha2::Sha256::new();
    hasher.input(&bytes.as_slice());
    let sha2_digest = hasher.result();
    let mut hash_buf: [u8; 32] = [0; 32];
    hash_buf.copy_from_slice(&sha2_digest);
    let big_uint = BigUint::from_bytes_be(&hash_buf[..]);
    let big_modulus = BigUint::from_bytes_be(E::Fr::char().to_string().as_ref());
    let hexresult = big_uint % big_modulus;
    return E::Fr::from_str(&hexresult.to_string()).unwrap();
}

pub fn hash_secret_to_fr<E: Engine>(bytes: &Vec<u8>) -> ([u8; 32], E::Fr) {
    let mut hasher = sha2::Sha256::new();
    hasher.input(&bytes.as_slice());
    let sha2_digest = hasher.result();
    let mut hash_buf: [u8; 32] = [0; 32];
    hash_buf.copy_from_slice(&sha2_digest);
    let intresult = fmt_bytes_to_int(hash_buf);
    let fr_value = E::Fr::from_str(&intresult).unwrap();
    return (hash_buf, fr_value);
}

pub fn hash_to_fr<E: Engine>(byteVec: Vec<u8>) -> E::Fr {
    return compute_the_hash::<E>(&byteVec);
}

pub fn hash_pubkey_to_fr<E: Engine>(wpk: &secp256k1::PublicKey) -> E::Fr {
    let x_slice = wpk.serialize_uncompressed();
    return compute_the_hash::<E>(&x_slice.to_vec());
}

pub fn encode_short_bytes_to_fr<E: Engine>(bytes: [u8; 16]) -> E::Fr {
    let mut result: String = "".to_string();
    for byte in bytes.iter() {
        // Decide if you want upper- or lowercase results,
        // padding the values to two characters, spaces
        // between bytes, etc.
        let s = format!("{}", *byte as u8);
        result = result + &s;
    }
    let hexresult = match result.starts_with('0') {
        true => result[1..].to_string(),
        false => result.to_string(),
    };
    return E::Fr::from_str(&hexresult).unwrap();
}

pub fn convert_int_to_fr<E: Engine>(value: i64) -> E::Fr {
    if value > 0 {
        return E::Fr::from_str(value.to_string().as_str()).unwrap();
    } else {
        // negative value
        let value2 = value * -1;
        let mut res = E::Fr::zero();
        let val = E::Fr::from_str(value2.to_string().as_str()).unwrap();
        res.sub_assign(&val);
        return res;
    }
}

pub fn convert_str_to_fr<E: Engine>(s: String) -> Option<E::Fr> {
    return E::Fr::from_str(s.as_str());
}

pub fn compute_pub_key_fingerprint(wpk: &secp256k1::PublicKey) -> String {
    let x_slice = wpk.serialize();
    let mut hasher = sha2::Sha256::new();
    hasher.input(&x_slice.to_vec());
    let sha2_digest = hasher.result();
    hex::encode(&sha2_digest[0..16])
}

pub fn hash_buffer_to_fr<'a, E: Engine>(prefix: &'a str, buf: &[u8; 64]) -> E::Fr {
    let mut input_buf = Vec::new();
    input_buf.extend_from_slice(prefix.as_bytes());
    input_buf.extend_from_slice(buf);
    return compute_the_hash::<E>(&input_buf);
}

pub fn hash_to_slice(input_buf: &Vec<u8>) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.input(&input_buf.as_slice());
    let sha2_digest = hasher.result();

    let mut hash_buf = [0u8; 32];
    hash_buf.copy_from_slice(&sha2_digest);
    return hash_buf;
}

pub fn compute_hash160(input_buf: &Vec<u8>) -> [u8; 20] {
    let sha2_hash_buf = hash_to_slice(input_buf);
    let mut ripemd_hasher = Ripemd160::new();

    ripemd_hasher.input(sha2_hash_buf);
    let md = ripemd_hasher.result();

    let mut hash_buf = [0u8; 20];
    hash_buf.copy_from_slice(&md);
    return hash_buf;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RevokedMessage {
    pub msgtype: String,
    pub wpk: secp256k1::PublicKey,
}

impl RevokedMessage {
    pub fn new(_msgtype: String, _wpk: secp256k1::PublicKey) -> RevokedMessage {
        RevokedMessage {
            msgtype: _msgtype,
            wpk: _wpk,
        }
    }

    pub fn hash<E: Engine>(&self) -> Vec<E::Fr> {
        let mut v: Vec<E::Fr> = Vec::new();
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        v.push(hash_to_fr::<E>(input_buf));
        v.push(hash_pubkey_to_fr::<E>(&self.wpk));
        return v;
    }

    // return a message digest (32-bytes)
    pub fn hash_to_slice(&self) -> [u8; 32] {
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(self.msgtype.as_bytes());
        input_buf.extend_from_slice(&self.wpk.serialize_uncompressed());

        return hash_to_slice(&input_buf);
    }
}

pub fn hmac_sign(key: Vec<u8>, message: &Vec<u8>) -> [u8; 32] {
    let mut mac = HmacSha256::new_varkey(&key).expect("HMAC can take key of any size");
    mac.input(message);
    let sha2_mac = mac.result().code();
    let mut hash: [u8; 32] = [0; 32];
    hash.copy_from_slice(&sha2_mac);
    return hash;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, G2};
    use pairing::CurveProjective;

    #[test]
    fn double_hash_to_ripemd160_works() {
        // test on a 0-message buffer
        let input_buf = [0u8; 32];
        let result = compute_hash160(&input_buf.to_vec());

        let result_hex = hex::encode(result);
        assert_eq!(result_hex, "b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6");

        // test on a public key
        let input_buf2 =
            hex::decode("02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737")
                .unwrap();
        let result2 = compute_hash160(&input_buf2);

        let result2_hex = hex::encode(result2);
        assert_eq!(result2_hex, "93ce48570b55c42c2af816aeaba06cfee1224fae");
    }

    #[test]
    fn hash_g2_to_fr_works() {
        let mut two = G2::one();
        two.double();
        assert_eq!(
            format!("{}", hash_g2_to_fr::<Bls12>(&two).into_repr()),
            "0x5926ca46945234004a7c779db0b4b2ab0c1458864971671bc327d72f444146f3" // "0x6550a1431236024424ac8e7f65781f244b70a38e5b3c275000a2b91089706868"
        );
    }

    #[test]
    fn hash_to_fr_works() {
        let mut two = G2::one();
        two.double();
        let mut x_vec: Vec<u8> = Vec::new();
        x_vec.extend(format!("{}", two).bytes());
        assert_eq!(
            format!("{}", hash_to_fr::<Bls12>(x_vec).into_repr()),
            "0x5926ca46945234004a7c779db0b4b2ab0c1458864971671bc327d72f444146f3" // "0x6550a1431236024424ac8e7f65781f244b70a38e5b3c275000a2b91089706868"
        );
    }

    #[test]
    fn fmt_byte_to_int_works() {
        assert_eq!(
            fmt_bytes_to_int([
                12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12,
                235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235
            ]), // , 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123, 13, 43, 12, 235, 23, 123]),
            "122352312313431223523123134312235231231343122352312313431223523123134312235"
        );
    }

    #[test]
    fn convert_int_to_fr_works() {
        assert_eq!(
            format!("{}", convert_int_to_fr::<Bls12>(1).into_repr()),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            format!("{}", convert_int_to_fr::<Bls12>(-1).into_repr()),
            "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"
        );
        assert_eq!(
            format!("{}", convert_int_to_fr::<Bls12>(365).into_repr()),
            "0x000000000000000000000000000000000000000000000000000000000000016d"
        );
    }

    #[test]
    fn hmac_sign_works() {
        let key: [u8; 64] = [
            118, 111, 110, 106, 117, 113, 102, 98, 108, 106, 116, 117, 97, 118, 116, 97, 111, 110,
            108, 112, 102, 120, 110, 102, 118, 122, 108, 121, 118, 113, 99, 104, 109, 103, 115,
            105, 108, 114, 105, 116, 117, 120, 115, 111, 102, 103, 114, 99, 102, 99, 113, 121, 110,
            122, 117, 108, 122, 99, 115, 117, 116, 111, 104, 109,
        ];
        let msg = vec![
            100, 99, 106, 98, 112, 119, 102, 109, 121, 119, 111, 102, 115, 108, 106, 121, 97, 117,
            99, 122, 109, 116, 103, 108, 111, 119, 121, 98, 116, 100, 108, 99, 120, 101, 109, 97,
            114, 105, 122, 100, 104, 109, 107, 122, 106, 112, 122, 115, 106, 118, 116, 122, 121,
            105, 105, 118, 104, 113, 116, 104, 103, 118, 112, 110, 101, 122, 106, 103, 102, 120,
            100, 102, 99, 118, 112, 117, 119, 121, 116, 102, 109, 108, 117, 114, 119, 115, 100,
            104, 105, 100, 104, 111, 115, 100, 97, 108, 116, 105, 104, 114, 98, 119, 115, 105, 110,
            122, 118, 103, 115, 118, 120, 121, 104, 100, 107, 122,
        ];

        let expected_mac: [u8; 32] = [
            175, 78, 45, 172, 162, 159, 124, 110, 104, 214, 160, 213, 54, 238, 197, 169, 101, 39,
            101, 10, 89, 80, 110, 234, 129, 80, 98, 183, 130, 204, 153, 187,
        ];
        let actual_mac = hmac_sign(key.to_vec(), &msg);

        assert_eq!(expected_mac, actual_mac);
    }
}
