// Useful routines that simplify the Bolt TZE implementation for Zcash
pub use channels_zk::ChannelToken;
use channels_zk::ChannelcloseM;
use crypto::ped92::CSMultiParams;
use crypto::pssig;
pub use crypto::pssig::Signature;
use pairing::bls12_381::Bls12;
pub use wallet::Wallet;
use zkchan_tx::fixed_size_array::{FixedSizeArray16, FixedSizeArray32};
use {util, BoltResult};

const BLS12_381_CHANNEL_TOKEN_LEN: usize = 1074;
const BLS12_381_G1_LEN: usize = 48;
const BLS12_381_G2_LEN: usize = 96;
const SECP256K1_PK_LEN: usize = 33;
const ADDRESS_LEN: usize = 33;

pub fn reconstruct_secp_public_key(pk_bytes: &[u8; SECP256K1_PK_LEN]) -> secp256k1::PublicKey {
    return secp256k1::PublicKey::from_slice(pk_bytes).unwrap();
}

pub fn reconstruct_secp_signature(sig_bytes: &[u8]) -> secp256k1::Signature {
    return secp256k1::Signature::from_der(sig_bytes).unwrap();
}

pub fn reconstruct_close_wallet_bls12(
    channel_token: &ChannelToken<Bls12>,
    nonce: &FixedSizeArray16,
    rev_lock: &FixedSizeArray32,
    cust_bal: u32,
    merch_bal: u32,
) -> Wallet<Bls12> {
    let channelId = channel_token.compute_channel_id();
    let nonce = util::encode_short_bytes_to_fr::<Bls12>(nonce.0);
    let rl = util::hash_to_fr::<Bls12>(rev_lock.0.to_vec());

    return Wallet {
        channelId,
        nonce: nonce,
        rev_lock: rl,
        bc: cust_bal as i64,
        bm: merch_bal as i64,
    };
}

pub fn reconstruct_signature_bls12(sig: &Vec<u8>) -> BoltResult<pssig::Signature<Bls12>> {
    if (sig.len() != BLS12_381_G1_LEN * 2) {
        return Err(String::from("signature has invalid length"));
    }

    let mut cur_index = 0;
    let mut end_index = BLS12_381_G1_LEN;
    let ser_cl_h = sig[cur_index..end_index].to_vec();
    let str_cl_h = util::encode_as_hexstring(&ser_cl_h);
    let h = str_cl_h.as_bytes();

    cur_index = end_index;
    end_index += BLS12_381_G1_LEN;
    let ser_cl_H = sig[cur_index..end_index].to_vec();
    let str_cl_H = util::encode_as_hexstring(&ser_cl_H);
    let H = str_cl_H.as_bytes();

    let cl_sig = pssig::Signature::<Bls12>::from_slice(&h, &H);

    Ok(Some(cl_sig))
}

pub fn reconstruct_channel_token_bls12(channel_token: &Vec<u8>) -> BoltResult<ChannelToken<Bls12>> {
    // parse pkc, pkm, pkM, mpk and comParams
    if channel_token.len() != BLS12_381_CHANNEL_TOKEN_LEN {
        return Err(String::from("could not reconstruct the channel token!"));
    }

    let num_y_elems = 5;
    let num_com_params = 6;

    let mut cur_index = 0;
    let mut end_index = SECP256K1_PK_LEN;
    let pkc = secp256k1::PublicKey::from_slice(&channel_token[cur_index..end_index]).unwrap();

    cur_index = end_index;
    end_index += SECP256K1_PK_LEN;
    let pkm = secp256k1::PublicKey::from_slice(&channel_token[cur_index..end_index]).unwrap();

    cur_index = end_index;
    end_index += BLS12_381_G2_LEN; // pk_M => (X, Y)
    let ser_cl_x = channel_token[cur_index..end_index].to_vec();
    let str_cl_x = util::encode_as_hexstring(&ser_cl_x);
    let X = str_cl_x.as_bytes();

    let mut Y = Vec::new();
    for _ in 0..num_y_elems {
        cur_index = end_index;
        end_index += BLS12_381_G2_LEN;
        let cl_y = channel_token[cur_index..end_index].to_vec();
        let ser_cl_y = util::encode_as_hexstring(&cl_y);
        let str_cl_y = ser_cl_y.as_bytes();
        Y.extend(str_cl_y);
    }
    let cl_pk =
        pssig::PublicKey::<Bls12>::from_slice(&X, &Y.as_slice(), str_cl_x.len(), num_y_elems);

    cur_index = end_index;
    end_index += BLS12_381_G1_LEN;
    let g1 = channel_token[cur_index..end_index].to_vec();
    let ser_mpk_g1 = util::encode_as_hexstring(&g1);

    cur_index = end_index;
    end_index += BLS12_381_G2_LEN;
    let g2 = channel_token[cur_index..end_index].to_vec();
    let ser_mpk_g2 = util::encode_as_hexstring(&g2);

    let ser_g1 = ser_mpk_g1.as_bytes();
    let ser_g2 = ser_mpk_g2.as_bytes();

    let mpk = pssig::PublicParams::<Bls12>::from_slice(&ser_g1, &ser_g2);

    let mut comparams = Vec::new();
    for _ in 0..num_com_params {
        cur_index = end_index;
        end_index += BLS12_381_G1_LEN;
        let com = channel_token[cur_index..end_index].to_vec();
        let ser_com = util::encode_as_hexstring(&com);
        let str_com = ser_com.as_bytes();
        comparams.extend(str_com);
    }

    let com_params =
        CSMultiParams::<Bls12>::from_slice(&comparams.as_slice(), ser_mpk_g1.len(), num_com_params);

    Ok(Some(ChannelToken {
        pk_c: Some(pkc),
        pk_m: pkm,
        cl_pk_m: cl_pk,
        mpk: mpk,
        comParams: com_params,
    }))
}

///
/// Used in open-channel WTP for validating that a close_token is a valid signature
///
// pub fn tze_verify_cust_close_message(
//     channel_token: &ChannelToken<Bls12>,
//     wpk: &secp256k1::PublicKey,
//     close_msg: &Wallet<Bls12>,
//     close_token: &pssig::Signature<Bls12>,
// ) -> bool {
//     // close_msg => <pkc> || <wpk> || <balance-cust> || <balance-merch> || CLOSE
//     // close_token = regular CL signature on close_msg
//     // channel_token => <pk_c, CL_PK_m, pk_m, mpk, comParams>

//     // (1) check that channel token and close msg are consistent (e.g., close_msg.channelId == H(channel_token.pk_c) &&
//     let chan_token_cid = channel_token.compute_channel_id(); // util::hash_pubkey_to_fr::<Bls12>(&pk_c);
//     let chan_token_wpk = util::hash_pubkey_to_fr::<Bls12>(&wpk);

//     let cid_thesame = (close_msg.channelId == chan_token_cid);
//     // (2) check that wpk matches what's in the close msg
//     let wpk_thesame = (close_msg.wpk == chan_token_wpk);
//     return cid_thesame
//         && wpk_thesame
//         && channel_token
//             .cl_pk_m
//             .verify(&channel_token.mpk, &close_msg.as_fr_vec(), &close_token);
// }

pub fn tze_generate_secp_signature(seckey: &[u8; 32], msg: &[u8; 32]) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::signing_only();

    let msg = secp256k1::Message::from_slice(msg).unwrap();
    let seckey = secp256k1::SecretKey::from_slice(seckey).unwrap();
    let sig = secp.sign(&msg, &seckey);

    // get serialized signature
    let ser_sig = sig.serialize_der();

    return ser_sig.to_vec();
}

pub fn tze_verify_secp_signature(
    pubkey: &secp256k1::PublicKey,
    hash: &Vec<u8>,
    sig: &secp256k1::Signature,
) -> bool {
    let secp = secp256k1::Secp256k1::verification_only();
    let msg = secp256k1::Message::from_slice(hash.as_slice()).unwrap();

    return secp.verify(&msg, &sig, &pubkey).is_ok();
}

pub fn reconstruct_secp_channel_close_m(
    address: &[u8; ADDRESS_LEN],
    ser_revoke_token: &Vec<u8>,
    ser_sig: &Vec<u8>,
) -> ChannelcloseM {
    let revoke_token = secp256k1::Signature::from_der(&ser_revoke_token.as_slice()).unwrap();
    let sig = secp256k1::Signature::from_der(&ser_sig.as_slice()).unwrap();
    ChannelcloseM {
        address: hex::encode(&address.to_vec()),
        revoke: Some(revoke_token),
        signature: sig,
    }
}
