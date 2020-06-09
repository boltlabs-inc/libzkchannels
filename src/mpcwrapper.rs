use bindings::{
    build_masked_tokens_cust, build_masked_tokens_merch, get_netio_ptr, get_unixnetio_ptr,
    Balance_l, BitcoinPublicKey_l, CommitmentRandomness_l, ConnType_NETIO, ConnType_TORNETIO,
    ConnType_UNIXNETIO, Conn_l, EcdsaSig_l, HMACKeyCommitment_l, HMACKey_l, MaskCommitment_l,
    Mask_l, Nonce_l, PayToken_l, PublicKeyHash_l, RevLockCommitment_l, RevLock_l, State_l, Txid_l,
};
// ConnType_CUSTOM, get_gonetio_ptr
use channels_mpc::NetworkConfig;
use ecdsa_partial::EcdsaPartialSig;
use libc::{c_int, c_void};
// c_uint, c_char
use rand::Rng;
use std::ffi::{CStr, CString};
use std::ptr;
use std::str;
use std::time::Instant;
use wallet::State;
use {secp256k1, util};

static MPC_ERROR: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
pub static CIRCUIT_FILE: &str = "/include/emp-tool/circuits/files/tokens.circuit.txt";

extern "C" fn io_callback(net_config: *mut c_void, party: c_int) -> *mut c_void {
    // unsafe is needed because we dereference a raw pointer to network config
    let nc: &mut Conn_l = unsafe { &mut *(net_config as *mut Conn_l) };
    let conn_debug = match nc.conn_type {
        ConnType_UNIXNETIO => "Unix domain socket connection",
        ConnType_NETIO => "TCP socket connection",
        ConnType_TORNETIO => "Tor connection",
        _ => "Unsupported connection type",
    };
    println!("IO callback: {}", conn_debug);
    if (nc.conn_type == ConnType_UNIXNETIO) {
        let io_ptr = unsafe { get_unixnetio_ptr(nc.path, party) };
        return io_ptr;
    } else if (nc.conn_type == ConnType_NETIO) {
        let bytes = unsafe { CStr::from_ptr(nc.dest_ip).to_bytes() };
        let ip: &str = str::from_utf8(bytes).unwrap();
        println!("Opening a connection: {}:{}", ip, nc.dest_port);
        let io_ptr = unsafe { get_netio_ptr(nc.dest_ip, nc.dest_port as i32, party) };
        return io_ptr;
    } else {
        /* use regular tcp conn */
        let io_ptr =
            unsafe { get_netio_ptr(CString::new("127.0.0.1").unwrap().into_raw(), 12345, party) };
        return io_ptr;
    }
}

pub fn mpc_build_masked_tokens_cust(
    net_conn: NetworkConfig,
    circuit_ptr: *mut c_void,
    amount: i64,
    pay_mask_com: &[u8],
    rev_lock_com: &[u8],
    rl_rand: &[u8; 16],
    hmac_key_com: &[u8],
    merch_escrow_pub_key: secp256k1::PublicKey,
    merch_dispute_key: secp256k1::PublicKey,
    merch_pub_key_hash: [u8; 20],
    merch_payout_pub_key: secp256k1::PublicKey,
    new_state: State,
    old_state: State,
    fee_cc: i64,
    pt_old: &[u8],
    cust_escrow_pub_key: secp256k1::PublicKey,
    cust_payout_pub_key: secp256k1::PublicKey,
    cust_pub_key_hash: [u8; 20],
) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    // translate wpk
    let rl_c = translate_revlock_com(&rev_lock_com);
    // translate blinding factor
    let rl_rand_c = translate_randomness(&rl_rand);

    // translate new_wallet
    let new_state_c = translate_state(&new_state);
    // translate old_wallet
    let old_state_c = translate_state(&old_state);
    //translate fee_cc
    let fee_cc_c = translate_balance(fee_cc);
    // translate payment_token
    let pt_old_c = translate_paytoken(&pt_old);
    // paymask_com
    let paymask_com = MaskCommitment_l {
        commitment: translate_256_string(pay_mask_com),
    };

    //key_com
    let key_com = HMACKeyCommitment_l {
        commitment: translate_256_string(hmac_key_com),
    };

    //translate bitcoin keys
    let merch_escrow_pub_key_c = translate_bitcoin_key(&merch_escrow_pub_key);
    let merch_dispute_key_c = translate_bitcoin_key(&merch_dispute_key);
    let merch_public_key_hash_c = translate_pub_key_hash(&merch_pub_key_hash);
    let merch_payout_pub_key_c = translate_bitcoin_key(&merch_payout_pub_key);

    let cust_escrow_pub_key_c = translate_bitcoin_key(&cust_escrow_pub_key);
    let cust_payout_pub_key_c = translate_bitcoin_key(&cust_payout_pub_key);
    let cust_public_key_hash_c = translate_pub_key_hash(&cust_pub_key_hash);

    let nonce = translate_nonce(&old_state.get_nonce());
    let val_cpfp_c = translate_balance(util::VAL_CPFP);

    // create pointers the output variables
    let pt_return_ar = [0u32; 8];
    let mut pt_return = PayToken_l {
        paytoken: pt_return_ar,
    };
    let sig1_ar = [0u32; 8];
    let mut ct_escrow = EcdsaSig_l { sig: sig1_ar };
    let sig2_ar = [0u32; 8];
    let mut ct_merch = EcdsaSig_l { sig: sig2_ar };

    // set the network config
    let path_ar = CString::new(net_conn.path).unwrap().into_raw();
    let ip_ar = CString::new(net_conn.dest_ip).unwrap().into_raw();
    let conn = Conn_l {
        conn_type: net_conn.conn_type,
        path: path_ar,
        dest_port: net_conn.dest_port as u16,
        dest_ip: ip_ar,
        peer_raw_fd: ptr::null_mut(),
    };

    let timer = Instant::now();
    let self_delay_int: i32 = 1487;
    let self_delay = bytes_to_u32(&self_delay_int.to_le_bytes(), 4)[0];
    let bal_min_cust = translate_balance(546);
    let bal_min_merch = translate_balance(546);
    unsafe {
        build_masked_tokens_cust(
            Some(io_callback),
            conn,
            circuit_ptr,
            translate_balance(amount),
            rl_c,
            paymask_com,
            key_com,
            merch_escrow_pub_key_c,
            merch_dispute_key_c,
            merch_public_key_hash_c,
            merch_payout_pub_key_c,
            nonce,
            val_cpfp_c,
            bal_min_cust,
            bal_min_merch,
            self_delay,
            rl_rand_c,
            new_state_c,
            old_state_c,
            fee_cc_c,
            pt_old_c,
            cust_escrow_pub_key_c,
            cust_payout_pub_key_c,
            cust_public_key_hash_c,
            &mut pt_return,
            &mut ct_escrow,
            &mut ct_merch,
        );
    };
    let stop = timer.elapsed();
    println!("Time to execute MPC: {} ms", stop.as_millis());

    let mut pt_masked_ar = [0u8; 32];
    pt_masked_ar.copy_from_slice(u32_to_bytes(&pt_return.paytoken[..]).as_slice());
    let mut ct_escrow_masked_ar = [0u8; 32];
    ct_escrow_masked_ar.copy_from_slice(u32_to_bytes(&ct_escrow.sig[..]).as_slice());
    let mut ct_merch_masked_ar = [0u8; 32];
    ct_merch_masked_ar.copy_from_slice(u32_to_bytes(&ct_merch.sig[..]).as_slice());

    // handle error case: if pt_masked_ar => 0xffff..
    let pt_masked_hex = hex::encode(&pt_masked_ar);
    let ct_escrow_masked_hex = hex::encode(&ct_escrow_masked_ar);
    let ct_merch_masked_hex = hex::encode(&ct_merch_masked_ar);
    if pt_masked_hex == MPC_ERROR
        || ct_escrow_masked_hex == MPC_ERROR
        || ct_merch_masked_hex == MPC_ERROR
    {
        return Err(format!("Failed to get valid output from MPC!"));
    }

    Ok((pt_masked_ar, ct_escrow_masked_ar, ct_merch_masked_ar))
}

fn translate_bitcoin_key(pub_key: &secp256k1::PublicKey) -> BitcoinPublicKey_l {
    let mut pub_key_ar = [0u32; 9];
    let pk_comp = pub_key.serialize();
    let mut pub_key_vec_padded = pk_comp.to_vec();
    pub_key_vec_padded.extend_from_slice(&[0, 0, 0]);
    let pub_key_vec = bytes_to_u32(pub_key_vec_padded.as_slice(), 36);
    pub_key_ar.copy_from_slice(pub_key_vec.as_slice());
    BitcoinPublicKey_l { key: pub_key_ar }
}

fn translate_pub_key_hash(pub_key_hash: &[u8; 20]) -> PublicKeyHash_l {
    let mut hash_ar = [0u32; 5];
    let hash_vec = bytes_to_u32(&pub_key_hash[..], 20);
    hash_ar.copy_from_slice(hash_vec.as_slice());
    PublicKeyHash_l { hash: hash_ar }
}

fn translate_nonce(nonce: &[u8; 16]) -> Nonce_l {
    let nonce_vec = bytes_to_u32(&nonce[..], 16);
    let mut nonce_ar = [0u32; 4];
    nonce_ar.copy_from_slice(nonce_vec.as_slice());
    Nonce_l { nonce: nonce_ar }
}

fn translate_randomness(randomness: &[u8; 16]) -> CommitmentRandomness_l {
    let random_vec = bytes_to_u32(&randomness[..], 16);
    let mut rand_ar = [0u32; 4];
    rand_ar.copy_from_slice(random_vec.as_slice());
    CommitmentRandomness_l {
        randomness: rand_ar,
    }
}

fn translate_paytoken(pt: &[u8]) -> PayToken_l {
    let mut pt_ar = [0u32; 8];
    let pt_vec = bytes_to_u32(pt.as_ref(), pt.len());
    pt_ar.copy_from_slice(&pt_vec.as_slice());
    let pt = PayToken_l { paytoken: pt_ar };
    pt
}

fn translate_state(state: &State) -> State_l {
    let txid_merch = translate_256_string(&state.merch_txid.0[..]);
    let txid_escrow = translate_256_string(&state.escrow_txid.0[..]);
    let prevout_escrow = translate_256_string(&state.escrow_prevout.0[..]);
    let prevout_merch = translate_256_string(&state.merch_prevout.0[..]);

    let nonce = translate_nonce(&state.get_nonce());
    let rev_lock = translate_revlock(&state.get_rev_lock()[..]);

    let bc = translate_balance(state.bc);
    let bm = translate_balance(state.bm);
    let min_fee = translate_balance(state.min_fee);
    let max_fee = translate_balance(state.max_fee);
    let fee_mc = translate_balance(state.fee_mc);

    let new_state = State_l {
        nonce,
        rl: rev_lock,
        balance_cust: bc,
        balance_merch: bm,
        txid_merch: Txid_l { txid: txid_merch },
        txid_escrow: Txid_l { txid: txid_escrow },
        HashPrevOuts_escrow: Txid_l {
            txid: prevout_escrow,
        },
        HashPrevOuts_merch: Txid_l {
            txid: prevout_merch,
        },
        min_fee,
        max_fee,
        fee_mc,
    };
    new_state
}

fn translate_balance(amount: i64) -> Balance_l {
    let mut balance = [0u32; 2];
    let balance_vec = bytes_to_u32(&amount.to_be_bytes(), 8);
    balance.copy_from_slice(balance_vec.as_slice());
    Balance_l { balance }
}

fn translate_256_string(input: &[u8]) -> [u32; 8] {
    let str_vec = bytes_to_u32(input, 32);
    let txid = str_vec.as_slice();
    let mut txid_ar = [0u32; 8];
    txid_ar.copy_from_slice(txid);
    txid_ar
}

fn translate_512_string(input: &[u8]) -> [u32; 16] {
    let str_vec = bytes_to_u32(input, 64);
    let txid = str_vec.as_slice();
    let mut txid_ar = [0u32; 16];
    txid_ar.copy_from_slice(txid);
    txid_ar
}

fn translate_revlock(rl: &[u8]) -> RevLock_l {
    RevLock_l {
        revlock: translate_256_string(rl),
    }
}

fn translate_revlock_com(rl: &[u8]) -> RevLockCommitment_l {
    RevLockCommitment_l {
        commitment: translate_256_string(rl),
    }
}

fn bytes_to_u32(input: &[u8], size: usize) -> Vec<u32> {
    let out_l = size / 4;
    let mut out = Vec::new();
    for i in 0..out_l {
        let start = i * 4;
        let end = i * 4 + 4;
        let mut byte4 = [0u8; 4];
        byte4.copy_from_slice(&input[start..end]);
        out.push(u32::from_be_bytes(byte4));
    }
    out
}

fn u32_to_bytes(input: &[u32]) -> Vec<u8> {
    let mut out = Vec::<u8>::new();
    for part in input.iter() {
        out.extend_from_slice(&part.to_be_bytes()[..]);
    }
    out
}

pub fn mpc_build_masked_tokens_merch<R: Rng>(
    rng: &mut R,
    net_conn: NetworkConfig,
    circuit_ptr: *mut c_void,
    amount: i64,
    com_new: &[u8],
    rev_lock_com: &[u8],
    key_com: &[u8],
    key_com_r: &[u8; 16],
    merch_escrow_pub_key: secp256k1::PublicKey,
    merch_dispute_key: secp256k1::PublicKey,
    merch_pub_key_hash: [u8; 20],
    merch_payout_pub_key: secp256k1::PublicKey,
    nonce: [u8; 16],
    hmac_key: &[u8],
    merch_escrow_secret_key: secp256k1::SecretKey,
    merch_mask: &[u8; 32],
    pay_mask: &[u8; 32],
    pay_mask_r: &[u8; 16],
    escrow_mask: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    // translate revlock commitment
    let rl_c = translate_revlock_com(rev_lock_com);

    //translate bitcoin keys
    let merch_escrow_pub_key_c = translate_bitcoin_key(&merch_escrow_pub_key);
    let merch_dispute_key_c = translate_bitcoin_key(&merch_dispute_key);
    let merch_public_key_hash_c = translate_pub_key_hash(&merch_pub_key_hash);
    let merch_payout_pub_key_c = translate_bitcoin_key(&merch_payout_pub_key);

    let nonce_c = translate_nonce(&nonce);
    let val_cpfp_c = translate_balance(util::VAL_CPFP);

    // Create ECDSA_params
    let pp1 = EcdsaPartialSig::New(rng, &merch_escrow_secret_key.clone());
    let params1 = pp1.getMpcRepr();
    let pp2 = EcdsaPartialSig::New(rng, &merch_escrow_secret_key.clone());
    let params2 = pp2.getMpcRepr();

    // Create merch_mask
    let merch_mask = Mask_l {
        mask: translate_256_string(merch_mask),
    };

    // Create pay_mask
    let paytoken_mask_c = Mask_l {
        mask: translate_256_string(pay_mask),
    };
    let paytoken_r = translate_randomness(pay_mask_r);

    //Create escrow_mask
    let escrow_mask = Mask_l {
        mask: translate_256_string(escrow_mask),
    };

    //paymask_com
    let paymask_com = MaskCommitment_l {
        commitment: translate_256_string(com_new),
    };

    //hmac_key_com
    let key_com = HMACKeyCommitment_l {
        commitment: translate_256_string(key_com),
    };
    // translate randomness for hmac_key_com
    let key_com_rand = translate_randomness(key_com_r);

    //hmac key
    let hmac_key = HMACKey_l {
        key: translate_512_string(hmac_key),
    };

    // set the network config
    let path_ar = CString::new(net_conn.path).unwrap().into_raw();
    let ip_ar = CString::new(net_conn.dest_ip).unwrap().into_raw();
    let conn = Conn_l {
        conn_type: net_conn.conn_type,
        path: path_ar,
        dest_port: net_conn.dest_port as u16,
        dest_ip: ip_ar,
        peer_raw_fd: ptr::null_mut(),
    };

    let timer = Instant::now();
    let self_delay_int: i32 = 1487;
    let self_delay = bytes_to_u32(&self_delay_int.to_le_bytes(), 4)[0];
    let bal_min_cust = translate_balance(546);
    let bal_min_merch = translate_balance(546);
    unsafe {
        build_masked_tokens_merch(
            Some(io_callback),
            conn,
            circuit_ptr,
            translate_balance(amount),
            rl_c,
            paymask_com,
            key_com,
            merch_escrow_pub_key_c,
            merch_dispute_key_c,
            merch_public_key_hash_c,
            merch_payout_pub_key_c,
            nonce_c,
            val_cpfp_c,
            bal_min_cust,
            bal_min_merch,
            self_delay,
            hmac_key,
            merch_mask,
            escrow_mask,
            paytoken_mask_c,
            key_com_rand,
            paytoken_r,
            params1,
            params2,
        );
    };
    let stop = timer.elapsed();
    println!("Time to execute MPC: {} ms", stop.as_millis());

    (pp1.getK(), pp2.getK())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bindings::load_circuit_file;
    use num::bigint::Sign;
    use num::BigInt;
    use rand::rngs::mock::StepRng;
    use rand::RngCore;
    use secp256k1::{Message, PartialSignature, PublicKey, Secp256k1, Signature};
    use sha2::{Digest, Sha256};
    use std::env;
    use std::ffi::CStr;
    use std::str;
    use util::{compute_hash160, hash_to_slice, hmac_sign};
    use zkchan_tx::fixed_size_array::{FixedSizeArray16, FixedSizeArray32};
    use zkchan_tx::transactions::btc::{create_cust_close_transaction, create_reverse_input};
    use zkchan_tx::transactions::ClosePublicKeys;
    use zkchan_tx::Testnet;

    fn compute_commitment(buf: &Vec<u8>, r: &[u8; 16]) -> [u8; 32] {
        let mut input_buf = buf.clone();
        input_buf.extend_from_slice(r);
        return hash_to_slice(&input_buf);
    }

    rusty_fork_test! {
        #[test]
        fn mpc_build_masked_tokens_merch_works() {
            let mut csprng = StepRng::new(172873415, 20);

            let merch_escrow_secret_key = secp256k1::SecretKey::from_slice(
                &hex::decode("bbb22af17dc660de6c26ff59e8090dbbc19dcde76beed4f5970c9eaccfbdc96c")
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();

            /* MERCHANT INPUTS */
            /*  HMAC Key, Pt_Mask, Merch_Mask, Escrow_ Mask, 2x Partial Sigs*/
            let mut hmac_key = [0u8; 64];
            hmac_key.copy_from_slice(hex::decode("439452e56db2398e05396328c5e037086c5167565736ce7041356f12d161821715656a1a16eeff47615e0494d7b3757d730517f1beebc45575beb1644ba48a1a").unwrap().as_slice());
            let mut paytoken_mask_bytes = [0u8; 32];
            paytoken_mask_bytes.copy_from_slice(
                hex::decode("0c8dda801001c9a55f720c5f379ce09e42416780f98fef7900bd26b372b81850")
                    .unwrap()
                    .as_slice(),
            );
            let mut merch_mask_bytes = [0u8; 32];
            merch_mask_bytes.copy_from_slice(
                hex::decode("1c92f6e3dfb5f805a436b727a340fd08d41e4de53b7f6dd5865b5f30fcf80709")
                    .unwrap()
                    .as_slice(),
            );
            let mut escrow_mask_bytes = [0u8; 32];
            escrow_mask_bytes.copy_from_slice(
                hex::decode("2670345a391379cd02514a35ee4fb3f1f0c14b5fb75381b7e797b5dd26ee057d")
                    .unwrap()
                    .as_slice(),
            );

            /* PULBIC MPC INPUTS */
            /* Balance amount, HMACKeyCommit, PT_MaskCommit, RevLockCommit, Nonce, 3x Public Key, 1x PK_Hash*/

            let amount = 10000;

            let key_com_r = [1u8; 16];
            let key_com = compute_commitment(&hmac_key.to_vec(), &key_com_r);
            println!("key_com_r: {}", hex::encode(&key_com_r));

            let paytoken_mask_r = [2u8; 16];
            let paytoken_mask_com = compute_commitment(&paytoken_mask_bytes.to_vec(), &paytoken_mask_r);
            println!("paytoken_mask_com : {}", hex::encode(&paytoken_mask_com));

            let mut rev_lock_com = [0u8; 32];
            rev_lock_com.copy_from_slice(
                hex::decode("7116eb1941ec8005c19b853d1102873be3bc2c3eb7ff1dce233e0ac5df5fcdf8")
                    .unwrap()
                    .as_slice(),
            );

            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(
                hex::decode("18670766caf2e5fec5f909d04acd5e86")
                    .unwrap()
                    .as_slice(),
            );

            let merch_escrow_pub_key = secp256k1::PublicKey::from_slice(
                hex::decode("03f5ebc49f568e80a1dfca988eccf5d30ef9a63ae9e89a3f68b959f59d811489bd")
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
            let merch_dispute_key = secp256k1::PublicKey::from_slice(
                hex::decode("0253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7c")
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
            let mut merch_public_key_hash = [0u8; 20];
            merch_public_key_hash.copy_from_slice(
                hex::decode("43e9e81bc632ad9cad48fc23f800021c5769a063")
                    .unwrap()
                    .as_slice(),
            );
            let merch_payout_pub_key = secp256k1::PublicKey::from_slice(
                hex::decode("02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90")
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();

            let nc = NetworkConfig {
                conn_type: ConnType_NETIO,
                path: String::from("127.0.0.1"),
                dest_ip: String::from("127.0.0.1"),
                dest_port: 12345,
                peer_raw_fd: 0,
            };

            let using_ag2pc = match env::var("AG2PC") {
                Ok(_s) => true,
                Err(_e) => false
            };

            let circuit_file = match using_ag2pc {
                true => match env::var("ZK_DEPS_INSTALL") {
                    Ok(s) => format!("{}{}", s, CIRCUIT_FILE),
                    Err(e) => panic!("ZK_DEPS_INSTALL env not set: {}", e)
                },
                false => String::new()
            };

            let cf_ptr = match using_ag2pc {
                true => {
                    let cf_ptr = unsafe {
                        let c_str = CString::new(circuit_file).unwrap();
                        load_circuit_file(c_str.as_ptr() as *const i8)
                    };
                    cf_ptr
                },
                false => ptr::null_mut()
            };

            let (r1, r2) = mpc_build_masked_tokens_merch(
                &mut csprng,
                nc,
                cf_ptr,
                amount,
                &paytoken_mask_com,
                &rev_lock_com,
                &key_com,
                &key_com_r,
                merch_escrow_pub_key,
                merch_dispute_key,
                merch_public_key_hash,
                merch_payout_pub_key,
                nonce,
                &hmac_key,
                merch_escrow_secret_key,
                &merch_mask_bytes,
                &paytoken_mask_bytes,
                &paytoken_mask_r,
                &escrow_mask_bytes,
            );

            assert_eq!(
                r1.to_vec(),
                hex::decode("2144e9c90f5799c98610719d735bd53dc6edbfc1e11c8a193070bf42230bc176")
                    .unwrap()
            );
            assert_eq!(
                r2.to_vec(),
                hex::decode("ca1248d5e6ac123c1a0d5b19dacec544d1068427a8cd3fc5d0a40c844c0dba4f")
                    .unwrap()
            );
            let secp = Secp256k1::new();
            let merch_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4000000007263522103f5ebc49f568e80a1dfca988eccf5d30ef9a63ae9e89a3f68b959f59d811489bd2103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752ae6702cf05b2752102f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90ac688000000000000000ffffffffba7b7eedb1ef8114e7ae39f8fa310b7db125dee0abb15a010673b92c48e008c30000000001000000").unwrap();
            let merch_tx_ar = Sha256::digest(&Sha256::digest(merch_preimage.as_slice()));
            println!("merch hash: {}", hex::encode(&merch_tx_ar[..]));
            let merch_tx = Message::from_slice(merch_tx_ar.as_slice()).unwrap();
            let signature = secp.compute_sign(&merch_tx, &PartialSignature::from_compact(hex::decode("2144e9c90f5799c98610719d735bd53dc6edbfc1e11c8a193070bf42230bc176ee304aefd29b5e379f1c6a3fa4a54728d422ccf5ec79b0f7469c67860180dc50f065220323875dc15ddf131486a481444116894dc3cd52e74248a99f506b213c").unwrap().as_slice()).unwrap());
            println!(
                "merch_tx merch: {}",
                hex::encode(&signature.serialize_compact()[..])
            );
            assert!(secp
                .verify(&merch_tx, &signature, &merch_escrow_pub_key)
                .is_ok());

            let escrow_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff40000000047522103f5ebc49f568e80a1dfca988eccf5d30ef9a63ae9e89a3f68b959f59d811489bd2103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752ae8000000000000000ffffffff18db38ef7dfc800123f89516094927d76ea60295c353e6717acb816d08a5e5900000000001000000").unwrap();
            let escrow_tx_ar = Sha256::digest(&Sha256::digest(escrow_preimage.as_slice()));
            println!("escrow hash: {}", hex::encode(&escrow_tx_ar[..]));
            let escrow_tx = Message::from_slice(escrow_tx_ar.as_slice()).unwrap();
            let signature_esc = secp.compute_sign(&escrow_tx, &PartialSignature::from_compact(hex::decode("ca1248d5e6ac123c1a0d5b19dacec544d1068427a8cd3fc5d0a40c844c0dba4fbb5ed98428e59d079676bd33bd88560cd0a4eb6d1d01a23f6802509da43908e4af898142598eb9b16ea6266072074477fdf565b2aedf3ed1a71e84beb46fc719").unwrap().as_slice()).unwrap());
            println!(
                "escrow_tx merch: {}",
                hex::encode(&signature_esc.serialize_compact()[..])
            );
            assert!(secp
                .verify(&escrow_tx, &signature_esc, &merch_escrow_pub_key)
                .is_ok());
        }
    }

    //    rusty_fork_test! {
    #[test]
    fn mpc_build_masked_tokens_cust_works() {
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        let sk_m = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let _pk_m = PublicKey::from_secret_key(&Secp256k1::new(), &sk_m);

        let sk_c = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        let _pk_c = PublicKey::from_secret_key(&Secp256k1::new(), &sk_c);

        /*   CUSTOMER SECRET INPUTS */
        /*   old_state, new_state, old_paytoken, 2x public_keys */

        let mut nonce1 = [0u8; 16];
        nonce1.copy_from_slice(
            hex::decode("b2f9b5a508cf8609f040641892824a61")
                .unwrap()
                .as_slice(),
        );
        let mut nonce2 = [0u8; 16];
        nonce2.copy_from_slice(
            hex::decode("18670766caf2e5fec5f909d04acd5e86")
                .unwrap()
                .as_slice(),
        );

        let mut rl_ar1 = [0u8; 32];
        rl_ar1.copy_from_slice(
            hex::decode("ca54e2bc080dc33895f8fadb72902337e3ee171dd57e1dcf12e8d0d9abae3b6c")
                .unwrap()
                .as_slice(),
        );

        let mut rl_ar2 = [0u8; 32];
        rl_ar2.copy_from_slice(
            hex::decode("0b744cf3475f300fe77d2e85c3a5911e603e725b17932ee90f99fc7a869b8307")
                .unwrap()
                .as_slice(),
        );
        let rev_lock = rl_ar2.clone();

        let mut tx_id_merch = [0u8; 32];
        tx_id_merch.copy_from_slice(
            hex::decode("e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4")
                .unwrap()
                .as_slice(),
        );

        let mut tx_id_esc = [0u8; 32];
        tx_id_esc.copy_from_slice(
            hex::decode("e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4")
                .unwrap()
                .as_slice(),
        );

        let mut hashouts_merch = [0u8; 32];
        hashouts_merch.copy_from_slice(
            hex::decode("7d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d738")
                .unwrap()
                .as_slice(),
        );

        let mut hashouts_escrow = [0u8; 32];
        hashouts_escrow.copy_from_slice(
            hex::decode("7d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d738")
                .unwrap()
                .as_slice(),
        );

        let new_state = State {
            nonce: FixedSizeArray16(nonce1),
            rev_lock: FixedSizeArray32(rl_ar1),
            bc: 90000,
            bm: 110000,
            escrow_txid: FixedSizeArray32(tx_id_esc),
            merch_txid: FixedSizeArray32(tx_id_merch),
            escrow_prevout: FixedSizeArray32(hashouts_escrow),
            merch_prevout: FixedSizeArray32(hashouts_merch),
            min_fee: 0,
            max_fee: 10000,
            fee_mc: 1500,
        };
        let old_state = State {
            nonce: FixedSizeArray16(nonce2),
            rev_lock: FixedSizeArray32(rl_ar2),
            bc: 100000,
            bm: 100000,
            escrow_txid: FixedSizeArray32(tx_id_esc),
            merch_txid: FixedSizeArray32(tx_id_merch),
            escrow_prevout: FixedSizeArray32(hashouts_escrow),
            merch_prevout: FixedSizeArray32(hashouts_merch),
            min_fee: 0,
            max_fee: 10000,
            fee_mc: 1500,
        };

        let mut hmac_key = [0u8; 64];
        hmac_key.copy_from_slice(hex::decode("439452e56db2398e05396328c5e037086c5167565736ce7041356f12d161821715656a1a16eeff47615e0494d7b3757d730517f1beebc45575beb1644ba48a1a").unwrap().as_slice());
        // confirm that initial pay token is computed correctly
        let ser_old_state = old_state.serialize_compact();
        let rec_old_paytoken = hmac_sign(hmac_key.to_vec(), &ser_old_state);

        let mut old_paytoken = [0u8; 32];
        old_paytoken.copy_from_slice(
            hex::decode("f07d85d1ea6e3e94e30f6c26f0e4cbcfc8e44281b1d3ebd6448737e005078e15")
                .unwrap()
                .as_slice(),
        );
        println!("paytoken: {}", hex::encode(rec_old_paytoken));
        assert_eq!(old_paytoken, rec_old_paytoken);

        let cust_escrow_pub_key = secp256k1::PublicKey::from_slice(
            hex::decode("03fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d7")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let cust_payout_pub_key = secp256k1::PublicKey::from_slice(
            hex::decode("03195e272df2310ded35f9958fd0c2847bf73b5b429a716c005d465009bd768641")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let cust_pk_input_buf = cust_payout_pub_key.serialize();
        let cust_pub_key_hash = compute_hash160(&cust_pk_input_buf.to_vec());

        /* END CUSTOMER INPUTS */

        /* PULBIC MPC INPUTS */
        /* Balance amount, HMACKeyCommit, PT_MaskCommit, RevLockCommit, Nonce, 3x Public Key, 1x PK_Hash*/

        let amount = 10000;

        let mut key_com = [0u8; 32];
        key_com.copy_from_slice(
            hex::decode("17ae203d3c0b350cc1d9113c454d7604b096b910c561025f8d610d2898f13a3e")
                .unwrap()
                .as_slice(),
        );

        let mut paytoken_mask_com = [0u8; 32];
        paytoken_mask_com.copy_from_slice(
            hex::decode("4680673eb9daea72cad23b211e3370086b3f9db74d870e87af492c32b6b9f5a7")
                .unwrap()
                .as_slice(),
        );

        // rev_lock_com.copy_from_slice(hex::decode("1caa135b24792810dcab8dffbb5157972e38dff248f0d43f5ea453111ca25852").unwrap().as_slice()); // without randomness
        let rev_lock_r = [3u8; 16];
        let rev_lock_com = compute_commitment(&rev_lock.to_vec(), &rev_lock_r);
        println!("rev_lock_com: {}", hex::encode(&rev_lock_com));

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(
            hex::decode("18670766caf2e5fec5f909d04acd5e86")
                .unwrap()
                .as_slice(),
        );

        let merch_escrow_pub_key = secp256k1::PublicKey::from_slice(
            hex::decode("03f5ebc49f568e80a1dfca988eccf5d30ef9a63ae9e89a3f68b959f59d811489bd")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let merch_dispute_key = secp256k1::PublicKey::from_slice(
            hex::decode("0253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7c")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let mut merch_public_key_hash = [0u8; 20];
        merch_public_key_hash.copy_from_slice(
            hex::decode("43e9e81bc632ad9cad48fc23f800021c5769a063")
                .unwrap()
                .as_slice(),
        );
        let merch_payout_pub_key = secp256k1::PublicKey::from_slice(
            hex::decode("02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let nc = NetworkConfig {
            conn_type: ConnType_NETIO,
            path: String::from("127.0.0.1"),
            dest_ip: String::from("127.0.0.1"),
            dest_port: 12345,
            peer_raw_fd: 0,
        };

        // check if AGPC=1 in env
        let using_ag2pc = match env::var("AG2PC") {
            Ok(_s) => true,
            Err(_e) => false,
        };

        let circuit_file = match using_ag2pc {
            true => match env::var("ZK_DEPS_INSTALL") {
                Ok(s) => format!("{}{}", s, CIRCUIT_FILE),
                Err(e) => panic!("ZK_DEPS_INSTALL env not set: {}", e),
            },
            false => String::new(),
        };

        let cf_ptr = match using_ag2pc {
            true => {
                let cf_ptr = unsafe {
                    let c_str = CString::new(circuit_file).unwrap();
                    // TODO: need a way to verify circuit is correctly generated
                    load_circuit_file(c_str.as_ptr() as *const i8)
                };
                cf_ptr
            }
            false => ptr::null_mut(),
        };

        let fee_cc = 1500;
        let mpc_result = mpc_build_masked_tokens_cust(
            nc,
            cf_ptr,
            amount,
            &paytoken_mask_com,
            &rev_lock_com,
            &rev_lock_r,
            &key_com,
            merch_escrow_pub_key,
            merch_dispute_key,
            merch_public_key_hash,
            merch_payout_pub_key,
            new_state,
            old_state,
            fee_cc,
            &old_paytoken,
            cust_escrow_pub_key,
            cust_payout_pub_key,
            cust_pub_key_hash,
        );

        // if this assert is triggered, then there was an error inside the mpc
        assert!(mpc_result.is_ok(), mpc_result.err().unwrap());
        let (pt_masked_ar, ct_escrow_masked_ar, ct_merch_masked_ar) = mpc_result.unwrap();

        let mut paytoken_mask_bytes = [0u8; 32];
        paytoken_mask_bytes.copy_from_slice(
            hex::decode("0c8dda801001c9a55f720c5f379ce09e42416780f98fef7900bd26b372b81850")
                .unwrap()
                .as_slice(),
        );
        let mut merch_mask_bytes = [0u8; 32];
        merch_mask_bytes.copy_from_slice(
            hex::decode("1c92f6e3dfb5f805a436b727a340fd08d41e4de53b7f6dd5865b5f30fcf80709")
                .unwrap()
                .as_slice(),
        );
        let mut escrow_mask_bytes = [0u8; 32];
        escrow_mask_bytes.copy_from_slice(
            hex::decode("2670345a391379cd02514a35ee4fb3f1f0c14b5fb75381b7e797b5dd26ee057d")
                .unwrap()
                .as_slice(),
        );
        // let sk_m = secp256k1::SecretKey::from_slice(&hex::decode("bbb22af17dc660de6c26ff59e8090dbbc19dcde76beed4f5970c9eaccfbdc96c").unwrap().as_slice()).unwrap();
        let secp = Secp256k1::new();

        // We are signing this thing (this is post hash): "c76b9fbe0364d533b6ee018de59b3f3d529c6caa1d6fbe28853785e03b006047"
        // the escrow Preimage is: "020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff40000000047522103f5ebc49f568e80a1dfca988eccf5d30ef9a63ae9e89a3f68b959f59d811489bd2103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752ae400d030000000000ffffffffab11137ab3c29c95e0c35debd9cfebf1e265ad5e496fa5964400767425e203cb0000000001000000"
        let escrow_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff40000000047522103f5ebc49f568e80a1dfca988eccf5d30ef9a63ae9e89a3f68b959f59d811489bd2103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752ae400d030000000000ffffffffab11137ab3c29c95e0c35debd9cfebf1e265ad5e496fa5964400767425e203cb0000000001000000").unwrap();
        // automatically generate the escrow_preimage
        let input1 = create_reverse_input(&tx_id_esc, 0, new_state.bc + new_state.bm);
        let mut pubkeys = ClosePublicKeys {
            cust_pk: cust_escrow_pub_key.serialize().to_vec(),
            cust_close_pk: cust_payout_pub_key.serialize().to_vec(),
            merch_pk: merch_escrow_pub_key.serialize().to_vec(),
            merch_close_pk: merch_payout_pub_key.serialize().to_vec(),
            merch_disp_pk: merch_dispute_key.serialize().to_vec(),
            rev_lock: FixedSizeArray32([0u8; 32]),
        };
        pubkeys
            .rev_lock
            .0
            .copy_from_slice(&new_state.get_rev_lock());
        let to_self_delay_be: [u8; 2] = [0x05, 0xcf]; // big-endian format
        let (tx_preimage, _, _) = create_cust_close_transaction::<Testnet>(
            &input1,
            &pubkeys,
            &to_self_delay_be,
            new_state.bc,
            new_state.bm,
            fee_cc,
            new_state.fee_mc,
            util::VAL_CPFP,
            true,
        );
        println!(
            "TX BUILDER: generated escrow tx preimage: {}",
            hex::encode(&tx_preimage)
        );
        assert_eq!(tx_preimage, escrow_preimage);

        let escrow_tx_ar = Sha256::digest(&Sha256::digest(escrow_preimage.as_slice()));
        let escrow_tx = Message::from_slice(escrow_tx_ar.as_slice()).unwrap();
        // the merch preimage is: "020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4000000007263522103f5ebc49f568e80a1dfca988eccf5d30ef9a63ae9e89a3f68b959f59d811489bd2103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752ae6702cf05b2752102f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90ac68400d030000000000ffffffffcb618c017ebbe60597107dbb2060df80bbbb03b8b3ea19d0dbf5f3553d55d4a10000000001000000"
        let merch_preimage = hex::decode("020000007d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d7383bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4000000007263522103f5ebc49f568e80a1dfca988eccf5d30ef9a63ae9e89a3f68b959f59d811489bd2103fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d752ae6702cf05b2752102f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90ac68400d030000000000ffffffffcb618c017ebbe60597107dbb2060df80bbbb03b8b3ea19d0dbf5f3553d55d4a10000000001000000").unwrap();
        let merch_tx_ar = Sha256::digest(&Sha256::digest(merch_preimage.as_slice()));
        let merch_tx = Message::from_slice(merch_tx_ar.as_slice()).unwrap();

        // automatically generate the escrow_preimage
        let input2 = create_reverse_input(&tx_id_merch, 0, new_state.bc + new_state.bm);
        let (m_tx_preimage, _, _) = create_cust_close_transaction::<Testnet>(
            &input2,
            &pubkeys,
            &to_self_delay_be,
            new_state.bc,
            new_state.bm,
            fee_cc,
            new_state.fee_mc,
            util::VAL_CPFP,
            false,
        );
        println!(
            "TX BUILDER: generated merch tx preimage: {}",
            hex::encode(&m_tx_preimage)
        );
        assert_eq!(m_tx_preimage, merch_preimage);

        // Asserts
        // 1. check that hmac(new_state) =  pt_mask ^ pt_masked_ar
        let ser_new_state = new_state.serialize_compact();
        let rec_new_paytoken = hmac_sign(hmac_key.to_vec(), &ser_new_state);
        xor_in_place(&mut paytoken_mask_bytes, &pt_masked_ar[..]);
        println!("paytoken cust: {}", hex::encode(paytoken_mask_bytes));
        assert_eq!(paytoken_mask_bytes, rec_new_paytoken);

        // 2. Unmask the escrow token, and check the sig
        println!("masked s: {}", hex::encode(&ct_escrow_masked_ar[..]));
        xor_in_place(&mut escrow_mask_bytes, &ct_escrow_masked_ar[..]);
        println!("unmasked s: {}", hex::encode(escrow_mask_bytes));
        let mut escrow_sig_vec =
            hex::decode("ca1248d5e6ac123c1a0d5b19dacec544d1068427a8cd3fc5d0a40c844c0dba4f")
                .unwrap();
        escrow_sig_vec.append(&mut escrow_mask_bytes.to_vec());
        let escrow_sig = Signature::from_compact(escrow_sig_vec.as_slice()).unwrap();
        println!(
            "escrow_sig cust: {}",
            hex::encode(&escrow_sig.serialize_compact()[..])
        );

        assert!(secp
            .verify(&escrow_tx, &escrow_sig, &merch_escrow_pub_key)
            .is_ok());

        // 3. Unmask the merch token, and check the sig
        println!("masked s: {}", hex::encode(&ct_merch_masked_ar[..]));
        xor_in_place(&mut merch_mask_bytes, &ct_merch_masked_ar[..]);
        println!("unmasked s: {}", hex::encode(merch_mask_bytes));
        let mut merch_sig_vec =
            hex::decode("2144e9c90f5799c98610719d735bd53dc6edbfc1e11c8a193070bf42230bc176")
                .unwrap();
        merch_sig_vec.append(&mut merch_mask_bytes.to_vec());
        let merch_sig = Signature::from_compact(merch_sig_vec.as_slice()).unwrap();
        println!(
            "merch_sig cust: {}",
            hex::encode(&merch_sig.serialize_compact()[..])
        );
        assert!(secp
            .verify(&merch_tx, &merch_sig, &merch_escrow_pub_key)
            .is_ok());
    }
    //}

    pub fn xor_in_place(a: &mut [u8], b: &[u8]) {
        for (b1, b2) in a.iter_mut().zip(b.iter()) {
            *b1 ^= *b2;
        }
    }

    #[test]
    // todo what does this actually test? there are no assertions
    fn createEcdsaParamsWorks() {
        let csprng = &mut rand::thread_rng();
        let mut seckey = [0u8; 32];
        csprng.fill_bytes(&mut seckey);

        let sk = secp256k1::SecretKey::from_slice(&seckey).unwrap();
        println!("secret key: {}", sk.to_string());
        let params = EcdsaPartialSig::New(csprng, &sk).getMpcRepr();
        let index_r = params.r.to_vec().iter().position(|&r| r == 0x0).unwrap();
        let index_k_inv = params
            .k_inv
            .to_vec()
            .iter()
            .position(|&r| r == 0x0)
            .unwrap();
        let rx = unsafe {
            str::from_utf8(CStr::from_ptr(params.r[0..index_r].as_ptr()).to_bytes()).unwrap()
        };
        let k_inv = unsafe {
            str::from_utf8(CStr::from_ptr(params.k_inv[0..index_k_inv].as_ptr()).to_bytes())
                .unwrap()
        };
        print!("r: {}\n", rx);
        print!("k^-1: {}\n", k_inv);
    }

    #[test]
    fn signature() {
        let secp = Secp256k1::new();
        let sig = hex::decode("96fec178aea8d00c83f36b3424dd56762a5440547938ecc82b5c204435418fd968bafe1af248ec2c9ff9aba262cfcf801b486c685467ebc567b9b4e5e5674135").unwrap();
        let signature = secp256k1::Signature::from_compact(&sig).unwrap();
        let par_sig_ser = hex::decode("96fec178aea8d00c83f36b3424dd56762a5440547938ecc82b5c204435418fd99eedce5c89bba8897758b7d7454eb5300657f6da1132d3a930fd9721c352b6e6ce6f2c740f993c6c60931ee965241e5a0527e4ab466d97dcc3436860370700d1").unwrap();
        let par_sig = secp256k1::PartialSignature::from_compact(&par_sig_ser).unwrap();
        let sk_ser =
            hex::decode("c71ffda863b14b3a9434a8799561cb15ac082cba2ad16bebae89a507cda267a2")
                .unwrap();
        let sk = secp256k1::SecretKey::from_slice(&sk_ser).unwrap();
        let msg = hex::decode("063157f426b2123c72182ed5e3f418ff26b13de970ec9c0a625a16f31ae0ce64")
            .unwrap();
        println!(
            "message: {}",
            BigInt::from_bytes_be(Sign::Plus, &msg).to_string()
        );
        println!(
            "{}",
            BigInt::from_bytes_be(
                Sign::Plus,
                &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
                    .unwrap(),
            )
            .to_string()
        );
        let mes = secp256k1::Message::from_slice(&msg).unwrap();
        println!("{:?}", mes);
        let sign = secp.compute_sign(&mes, &par_sig);
        println!("{}", hex::encode(&sign.serialize_compact()[..]));
        assert!(secp
            .verify(
                &mes,
                &signature,
                &secp256k1::PublicKey::from_secret_key(&secp, &sk),
            )
            .is_ok());
        assert!(secp
            .verify(
                &mes,
                &sign,
                &secp256k1::PublicKey::from_secret_key(&secp, &sk),
            )
            .is_ok());
    }
}
