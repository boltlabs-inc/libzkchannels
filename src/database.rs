use super::*;
use rand::Rng;
use redis::{Commands, Connection};
use std::hash::Hash;
use std::collections::hash_map::RandomState;
use util::hash_to_slice;
use fixed_size_array::{FixedSizeArray16, FixedSizeArray32};

fn create_db_connection(url: String) -> redis::RedisResult<Connection> {
    let client = redis::Client::open(url.as_str())?;
    let mut con = client.get_connection()?;

    Ok(con)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PayMaskMap {
    pub mask: FixedSizeArray32,
    pub r: FixedSizeArray16
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MaskedMPCInputs {
    pub pt_mask: FixedSizeArray32,
    pub pt_mask_r: FixedSizeArray16,
    pub escrow_mask: FixedSizeArray32,
    pub merch_mask: FixedSizeArray32,
    pub r_escrow_sig: FixedSizeArray32,
    pub r_merch_sig: FixedSizeArray32,
}

impl MaskedMPCInputs {
    pub fn get_tx_masks(&self) -> MaskedTxMPCInputs {
        return MaskedTxMPCInputs {
            escrow_mask: self.escrow_mask,
            merch_mask: self.merch_mask,
            r_escrow_sig: self.r_escrow_sig,
            r_merch_sig: self.r_merch_sig,
        }
    }
}


#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MaskedTxMPCInputs {
    pub escrow_mask: FixedSizeArray32,
    pub merch_mask: FixedSizeArray32,
    pub r_escrow_sig: FixedSizeArray32,
    pub r_merch_sig: FixedSizeArray32,
}

impl MaskedTxMPCInputs {
    pub fn new(escrow_mask: [u8; 32], merch_mask: [u8; 32], r_escrow_sig: [u8; 32], r_merch_sig: [u8; 32]) -> Self {
        MaskedTxMPCInputs {
            escrow_mask: FixedSizeArray32(escrow_mask),
            merch_mask: FixedSizeArray32(merch_mask),
            r_escrow_sig: FixedSizeArray32(r_escrow_sig),
            r_merch_sig: FixedSizeArray32(r_merch_sig)
        }
    }

    pub fn get_escrow_mask(&self) -> [u8; 32] {
        self.escrow_mask.0
    }

    pub fn get_merch_mask(&self) -> [u8; 32] {
        self.merch_mask.0
    }

    pub fn get_r_escrow_sig(&self) -> [u8; 32] {
        self.r_escrow_sig.0
    }

    pub fn get_r_merch_sig(&self) -> [u8; 32] {
        self.r_merch_sig.0
    }
}

pub trait StateDatabase {
    fn new(prefix: &'static str, url: String) -> Result<Self, String> where Self: Sized;
    fn update_spent_map(&mut self, nonce: &String, rev_lock: &String) -> Result<bool, String>;
    fn check_spent_map(&mut self, nonce: &String) -> bool;
    fn update_rev_lock_map(&mut self, rev_lock: &String, rev_secret: &String) -> Result<bool, String>;
    fn check_rev_lock_map(&mut self, rev_lock: &String) -> bool;
    fn update_unlink_set(&mut self, nonce: &String) -> Result<bool, String>;
    fn get_unlink_set(&mut self) -> Result<HashSet<String>, String>;
    fn is_member_unlink_set(&mut self, nonce: &String) -> bool;
    fn remove_from_unlink_set(&mut self, nonce: &String) -> Result<(), String>;
    fn clear_state(&mut self) -> bool;
    fn update_nonce_mask_map(&mut self, nonce: &String, mask: [u8; 32], mask_r: [u8; 16]) -> Result<bool, String>;
    fn get_mask_map_from_nonce(&mut self, nonce: &String) -> Result<([u8; 32], [u8; 16]), String>;
    fn update_masked_mpc_inputs(&mut self, nonce: &String, mask_bytes: MaskedMPCInputs) -> bool;
    fn get_masked_mpc_inputs(&mut self, nonce: &String) -> Result<MaskedMPCInputs, String>;
}

pub struct RedisDatabase {
    pub conn: redis::Connection,
    unlink_set_key: String,
    spent_map_key: String,
    rev_lock_map_key: String,
    nonce_mask_map_key: String,
    masked_bytes_key: String,
}

impl StateDatabase for RedisDatabase {
    fn new(prefix: &'static str, url: String) -> Result<Self, String> {
        let conn = match create_db_connection(url) {
            Ok(c) => c,
            Err(e) => return Err(e.to_string())
        };
        Ok(RedisDatabase {
            conn: conn,
            unlink_set_key: format!("{}:hashset:unlink", prefix),
            spent_map_key: format!("{}:hashmap:spent", prefix),
            rev_lock_map_key: format!("{}:hashmap:revlock", prefix),
            nonce_mask_map_key: format!("{}:hashmap:nonce_paymasks", prefix),
            masked_bytes_key: format!("{}:hashmap:masked_bytes", prefix)
        })
    }

    // spent map calls
    fn update_spent_map(&mut self, nonce_hex: &String, rev_lock_hex: &String) -> Result<bool, String> {
        match self.conn.hset::<String, String, String, i32>(self.spent_map_key.clone(), nonce_hex.clone(), rev_lock_hex.clone()) {
            Ok(s) => match s >= 1 {
                true => Ok(true),
                false => Ok(false)
            },
            Err(e) => return Err(e.to_string())
        }
    }

    fn check_spent_map(&mut self, nonce_hex: &String) -> bool {
        match self.conn.hexists(self.spent_map_key.clone(), nonce_hex.clone())  {
            Ok(s) => s,
            Err(e) => {
                println!("check_spent_map: {}", e.to_string());
                false
            }
        }
    }

    // rev_lock map calls
    fn update_rev_lock_map(&mut self, rev_lock_hex: &String, rev_secret_hex: &String) -> Result<bool, String> {
        match self.conn.hset::<String, String, String, i32>(self.rev_lock_map_key.clone(), rev_lock_hex.clone(), rev_secret_hex.clone()) {
            Ok(s) => Ok(s != 0),
            Err(e) => return Err(e.to_string())
        }
    }

    fn check_rev_lock_map(&mut self, rev_lock_hex: &String) -> bool {
        match self.conn.hexists(self.rev_lock_map_key.clone(), rev_lock_hex.clone())  {
            Ok(s) => s,
            Err(e) => {
                println!("check_rev_lock_map: {}", e.to_string());
                false
            }
        }
    }

    // unlink set calls
    fn update_unlink_set(&mut self, nonce: &String) -> Result<bool, String> {
        match self.conn.sadd::<String, String, String>(self.unlink_set_key.clone(), nonce.clone()) {
            Ok(_) => Ok(true),
            Err(e) => Err(e.to_string())
        }
    }

    fn get_unlink_set(&mut self) -> Result<HashSet<String>, String> {
        let hash_set: HashSet<String> = match self.conn.smembers(&self.unlink_set_key) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string())
        };
        Ok(hash_set)
    }

    fn is_member_unlink_set(&mut self, nonce: &String) -> bool {
        match self.conn.sismember(self.unlink_set_key.clone(), nonce.clone()) {
            Ok(s) => s,
            Err(e) => {
                println!("is_member_unlink_set: {}", e);
                false
            }
        }
    }

    fn remove_from_unlink_set(&mut self, nonce: &String) -> Result<(), String> {
        match self.conn.hdel(self.unlink_set_key.clone(), nonce.clone()) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string())
        };
        Ok(())
    }

    fn clear_state(&mut self) -> bool {
        match self.conn.del(self.unlink_set_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {}", self.unlink_set_key);
                return false;
            }
        }
        match self.conn.del(self.spent_map_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {}", self.spent_map_key);
                return false;
            }
        }
        match self.conn.del(self.rev_lock_map_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {}", self.rev_lock_map_key);
                return false;
            }
        }
        match self.conn.del(self.nonce_mask_map_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {}", self.nonce_mask_map_key);
                return false;
            }
        }
        match self.conn.del(self.masked_bytes_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {}", self.masked_bytes_key);
                return false;
            }
        }
        return true;
    }

    // nonce -> masks calls
    fn update_nonce_mask_map(&mut self, nonce: &String, mask: [u8; 32], mask_r: [u8; 16]) -> Result<bool, String> {
        let mut m = mask.to_vec();
        m.extend(mask_r.to_vec());
        match self.conn.hset::<String, String, String, i32>(self.nonce_mask_map_key.clone(), nonce.clone(), hex::encode(&m)) {
            Ok(s) => Ok(s != 0),
            Err(e) => return Err(e.to_string())
        }
    }

    fn get_mask_map_from_nonce(&mut self, nonce: &String) -> Result<([u8; 32], [u8; 16]), String> {
        let (mask, mask_r) = match self.conn.hget::<String, String, String>(self.nonce_mask_map_key.clone(), nonce.clone()) {
            Ok(s) => match hex::decode(s) {
                Ok(t) => {
                    if t.len() == 48 {
                        let mut mask = [0u8; 32];
                        let mut mask_r = [0u8; 16];
                        mask.copy_from_slice(&t[0..32]);
                        mask_r.copy_from_slice(&t[32..48]);
                        (mask, mask_r)
                    } else {
                        return Err(format!("Invalid length for mask: {}", t.len()));
                    }
                },
                Err(e) => return Err(e.to_string())
            },
            Err(e) => return Err(format!("could not find mask for specified nonce: {}. reason: {}", nonce, e.to_string()))
        };
        Ok((mask, mask_r))
    }

    // rev-lock -> masked inputs calls
    fn update_masked_mpc_inputs(&mut self, nonce: &String, mask_bytes: MaskedMPCInputs) -> bool {
        let ser_mask_bytes = match serde_json::to_string(&mask_bytes) {
            Ok(s) => s,
            Err(e) => return false
        };

        match self.conn.hset::<String, String, String, i32>(self.masked_bytes_key.clone(), nonce.clone(), ser_mask_bytes) {
            Ok(c) => c != 0,
            Err(e) => false
        }
    }

    fn get_masked_mpc_inputs(&mut self, nonce: &String) -> Result<MaskedMPCInputs, String> {
        let ser_masked_bytes = match self.conn.hget::<String, String, String>(self.masked_bytes_key.clone(), nonce.clone()) {
            Ok(s) => s,
            Err(e) => return Err(format!("get_masked_mpc_inputs: {}", e.to_string()))
        };

        let t: MaskedMPCInputs = handle_error_util!(serde_json::from_str(&ser_masked_bytes));

        Ok(t)
    }
}

pub struct HashMapDatabase {
    pub nonce_mask_map: HashMap<String, PayMaskMap>,
    pub unlink_map: HashSet<String>,
    pub spent_lock_map: HashMap<String, String>,
    pub rev_lock_map: HashMap<String, String>,
    pub mask_mpc_bytes: HashMap<String, MaskedMPCInputs>
}

impl StateDatabase for HashMapDatabase {
    fn new(prefix: &'static str, url: String) -> Result<Self, String> {
        Ok(HashMapDatabase {
            nonce_mask_map: HashMap::new(),
            unlink_map: HashSet::new(),
            spent_lock_map: HashMap::new(),
            rev_lock_map: HashMap::new(),
            mask_mpc_bytes: HashMap::new()
        })
    }

    fn update_spent_map(&mut self, nonce: &String, rev_lock: &String) -> Result<bool, String> {
        match self.spent_lock_map.insert(nonce.clone(), rev_lock.clone()) {
            Some(c) => c,
            None => return Err(format!("could not update spent_map"))
        };
        Ok(true)
    }

    fn check_spent_map(&mut self, nonce: &String) -> bool {
        return self.spent_lock_map.get(nonce).is_some()
    }

    fn update_rev_lock_map(&mut self, rev_lock: &String, rev_secret: &String) -> Result<bool, String> {
        match self.spent_lock_map.insert(rev_lock.clone(), rev_secret.clone()) {
            Some(c) => c,
            None => return Err(format!("could not update spent_map"))
        };
        Ok(true)
    }

    fn check_rev_lock_map(&mut self, rev_lock: &String) -> bool {
        return self.rev_lock_map.get(rev_lock).is_some()
    }

    fn update_unlink_set(&mut self, nonce: &String) -> Result<bool, String> {
        Ok(self.unlink_map.insert(nonce.clone()))
    }

    fn get_unlink_set(&mut self) -> Result<HashSet<String, RandomState>, String> {
        Ok(self.unlink_map.clone())
    }

    fn is_member_unlink_set(&mut self, nonce: &String) -> bool {
        self.unlink_map.contains(nonce)
    }

    fn remove_from_unlink_set(&mut self, nonce: &String) -> Result<(), String> {
        if self.unlink_map.contains(nonce) {
            self.unlink_map.remove(nonce);
        }
        Ok(())
    }

    fn clear_state(&mut self) -> bool {
        return true;
    }

    fn update_nonce_mask_map(&mut self, nonce: &String, mask: [u8; 32], mask_r: [u8; 16]) -> Result<bool, String> {
        let pay_mask_map = PayMaskMap { mask: FixedSizeArray32(mask), r: FixedSizeArray16(mask_r) };
        self.nonce_mask_map.insert(nonce.clone(), pay_mask_map);
        Ok(true)
    }

    fn get_mask_map_from_nonce(&mut self, nonce: &String) -> Result<([u8; 32], [u8; 16]), String> {
        match self.nonce_mask_map.get(nonce) {
            Some(p) => Ok((p.mask.0, p.r.0)),
            None => return Err(format!("could not find pay mask for specified nonce: {}", nonce))
        }
    }

    fn update_masked_mpc_inputs(&mut self, nonce: &String, mask_bytes: MaskedMPCInputs) -> bool {
        match self.mask_mpc_bytes.insert(nonce.clone(), mask_bytes) {
            Some(c) => true,
            None => false
        }
    }

    fn get_masked_mpc_inputs(&mut self, nonce: &String) -> Result<MaskedMPCInputs, String> {
        match self.mask_mpc_bytes.get(nonce) {
            Some(m) => Ok(m.clone()),
            None => return Err(format!("could not find masked mpc inputs for specified nonce: {}", nonce))
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_xorshift::XorShiftRng;
    use rand::SeedableRng;

    #[test]
    fn mpc_test_redis_database() {
        let mut rng = XorShiftRng::seed_from_u64(0x8d863e545dbe6259);
        let db_url = "redis://127.0.0.1/".to_string();
        let mut db = RedisDatabase::new("test", db_url).unwrap();
        db.clear_state();

        let key1 = "key1";
        let key2 = "key3";

        let a = hex::encode([0u8; 32]);
        let _ = db.conn.set::<String, String, String>(key1.to_string(), a.clone());

        let orig_a: String = db.conn.get(key1.to_string()).unwrap();

        assert_eq!(a, orig_a);

        let mut value1: HashSet<String> = HashSet::new();
        let b = hex::encode([1u8; 32]);
        let c = hex::encode([2u8; 32]);
        let d = hex::encode([3u8; 32]);

        db.update_unlink_set(&b);
        db.update_unlink_set(&c);
        db.update_unlink_set(&d);

        let hash_set1: HashSet<String> = db.get_unlink_set().unwrap();
        println!("Unlink HashSet: ");
        for i in &hash_set1 {
            println!("{}", i);
        }

        let e = hex::encode([2u8; 32]);
        let f = hex::encode([4u8; 32]);

        let is_in_set = db.is_member_unlink_set(&e);
        println!("In Set: {} => {}", e, is_in_set);

        let is_in_set = db.is_member_unlink_set(&f);
        println!("In Set: {} => {}", f, is_in_set);

        let nonce1 = hex::encode([2u8; 16]);
        let nonce2 = hex::encode([5u8; 16]);
        let rev_lock = hex::encode([4u8; 32]);

        match db.update_spent_map(&nonce1, &rev_lock) {
            Ok(n) => (),
            Err(e) => println!("ERROR update_spent_map: {}", e)
        }
        let is_spent1 = db.check_spent_map(&nonce1);
        println!("Is spent 1: {} => {}", nonce1, is_spent1);

        let is_spent2 = db.check_spent_map(&nonce2);
        println!("Is spent 2: {} => {}", nonce2, is_spent2);

        let rev_sec1 = hex::encode([6u8; 32]);
        let rev_lock1 = hex::encode(hash_to_slice(&[6u8; 32].to_vec()));

        match db.update_rev_lock_map(&rev_lock1, &rev_sec1) {
            Ok(n) => (),
            Err(e) => println!("ERROR update_rev_lock_map: {}", e)
        }

        let rl_ok = db.check_rev_lock_map(&rev_lock1);
        assert!(rl_ok);

        // let value1_str = serde_json::to_string(&value1).unwrap();
        // let f = match redis::cmd("SET").arg("key2").arg(value1_str).query(&mut db.conn) {
        //     Ok(n) => n,
        //     Err(e) => return println!("SET ERROR: {}", e.to_string())
        // };

        // let skey = format!("hashset:{}", key2);
        //
        // let _ : () = match db.conn.zadd(skey.clone(), b) {
        //     Ok(n) => n,
        //     Err(e) => return println!("SET ERROR: {}", e.to_string())
        // };
        //
        // let _ : () = db.conn.zadd(skey.clone(), c).unwrap();
        //
        // // let e = match db.conn.set::<String, Vec<String>, String>(key2.to_string(), value1) {
        // //     Ok(n) => n,
        // //     Err(e) => return println!("Set Error: {}", e.to_string())
        // // };
        //
        // let some_map: HashSet<String> = match db.conn.smembers(skey) {
        //     Ok(n) => n,
        //     Err(e) => return println!("Get Error: {}", e.to_string())
        // };
    }

}
