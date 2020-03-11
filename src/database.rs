use super::*;
use std::hash::Hash;
use redis::{Commands, Connection};
use std::collections::hash_map::RandomState;
use rand::Rng;

fn create_db_connection(url: &'static str) -> redis::RedisResult<Connection> {
    let client = redis::Client::open(url)?;
    let mut con = client.get_connection()?;

    Ok(con)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PayMaskMap {
    pub mask: String,
    pub r: String
}

// #[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
// struct MaskedMPCInputs {
//     pt_mask: FixedSizeArray32,
//     pt_mask_r: FixedSizeArray16,
//     escrow_mask: FixedSizeArray32,
//     merch_mask: FixedSizeArray32,
//     r_escrow_sig: FixedSizeArray32,
//     r_merch_sig: FixedSizeArray32,
// }


pub trait StateDatabase {
    fn new(prefix: &'static str, url: &'static str) -> Result<Self, String> where Self: Sized;
    fn update_spent_map(&mut self, nonce: &String, rev_lock: &String) -> Result<bool, String>;
    fn check_spent_map(&mut self, nonce: &String) -> bool;
    fn update_rev_lock_map(&mut self, rev_lock: &String, rev_secret: &String) -> Result<bool, String>;
    fn check_rev_lock_map(&mut self, rev_lock: &String) -> bool;
    fn update_unlink_set(&mut self, nonce: &String) -> Result<bool, String>;
    fn get_unlink_set(&mut self) -> Result<HashSet<String>, String>;
    fn is_member_unlink_set(&mut self, nonce: &String) -> bool;
    fn remove_from_unlink_set(&mut self, nonce: &String) -> Result<(), String>;
    fn clear_state(&mut self) -> bool;
}

pub struct RedisDatabase {
    pub conn: redis::Connection,
    unlink_set_key: String,
    spent_map_key: String,
    rev_lock_map_key: String,
    nonce_mask_map_key: String,
}

impl StateDatabase for RedisDatabase {
    fn new(prefix: &'static str, url: &'static str) -> Result<Self, String> {
        let conn = match create_db_connection(url) {
            Ok(c) => c,
            Err(e) => return Err(e.to_string())
        };
        Ok(RedisDatabase {
            conn: conn,
            unlink_set_key: format!("{}:hashset:unlink", prefix),
            spent_map_key: format!("{}:hashmap:spent", prefix),
            rev_lock_map_key: format!("{}:hashmap:revlock", prefix),
            nonce_mask_map_key: format!("{}:hashmap:nonce_paymasks", prefix)
        })
    }

    // spent map calls
    fn update_spent_map(&mut self, nonce: &String, rev_lock: &String) -> Result<bool, String> {
        match self.conn.hset::<String, String, String, i32>(self.spent_map_key.clone(), nonce.clone(), rev_lock.clone()) {
            Ok(s) => match s >= 1 {
                true => Ok(true),
                false => Ok(false)
            },
            Err(e) => return Err(e.to_string())
        }
    }

    fn check_spent_map(&mut self, nonce: &String) -> bool {
        match self.conn.hexists(self.spent_map_key.clone(), nonce.clone())  {
            Ok(s) => s,
            Err(e) => {
                println!("check_spent_map: {}", e.to_string());
                false
            }
        }
    }

    // rev_lock map calls
    fn update_rev_lock_map(&mut self, rev_lock: &String, rev_secret: &String) -> Result<bool, String> {
        match self.conn.hset::<String, String, String, i32>(self.rev_lock_map_key.clone(), rev_lock.clone(), rev_secret.clone()) {
            Ok(s) => match s >= 1 {
                true => Ok(true),
                false => Ok(false)
            },
            Err(e) => return Err(e.to_string())
        }
    }

    fn check_rev_lock_map(&mut self, rev_lock: &String) -> bool {
        match self.conn.hexists(self.rev_lock_map_key.clone(), rev_lock.clone())  {
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
        return true;
    }
}

pub struct HashMapDatabase {
    pub nonce_mask_map: HashMap<String, PayMaskMap>,
    pub unlink_map: HashSet<String>,
    pub spent_lock_map: HashMap<String, String>,
    pub rev_lock_map: HashMap<String, String>,
    // pub mask_mpc_bytes: HashMap<String, MaskedMPCInputs>
}

impl StateDatabase for HashMapDatabase {
    fn new(prefix: &'static str, url: &'static str) -> Result<Self, String> {
        Ok(HashMapDatabase {
            nonce_mask_map: HashMap::new(),
            unlink_map: HashSet::new(),
            spent_lock_map: HashMap::new(),
            rev_lock_map: HashMap::new(),
            // mask_mpc_bytes: HashMap::new()
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn mpc_test_redis_database() {
        let mut rng = XorShiftRng::seed_from_u64(0x8d863e545dbe6259);

        // let mut channel_state = ChannelMPCState::new(String::from("Channel A <-> B"), false);

        // let url = String::from("redis://127.0.0.1/");
        let mut db = RedisDatabase::new("test","redis://127.0.0.1/").unwrap();
        db.clear_state();

        let key1 = "key1";
        let key2 = "key3";

        let a = hex::encode([0u8; 32]);
        let _ = db.conn.set::<String, String, String>(key1.to_string(), a);

        let orig_a: String = db.conn.get(key1.to_string()).unwrap();

        println!("Orig value a: {}", orig_a);

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
