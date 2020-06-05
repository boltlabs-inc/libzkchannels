use super::*;
use channels_mpc::PaymentStatus;
use redis::{Commands, Connection};
use std::collections::hash_map::RandomState;
use zkchan_tx::fixed_size_array::{FixedSizeArray16, FixedSizeArray32};

pub fn create_db_connection(url: String) -> redis::RedisResult<Connection> {
    let client = redis::Client::open(url.as_str())?;
    let con: Connection = client.get_connection()?;

    Ok(con)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PayMaskMap {
    pub mask: FixedSizeArray32,
    pub r: FixedSizeArray16,
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
        };
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
    pub fn new(
        escrow_mask: [u8; 32],
        merch_mask: [u8; 32],
        r_escrow_sig: [u8; 32],
        r_merch_sig: [u8; 32],
    ) -> Self {
        MaskedTxMPCInputs {
            escrow_mask: FixedSizeArray32(escrow_mask),
            merch_mask: FixedSizeArray32(merch_mask),
            r_escrow_sig: FixedSizeArray32(r_escrow_sig),
            r_merch_sig: FixedSizeArray32(r_merch_sig),
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionState {
    pub nonce: FixedSizeArray16,
    pub rev_lock_com: FixedSizeArray32,
    pub amount: i64,
    pub status: PaymentStatus,
}

pub trait StateDatabase {
    // creating a new database
    fn new(prefix: &'static str, url: String) -> Result<Self, String>
    where
        Self: Sized;

    // manage session state
    fn check_session_id(&mut self, session_id_hex: &String) -> Result<bool, String>;
    fn save_new_session_state(
        &mut self,
        session_id_hex: &String,
        session_state: &SessionState,
    ) -> bool;
    fn load_session_state(&mut self, session_id_hex: &String) -> Result<SessionState, String>;
    fn update_session_state(
        &mut self,
        session_id_hex: &String,
        session_state: &SessionState,
    ) -> bool;
    fn clear_session_state(&mut self, session_id_hex: &String) -> bool;

    // spent rev_lock map methods
    fn update_spent_map(
        &mut self,
        nonce_hex: &String,
        rev_lock_hex: &String,
    ) -> Result<bool, String>;
    fn check_spent_map(&mut self, nonce_hex: &String) -> bool;
    // rev_lock map methods
    fn update_rev_lock_map(
        &mut self,
        rev_lock_hex: &String,
        rev_secret_hex: &String,
    ) -> Result<bool, String>;
    fn check_rev_lock_map(&mut self, rev_lock_hex: &String) -> bool;
    fn get_rev_secret(&mut self, rev_lock_hex: &String) -> Result<String, String>;
    // unlink set methods
    fn update_unlink_set(&mut self, nonce: &String) -> Result<bool, String>;
    fn get_unlink_set(&mut self) -> Result<HashSet<String>, String>;
    fn is_member_unlink_set(&mut self, nonce: &String) -> bool;
    fn remove_from_unlink_set(&mut self, nonce: &String) -> bool;
    // nonce to session ids
    fn check_dup_nonce_to_session_id(
        &mut self,
        nonce_hex: &String,
        session_id_hex: &String,
    ) -> bool;
    fn update_nonce_to_session_id(
        &mut self,
        nonce_hex: &String,
        session_id_hex: &String,
    ) -> Result<bool, String>;
    // nonce to pay mask methods
    fn update_nonce_mask_map(
        &mut self,
        nonce_hex: &String,
        mask: [u8; 32],
        mask_r: [u8; 16],
    ) -> Result<bool, String>;
    fn get_mask_map_from_nonce(
        &mut self,
        nonce_hex: &String,
    ) -> Result<([u8; 32], [u8; 16]), String>;
    // masked mpc input methods
    fn update_masked_mpc_inputs(&mut self, nonce_hex: &String, mask_bytes: MaskedMPCInputs)
        -> bool;
    fn get_masked_mpc_inputs(&mut self, nonce_hex: &String) -> Result<MaskedMPCInputs, String>;
    // helper methods
    fn clear_state(&mut self) -> bool;
}

pub struct RedisDatabase {
    pub conn: redis::Connection,
    session_map_key: String,
    nonce_to_session_key: String,
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
            Err(e) => return Err(e.to_string()),
        };
        Ok(RedisDatabase {
            conn: conn,
            session_map_key: format!("{}:hashmap:session", prefix),
            unlink_set_key: format!("{}:hashset:unlink", prefix),
            spent_map_key: format!("{}:hashmap:spent", prefix),
            rev_lock_map_key: format!("{}:hashmap:revlock", prefix),
            nonce_to_session_key: format!("{}:hashmap:nonce_session", prefix),
            nonce_mask_map_key: format!("{}:hashmap:nonce_paymasks", prefix),
            masked_bytes_key: format!("{}:hashmap:masked_bytes", prefix),
        })
    }

    fn check_session_id(&mut self, session_id_hex: &String) -> Result<bool, String> {
        match self
            .conn
            .hexists(self.session_map_key.clone(), session_id_hex.clone())
        {
            Ok(s) => Ok(s),
            Err(e) => return Err(format!("check_session_id: {}", e.to_string())),
        }
    }

    fn save_new_session_state(
        &mut self,
        session_id_hex: &String,
        session_state: &SessionState,
    ) -> bool {
        let ser_session_state = match serde_json::to_string(session_state) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Sets field in the hash stored at key to value, only if field does not yet exist.
        // If key does not exist, a new key holding a hash is created.
        // If field already exists, this operation has no effect.
        match self.conn.hset_nx::<String, String, String, i32>(
            self.session_map_key.clone(),
            session_id_hex.clone(),
            ser_session_state,
        ) {
            // 1 if field is a new field and value was set.
            // 0 if field already exists in the hash and no operation was performed
            Ok(c) => c != 0,
            Err(_) => false,
        }
    }

    fn update_session_state(
        &mut self,
        session_id_hex: &String,
        session_state: &SessionState,
    ) -> bool {
        let ser_session_state = match serde_json::to_string(session_state) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Sets field in the hash stored at key to value.
        // If key does not exist, a new key holding a hash is created.
        // If field already exists in the hash, it is overwritten.
        match self.conn.hset::<String, String, String, i32>(
            self.session_map_key.clone(),
            session_id_hex.clone(),
            ser_session_state,
        ) {
            Ok(c) => c >= 0,
            Err(_) => false,
        }
    }

    fn load_session_state(&mut self, session_id_hex: &String) -> Result<SessionState, String> {
        let ser_session_data = match self
            .conn
            .hget::<String, String, String>(self.session_map_key.clone(), session_id_hex.clone())
        {
            Ok(s) => s,
            Err(e) => return Err(format!("load_session_state: {}", e.to_string())),
        };

        let t: SessionState = handle_error_util!(serde_json::from_str(&ser_session_data));

        Ok(t)
    }

    fn clear_session_state(&mut self, session_id_hex: &String) -> bool {
        match self
            .conn
            .hdel(self.session_map_key.clone(), session_id_hex.clone())
        {
            Ok(c) => return c,
            Err(e) => {
                println!(
                    "clear_session_state: failed to delete key: {} => {}",
                    session_id_hex, e
                );
                return false;
            }
        }
    }

    // spent map calls
    fn update_spent_map(
        &mut self,
        nonce_hex: &String,
        rev_lock_hex: &String,
    ) -> Result<bool, String> {
        match self.conn.hset::<String, String, String, i32>(
            self.spent_map_key.clone(),
            nonce_hex.clone(),
            rev_lock_hex.clone(),
        ) {
            Ok(s) => Ok(s != 0),
            Err(e) => return Err(e.to_string()),
        }
    }

    fn check_spent_map(&mut self, nonce_hex: &String) -> bool {
        match self
            .conn
            .hexists(self.spent_map_key.clone(), nonce_hex.clone())
        {
            Ok(s) => s,
            Err(e) => {
                println!("check_spent_map: {}", e.to_string());
                false
            }
        }
    }

    // rev_lock map calls
    fn update_rev_lock_map(
        &mut self,
        rev_lock_hex: &String,
        rev_secret_hex: &String,
    ) -> Result<bool, String> {
        match self.conn.hset::<String, String, String, i32>(
            self.rev_lock_map_key.clone(),
            rev_lock_hex.clone(),
            rev_secret_hex.clone(),
        ) {
            Ok(s) => Ok(s != 0),
            Err(e) => return Err(e.to_string()),
        }
    }

    fn check_rev_lock_map(&mut self, rev_lock_hex: &String) -> bool {
        match self
            .conn
            .hexists(self.rev_lock_map_key.clone(), rev_lock_hex.clone())
        {
            Ok(s) => s,
            Err(e) => {
                println!("check_rev_lock_map: {}", e.to_string());
                false
            }
        }
    }

    fn get_rev_secret(&mut self, rev_lock_hex: &String) -> Result<String, String> {
        match self
            .conn
            .hget::<String, String, String>(self.rev_lock_map_key.clone(), rev_lock_hex.clone())
        {
            Ok(s) => Ok(s),
            Err(e) => return Err(e.to_string()),
        }
    }

    // unlink set calls
    fn update_unlink_set(&mut self, nonce: &String) -> Result<bool, String> {
        match self
            .conn
            .sadd::<String, String, i32>(self.unlink_set_key.clone(), nonce.clone())
        {
            Ok(_) => Ok(true),
            Err(e) => Err(format!("ERROR: update_unlink_set => {}", e.to_string())),
        }
    }

    fn get_unlink_set(&mut self) -> Result<HashSet<String>, String> {
        let hash_set: HashSet<String> = match self.conn.smembers(&self.unlink_set_key) {
            Ok(n) => n,
            Err(e) => return Err(e.to_string()),
        };
        Ok(hash_set)
    }

    fn is_member_unlink_set(&mut self, nonce_hex: &String) -> bool {
        match self
            .conn
            .sismember(self.unlink_set_key.clone(), nonce_hex.clone())
        {
            Ok(s) => s,
            Err(e) => {
                println!("is_member_unlink_set: {}", e);
                false
            }
        }
    }

    fn remove_from_unlink_set(&mut self, nonce_hex: &String) -> bool {
        match self
            .conn
            .srem(self.unlink_set_key.clone(), nonce_hex.clone())
        {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "remove_from_unlink_set: {} {} {}",
                    self.unlink_set_key.clone(),
                    e.to_string(),
                    nonce_hex
                );
                false
            }
        }
    }

    fn clear_state(&mut self) -> bool {
        match self.conn.del(self.session_map_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {} => {}", self.session_map_key, e);
                return false;
            }
        }
        match self.conn.del(self.unlink_set_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {} => {}", self.unlink_set_key, e);
                return false;
            }
        }
        match self.conn.del(self.spent_map_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {} => {}", self.spent_map_key, e);
                return false;
            }
        }
        match self.conn.del(self.rev_lock_map_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {} => {}", self.rev_lock_map_key, e);
                return false;
            }
        }
        match self.conn.del(self.nonce_to_session_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {} => {}", self.nonce_to_session_key, e);
                return false;
            }
        }
        match self.conn.del(self.nonce_mask_map_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {} => {}", self.nonce_mask_map_key, e);
                return false;
            }
        }
        match self.conn.del(self.masked_bytes_key.clone()) {
            Ok(c) => c,
            Err(e) => {
                println!("could not delete: {} => {}", self.masked_bytes_key, e);
                return false;
            }
        }
        return true;
    }

    // nonce -> session id
    fn update_nonce_to_session_id(
        &mut self,
        nonce_hex: &String,
        session_id_hex: &String,
    ) -> Result<bool, String> {
        match self.conn.hset_nx::<String, String, String, i32>(
            self.nonce_to_session_key.clone(),
            nonce_hex.clone(),
            session_id_hex.clone(),
        ) {
            Ok(s) => Ok(s != 0),
            Err(e) => return Err(e.to_string()),
        }
    }

    fn check_dup_nonce_to_session_id(
        &mut self,
        nonce_hex: &String,
        session_id_hex: &String,
    ) -> bool {
        match self
            .conn
            .hget::<String, String, String>(self.nonce_to_session_key.clone(), nonce_hex.clone())
        {
            Ok(s) => !s.eq_ignore_ascii_case(session_id_hex),
            Err(_) => return false,
        }
    }

    // nonce -> masks calls
    fn update_nonce_mask_map(
        &mut self,
        nonce_hex: &String,
        mask: [u8; 32],
        mask_r: [u8; 16],
    ) -> Result<bool, String> {
        let mut m = mask.to_vec();
        m.extend(mask_r.to_vec());
        match self.conn.hset::<String, String, String, i32>(
            self.nonce_mask_map_key.clone(),
            nonce_hex.clone(),
            hex::encode(&m),
        ) {
            Ok(s) => Ok(s != 0),
            Err(e) => return Err(e.to_string()),
        }
    }

    fn get_mask_map_from_nonce(
        &mut self,
        nonce_hex: &String,
    ) -> Result<([u8; 32], [u8; 16]), String> {
        let (mask, mask_r) = match self
            .conn
            .hget::<String, String, String>(self.nonce_mask_map_key.clone(), nonce_hex.clone())
        {
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
                }
                Err(e) => return Err(e.to_string()),
            },
            Err(e) => {
                return Err(format!(
                    "could not find mask for specified nonce: {}. reason: {}",
                    nonce_hex,
                    e.to_string()
                ))
            }
        };
        Ok((mask, mask_r))
    }

    // rev-lock -> masked inputs calls
    fn update_masked_mpc_inputs(
        &mut self,
        nonce_hex: &String,
        mask_bytes: MaskedMPCInputs,
    ) -> bool {
        let ser_mask_bytes = match serde_json::to_string(&mask_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        match self.conn.hset::<String, String, String, i32>(
            self.masked_bytes_key.clone(),
            nonce_hex.clone(),
            ser_mask_bytes,
        ) {
            Ok(c) => c != 0,
            Err(_) => false,
        }
    }

    fn get_masked_mpc_inputs(&mut self, nonce_hex: &String) -> Result<MaskedMPCInputs, String> {
        let ser_masked_bytes = match self
            .conn
            .hget::<String, String, String>(self.masked_bytes_key.clone(), nonce_hex.clone())
        {
            Ok(s) => s,
            Err(e) => {
                return Err(format!(
                    "get_masked_mpc_inputs: key({}) field({}) => {}",
                    &self.masked_bytes_key,
                    nonce_hex,
                    e.to_string()
                ))
            }
        };

        let t: MaskedMPCInputs = handle_error_util!(serde_json::from_str(&ser_masked_bytes));

        Ok(t)
    }
}

#[derive(Debug)]
pub struct HashMapDatabase {
    pub session_state_map: HashMap<String, SessionState>,
    pub nonce_session_map: HashMap<String, String>,
    pub nonce_mask_map: HashMap<String, PayMaskMap>,
    pub unlink_map: HashSet<String>,
    pub spent_lock_map: HashMap<String, String>,
    pub rev_lock_map: HashMap<String, String>,
    pub mask_mpc_bytes: HashMap<String, MaskedMPCInputs>,
}

impl StateDatabase for HashMapDatabase {
    fn new(_prefix: &'static str, _url: String) -> Result<Self, String> {
        Ok(HashMapDatabase {
            session_state_map: HashMap::new(),
            nonce_session_map: HashMap::new(),
            nonce_mask_map: HashMap::new(),
            unlink_map: HashSet::new(),
            spent_lock_map: HashMap::new(),
            rev_lock_map: HashMap::new(),
            mask_mpc_bytes: HashMap::new(),
        })
    }

    fn check_session_id(&mut self, session_id_hex: &String) -> Result<bool, String> {
        Ok(self.session_state_map.get(session_id_hex).is_some())
    }

    fn save_new_session_state(
        &mut self,
        session_id_hex: &String,
        session_state: &SessionState,
    ) -> bool {
        match self
            .session_state_map
            .insert(session_id_hex.clone(), session_state.clone())
        {
            Some(_) => true,
            None => false,
        }
    }

    fn update_session_state(
        &mut self,
        session_id_hex: &String,
        session_state: &SessionState,
    ) -> bool {
        return self.save_new_session_state(session_id_hex, session_state);
    }

    fn load_session_state(&mut self, session_id_hex: &String) -> Result<SessionState, String> {
        match self.session_state_map.get(session_id_hex) {
            Some(m) => Ok(m.clone()),
            None => {
                return Err(format!(
                    "could not find session state for session id: {}",
                    session_id_hex
                ))
            }
        }
    }

    fn clear_session_state(&mut self, session_id_hex: &String) -> bool {
        self.session_state_map.remove(session_id_hex);
        return true;
    }

    fn update_spent_map(&mut self, nonce: &String, rev_lock: &String) -> Result<bool, String> {
        match self.spent_lock_map.insert(nonce.clone(), rev_lock.clone()) {
            Some(c) => c,
            None => return Err(format!("could not update spent_map")),
        };
        Ok(true)
    }

    fn check_spent_map(&mut self, nonce: &String) -> bool {
        return self.spent_lock_map.get(nonce).is_some();
    }

    fn update_rev_lock_map(
        &mut self,
        rev_lock_hex: &String,
        rev_secret_hex: &String,
    ) -> Result<bool, String> {
        match self
            .spent_lock_map
            .insert(rev_lock_hex.clone(), rev_secret_hex.clone())
        {
            Some(c) => c,
            None => return Err(format!("could not update spent_map")),
        };
        Ok(true)
    }

    fn check_rev_lock_map(&mut self, rev_lock_hex: &String) -> bool {
        return self.rev_lock_map.get(rev_lock_hex).is_some();
    }

    fn get_rev_secret(&mut self, rev_lock_hex: &String) -> Result<String, String> {
        match self.rev_lock_map.get(rev_lock_hex) {
            Some(c) => Ok(c.clone()),
            None => return Err(format!("could not find rev_lock: {}", rev_lock_hex)),
        }
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

    fn remove_from_unlink_set(&mut self, nonce: &String) -> bool {
        if self.unlink_map.contains(nonce) {
            self.unlink_map.remove(nonce);
        }
        return true;
    }

    fn clear_state(&mut self) -> bool {
        self.session_state_map.clear();
        self.unlink_map.clear();
        self.spent_lock_map.clear();
        self.rev_lock_map.clear();
        self.nonce_session_map.clear();
        self.nonce_mask_map.clear();
        self.mask_mpc_bytes.clear();
        return true;
    }

    fn check_dup_nonce_to_session_id(
        &mut self,
        nonce_hex: &String,
        session_id_hex: &String,
    ) -> bool {
        match self.nonce_session_map.get(nonce_hex) {
            Some(s) => !s.eq_ignore_ascii_case(session_id_hex),
            _ => return false,
        }
    }

    fn update_nonce_to_session_id(
        &mut self,
        nonce_hex: &String,
        session_id_hex: &String,
    ) -> Result<bool, String> {
        self.nonce_session_map
            .insert(nonce_hex.clone(), session_id_hex.clone());
        Ok(true)
    }

    fn update_nonce_mask_map(
        &mut self,
        nonce_hex: &String,
        mask: [u8; 32],
        mask_r: [u8; 16],
    ) -> Result<bool, String> {
        let pay_mask_map = PayMaskMap {
            mask: FixedSizeArray32(mask),
            r: FixedSizeArray16(mask_r),
        };
        self.nonce_mask_map.insert(nonce_hex.clone(), pay_mask_map);
        Ok(true)
    }

    fn get_mask_map_from_nonce(
        &mut self,
        nonce_hex: &String,
    ) -> Result<([u8; 32], [u8; 16]), String> {
        match self.nonce_mask_map.get(nonce_hex) {
            Some(p) => Ok((p.mask.0, p.r.0)),
            None => {
                return Err(format!(
                    "could not find pay mask for specified nonce: {}",
                    nonce_hex
                ))
            }
        }
    }

    fn update_masked_mpc_inputs(
        &mut self,
        nonce_hex: &String,
        mask_bytes: MaskedMPCInputs,
    ) -> bool {
        match self.mask_mpc_bytes.insert(nonce_hex.clone(), mask_bytes) {
            Some(_) => true,
            None => false,
        }
    }

    fn get_masked_mpc_inputs(&mut self, nonce_hex: &String) -> Result<MaskedMPCInputs, String> {
        match self.mask_mpc_bytes.get(nonce_hex) {
            Some(m) => Ok(m.clone()),
            None => {
                return Err(format!(
                    "could not find masked mpc inputs for specified nonce: {}",
                    nonce_hex
                ))
            }
        }
    }
}

pub fn get_file_from_db(
    conn: &mut redis::Connection,
    key: &String,
    field_name: &String,
) -> Result<String, String> {
    match conn.hget::<String, String, String>(key.clone(), field_name.clone()) {
        Ok(s) => Ok(s),
        Err(e) => return Err(e.to_string()),
    }
}

pub fn store_file_in_db(
    conn: &mut redis::Connection,
    key: &String,
    field_name: &String,
    json_blob: &String,
) -> Result<bool, String> {
    match conn.hset::<String, String, String, i32>(
        key.clone(),
        field_name.clone(),
        json_blob.clone(),
    ) {
        Ok(s) => Ok(s != 0),
        Err(e) => return Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use util::hash_to_slice;

    #[test]
    fn test_redis_unlink_set() {
        let db_url = "redis://127.0.0.1/".to_string();
        let mut db = RedisDatabase::new("test", db_url).unwrap();
        db.clear_state();

        let key1 = "key1";
        let a = hex::encode([0u8; 32]);
        let _ = db
            .conn
            .set::<String, String, String>(key1.to_string(), a.clone());

        let orig_a: String = db.conn.get(key1.to_string()).unwrap();

        assert_eq!(a, orig_a);

        let b = hex::encode([1u8; 32]);
        let c = hex::encode([2u8; 32]);
        let d = hex::encode([3u8; 32]);

        db.update_unlink_set(&b).unwrap();
        db.update_unlink_set(&c).unwrap();
        db.update_unlink_set(&d).unwrap();

        let hash_set1: HashSet<String> = db.get_unlink_set().unwrap();
        println!("Unlink HashSet: ");
        for i in &hash_set1 {
            println!("{}", i);
        }

        let e = hex::encode([2u8; 32]);
        let f = hex::encode([4u8; 32]);

        let is_in_set = db.is_member_unlink_set(&e);
        assert!(is_in_set);
        // println!("In Set: {} => {}", e, is_in_set);

        let is_in_set = db.is_member_unlink_set(&f);
        assert!(!is_in_set);
        // println!("In Set: {} => {}", f, is_in_set);
    }

    #[test]
    fn test_redis_spent_map() {
        let db_url = "redis://127.0.0.1/".to_string();
        let mut db = RedisDatabase::new("test", db_url).unwrap();
        db.clear_state();

        let nonce1 = hex::encode([2u8; 16]);
        let nonce2 = hex::encode([5u8; 16]);
        let rev_lock = hex::encode([4u8; 32]);

        match db.update_spent_map(&nonce1, &rev_lock) {
            Ok(_) => (),
            Err(e) => println!("ERROR update_spent_map: {}", e),
        }
        let is_spent1 = db.check_spent_map(&nonce1);
        assert!(is_spent1);
        println!("Is spent 1: {} => {}", nonce1, is_spent1);

        let is_spent2 = db.check_spent_map(&nonce2);
        assert!(!is_spent2);
        println!("Is spent 2: {} => {}", nonce2, is_spent2);
    }

    #[test]
    fn test_redis_rev_lock_map() {
        let rng = &mut rand::thread_rng();
        let db_url = "redis://127.0.0.1/".to_string();
        let mut db = RedisDatabase::new("test", db_url).unwrap();
        db.clear_state();

        let mut rev_sec = [0u8; 32];
        rng.fill_bytes(&mut rev_sec);
        let rev_lock = hash_to_slice(&rev_sec.to_vec());

        let rev_sec_hex = hex::encode(&rev_sec.to_vec());
        let rev_lock_hex = hex::encode(&rev_lock);

        match db.update_rev_lock_map(&rev_lock_hex, &rev_sec_hex) {
            Ok(n) => println!("rev lock map update status: {}", n),
            Err(e) => println!("ERROR: failed to update - {}", e),
        };

        // let's check that rev_lock exists in the database
        assert!(db.check_rev_lock_map(&rev_lock_hex));

        // let's check that we can retrieve the original secret
        let orig_rev_sec = match db.get_rev_secret(&rev_lock_hex) {
            Ok(n) => n,
            Err(e) => panic!(format!("Could not retrieve rev secret from DB: {}", e)),
        };

        assert_eq!(orig_rev_sec, rev_sec_hex);
        println!("Orig rev secret: {}", rev_sec_hex);

        let bad_rev_lock = hex::encode([1u8; 32]);

        let bad_rev_sec = db.get_rev_secret(&bad_rev_lock);
        assert!(bad_rev_sec.is_err());
    }

    #[test]
    fn test_redis_nonce_mask_map() {
        let db_url = "redis://127.0.0.1/".to_string();
        let mut db = RedisDatabase::new("test", db_url).unwrap();
        db.clear_state();

        let nonce_hex = hex::encode([2u8; 16]);
        let mask = [3u8; 32];
        let mask_r = [4u8; 16];

        let result = db.update_nonce_mask_map(&nonce_hex, mask, mask_r);
        assert!(result.is_ok());

        let (orig_mask, orig_mask_r) = db.get_mask_map_from_nonce(&nonce_hex).unwrap();
        assert_eq!(mask, orig_mask);
        assert_eq!(mask_r, orig_mask_r);
    }

    #[test]
    fn test_redis_masked_mpc_input() {
        let db_url = "redis://127.0.0.1/".to_string();
        let mut db = RedisDatabase::new("test", db_url).unwrap();
        db.clear_state();

        let nonce_hex = hex::encode([0u8; 16]);
        let mask_bytes = MaskedMPCInputs {
            pt_mask: FixedSizeArray32([1u8; 32]),
            pt_mask_r: FixedSizeArray16([2u8; 16]),
            escrow_mask: FixedSizeArray32([3u8; 32]),
            merch_mask: FixedSizeArray32([4u8; 32]),
            r_escrow_sig: FixedSizeArray32([5u8; 32]),
            r_merch_sig: FixedSizeArray32([6u8; 32]),
        };
        let result = db.update_masked_mpc_inputs(&nonce_hex, mask_bytes);
        assert!(result);

        let mask_bytes_result = db.get_masked_mpc_inputs(&nonce_hex);
        assert!(mask_bytes_result.is_ok());

        let rec_mask_bytes = mask_bytes_result.unwrap();
        assert_eq!(mask_bytes, rec_mask_bytes);
    }

    #[test]
    fn test_redis_session_state() {
        let db_url = "redis://127.0.0.1/".to_string();
        let mut db = RedisDatabase::new("test", db_url).unwrap();
        db.clear_state();

        let session_id = hex::encode([1u8; 16]);
        let nonce = [2u8; 16];
        let amount = 10000;
        let rev_lock_com = hash_to_slice(&[1u8; 32].to_vec());

        let result = db.check_session_id(&session_id).unwrap();
        assert!(!result);

        let mut session_state = SessionState {
            nonce: FixedSizeArray16(nonce),
            rev_lock_com: FixedSizeArray32(rev_lock_com),
            amount: amount,
            status: PaymentStatus::Prepare,
        };

        let result = db.save_new_session_state(&session_id, &session_state);
        assert!(result);

        let session_state_result = db.load_session_state(&session_id);
        assert!(session_state_result.is_ok());

        let rec_session_state = session_state_result.unwrap();
        assert_eq!(session_state, rec_session_state);

        session_state.status = PaymentStatus::Error; // change error status
        let result = db.update_session_state(&session_id, &session_state);
        assert!(result);

        // check for existing session
        let result = db.check_session_id(&session_id).unwrap();
        assert!(result);

        let bad_session_id = hex::encode([2u8; 16]);
        let result = db.check_session_id(&bad_session_id).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_redis_duplicate_nonce_to_session_ids() {
        let db_url = "redis://127.0.0.1/".to_string();
        let mut db = RedisDatabase::new("test", db_url).unwrap();
        db.clear_state();

        let session_id1 = hex::encode([1u8; 16]);
        let session_id2 = hex::encode([2u8; 16]);

        let nonce = hex::encode([3u8; 16]);

        let result = db.check_dup_nonce_to_session_id(&nonce, &session_id1);
        assert!(!result); // should be false, no existing entry for nonce -> session id

        // write the session id -> nonce to the DB
        let result = db.update_nonce_to_session_id(&nonce, &session_id1);
        assert!(result.is_ok());

        let result = db.check_dup_nonce_to_session_id(&nonce, &session_id1);
        assert!(!result); // should be false, there's the same session id with this nonce

        let result = db.check_dup_nonce_to_session_id(&nonce, &session_id2);
        assert!(result); // should be true, there's a different existing session id with same nonce
    }
}
