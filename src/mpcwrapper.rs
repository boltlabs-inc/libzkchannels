use libc::{c_int};

#[repr(C)]
struct c_wallet {
    channelId: *mut c_pubkey,
    wpk: *mut c_pubkey,
    bc: c_int,
    bm: c_int,
    txidM: *const bool,
    txidE: *const bool,
}

#[repr(C)]
struct c_commit {
    c: *const bool,
    params: *const *const bool,
}

#[repr(C)]
struct c_pubkey {
    pk: *const bool,
}

#[repr(C)]
struct c_privkey {
    sk: *const bool,
}

extern {
    fn build_masked_tokens_cust(pkM: *mut c_pubkey, amount: c_int, com_new: *mut c_commit, wpk_old: *mut c_pubkey, port: c_int,
                                ip_addr: c_int, w_new: *mut c_wallet, w_old: *mut c_wallet, t: c_int, pt_old: c_int,
                                close_tx_escrow: *const bool, //[bool; 1024],
                                close_tx_merch: *const bool, //[bool; 1024],
                                ct_masked: * c_int, pt_masked: * c_int);
    fn build_masked_tokens_merch(pkM: *mut c_pubkey, amount: c_int, com_new: *mut c_commit, wpk_old: *mut c_pubkey,
                                 port: c_int, ip_addr: c_int, skM: *mut c_privkey);
}

pub fn build_masked_tokens_cust() {
    unsafe { build_masked_tokens_cust()}
}