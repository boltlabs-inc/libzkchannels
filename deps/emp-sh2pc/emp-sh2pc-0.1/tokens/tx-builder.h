#pragma once
#include "tokens-misc.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include "sha256.h"
#include "constants.h"

using namespace emp;

void validate_transactions(State_d new_state_d,
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d, PublicKeyHash_d cust_child_publickey_hash_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, BitcoinPublicKey_d merch_payout_pub_key_d,
  PublicKeyHash_d merch_publickey_hash_d, Integer escrow_digest[8], Integer merch_digest[8], Balance_d fee_cc_d, Integer k[64], Integer H[8], Balance_d val_cpfp_d, Integer self_delay_d, Constants constants);