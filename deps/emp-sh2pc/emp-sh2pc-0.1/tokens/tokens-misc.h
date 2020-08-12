#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens.h"
#include "constants.h"
using namespace emp;

#define MERCH ALICE
#define CUST BOB

/*********** We give all the types in pairs. _l structures are local var and _d are distributed**************/

/* HMAC Key structure.
 * HMAC Keys are the length of the block-size of the underlying hash functions
 * SHA256 has a block size of 512 bits, so we need 16 integers to represent the whole thing
 */
typedef struct HMACKey_l HMACKey_l;
struct HMACKey_d {
  Integer key[16];
};

/* Revocation lock - TYPISSUE: not sure what type this is yet.
 * Tentatively sized to use a hash (SHA256-based) commitment scheme.
 * \param rl 	: a revocation lock.
 */
typedef struct RevLock_l RevLock_l;
struct RevLock_d {
  Integer revlock[8];
};

typedef struct RevLockCommitment_l RevLockCommitment_l;
struct RevLockCommitment_d {
  Integer commitment[8];
};

/* This is a pay token
 * Is is an HMAC computed on the state 
 * The output of HMAC is the underlying block size.  In this case 256 bits
 */
typedef struct PayToken_l PayToken_l;
struct PayToken_d {
  Integer paytoken[8];
};

struct ClosingTokenMerch_l {
  uint32_t token[8];
};

struct ClosingTokenMerch_d {
  Integer token[8];
};

struct ClosingTokenEscrow_l {
  uint32_t token[8];
};

struct ClosingTokenEscrow_d {
  Integer token[8];
};

/* This is a nonce.  Its used to prevent double spends
 * RIGHT NOW THIS THING IS 96 BITS.  WE MAY WANT TO INCREASE ITS LENGTH IN THE FUTURE!!!
 */
typedef struct Nonce_l Nonce_l;
struct Nonce_d {
  Integer nonce[4];
};

struct TxSerialized_l {
  uint32_t tx[32];
};

struct TxSerialized_d {
  Integer tx[32];
};

typedef struct Txid_l Txid_l;
struct Txid_d {
  Integer txid[8];
};

struct BitcoinPublicKey_d {
  Integer key[9]; // last byte padded with zeros.
};

struct PublicKeyHash_d {
  Integer hash[5];
};

struct Balance_d {
  Integer balance[2];
};

struct CommitmentRandomness_d {
  Integer randomness[4];
};

/* This is the second part of an ecdsa signature
 * In this case 256 bits
 */
struct EcdsaSig_d {
  Integer sig[8];
};


/* state type
 *
 * \param pkC           : customer public key 
 * \param rl 			: revocation lock for 
 * \param balance_cust  : customer balance 
 * \param balance_merch : merchant balance
 * \param txid_merch    : transaction ID for merchant close transaction (bits, formatted as they appear in the 'source' field of a transaction that spends it) 
 * \param txid_escrow   : transaction ID for escrow transaction (ditto on format)
 */
typedef struct State_l State_l;

struct State_d {
  Nonce_d nonce;
  RevLock_d rl;
  Balance_d balance_cust;
  Balance_d balance_merch;
  Txid_d txid_merch;
  Txid_d txid_escrow;
  Txid_d HashPrevOuts_merch;
  Txid_d HashPrevOuts_escrow;
  Balance_d min_fee;
  Balance_d max_fee;
  Balance_d fee_mc;
};

/* Commitment stuff
 *
 * Everything we are doing is a sha256 hash based commitment
 */
typedef struct HMACKeyCommitment_l HMACKeyCommitment_l;
struct HMACKeyCommitment_d {
  Integer commitment[8];
};

typedef struct Mask_l Mask_l;
struct Mask_d {
  Integer mask[8];
};

typedef struct MaskCommitment_l MaskCommitment_l;
struct MaskCommitment_d {
  Integer commitment[8];
};


/* Partial ECDSA signature
 * This is a partial signature. It is based on a raondomly chosen k, message x, public key G, and public modulus q. Let (rx, ry) = kG.
 * \param r     : r = rx*x mod q. Represented as a decimal string. (256 bits)
 * \param k_inv : k_inv = k^-1. Represented as a decimal string. (256 bits)
 */
typedef struct EcdsaPartialSig_l EcdsaPartialSig_l;
struct EcdsaPartialSig_d {
  Integer r;
  Integer k_inv;
};


/********************* Casting functions  **********************/

HMACKey_d distribute_HMACKey(HMACKey_l key, const int party);
HMACKey_l localize_HMACKey(HMACKey_d key, const int party);

RevLock_d distribute_RevLock(RevLock_l revlock, const int party);
RevLock_l localize_RevLock(RevLock_d revlock, const int party);

RevLockCommitment_d distribute_RevLockCommitment(RevLockCommitment_l rlc, const int party);
RevLockCommitment_l localize_RevLockCommitment(RevLockCommitment_d rlc, const int party);

PayToken_d distribute_PayToken(PayToken_l paytoken, const int party);
void localize_PayToken(PayToken_l *target, PayToken_d paytoken, const int party=CUST);

Nonce_d distribute_Nonce(Nonce_l nonce, const int party);
Nonce_l localize_Nonce(Nonce_d nonce, const int party);

Txid_d distribute_Txid(Txid_l txid, const int party);
Txid_l localize_Txid(Txid_d txid, const int party);

State_d distribute_State(State_l state, const int party);
State_l localize_State(State_d state, const int party);

HMACKeyCommitment_d distribute_HMACKeyCommitment(HMACKeyCommitment_l commitment, const int party);
HMACKeyCommitment_l localize_HMACKeyCommitment(HMACKeyCommitment_d commitment, const int party);

MaskCommitment_d distribute_MaskCommitment(MaskCommitment_l commitment, const int party);
MaskCommitment_l localize_MaskCommitment(MaskCommitment_d commitment, const int party);

PublicKeyHash_d distribute_PublicKeyHash(PublicKeyHash_l hash, const int party);
PublicKeyHash_l localize_PublicKeyHash(PublicKeyHash_d hash, const int party);

Mask_d distribute_Mask(Mask_l mask, const int party);
Mask_l localize_Mask(Mask_d mask, const int party);

Balance_d distribute_Balance(Balance_l balance, const int party);
Balance_l localize_Balance(Balance_d balance, const int party);

Balance_d convert_to_little_endian(Balance_d big_endian_balance, Constants constants);
Balance_d convert_to_big_endian(Balance_d little_endian_balance, Constants constants);
Integer switch_endianness(Integer big_endian_int, Constants constants);

CommitmentRandomness_d distribute_CommitmentRandomness(CommitmentRandomness_l rand, const int party);
CommitmentRandomness_l localize_CommitmentRandomness(CommitmentRandomness_d rand, const int party);

Integer combine_balance(Balance_d balance);
Balance_d split_integer_to_balance(Integer integer, Integer mask);

BitcoinPublicKey_d distribute_BitcoinPublicKey(BitcoinPublicKey_l pubKey, const int party);
BitcoinPublicKey_l localize_BitcoinPublicKey(BitcoinPublicKey_d pubKey, const int party);

EcdsaPartialSig_d distribute_EcdsaPartialSig(EcdsaPartialSig_l ecdsapartialsig, const int party=MERCH);
EcdsaPartialSig_l localize_EcdsaPartialSig(EcdsaPartialSig_d ecdsapartialsig, const int party);

EcdsaSig_d distribute_EcdsaSig(EcdsaSig_l EcdsaSig, const int party=MERCH);
void localize_EcdsaSig(EcdsaSig_l *target, EcdsaSig_d EcdsaSig, const int party=CUST);

// easy initialization of ecdsapartialsig
void fillEcdsaPartialSig_l(EcdsaPartialSig_l *eps, string r, string kinv);


/*****  Helpful for the final fail case editing *******/

Integer handle_error_case(Integer data, Bit mask);


/****** Helpful for debugging ***********/

Integer compose_buffer(Integer buffer[16]);
void dump_buffer(string label, Integer buffer[16]);
void dump_hash(string label, Integer buffer[8]);

void dump_bit(string label, Bit b);

/***************************** THIS FROM MARCELLA BEFORE THE GREAT RE-TYPING ************************/

/* TODO: Fix types for all of these */

/* issue tokens
 * parent function; implements Protocol Pi_{ IssueTokens }
 * as described in bolt.pdf
 */
void issue_tokens(
/* CUSTOMER INPUTS */
  State_l old_state_l,
  State_l new_state_l,
  PayToken_l old_paytoken_l,
  BitcoinPublicKey_l cust_escrow_pub_key_l,
  BitcoinPublicKey_l cust_payout_pub_key_l,
/* MERCHANT INPUTS */
  HMACKey_l hmac_key_l,
  Mask_l paytoken_mask_l,
  Mask_l merch_mask_l,
  Mask_l escrow_mask_l,
  EcdsaPartialSig_l sig1,
  EcdsaPartialSig_l sig2,
/* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  Balance_l epsilon_l,
  HMACKeyCommitment_l hmac_key_commitment_l,
  MaskCommitment_l paytoken_mask_commitment_l,
  RevLockCommitment_l rlc_l,
  Nonce_l nonce_l,
  BitcoinPublicKey_l merch_escrow_pub_key_l,
  BitcoinPublicKey_l merch_dispute_key_l, 
  BitcoinPublicKey_l merch_payout_pub_key_l,
  PublicKeyHash_l merch_publickey_hash_l,
/* OUTPUTS */
  PayToken_l* pt_return,
  EcdsaSig_l* ct_escrow,
  EcdsaSig_l* ct_merch
  );

/* SIGNATURE SCHEME
 * for the pay token. We haven't decided which one to use.
 * Also haven't finalized representation for tokens.
 */
// void sign_token();
PayToken_d sign_token(State_d state, HMACKey_d key,  Constants constants, Integer k[64], Integer H[8]);
// Bit verify_token_sig();
Bit verify_token_sig(HMACKeyCommitment_d commitment, CommitmentRandomness_d hmac_commitment_randomness_d, HMACKey_d opening, State_d old_state, PayToken_d old_paytoken, Constants constants, Integer k[64], Integer H[8]);


/* checks that the wallets are appropriately updated
 * TODO: update this documentation to describe rlc, nonce stuff
 * 0. old wallet ID matches publicly revealed wkpi --> TODO??
 * 1. wallet customer keys match
 * 2. escrow transactions match
 * 3. merchant-close transactions match
 * 4. balances are correctly updated by amt
 *  
 * \param[in] old_state_d 	: old wallet
 * \param[in] new_state_d   : new wallet
 * \param[in] epsilon_d     : transaction amount
 * \param[in] wpk_old 	: old wallet ID
 *
 * \return b 	: success bit
 */
Bit compare_states(State_d old_state_d, State_d new_state_d, RevLockCommitment_d rlc_d, CommitmentRandomness_d rl_rand_d, Nonce_d nonce_d, Balance_d epsilon_d, Balance_d fee_cc_d, Balance_d val_cpfp_d, Balance_d bal_min_cust_d, Balance_d bal_min_merch_d, Integer k[64], Integer H[8],  Constants constants);

Bit verify_revlock_commitment(RevLock_d rl_d, RevLockCommitment_d rlc_d, CommitmentRandomness_d rl_rand_d, Integer k[64], Integer H[8], Constants constants);

Bit verify_mask_commitment(Mask_d mask, MaskCommitment_d maskcommitment, CommitmentRandomness_d mask_commitment_randomness_d, Integer k[64], Integer H[8], Constants constants);


/* validates closing transactions against a wallet
 * for each transaction:
 * 0. check that balances are correct
 * 1. check that wallet key is integrated correctly
 * 2. check that source is correct
 *    for close_tx_merch, source is txid_merch
 *    for close_tx_escrow, source is txid_escrow
 * 
 * \param[in] w     			: wallet object
 * \param[in] close_tx_escrow   : (private) bits of new close transaction (spends from escrow). no more than 1024 bits.
 * \param[in] close_tx_merch    : (private) bits of new close transaction (spends from merchant close transaction). No more than 1024 bits.
 *
 * \return b 	: success bit
 */
void validate_transactions(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d, PublicKeyHash_d cust_child_publickey_hash_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, BitcoinPublicKey_d merch_payout_pub_key_d, 
  PublicKeyHash_d merch_publickey_hash_d, Integer escrow_digest[8], Integer merch_digest[8], Balance_d fee_cc_d, Integer k[64], Integer H[8], Balance_d val_cfcp_d, Constants constants);

/* applies a mask to a pay token
 * uses a one-time-pad scheme (just xors mask with token bits)
 * Also checks to make sure that the mask matches the commited to randomness
 * 
 * updates the token in-line
 *
 * \param[in] mask 	: A random mask 
 * \param[in] token : Sequence of bits representing a token
 *
 */
Bit mask_paytoken(Integer paytoken[8], Mask_d mask, MaskCommitment_d maskcommitment, CommitmentRandomness_d paytoken_mask_commitment_randomness_d, Integer k[64], Integer H[8], Constants constants);

/* applies a mask to a token
 * uses a one-time-pad scheme (just xors mask with token bits)
 * Also checks to make sure that the mask matches the commited to randomness
 *
 * updates the token in-line
 *
 * \param[in] mask  : A random mask 
 * \param[in] token : Sequence of bits representing a token
 *
 */
void mask_closetoken(Integer token[8], Mask_d mask);


void bigint_into_smallint_array(Integer target[8], Integer source, Integer fullF);

Bit compare_k_H(Integer k[64], Integer H[8], Integer k_merch[64], Integer H_merch[8]);
Bit compare_public_input(Balance_d epsilon_d, HMACKeyCommitment_d hmac_key_commitment_d, MaskCommitment_d paytoken_mask_commitment_d, RevLockCommitment_d rlc_d, Nonce_d nonce_d, Balance_d val_cpfp_d, Balance_d bal_min_cust_d, Balance_d bal_min_merch_d, Integer to_self_delay_d, BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, BitcoinPublicKey_d merch_payout_pub_key_d, PublicKeyHash_d merch_publickey_hash_d,
                                        Balance_d epsilon_d_merch, HMACKeyCommitment_d hmac_key_commitment_d_merch, MaskCommitment_d paytoken_mask_commitment_d_merch, RevLockCommitment_d rlc_d_merch, Nonce_d nonce_d_merch, Balance_d val_cpfp_d_merch, Balance_d bal_min_cust_d_merch, Balance_d bal_min_merch_d_merch, Integer to_self_delay_d_merch, BitcoinPublicKey_d merch_escrow_pub_key_d_merch, BitcoinPublicKey_d merch_dispute_key_d_merch, BitcoinPublicKey_d merch_payout_pub_key_d_merch, PublicKeyHash_d merch_publickey_hash_d_merch);