#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens.h"
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
  Integer nonce[3];
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
  Integer balance_cust;
  Integer balance_merch;
  Txid_d txid_merch;
  Txid_d txid_escrow;
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

HMACKey_d distribute_HMACKey(HMACKey_l key, int party);
HMACKey_l localize_HMACKey(HMACKey_d key);

RevLock_d distribute_RevLock(RevLock_l revlock, int party);
RevLock_l localize_RevLock(RevLock_d revlock);

PayToken_d distribute_PayToken(PayToken_l paytoken, int party);
PayToken_l localize_PayToken(PayToken_d paytoken);

Nonce_d distribute_Nonce(Nonce_l nonce, int party);
Nonce_l localize_Nonce(Nonce_d nonce);

Txid_d distribute_Txid(Txid_l txid, int party);
Txid_l localize_Txid(Txid_d txid);

State_d distribute_State(State_l state, int party);
State_l localize_State(State_d state);

HMACKeyCommitment_d distribute_HMACKeyCommitment(HMACKeyCommitment_l commitment, int party);
HMACKeyCommitment_l localize_HMACKeyCommitment(HMACKeyCommitment_d commitment);

MaskCommitment_d distribute_MaskCommitment(MaskCommitment_l commitment, int party);
MaskCommitment_l localize_MaskCommitment(MaskCommitment_d commitment);

Mask_d distribute_Mask(Mask_l mask, int party);
Mask_l localize_Mask(Mask_d mask);

EcdsaPartialSig_d distribute_EcdsaPartialSig(EcdsaPartialSig_l ecdsapartialsig, int party=MERCH);
EcdsaPartialSig_l localize_EcdsaPartialSig(EcdsaPartialSig_d ecdsapartialsig);
// easy initialization of ecdsapartialsig
void fillEcdsaPartialSig_l(EcdsaPartialSig_l *eps, string r, string kinv);

/***************************** THIS FROM MARCELLA BEFORE THE GREAT RE-TYPING ************************/

Integer makeInteger(bool *bits, int len, int intlen, int party);

/* TODO: Fix types for all of these */

/* issue tokens
 * parent function; implements Protocol Pi_{ IssueTokens }
 * as described in bolt.pdf
 */
void issue_tokens(
  State_l old_state_l,
  State_l new_state_l,
  int32_t epsilon_l,
  HMACKeyCommitment_l hmac_key_commitment_l,
  HMACKey_l hmac_key_l,
  PayToken_l old_paytoken_l,
  Mask_l paytoken_mask_l,
  MaskCommitment_l paytoken_mask_commitment_l,
  Mask_l merch_mask_l,
  MaskCommitment_l merch_mask_commitment_l,
  Mask_l escrow_mask_l,
  MaskCommitment_l escrow_mask_commitment_l,
  EcdsaPartialSig_l sig1, 
  bool close_tx_escrow[1024],
  EcdsaPartialSig_l sig2, 
  bool close_tx_merch[1024]
  );

/* SIGNATURE SCHEME
 * for the pay token. We haven't decided which one to use.
 * Also haven't finalized representation for tokens.
 */
// void sign_token();
PayToken_d sign_token(State_d state, HMACKey_d key);
// Bit verify_token_sig();
Bit verify_token_sig(HMACKeyCommitment_d commitment, HMACKey_d opening, State_d old_state, PayToken_d old_paytoken);


/* checks that the wallets are appropriately updated
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
Bit compare_wallets(State_d old_state_d, State_d new_state_d, Integer epsilon_d);

/* opens and verifies commitment to a wallet
 * e.g. checks that com == commit(w;t)
 * where commit is a SHA256 commitment scheme
 * 
 * \param[in] com   : commitment to new wallet object using a SHA256 commitment
 * \param[in] w     : wallet object
 * \param[in] t     : commitment randomness (TYPISSUE)
 *
 * \return b 	: success bit
 */
Bit open_commitment();


Bit verify_mask_commitment(Mask_d mask, MaskCommitment_d maskcommitment);


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
Bit validate_transactions(State_d new_state_d, TxSerialized_d close_tx_escrow_d, TxSerialized_d close_tx_merch_d);

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
Bit mask_paytoken(Integer paytoken[8], Mask_d mask, MaskCommitment_d maskcommitment);

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
Bit mask_closemerchtoken(Integer token[8], Mask_d mask, MaskCommitment_d maskcommitment);
Bit mask_closeescrowtoken(Integer token[8], Mask_d mask, MaskCommitment_d maskcommitment);


