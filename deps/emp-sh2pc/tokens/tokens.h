#pragma once 

#include "tokens-misc.h"
using namespace std;

//struct EcdsaPartialSig_l {
//  char* r;
//  char* k_inv;
//};

/*
 * describes an API for calling MPC functions 
 * 
 * to be integrated into Rust implementation
 *
 * This describes the basic high-level inputs we expect from the protocol.
 * There is some additional precomputation that will happen in the clear,
 * plus mangling of pretty Rust/C++ types to match the format used by
 * the MPC frameworks
 *
 * TYPISSUE - There are some weird types here, as well. Everything has a type,
 * but some of them are clearly incorrect 
 * (e.g.a public key will not fit into a normal 32-bit integer). 
 * but I don't know what representation they -will- take.
 * I've marked such parameters with TYPISSUE
 *
 * Comments are sort of in doxygen style.
 */

/* HMAC Key structure.
 * HMAC Keys are the length of the block-size of the underlying hash functions
 * SHA256 has a block size of 512 bits, so we need 16 integers to represent the whole thing
 */
struct HMACKey {
  int key[16];
};

/* A Commitment to an HMAC Key
 * We are using hash based commitments, so this is really just the output of a SHA256 invocation
 */
struct HMACKeyCommitment {
  int commitment[8];
};

/* The opening to a commitment to an HMAC key
 * To open a hash based commitment, we need an actual key and potentially randomness
 * GABE: I'm throwing randomness in here for now, but we can rip it out?
 */
struct HMACKeyCommitmnetOpening {
  struct HMACKey* key;
  int randomness[8];
};

/* This is a pay token
 * Is is an HMAC computed on the state 
 * The output of HMAC is the underlying block size.  In this case 256 bits
 */
struct PayToken {
  int paytoken[8];
};


/* ECDSA public key type 
 * \param pubkey    : a public key. TYPISSUE - probably not an integer */
struct PubKey{
  char* pubkey;
};

/* Revocation lock - TYPISSUE: not sure what type this is yet.
 * Tentatively sized to use a hash (SHA256-based) commitment scheme.
 * \param rl 	: a revocation lock.
 */
struct RevLock {
  char* revlock;
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
struct State {
  struct PubKey* pkC;
  struct RevLock* rl;
  int balance_cust;
  int balance_merch;
  char *txid_merch[256];
  char *txid_escrow[256];
};


/* customer's token generation function
 *
 * runs MPC to compute masked tokens (close- and pay-).
 * blocks until computation is finished.
 *
 * Pads close_tx_escrow and close_tx_merch to exactly 1024 bits according to the SHA256 spec.
 *
 * option: port could be fixed in advance (not passed in here)
 * 
 * \param[in] pkM       : (shared) merchant public key
 * \param[in] amount    : (shared) transaction amount 
 * \param[in] com_new   : (shared) commitment to new state object using a SHA256 commitment
 * \param[in] rl_old   	: (shared) previous state revocation lock 
 * \param[in] port      : (shared) communication port
 * \param[in] ip_addr   : (shared) merchant's IP address
 *
 * \param[in] w_new     : (private) new state object
 * \param[in] w_old     : (private) previous state object
 * \param[in] t_new     : (private) commitment randomness (TYPISSUE - size?)
 * \param[in] pt_old    : (private) previous pay token (tentative: ECDSA signature)
 * \param[in] close_tx_escrow   : (private) bits of new close transaction (spends from escrow). no more than 1024 bits.
 * \param[in] close_tx_merch    : (private) bits of new close transaction (spends from merchant close transaction). No more than 1024 bits.
 * 
 * \param[out] ct_masked    : masked close token (ECDSA signature) (TYPISSUE - representation (serialized)?)
 * \param[out] pt_masked    : masked pay token (tentative: ECDSA signature) (TYPISSUE - representation (serialized)?)
 *
 */
void build_masked_tokens_cust(
  struct PubKey* pkM,
  char amount[64],
  char *com_new,
  struct RevLock* rl_old,
  int port,
  char* ip_addr,

  struct State* w_new,
  struct State* w_old,
  char *t,
  char pt_old[256],
  char close_tx_escrow[1024],
  char close_tx_merch[1024],

  char ct_masked[256],
  char pt_masked[256]
);


/* merchant's close-token computation function 
 *
 * Pre-computes some parameters, then runs MPC to compute masked tokens (close- and pay-)
 * blocks until computation is finished.
 *
 * Generates a partial ECDSA signature:
 *   1. Sample: k <- Z_q, k
 *   2. Compute random curve point: (r_x, r_y) = k * G
 *   3. Compute secret curve point: spt = (r_x * skM) mod q
 *   4. Compute inverse: k_inv = k^(-1)
 * Then calls MPC with shared inputs, plus k_inv, spt.
 *
 * option: port could be fixed in advance (not passed in here)
 *
 * \param[in] pkM       : (shared) merchant public key
 * \param[in] amount    : (shared) transaction amount 
 * \param[in] com_new   : (shared) commitment to new state object
 * \param[in] rl_old 	: (shared) previous state revocation lock
 * \param[in] port      : (shared) communication port
 * \param[in] ip_addr   : (shared) customer's IP address
 *
 * \param[in] close_mask: (private) A random mask for the close token 
 * \param[in] pay_mask  : (private) A random mask for the pay token 
 * \param[in] sig1      : (private) A partial ECDSA signature
 * \param[in] sig2      : (private) A partial ECDSA signature
 * \param[in] sig3      : (private) A partial ECDSA signature
 *
 * Merchant does not receive output.
 *
 */
void build_masked_tokens_merch(
  struct PubKey* pkM,
  char amount[64],
  char *com_new,
  struct RevLock* rl_old,
  int port,
  char* ip_addr,

  char close_mask[256],
  char pay_mask[256],
  struct EcdsaPartialSig_l* sig1,
  struct EcdsaPartialSig_l* sig2,
  struct EcdsaPartialSig_l* sig3
);


