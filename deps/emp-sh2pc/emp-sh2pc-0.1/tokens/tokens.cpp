#include "tokens.h"
#include "tokens-misc.h"
#include "ecdsa.h"
#include "hmac.h"
#include "sha256.h"
#include "constants.h"
#include "tx-builder.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <memory>

#define MERCH ALICE
#define CUST BOB

using namespace emp;

void* get_netio_ptr(char *address, int port, int party) {
    char *address_ptr = (party == MERCH) ? nullptr : address;
    NetIO *io_ptr = new NetIO(address_ptr, port);
    return static_cast<void *>(io_ptr);
}

/* Returns a pointer to a UnixNetIO ptr */
void* get_unixnetio_ptr(char *socket_path, int party) {
    bool is_server = (party == MERCH) ? true : false;
    UnixNetIO *io_ptr = new UnixNetIO(socket_path, is_server);
    return static_cast<void *>(io_ptr);
}

void* get_gonetio_ptr(void *raw_stream_fd, int party) {
    bool is_server = (party == MERCH) ? true : false;
    GoNetIO *io_ptr = new GoNetIO(raw_stream_fd, is_server);
    return static_cast<void *>(io_ptr);
}

/* Returns a pointer to a LndNetIO ptr */
void* get_lndnetio_ptr(void* peer, cb_send send_cb, cb_receive receive_cb, int party) {
    bool is_server = (party == MERCH) ? true : false;
    LndNetIO *io_ptr = new LndNetIO(peer, send_cb, receive_cb, is_server);
    return static_cast<void *>(io_ptr);
}

void* load_circuit_file(const char *filename) {
  cout << "Loading circuit file for SH2PC: " << string(filename) << endl;
  setup_plain_prot(true, filename);
  return nullptr;
}

// TODO: add more meaningful fail / error states
// TODO: rename to update_state
void issue_tokens(
/* CUSTOMER INPUTS */
  State_l old_state_l,
  State_l new_state_l,
  Balance_l fee_cc,
  PayToken_l old_paytoken_l,
  BitcoinPublicKey_l cust_escrow_pub_key_l,
  BitcoinPublicKey_l cust_payout_pub_key_l,
  CommitmentRandomness_l revlock_commitment_randomness_l,
  PublicKeyHash_l cust_publickey_hash_l,
/* MERCHANT INPUTS */
  HMACKey_l hmac_key_l,
  Mask_l paytoken_mask_l,
  Mask_l merch_mask_l,
  Mask_l escrow_mask_l,
  EcdsaPartialSig_l sig1,
  EcdsaPartialSig_l sig2,
  CommitmentRandomness_l hmac_commitment_randomness_l,
  CommitmentRandomness_l paytoken_mask_commitment_randomness_l,

/* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  Balance_l epsilon_l,
  HMACKeyCommitment_l hmac_key_commitment_l,
  MaskCommitment_l paytoken_mask_commitment_l,
  RevLockCommitment_l rlc_l,
  Nonce_l nonce_l,
  Balance_l val_cpfp,
  Balance_l bal_min_cust,
  Balance_l bal_min_merch,
  uint16_t self_delay,
  BitcoinPublicKey_l merch_escrow_pub_key_l,
  BitcoinPublicKey_l merch_dispute_key_l,
  BitcoinPublicKey_l merch_payout_pub_key_l,
  PublicKeyHash_l merch_publickey_hash_l,
/* OUTPUTS */
  PayToken_l* pt_return,
  EcdsaSig_l* ct_escrow,
  EcdsaSig_l* ct_merch
  ) {
#if defined(DEBUG)
  cout << "issuing tokens" << endl;
#endif

  State_d old_state_d = distribute_State(old_state_l, CUST);
  State_d new_state_d = distribute_State(new_state_l, CUST);
  Balance_d fee_cc_d = distribute_Balance(fee_cc, CUST);
  PayToken_d old_paytoken_d = distribute_PayToken(old_paytoken_l, CUST);
  BitcoinPublicKey_d cust_escrow_pub_key_d = distribute_BitcoinPublicKey(cust_escrow_pub_key_l, CUST);
  BitcoinPublicKey_d cust_payout_pub_key_d = distribute_BitcoinPublicKey(cust_payout_pub_key_l, CUST);
  CommitmentRandomness_d revlock_commitment_randomness_d = distribute_CommitmentRandomness(revlock_commitment_randomness_l, CUST);
  PublicKeyHash_d cust_publickey_hash_d = distribute_PublicKeyHash(cust_publickey_hash_l, CUST);

  // PUBLIC values
  Balance_d epsilon_d = distribute_Balance(epsilon_l, CUST); // IVE BEEN TREATING THIS LIKE A 32 BIT VALUE, BUT ITS 64
  HMACKeyCommitment_d hmac_key_commitment_d = distribute_HMACKeyCommitment(hmac_key_commitment_l, CUST);
  MaskCommitment_d paytoken_mask_commitment_d = distribute_MaskCommitment(paytoken_mask_commitment_l, CUST);
  RevLockCommitment_d rlc_d = distribute_RevLockCommitment(rlc_l, CUST);
  Nonce_d nonce_d = distribute_Nonce(nonce_l, CUST);
  Balance_d val_cpfp_d = distribute_Balance(val_cpfp, CUST);
  Balance_d bal_min_cust_d = distribute_Balance(bal_min_cust, CUST);
  Balance_d bal_min_merch_d = distribute_Balance(bal_min_merch, CUST);
  Integer self_delay_d = Integer(16, self_delay, CUST);
  BitcoinPublicKey_d merch_escrow_pub_key_d = distribute_BitcoinPublicKey(merch_escrow_pub_key_l, CUST);
  BitcoinPublicKey_d merch_dispute_key_d = distribute_BitcoinPublicKey(merch_dispute_key_l, CUST);
  BitcoinPublicKey_d merch_payout_pub_key_d = distribute_BitcoinPublicKey(merch_payout_pub_key_l, CUST);
  PublicKeyHash_d merch_publickey_hash_d = distribute_PublicKeyHash(merch_publickey_hash_l, CUST);
  //Hardcoded values
  Constants constants = distribute_Constants(CUST);

  Integer k[64];
  Integer H[8];
  initSHA256(k, H, CUST);

  Q qs = distribute_Q(CUST);

  //MERCH input
  HMACKey_d hmac_key_d = distribute_HMACKey(hmac_key_l, MERCH);
  Mask_d paytoken_mask_d = distribute_Mask(paytoken_mask_l, MERCH);
  Mask_d merch_mask_d = distribute_Mask(merch_mask_l, MERCH);
  Mask_d escrow_mask_d = distribute_Mask(escrow_mask_l, MERCH);

  CommitmentRandomness_d hmac_commitment_randomness_d = distribute_CommitmentRandomness(hmac_commitment_randomness_l, MERCH);
  CommitmentRandomness_d paytoken_mask_commitment_randomness_d = distribute_CommitmentRandomness(paytoken_mask_commitment_randomness_l, MERCH);
  EcdsaPartialSig_d epsd1 = distribute_EcdsaPartialSig(sig1);
  EcdsaPartialSig_d epsd2 = distribute_EcdsaPartialSig(sig2);

  //PUBLIC values
  Balance_d epsilon_d_merch = distribute_Balance(epsilon_l, MERCH); // IVE BEEN TREATING THIS LIKE A 32 BIT VALUE, BUT ITS 64
  HMACKeyCommitment_d hmac_key_commitment_d_merch = distribute_HMACKeyCommitment(hmac_key_commitment_l, MERCH);
  MaskCommitment_d paytoken_mask_commitment_d_merch = distribute_MaskCommitment(paytoken_mask_commitment_l, MERCH);
  RevLockCommitment_d rlc_d_merch = distribute_RevLockCommitment(rlc_l, MERCH);
  Nonce_d nonce_d_merch = distribute_Nonce(nonce_l, MERCH);
  Balance_d val_cpfp_d_merch = distribute_Balance(val_cpfp, MERCH);
  Balance_d bal_min_cust_d_merch = distribute_Balance(bal_min_cust, MERCH);
  Balance_d bal_min_merch_d_merch = distribute_Balance(bal_min_merch, MERCH);
  Integer self_delay_d_merch = Integer(16, self_delay, MERCH);
  BitcoinPublicKey_d merch_escrow_pub_key_d_merch = distribute_BitcoinPublicKey(merch_escrow_pub_key_l, MERCH);
  BitcoinPublicKey_d merch_dispute_key_d_merch = distribute_BitcoinPublicKey(merch_dispute_key_l, MERCH);
  BitcoinPublicKey_d merch_payout_pub_key_d_merch = distribute_BitcoinPublicKey(merch_payout_pub_key_l, MERCH);
  PublicKeyHash_d merch_publickey_hash_d_merch = distribute_PublicKeyHash(merch_publickey_hash_l, MERCH);
  //Hardcoded values
  Constants constants_merch = distribute_Constants(MERCH);

  Integer k_merch[64];
  Integer H_merch[8];
  initSHA256(k_merch, H_merch, MERCH);

  Q qs_merch = distribute_Q(MERCH);

  Integer(1556, 0, MERCH); //Fix for different number of input wires between parties

  //Compare public inputs + constants to be the same between CUST and MERCH
  Bit error_signal(false);
  error_signal = error_signal | compare_public_input(epsilon_d, hmac_key_commitment_d, paytoken_mask_commitment_d, rlc_d, nonce_d, val_cpfp_d, bal_min_cust_d, bal_min_merch_d, self_delay_d, merch_escrow_pub_key_d, merch_dispute_key_d, merch_payout_pub_key_d, merch_publickey_hash_d,
                                    epsilon_d_merch, hmac_key_commitment_d_merch, paytoken_mask_commitment_d_merch, rlc_d_merch, nonce_d_merch, val_cpfp_d_merch, bal_min_cust_d_merch, bal_min_merch_d_merch, self_delay_d_merch, merch_escrow_pub_key_d_merch, merch_dispute_key_d_merch, merch_payout_pub_key_d_merch, merch_publickey_hash_d_merch);
  error_signal = error_signal | constants_not_equal(constants, constants_merch);
  error_signal = error_signal | q_not_equal(qs, qs_merch);
  error_signal = error_signal | compare_k_H(k, H, k_merch, H_merch);

  Integer zero = constants.zero;
  zero.resize(16, false);
  error_signal = error_signal | (self_delay_d == zero);
  error_signal = error_signal | (self_delay_d > constants.maxint16);
  if (self_delay <= 16) {
    self_delay_d.resize(8, false);
    self_delay_d = self_delay_d + constants.eighty;
  } else if (self_delay < 128) {
    Integer one = constants.one;
//    one = one << 24;
    one.resize(16, false);
    self_delay_d = one << 8 | self_delay_d;
    self_delay_d_merch = one << 8 | self_delay_d_merch;
  } else {
    Integer two = constants.two;
    self_delay_d = self_delay_d << 8 | self_delay_d >> 8;
    self_delay_d_merch = self_delay_d_merch << 8 | self_delay_d_merch >> 8;
    self_delay_d.resize(24, false);
    self_delay_d_merch.resize(24, false);
    two.resize(24, false);
    self_delay_d = two << 16 | self_delay_d;
    self_delay_d_merch = two << 16 | self_delay_d_merch;
  }

#if defined(DEBUG)
  cout << "distributed everything. verifying token sig" << endl;
#endif
// check old pay token
  error_signal = error_signal | verify_token_sig(hmac_key_commitment_d, hmac_commitment_randomness_d, hmac_key_d, old_state_d, old_paytoken_d, constants, k, H);

  // make sure old/new state are well-formed
#if defined(DEBUG)
  cout << "comparing old to new state" << endl;
#endif
  error_signal = (error_signal | compare_states(old_state_d, new_state_d, rlc_d, revlock_commitment_randomness_d, nonce_d, epsilon_d, fee_cc_d, val_cpfp_d, bal_min_cust_d, bal_min_merch_d, k, H, constants));

  // constructs new close transactions and computes hash
#if defined(DEBUG)
  cout << "hashing transactions" << endl;
#endif
  Integer escrow_digest[8];
  Integer merch_digest[8];

  validate_transactions(new_state_d,
    cust_escrow_pub_key_d, cust_payout_pub_key_d, cust_publickey_hash_d,
    merch_escrow_pub_key_d, merch_dispute_key_d, merch_payout_pub_key_d,
    merch_publickey_hash_d, escrow_digest, merch_digest, fee_cc_d, k, H, val_cpfp_d, self_delay_d, constants);

  // we should return into these txserialized_d or hash

  // sign new close transactions
#if defined(DEBUG)
  cout << "signing transactions" << endl;
#endif

  Integer signed_merch_tx = ecdsa_sign_hashed(merch_digest, epsd1, constants.thirtytwo, qs);
  Integer signed_escrow_tx = ecdsa_sign_hashed(escrow_digest, epsd2, constants.thirtytwo, qs);

  // sign new pay token
#if defined(DEBUG)
  cout << "signing token" << endl;
#endif
  PayToken_d new_paytoken_d = sign_token(new_state_d, hmac_key_d, constants, k, H);

  // Transform the signed_merch_tx into the correct format --> array of 8 32bit uints
  EcdsaSig_d signed_merch_tx_parsed;
  EcdsaSig_d signed_escrow_tx_parsed;

  bigint_into_smallint_array(signed_merch_tx_parsed.sig, signed_merch_tx, constants.fullF);
  bigint_into_smallint_array(signed_escrow_tx_parsed.sig, signed_escrow_tx, constants.fullF);

  // mask pay and close tokens
#if defined(DEBUG)
  cout << "masking pay token" << endl;
#endif
  error_signal = ( error_signal | mask_paytoken(new_paytoken_d.paytoken, paytoken_mask_d, paytoken_mask_commitment_d, paytoken_mask_commitment_randomness_d, k, H, constants)); // pay token

#if defined(DEBUG)
  cout << "masking close merch token" << endl;
#endif
  mask_closetoken(signed_merch_tx_parsed.sig, merch_mask_d); // close token - merchant close

#if defined(DEBUG)
  cout << "masking close escrow token" << endl;
#endif
  mask_closetoken(signed_escrow_tx_parsed.sig, escrow_mask_d); // close token - escrow close

  // handle errors
  // If there has been an error, we need to destroy the token values.
#if defined(DEBUG)
  cout << "handling errors" << endl;
#endif
  for(int i=0; i<8; i++) {
    new_paytoken_d.paytoken[i] = handle_error_case(new_paytoken_d.paytoken[i], error_signal);
  }
  for(int i=0; i<8; i++) {
    signed_merch_tx_parsed.sig[i] = handle_error_case(signed_merch_tx_parsed.sig[i], error_signal);
  }
  for(int i=0; i<8; i++) {
    signed_escrow_tx_parsed.sig[i] = handle_error_case(signed_escrow_tx_parsed.sig[i], error_signal);
  }

  localize_PayToken(pt_return, new_paytoken_d, CUST);
  localize_EcdsaSig(ct_escrow, signed_escrow_tx_parsed, CUST);
  localize_EcdsaSig(ct_merch, signed_merch_tx_parsed, CUST);
}

/* customer's token generation function
 *
 * runs MPC to compute masked tokens (close- and pay-).
 * blocks until computation is finished.
 *
 * Assumes close_tx_escrow and close_tx_merch are padded to 
 * exactly 1024 bits according to the SHA256 spec.
 */
void build_masked_tokens_cust(IOCallback io_callback,
  struct Conn_l conn,
  void *peer,
  cb_send send_cb,
  cb_receive receive_cb,
  void *circuit_file,

  struct Balance_l epsilon_l,
  struct RevLockCommitment_l rlc_l, // TYPISSUE: this doesn't match the docs. should be a commitment

  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,
  struct BitcoinPublicKey_l merch_escrow_pub_key_l,
  struct BitcoinPublicKey_l merch_dispute_key_l,
  struct PublicKeyHash_l merch_publickey_hash,
  struct BitcoinPublicKey_l merch_payout_pub_key_l,
  struct Nonce_l nonce_l,
  struct Balance_l val_cpfp,
  struct Balance_l bal_min_cust,
  struct Balance_l bal_min_merch,
  uint16_t self_delay,

  struct CommitmentRandomness_l revlock_commitment_randomness_l,
  struct State_l w_new,
  struct State_l w_old,
  struct Balance_l fee_cc,
  struct PayToken_l pt_old,
  struct BitcoinPublicKey_l cust_escrow_pub_key_l,
  struct BitcoinPublicKey_l cust_payout_pub_key_l,
  struct PublicKeyHash_l cust_publickey_hash_l,

  struct PayToken_l* pt_return,
  struct EcdsaSig_l* ct_escrow,
  struct EcdsaSig_l* ct_merch
) {
  // select the IO interface
  UnixNetIO *io1 = nullptr;
  NetIO *io2 = nullptr;
  GoNetIO *io3 = nullptr;
  LndNetIO *io4 = nullptr;
  ConnType conn_type = conn.conn_type;
  if (io_callback != NULL) {
      if (conn_type == LNDNETIO) {
          io4 = static_cast<LndNetIO *>(get_lndnetio_ptr(peer, send_cb, receive_cb, CUST));
          setup_semi_honest(io4, CUST);
      } else {
          auto *io_ptr = io_callback((void *) &conn, CUST);
          if (conn_type == UNIXNETIO) {
              io1 = static_cast<UnixNetIO *>(io_ptr);
              setup_semi_honest(io1, CUST);
          } else if (conn_type == NETIO) {
              io2 = static_cast<NetIO *>(io_ptr);
              setup_semi_honest(io2, CUST);
          } else if (conn_type == CUSTOM) {
              io3 = static_cast<GoNetIO *>(io_ptr);
              setup_semi_honest(io3, CUST);
          } else {
              /* custom IO connection */
              cout << "specify a supported connection type" << endl;
              return;
          }
      }
  } else {
    cout << "did not specify a IO connection callback for customer" << endl;
    return;
  }

  // placeholders for vars passed by merchant
  // TODO maybe do all the distributing here, before calling issue_tokens
  HMACKey_l hmac_key_l;
  Mask_l paytoken_mask_l;
  Mask_l merch_mask_l;
  Mask_l escrow_mask_l;
  EcdsaPartialSig_l dummy_sig;

  CommitmentRandomness_l hmac_commitment_randomness_l;
  CommitmentRandomness_l paytoken_mask_commitment_randomness_l;

issue_tokens(
/* CUSTOMER INPUTS */
  w_old,
  w_new,
  fee_cc,
  pt_old,
  cust_escrow_pub_key_l,
  cust_payout_pub_key_l,
  revlock_commitment_randomness_l,
  cust_publickey_hash_l,
/* MERCHANT INPUTS */
  hmac_key_l,
  paytoken_mask_l,
  merch_mask_l,
  escrow_mask_l,
  dummy_sig,
  dummy_sig,
  hmac_commitment_randomness_l,
  paytoken_mask_commitment_randomness_l,
/* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  epsilon_l,
  key_com,
  paymask_com,
  rlc_l,
  nonce_l,
  val_cpfp,
  bal_min_cust,
  bal_min_merch,
  self_delay,
  merch_escrow_pub_key_l,
  merch_dispute_key_l,
  merch_payout_pub_key_l,
  merch_publickey_hash,
/* OUTPUTS */
  pt_return,
  ct_escrow,
  ct_merch
  );
#if defined(DEBUG)
  cout << "customer finished!" << endl;
#endif
  if (io1 != nullptr) {
      io1->flush();
      delete io1;
  }
  if (io2 != nullptr) {
      io2->flush();
      delete io2;
  }
  if (io3 != nullptr) {
      io3->flush();
      delete io3;
  }
  if (io4 != nullptr) {
      io4->flush();
      delete io4;
  }
}

void build_masked_tokens_merch(IOCallback io_callback,
  struct Conn_l conn,
  void *peer,
  cb_send send_cb,
  cb_receive receive_cb,
  void *circuit_file,
  struct Balance_l epsilon_l,
  struct RevLockCommitment_l rlc_l, // TYPISSUE: this doesn't match the docs. should be a commitment

  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,
  struct BitcoinPublicKey_l merch_escrow_pub_key_l,
  struct BitcoinPublicKey_l merch_dispute_key_l,
  struct PublicKeyHash_l merch_publickey_hash,
  struct BitcoinPublicKey_l merch_payout_pub_key_l,
  struct Nonce_l nonce_l,
  struct Balance_l val_cpfp,
  struct Balance_l bal_min_cust,
  struct Balance_l bal_min_merch,
  uint16_t self_delay,

  struct HMACKey_l hmac_key,
  struct Mask_l merch_mask_l,
  struct Mask_l escrow_mask_l,
  struct Mask_l paytoken_mask_l,
  struct CommitmentRandomness_l hmac_commitment_randomness_l,
  struct CommitmentRandomness_l paytoken_mask_commitment_randomness_l,
  struct EcdsaPartialSig_l sig1,
  struct EcdsaPartialSig_l sig2
) {

  // TODO: switch to smart pointer
  UnixNetIO *io1 = nullptr;
  NetIO *io2 = nullptr;
  GoNetIO *io3 = nullptr;
  LndNetIO *io4 = nullptr;
  ConnType conn_type = conn.conn_type;
  if (io_callback != NULL) {
      if (conn_type == LNDNETIO) {
          io4 = static_cast<LndNetIO *>(get_lndnetio_ptr(peer, send_cb, receive_cb, MERCH));
          setup_semi_honest(io4, MERCH);
      } else {
          auto *io_ptr = io_callback((void *) &conn, MERCH);
          if (conn_type == UNIXNETIO) {
              io1 = static_cast<UnixNetIO *>(io_ptr);
              setup_semi_honest(io1, MERCH);
          } else if (conn_type == NETIO) {
              io2 = static_cast<NetIO *>(io_ptr);
              setup_semi_honest(io2, MERCH);
          } else if (conn_type == CUSTOM) {
              io3 = static_cast<GoNetIO *>(io_ptr);
              setup_semi_honest(io3, MERCH);
          } else {
              /* custom IO connection */
              cout << "specify a supported connection type" << endl;
              return;
          }
      }
  } else {
    cout << "did not specify a IO connection callback for merchant" << endl;
    return;
  }

  State_l old_state_l;
  State_l new_state_l;
  Balance_l fee_cc;
  PayToken_l old_paytoken_l;
  BitcoinPublicKey_l cust_escrow_pub_key_l;
  BitcoinPublicKey_l cust_payout_pub_key_l;
  PayToken_l pt_return;
  EcdsaSig_l ct_escrow;
  EcdsaSig_l ct_merch;
  CommitmentRandomness_l revlock_commitment_randomness_l;
  PublicKeyHash_l cust_publickey_hash_l;


issue_tokens(
/* CUSTOMER INPUTS */
  old_state_l,
  new_state_l,
  fee_cc,
  old_paytoken_l,
  cust_escrow_pub_key_l,
  cust_payout_pub_key_l,
  revlock_commitment_randomness_l,
  cust_publickey_hash_l,
/* MERCHANT INPUTS */
  hmac_key,
  paytoken_mask_l,
  merch_mask_l,
  escrow_mask_l,
  sig1,
  sig2,
  hmac_commitment_randomness_l,
  paytoken_mask_commitment_randomness_l,
/* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  epsilon_l,
  key_com,
  paymask_com,
  rlc_l,
  nonce_l,
  val_cpfp,
  bal_min_cust,
  bal_min_merch,
  self_delay,
  merch_escrow_pub_key_l,
  merch_dispute_key_l,
  merch_payout_pub_key_l,
  merch_publickey_hash,
/* OUTPUTS */
  &pt_return,
  &ct_escrow,
  &ct_merch
  );

#if defined(DEBUG)
  cout << "merchant finished!" << endl;
#endif
    if (io1 != nullptr) {
        io1->flush();
        delete io1;
    }
    if (io2 != nullptr) {
        io2->flush();
        delete io2;
    }
    if (io3 != nullptr) {
        io3->flush();
        delete io3;
    }
    if (io4 != nullptr) {
        io4->flush();
        delete io4;
    }
}

PayToken_d sign_token(State_d state, HMACKey_d key, Constants constants, Integer k[64], Integer H[8]) {
  PayToken_d paytoken;
  HMACsign(key, state, paytoken.paytoken, constants, k, H);
  return paytoken;
}

Bit verify_token_sig(HMACKeyCommitment_d commitment, CommitmentRandomness_d hmac_commitment_randomness_d, HMACKey_d opening, State_d old_state, PayToken_d old_paytoken, Constants constants, Integer k[64], Integer H[8]) {

  // check that the opening is valid
  Integer message[2][16];

  for(int i=0; i<16; i++) {
    message[0][i] = opening.key[i];
  }

  // Padding
  message[1][0] = hmac_commitment_randomness_d.randomness[0];
  message[1][1] = hmac_commitment_randomness_d.randomness[1];
  message[1][2] = hmac_commitment_randomness_d.randomness[2];
  message[1][3] = hmac_commitment_randomness_d.randomness[3];
  message[1][4] = constants.xeightfirstbyte; //0x80000000;
  message[1][5] = constants.zero; //0x00000000;
  message[1][6] = constants.zero; //0x00000000;
  message[1][7] = constants.zero; //0x00000000;
  message[1][8] = constants.zero; //0x00000000;
  message[1][9] = constants.zero; //0x00000000;
  message[1][10] = constants.zero; //0x00000000;
  message[1][11] = constants.zero; //0x00000000;
  message[1][12] = constants.zero; //0x00000000;
  message[1][13] = constants.zero; //0x00000000;

  // Message length
  message[1][14] = constants.zero; //0x00000000;
  message[1][15] = constants.hmackeycommitmentpreimagelength;

  Integer hashresult[8];

  computeSHA256_2d_noinit(message, hashresult, k, H);

  Bit b(false);

  for(int i=0; i<8; i++) {
     Bit not_equal = !(commitment.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }

  // // Sign the old state again to compare
  PayToken_d recomputed_paytoken;
  HMACsign(opening, old_state, recomputed_paytoken.paytoken, constants, k, H);

  for(int i=0; i<8; i++) {
    Bit not_equal = !(recomputed_paytoken.paytoken[i].equal(old_paytoken.paytoken[i]));
    b = b | not_equal;
  }
  return b;
}

// make sure wallets are well-formed
Bit compare_states(State_d old_state_d, State_d new_state_d, RevLockCommitment_d rlc_d, CommitmentRandomness_d revlock_commitment_randomness_d, Nonce_d nonce_d, Balance_d epsilon_d, Balance_d fee_cc_d, Balance_d val_cpfp_d, Balance_d bal_min_cust_d, Balance_d bal_min_merch_d, Integer k[64], Integer H[8], Constants constants) {

  //Make sure the fields are all correct
  Bit b(false);

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.txid_merch.txid[i].equal(new_state_d.txid_merch.txid[i]));
     b = b | not_equal;
  }

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.txid_escrow.txid[i].equal(new_state_d.txid_escrow.txid[i]));
     b = b | not_equal;
  }

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.HashPrevOuts_merch.txid[i].equal(new_state_d.HashPrevOuts_merch.txid[i]));
     b = b | not_equal;
  }

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.HashPrevOuts_escrow.txid[i].equal(new_state_d.HashPrevOuts_escrow.txid[i]));
     b = b | not_equal;
  }

  // nonce_d has to match the nonce in old state
  b = (b | (!old_state_d.nonce.nonce[0].equal(nonce_d.nonce[0])));
  b = (b | (!old_state_d.nonce.nonce[1].equal(nonce_d.nonce[1])));
  b = (b | (!old_state_d.nonce.nonce[2].equal(nonce_d.nonce[2])));
  b = (b | (!old_state_d.nonce.nonce[3].equal(nonce_d.nonce[3])));

  // check that the rlc is a commitment to the rl in old_state
  b = (b | verify_revlock_commitment(old_state_d.rl, rlc_d, revlock_commitment_randomness_d, k, H, constants));

  // check that the min and max fee haven't not changed.  Also check fee_mc stayed the same
  b = (b | (!old_state_d.min_fee.balance[0].equal(new_state_d.min_fee.balance[0])));
  b = (b | (!old_state_d.min_fee.balance[1].equal(new_state_d.min_fee.balance[1])));
  b = (b | (!old_state_d.max_fee.balance[0].equal(new_state_d.max_fee.balance[0])));
  b = (b | (!old_state_d.max_fee.balance[1].equal(new_state_d.max_fee.balance[1])));
  b = (b | (!old_state_d.fee_mc.balance[0].equal(new_state_d.fee_mc.balance[0])));
  b = (b | (!old_state_d.fee_mc.balance[1].equal(new_state_d.fee_mc.balance[1])));

  // check that the new fee selected by the customer is in the right range
  Integer current_fee_combined = combine_balance(fee_cc_d);
  Integer min_fee_combined = combine_balance(old_state_d.min_fee);
  Integer max_fee_combined = combine_balance(old_state_d.max_fee);
  Integer fee_mc_combined = combine_balance(old_state_d.fee_mc);

  b = (b | (!max_fee_combined.geq(current_fee_combined)));
  b = (b | (!current_fee_combined.geq(min_fee_combined)));

  // Make sure that balances have been correctly updated
  Integer epsilon_combined = combine_balance(epsilon_d);
  Integer old_balance_merch_combined = combine_balance(old_state_d.balance_merch);
  Integer old_balance_cust_combined = combine_balance(old_state_d.balance_cust);
  Integer new_balance_merch_combined = combine_balance(new_state_d.balance_merch);
  Integer new_balance_cust_combined = combine_balance(new_state_d.balance_cust);

  Integer fee_cc_combined = combine_balance(fee_cc_d);
  Integer val_cpfp_combined = combine_balance(val_cpfp_d);

  b = (b | (!new_balance_merch_combined.equal(old_balance_merch_combined + epsilon_combined)));
  b = (b | (!new_balance_cust_combined.equal(old_balance_cust_combined - epsilon_combined)));

  // Dustlimit checks
  // make sure theres enough funds for the amount we have payed
  // We want to make sure we never go below the dust limit on either payout
  Integer bal_min_cust_combined = combine_balance(bal_min_cust_d);
  Integer bal_min_merch_combined = combine_balance(bal_min_merch_d);
  b = (b | (!(old_balance_merch_combined + epsilon_combined).geq(bal_min_merch_combined + fee_mc_combined + val_cpfp_combined)));
  b = (b | (!(old_balance_cust_combined - epsilon_combined).geq(bal_min_cust_combined + fee_cc_combined + val_cpfp_combined)));

  return b;
}

Bit verify_revlock_commitment(RevLock_d rl_d, RevLockCommitment_d rlc_d, CommitmentRandomness_d rl_rand_d, Integer k[64], Integer H[8], Constants constants) {
  Bit b(false);  // TODO initialize to 0

  Integer message[1][16];

  for(int i=0; i<8; i++) {
    message[0][i] = rl_d.revlock[i];
  }

  message[0][8] = rl_rand_d.randomness[0];
  message[0][9] = rl_rand_d.randomness[1];
  message[0][10] = rl_rand_d.randomness[2];
  message[0][11] = rl_rand_d.randomness[3];
  message[0][12] = constants.xeightfirstbyte; //0x80000000;
  message[0][13] = constants.zero; //0x00000000;

  // Message length
  message[0][14] = constants.zero; //0x00000000;
  message[0][15] = constants.commitmentpreimagelength; // 256 bit RL

  Integer hashresult[8];

  computeSHA256_1d_noinit(message, hashresult, k, H);

  for(int i=0; i<8; i++) {
     Bit not_equal = !(rlc_d.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }
  return b;
}

Bit verify_mask_commitment(Mask_d mask, MaskCommitment_d maskcommitment, CommitmentRandomness_d mask_commitment_randomness_d, Integer k[64], Integer H[8], Constants constants) {
  Bit b(false);

  Integer message[1][16];

  for(int i=0; i<8; i++) {
    message[0][i] = mask.mask[i];
  }

  message[0][8] = mask_commitment_randomness_d.randomness[0];
  message[0][9] = mask_commitment_randomness_d.randomness[1];
  message[0][10] = mask_commitment_randomness_d.randomness[2];
  message[0][11] = mask_commitment_randomness_d.randomness[3];
//  message[0][12] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[0][12] = constants.xeightfirstbyte; //0x80000000;
  message[0][13] = constants.zero; //0x00000000;

  // Message length
  message[0][14] = constants.zero; //0x00000000;
  message[0][15] = constants.commitmentpreimagelength;

  Integer hashresult[8];

  computeSHA256_1d_noinit(message, hashresult, k, H);

  for(int i=0; i<8; i++) {
     Bit not_equal = !(maskcommitment.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }
  return b;
}

// mask pay and close tokens
Bit mask_paytoken(Integer paytoken[8], Mask_d mask, MaskCommitment_d maskcommitment, CommitmentRandomness_d paytoken_mask_commitment_randomness_d, Integer k[64], Integer H[8], Constants constants) {

  // The pay token is 256 bits long.
  // Thus the mask is 256 bits long.
  // First we check to see if the mask was correct

  Bit b = verify_mask_commitment(mask, maskcommitment, paytoken_mask_commitment_randomness_d, k, H, constants);

  for(int i=0; i<8; i++) {
    paytoken[i] = paytoken[i] ^ mask.mask[i];
  }

  return b;
}

// applies a mask to a 256-bit token (made of 8x32-bit integers)
void mask_closetoken(Integer token[8], Mask_d mask) {
  for(int i=0; i<8; i++) {
    token[i] = token[i] ^ mask.mask[i];
  }
}