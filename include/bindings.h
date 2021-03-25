#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define _STDINT_H 1

#define _FEATURES_H 1

#define _ISOC95_SOURCE 1

#define _ISOC99_SOURCE 1

#define _ISOC11_SOURCE 1

#define _ISOC2X_SOURCE 1

#define _POSIX_SOURCE 1

#define _POSIX_C_SOURCE 200809

#define _XOPEN_SOURCE 700

#define _XOPEN_SOURCE_EXTENDED 1

#define _LARGEFILE64_SOURCE 1

#define _DEFAULT_SOURCE 1

#define _ATFILE_SOURCE 1

#define __GLIBC_USE_ISOC2X 1

#define __USE_ISOC11 1

#define __USE_ISOC99 1

#define __USE_ISOC95 1

#define __USE_ISOCXX11 1

#define __USE_POSIX 1

#define __USE_POSIX2 1

#define __USE_POSIX199309 1

#define __USE_POSIX199506 1

#define __USE_XOPEN2K 1

#define __USE_XOPEN2K8 1

#define __USE_XOPEN 1

#define __USE_XOPEN_EXTENDED 1

#define __USE_UNIX98 1

#define _LARGEFILE_SOURCE 1

#define __USE_XOPEN2K8XSI 1

#define __USE_XOPEN2KXSI 1

#define __USE_LARGEFILE 1

#define __USE_LARGEFILE64 1

#define __USE_MISC 1

#define __USE_ATFILE 1

#define __USE_GNU 1

#define __USE_FORTIFY_LEVEL 0

#define __GLIBC_USE_DEPRECATED_GETS 0

#define __GLIBC_USE_DEPRECATED_SCANF 0

#define _STDC_PREDEF_H 1

#define __STDC_IEC_559__ 1

#define __STDC_IEC_559_COMPLEX__ 1

#define __STDC_ISO_10646__ 201706

#define __GNU_LIBRARY__ 6

#define __GLIBC__ 2

#define __GLIBC_MINOR__ 31

#define _SYS_CDEFS_H 1

#define __glibc_c99_flexarr_available 1

#define __WORDSIZE_TIME64_COMPAT32 1

#define __SYSCALL_WORDSIZE 64

#define __LONG_DOUBLE_USES_FLOAT128 0

#define __HAVE_GENERIC_SELECTION 0

#define __GLIBC_USE_LIB_EXT2 1

#define __GLIBC_USE_IEC_60559_BFP_EXT 1

#define __GLIBC_USE_IEC_60559_BFP_EXT_C2X 1

#define __GLIBC_USE_IEC_60559_FUNCS_EXT 1

#define __GLIBC_USE_IEC_60559_FUNCS_EXT_C2X 1

#define __GLIBC_USE_IEC_60559_TYPES_EXT 1

#define _BITS_TYPES_H 1

#define __TIMESIZE 64

#define _BITS_TYPESIZES_H 1

#define __OFF_T_MATCHES_OFF64_T 1

#define __INO_T_MATCHES_INO64_T 1

#define __RLIM_T_MATCHES_RLIM64_T 1

#define __STATFS_MATCHES_STATFS64 1

#define __FD_SETSIZE 1024

#define _BITS_TIME64_H 1

#define _BITS_WCHAR_H 1

#define _BITS_STDINT_INTN_H 1

#define _BITS_STDINT_UINTN_H 1

#define INT8_WIDTH 8

#define UINT8_WIDTH 8

#define INT16_WIDTH 16

#define UINT16_WIDTH 16

#define INT32_WIDTH 32

#define UINT32_WIDTH 32

#define INT64_WIDTH 64

#define UINT64_WIDTH 64

#define INT_LEAST8_WIDTH 8

#define UINT_LEAST8_WIDTH 8

#define INT_LEAST16_WIDTH 16

#define UINT_LEAST16_WIDTH 16

#define INT_LEAST32_WIDTH 32

#define UINT_LEAST32_WIDTH 32

#define INT_LEAST64_WIDTH 64

#define UINT_LEAST64_WIDTH 64

#define INT_FAST8_WIDTH 8

#define UINT_FAST8_WIDTH 8

#define INT_FAST16_WIDTH 64

#define UINT_FAST16_WIDTH 64

#define INT_FAST32_WIDTH 64

#define UINT_FAST32_WIDTH 64

#define INT_FAST64_WIDTH 64

#define UINT_FAST64_WIDTH 64

#define INTPTR_WIDTH 64

#define UINTPTR_WIDTH 64

#define INTMAX_WIDTH 64

#define UINTMAX_WIDTH 64

#define PTRDIFF_WIDTH 64

#define SIG_ATOMIC_WIDTH 32

#define SIZE_WIDTH 64

#define WCHAR_WIDTH 32

#define WINT_WIDTH 32

typedef struct Nonce_l {
  uint32_t nonce[4];
} Nonce_l;

typedef struct RevLock_l {
  uint32_t revlock[8];
} RevLock_l;

typedef struct Balance_l {
  uint32_t balance[2];
} Balance_l;

typedef struct Txid_l {
  uint32_t txid[8];
} Txid_l;

typedef struct State_l {
  struct Nonce_l nonce;
  struct RevLock_l rl;
  struct Balance_l balance_cust;
  struct Balance_l balance_merch;
  struct Txid_l txid_merch;
  struct Txid_l txid_escrow;
  struct Txid_l HashPrevOuts_merch;
  struct Txid_l HashPrevOuts_escrow;
  struct Balance_l min_fee;
  struct Balance_l max_fee;
  struct Balance_l fee_mc;
} State_l;

typedef struct PayToken_l {
  uint32_t paytoken[8];
} PayToken_l;

typedef struct BitcoinPublicKey_l {
  uint32_t key[9];
} BitcoinPublicKey_l;

typedef struct CommitmentRandomness_l {
  uint32_t randomness[4];
} CommitmentRandomness_l;

typedef struct PublicKeyHash_l {
  uint32_t hash[5];
} PublicKeyHash_l;

typedef struct HMACKey_l {
  uint32_t key[16];
} HMACKey_l;

typedef struct Mask_l {
  uint32_t mask[8];
} Mask_l;

typedef struct EcdsaPartialSig_l {
  char r[256];
  char k_inv[256];
} EcdsaPartialSig_l;

typedef struct Randomness_l {
  uint32_t randomness[4];
} Randomness_l;

typedef struct HMACKeyCommitment_l {
  uint32_t commitment[8];
} HMACKeyCommitment_l;

typedef struct MaskCommitment_l {
  uint32_t commitment[8];
} MaskCommitment_l;

typedef struct RevLockCommitment_l {
  uint32_t commitment[8];
} RevLockCommitment_l;

typedef struct EcdsaSig_l {
  uint32_t sig[8];
} EcdsaSig_l;

typedef char *(*cb_send)(void *arg1, int arg2, void *arg3);

typedef struct Receive_return {
  char *r0;
  int r1;
  char *r2;
} Receive_return;

typedef struct Receive_return (*cb_receive)(void *arg1);

typedef unsigned int ConnType;

#define ConnType_CUSTOM 0

#define ConnType_NETIO 1

#define ConnType_UNIXNETIO 2

#define ConnType_LNDNETIO 3

#define ConnType_TORNETIO 4

extern void *get_gonetio_ptr(void *raw_stream_fd, int party);

extern void *load_circuit_file(const char *path);

extern void issue_tokens(struct State_l old_state_l,
                         struct State_l new_state_l,
                         struct Balance_l fee_cc,
                         struct PayToken_l old_paytoken_l,
                         struct BitcoinPublicKey_l cust_escrow_pub_key_l,
                         struct BitcoinPublicKey_l cust_payout_pub_key_l,
                         struct CommitmentRandomness_l revlock_commitment_randomness_l,
                         struct PublicKeyHash_l cust_publickey_hash_l,
                         struct HMACKey_l hmac_key_l,
                         struct Mask_l paytoken_mask_l,
                         struct Mask_l merch_mask_l,
                         struct Mask_l escrow_mask_l,
                         struct EcdsaPartialSig_l sig1,
                         struct EcdsaPartialSig_l sig2,
                         struct CommitmentRandomness_l hmac_commitment_randomness_l,
                         struct CommitmentRandomness_l paytoken_mask_commitment_randomness_l,
                         struct Randomness_l verify_success,
                         struct Balance_l epsilon_l,
                         struct HMACKeyCommitment_l hmac_key_commitment_l,
                         struct MaskCommitment_l paytoken_mask_commitment_l,
                         struct RevLockCommitment_l rlc_l,
                         struct Nonce_l nonce_l,
                         struct Balance_l val_cpfp,
                         struct Balance_l bal_min_cust,
                         struct Balance_l bal_min_merch,
                         uint16_t self_delay,
                         struct BitcoinPublicKey_l merch_escrow_pub_key_l,
                         struct BitcoinPublicKey_l merch_dispute_key_l,
                         struct BitcoinPublicKey_l merch_payout_pub_key_l,
                         struct PublicKeyHash_l merch_publickey_hash_l,
                         struct PayToken_l *pt_return,
                         struct EcdsaSig_l *ct_escrow,
                         struct EcdsaSig_l *ct_merch,
                         struct Randomness_l *success);

void ffishim_free_string(char *pointer);

char *ffishim_bls12_tze_check_wpk(char *ser_wpk);

char *ffishim_bls12_channel_setup(const char *channel_name, uint32_t third_party_support);

char *ffishim_bls12_init_merchant_init(char *ser_channel_state, const char *name_ptr);

char *ffishim_bls12_init_customer_init(char *ser_channel_token,
                                       int64_t balance_customer,
                                       int64_t balance_merchant,
                                       const char *name_ptr);

char *ffishim_bls12_generate_channel_id(char *ser_channel_token);

char *ffishim_bls12_validate_channel_params(char *ser_init_state, char *ser_merch_state);

char *ffishim_bls12_verify_init_close_token(char *ser_channel_state,
                                            char *ser_customer_state,
                                            char *ser_close_token);

char *ffishim_bls12_activate_customer(char *ser_cust_state);

char *ffishim_bls12_activate_merchant(char *ser_init_state, char *ser_merch_state);

char *ffishim_bls12_verify_close_token(char *ser_channel_state,
                                       char *ser_customer_state,
                                       char *ser_close_token);

char *ffishim_bls12_activate_customer_finalize(char *ser_channel_state,
                                               char *ser_customer_state,
                                               char *ser_pay_token);

char *ffishim_bls12_unlink_customer_update_state(char *ser_channel_state, char *ser_customer_state);

char *ffishim_bls12_unlink_merchant_update_state(char *ser_channel_state,
                                                 char *ser_session_id,
                                                 char *ser_pay_proof,
                                                 char *ser_merch_state);

char *ffishim_bls12_unlink_customer_unmask(char *ser_channel_state,
                                           char *ser_cust_state,
                                           char *ser_new_cust_state,
                                           char *ser_new_close_token);

char *ffishim_bls12_unlink_merchant_validate_rev_lock(char *ser_session_id,
                                                      char *ser_revoked_state,
                                                      char *ser_merch_state);

char *ffishim_bls12_unlink_customer_finalize(char *ser_channel_state,
                                             char *ser_cust_state,
                                             char *ser_pay_token);

char *ffishim_bls12_pay_customer_prepare(char *ser_channel_state,
                                         int64_t amount,
                                         char *ser_cust_state);

char *ffishim_bls12_pay_merchant_prepare(char *ser_session_id,
                                         char *ser_nonce,
                                         int64_t amount,
                                         char *ser_merchant_state);

char *ffishim_bls12_pay_customer_update_state(char *ser_channel_state,
                                              char *ser_customer_state,
                                              int64_t amount);

char *ffishim_bls12_pay_merchant_update_state(char *ser_channel_state,
                                              char *ser_session_id,
                                              char *ser_pay_proof,
                                              char *ser_merch_state);

char *ffishim_bls12_pay_verify_multiple_payment_proofs(char *ser_channel_state,
                                                       char *ser_sender_pay_proof,
                                                       char *ser_receiver_pay_proof,
                                                       char *ser_merch_state);

char *ffishim_bls12_pay_customer_unmask(char *ser_channel_state,
                                        char *ser_cust_state,
                                        char *ser_new_cust_state,
                                        char *ser_close_token);

char *ffishim_bls12_pay_merchant_validate_rev_lock(char *ser_session_id,
                                                   char *ser_revoke_token,
                                                   char *ser_merch_state);

char *ffishim_bls12_pay_customer_unmask_pay_token(char *ser_channel_state,
                                                  char *ser_cust_state,
                                                  char *ser_pay_token);

char *ffishim_bls12_multi_pay_merchant_unmask(char *ser_sender_revoke_token,
                                              char *ser_receiver_revoke_token,
                                              char *ser_merch_state);

char *ffishim_bls12_customer_close(char *ser_channel_state, char *ser_cust_state);

char *ffishim_bls12_decompress_cust_close_message(char *ser_channel_state, char *ser_cust_close);

char *ffishim_bls12_merchant_close(char *ser_channel_state,
                                   char *ser_channel_token,
                                   const char *_ser_address,
                                   char *ser_cust_close,
                                   char *ser_merch_state);

void mpc_free_string(char *pointer);

char *get_self_delay_be_hex(char *ser_channel_state);

char *mpc_channel_setup(const char *channel_name,
                        uint16_t self_delay,
                        int64_t bal_min_cust,
                        int64_t bal_min_merch,
                        int64_t val_cpfp,
                        uint32_t third_party_support);

char *mpc_init_merchant(char *db_url_str, char *ser_channel_state, const char *name_ptr);

char *mpc_load_merchant_wallet(char *ser_merch_state,
                               char *ser_channel_state,
                               char *ser_sk_m,
                               char *ser_payout_sk,
                               char *ser_child_sk,
                               char *ser_dispute_sk);

char *mpc_init_customer(char *ser_merch_pk,
                        int64_t cust_bal,
                        int64_t merch_bal,
                        char *ser_tx_fee_info,
                        const char *name_ptr);

char *mpc_load_customer_wallet(char *ser_cust_state,
                               char *ser_channel_token,
                               char *ser_sk_c,
                               char *ser_payout_sk);

char *mpc_get_initial_state(char *ser_cust_state);

char *mpc_validate_channel_params(char *ser_channel_token,
                                  char *ser_init_state,
                                  char *ser_init_hash,
                                  char *ser_merch_state);

char *mpc_get_channel_id(char *ser_channel_token);

char *mpc_activate_customer(char *ser_cust_state);

char *mpc_activate_merchant(char *ser_channel_token, char *ser_state, char *ser_merch_state);

char *mpc_activate_customer_finalize(char *ser_pay_token, char *ser_cust_state);

char *mpc_prepare_payment_customer(char *ser_channel_state, int64_t amount, char *ser_cust_state);

char *mpc_prepare_payment_merchant(char *ser_channel_state,
                                   char *ser_session_id,
                                   char *ser_nonce,
                                   char *ser_rev_lock_com,
                                   int64_t amount,
                                   char *ser_justification,
                                   char *ser_merch_state);

char *mpc_pay_update_customer(char *ser_channel_state,
                              char *ser_channel_token,
                              char *ser_start_state,
                              char *ser_end_state,
                              char *ser_pay_token_mask_com,
                              char *ser_rev_lock_com,
                              int64_t amount,
                              char *ser_cust_state,
                              void *p_ptr,
                              cb_send send_cb,
                              cb_receive receive_cb);

char *mpc_pay_update_merchant(char *ser_channel_state,
                              char *ser_session_id,
                              char *ser_pay_token_mask_com,
                              char *ser_merch_state,
                              void *p_ptr,
                              cb_send send_cb,
                              cb_receive receive_cb);

char *mpc_get_masked_tx_inputs(char *ser_session_id, char *ser_success, char *ser_merch_state);

char *mpc_pay_unmask_sigs_customer(char *ser_channel_state,
                                   char *ser_channel_token,
                                   char *ser_masked_tx_inputs,
                                   char *ser_cust_state);

char *mpc_pay_validate_rev_lock_merchant(char *ser_session_id,
                                         char *ser_revoked_state,
                                         char *ser_merch_state);

char *mpc_pay_unmask_pay_token_customer(char *ser_pt_mask_bytes,
                                        char *ser_pt_mask_r,
                                        char *ser_cust_state);

char *cust_change_channel_status_to_open(char *ser_cust_state);

char *cust_change_channel_status_to_pending_close(char *ser_cust_state);

char *cust_change_channel_status_to_confirmed_close(char *ser_cust_state);

char *cust_clear_channel_status(char *ser_cust_state);

char *merch_change_channel_status_to_open(char *ser_escrow_txid, char *ser_merch_state);

char *merch_change_channel_status_to_pending_close(char *ser_escrow_txid, char *ser_merch_state);

char *merch_change_channel_status_to_confirmed_close(char *ser_escrow_txid, char *ser_merch_state);

char *merch_clear_channel_status(char *ser_escrow_txid, char *ser_merch_state);

char *force_customer_close_tx(char *ser_channel_state,
                              char *ser_channel_token,
                              uint32_t ser_from_escrow,
                              char *ser_cust_state);

char *force_merchant_close_tx(char *ser_escrow_txid, char *ser_merch_state, int64_t val_cpfp);

char *merchant_check_rev_lock(char *ser_rev_lock, char *ser_merch_state);

char *cust_create_escrow_transaction(char *ser_txid,
                                     uint32_t index,
                                     char *ser_cust_sk,
                                     int64_t input_sats,
                                     int64_t output_sats,
                                     char *ser_cust_pk,
                                     char *ser_merch_pk,
                                     char *ser_change_pk,
                                     uint32_t ser_change_pk_is_hash,
                                     int64_t tx_fee,
                                     uint32_t ser_should_sign);

char *form_merch_close_transaction(char *ser_escrow_txid,
                                   char *ser_cust_pk,
                                   char *ser_merch_pk,
                                   char *ser_merch_close_pk,
                                   char *ser_merch_child_pk,
                                   int64_t cust_bal_sats,
                                   int64_t merch_bal_sats,
                                   int64_t fee_mc,
                                   int64_t val_cpfp,
                                   char *ser_self_delay);

char *customer_sign_merch_close_tx(char *ser_cust_sk, char *ser_merch_tx_preimage);

char *merchant_verify_merch_close_tx(char *ser_escrow_txid,
                                     char *ser_cust_pk,
                                     int64_t cust_bal_sats,
                                     int64_t merch_bal_sats,
                                     int64_t fee_mc,
                                     int64_t val_cpfp,
                                     char *ser_self_delay,
                                     char *ser_cust_sig,
                                     char *ser_merch_state);

char *merch_sign_init_cust_close_txs(char *ser_funding_tx,
                                     char *ser_rev_lock,
                                     char *ser_cust_pk,
                                     char *ser_cust_close_pk,
                                     char *ser_self_delay,
                                     char *ser_merch_state,
                                     int64_t fee_cc,
                                     int64_t fee_mc,
                                     int64_t val_cpfp);

char *cust_verify_init_cust_close_txs(char *ser_funding_tx,
                                      char *ser_tx_fee_info,
                                      char *ser_channel_state,
                                      char *ser_channel_token,
                                      char *ser_escrow_sig,
                                      char *ser_merch_sig,
                                      char *ser_cust_state);

char *sign_merch_dispute_tx(char *ser_escrow_txid,
                            char *ser_tx_index,
                            uint32_t index,
                            int64_t input_amount,
                            int64_t output_amount,
                            char *ser_self_delay,
                            char *ser_output_pk,
                            char *ser_rev_lock,
                            char *ser_rev_secret,
                            char *ser_cust_close_pk,
                            char *ser_merch_state);

/**
 * Merchant - claim output from cust-close-tx which is spendable immediately
 */
char *merch_claim_tx_from_cust_close(char *ser_tx_index,
                                     uint32_t index,
                                     int64_t input_amount,
                                     int64_t output_amount,
                                     char *ser_output_pk,
                                     char *ser_merch_state);

/**
 * Merchant - claim output from merch-close-tx after timeout
 */
char *merch_claim_tx_from_merch_close(char *ser_tx_index,
                                      uint32_t index,
                                      int64_t input_amount,
                                      int64_t output_amount,
                                      char *ser_self_delay,
                                      char *ser_cust_pk,
                                      char *ser_output_pk,
                                      uint32_t cpfp_index,
                                      int64_t cpfp_amount,
                                      char *ser_merch_state);

char *cust_claim_tx_from_cust_close(char *ser_channel_state,
                                    char *ser_tx_index,
                                    uint32_t index,
                                    int64_t input_amount,
                                    int64_t output_amount,
                                    char *ser_self_delay,
                                    char *ser_output_pk,
                                    char *ser_rev_lock,
                                    char *ser_cust_close_pk,
                                    uint32_t cpfp_index,
                                    int64_t cpfp_amount,
                                    char *ser_cust_state);

char *cust_sign_mutual_close_tx(char *ser_tx_index,
                                uint32_t index,
                                int64_t input_amount,
                                int64_t cust_amount,
                                int64_t merch_amount,
                                char *ser_merch_close_pk,
                                char *ser_cust_close_pk,
                                char *ser_merch_pk,
                                char *ser_cust_pk,
                                char *ser_cust_sk);

char *merch_sign_mutual_close_tx(char *ser_tx_index,
                                 uint32_t index,
                                 int64_t input_amount,
                                 int64_t cust_amount,
                                 int64_t merch_amount,
                                 char *ser_merch_close_pk,
                                 char *ser_cust_close_pk,
                                 char *ser_merch_pk,
                                 char *ser_cust_pk,
                                 char *ser_cust_sig,
                                 char *ser_merch_sk);

char *create_child_tx_to_bump_fee_via_p2wpkh_input(char *ser_tx_index1,
                                                   uint32_t index1,
                                                   int64_t input_amount1,
                                                   char *ser_sk1,
                                                   char *ser_tx_index2,
                                                   uint32_t index2,
                                                   int64_t input_amount2,
                                                   char *ser_sk2,
                                                   char *ser_redeem_script,
                                                   int64_t tx_fee,
                                                   char *ser_output_pk);
