#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define _LIBCPP_DEBUG_LEVEL 0

#define _LIBCPP_HAS_MERGED_TYPEINFO_NAMES_DEFAULT 1

#define __STDCPP_THREADS__ 1

typedef struct {
  uint32_t nonce[4];
} Nonce_l;

typedef struct {
  uint32_t revlock[8];
} RevLock_l;

typedef struct {
  uint32_t balance[2];
} Balance_l;

typedef struct {
  uint32_t txid[8];
} Txid_l;

typedef struct {
  Nonce_l nonce;
  RevLock_l rl;
  Balance_l balance_cust;
  Balance_l balance_merch;
  Txid_l txid_merch;
  Txid_l txid_escrow;
  Txid_l HashPrevOuts_merch;
  Txid_l HashPrevOuts_escrow;
  Balance_l min_fee;
  Balance_l max_fee;
  Balance_l fee_mc;
} State_l;

typedef struct {
  uint32_t paytoken[8];
} PayToken_l;

typedef struct {
  uint32_t key[9];
} BitcoinPublicKey_l;

typedef struct {
  uint32_t randomness[4];
} CommitmentRandomness_l;

typedef struct {
  uint32_t hash[5];
} PublicKeyHash_l;

typedef struct {
  uint32_t key[16];
} HMACKey_l;

typedef struct {
  uint32_t mask[8];
} Mask_l;

typedef struct {
  char r[256];
  char k_inv[256];
} EcdsaPartialSig_l;

typedef struct {
  uint32_t commitment[8];
} HMACKeyCommitment_l;

typedef struct {
  uint32_t commitment[8];
} MaskCommitment_l;

typedef struct {
  uint32_t commitment[8];
} RevLockCommitment_l;

typedef struct {
  uint32_t sig[8];
} EcdsaSig_l;

typedef char *(*cb_send)(void *arg1, int arg2, void *arg3);

typedef struct {
  char *r0;
  int r1;
  char *r2;
} Receive_return;

typedef Receive_return (*cb_receive)(void *arg1);

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

char *cust_change_channel_status_to_confirmed_close(char *ser_cust_state);

char *cust_change_channel_status_to_open(char *ser_cust_state);

char *cust_change_channel_status_to_pending_close(char *ser_cust_state);

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

char *cust_clear_channel_status(char *ser_cust_state);

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

char *cust_verify_init_cust_close_txs(char *ser_funding_tx,
                                      char *ser_tx_fee_info,
                                      char *ser_channel_state,
                                      char *ser_channel_token,
                                      char *ser_escrow_sig,
                                      char *ser_merch_sig,
                                      char *ser_cust_state);

char *customer_sign_merch_close_tx(char *ser_cust_sk, char *ser_merch_tx_preimage);

char *ffishim_bls12_activate_customer_finalize(char *ser_channel_state,
                                               char *ser_customer_state,
                                               char *ser_pay_token);

char *ffishim_bls12_activate_merchant(char *ser_init_state, char *ser_merch_state);

char *ffishim_bls12_channel_setup(const char *channel_name, uint32_t third_party_support);

char *ffishim_bls12_customer_close(char *ser_channel_state, char *ser_cust_state);

char *ffishim_bls12_decompress_cust_close_message(char *ser_channel_state, char *ser_cust_close);

char *ffishim_bls12_generate_channel_id(char *ser_channel_token);

char *ffishim_bls12_init_customer(char *ser_channel_token,
                                  int64_t balance_customer,
                                  int64_t balance_merchant,
                                  const char *name_ptr);

char *ffishim_bls12_init_merchant(char *ser_channel_state, const char *name_ptr);

char *ffishim_bls12_init_merchant_issue_close_token(char *ser_init_state, char *ser_merch_state);

char *ffishim_bls12_merchant_close(char *ser_channel_state,
                                   char *ser_channel_token,
                                   const char *_ser_address,
                                   char *ser_cust_close,
                                   char *ser_merch_state);

char *ffishim_bls12_multi_pay_unmask_merchant(char *ser_sender_revoke_token,
                                              char *ser_receiver_revoke_token,
                                              char *ser_merch_state);

char *ffishim_bls12_pay_generate_payment_proof(char *ser_channel_state,
                                               char *ser_customer_state,
                                               int64_t amount);

char *ffishim_bls12_pay_get_revoke_lock_pair(char *ser_channel_state,
                                             char *ser_cust_state,
                                             char *ser_new_cust_state,
                                             char *ser_close_token);

char *ffishim_bls12_pay_prepare_merchant(char *ser_nonce, int64_t amount, char *ser_merchant_state);

char *ffishim_bls12_pay_unmask_merchant(char *ser_revoke_token, char *ser_merch_state);

char *ffishim_bls12_pay_verify_multiple_payment_proofs(char *ser_channel_state,
                                                       char *ser_sender_pay_proof,
                                                       char *ser_receiver_pay_proof,
                                                       char *ser_merch_state);

char *ffishim_bls12_pay_verify_payment_proof(char *ser_channel_state,
                                             char *ser_pay_proof,
                                             char *ser_merch_state);

char *ffishim_bls12_pay_verify_payment_token(char *ser_channel_state,
                                             char *ser_cust_state,
                                             char *ser_pay_token);

char *ffishim_bls12_tze_check_wpk(char *ser_wpk);

char *ffishim_bls12_unlink_channel_customer(char *ser_channel_state, char *ser_customer_state);

char *ffishim_bls12_unlink_channel_merchant(char *ser_channel_state,
                                            char *ser_pay_proof,
                                            char *ser_merch_state);

char *ffishim_bls12_unlink_verify_pay_token(char *ser_channel_state,
                                            char *ser_cust_state,
                                            char *ser_pay_token);

char *ffishim_bls12_verify_close_token(char *ser_channel_state,
                                       char *ser_customer_state,
                                       char *ser_close_token);

char *ffishim_bls12_verify_init_close_token(char *ser_channel_state,
                                            char *ser_customer_state,
                                            char *ser_close_token);

char *ffishim_bn256_activate_customer_finalize(char *ser_channel_state,
                                               char *ser_customer_state,
                                               char *ser_pay_token);

char *ffishim_bn256_activate_merchant(char *ser_init_state, char *ser_merch_state);

char *ffishim_bn256_channel_setup(const char *channel_name, uint32_t third_party_support);

char *ffishim_bn256_customer_close(char *ser_channel_state, char *ser_cust_state);

char *ffishim_bn256_decompress_cust_close_message(char *ser_channel_state, char *ser_cust_close);

char *ffishim_bn256_generate_channel_id(char *ser_channel_token);

char *ffishim_bn256_init_customer(char *ser_channel_token,
                                  int64_t balance_customer,
                                  int64_t balance_merchant,
                                  const char *name_ptr);

char *ffishim_bn256_init_merchant(char *ser_channel_state, const char *name_ptr);

char *ffishim_bn256_init_merchant_issue_close_token(char *ser_init_wallet, char *ser_merch_state);

char *ffishim_bn256_merchant_close(char *ser_channel_state,
                                   char *ser_channel_token,
                                   const char *_ser_address,
                                   char *ser_cust_close,
                                   char *ser_merch_state);

char *ffishim_bn256_multi_pay_unmask_merchant(char *ser_sender_revoke_token,
                                              char *ser_receiver_revoke_token,
                                              char *ser_merch_state);

char *ffishim_bn256_pay_get_revoke_lock_pair(char *ser_channel_state,
                                             char *ser_cust_state,
                                             char *ser_new_cust_state,
                                             char *ser_close_token);

char *ffishim_bn256_pay_prepare_merchant(char *ser_nonce, int64_t amount, char *ser_merchant_state);

char *ffishim_bn256_pay_unmask_merchant(char *ser_revoke_token, char *ser_merch_state);

char *ffishim_bn256_pay_update_state_customer(char *ser_channel_state,
                                              char *ser_customer_state,
                                              int64_t amount);

char *ffishim_bn256_pay_update_state_merchant(char *ser_channel_state,
                                              char *ser_pay_proof,
                                              char *ser_merch_state);

char *ffishim_bn256_pay_verify_multiple_payment_proofs(char *ser_channel_state,
                                                       char *ser_sender_pay_proof,
                                                       char *ser_receiver_pay_proof,
                                                       char *ser_merch_state);

char *ffishim_bn256_pay_verify_payment_token(char *ser_channel_state,
                                             char *ser_cust_state,
                                             char *ser_pay_token);

char *ffishim_bn256_tze_check_wpk(char *ser_wpk);

char *ffishim_bn256_unlink_channel_customer(char *ser_channel_state, char *ser_customer_state);

char *ffishim_bn256_unlink_channel_merchant(char *ser_channel_state,
                                            char *ser_pay_proof,
                                            char *ser_merch_state);

char *ffishim_bn256_unlink_verify_pay_token(char *ser_channel_state,
                                            char *ser_cust_state,
                                            char *ser_pay_token);

char *ffishim_bn256_verify_close_token(char *ser_channel_state,
                                       char *ser_customer_state,
                                       char *ser_close_token);

char *ffishim_bn256_verify_init_close_token(char *ser_channel_state,
                                            char *ser_customer_state,
                                            char *ser_close_token);

void ffishim_free_string(char *pointer);

char *force_customer_close_tx(char *ser_channel_state,
                              char *ser_channel_token,
                              uint32_t ser_from_escrow,
                              char *ser_cust_state);

char *force_merchant_close_tx(char *ser_escrow_txid, char *ser_merch_state, int64_t val_cpfp);

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

extern void *get_gonetio_ptr(void *raw_stream_fd, int party);

char *get_self_delay_be_hex(char *ser_channel_state);

extern void issue_tokens(State_l old_state_l,
                         State_l new_state_l,
                         Balance_l fee_cc,
                         PayToken_l old_paytoken_l,
                         BitcoinPublicKey_l cust_escrow_pub_key_l,
                         BitcoinPublicKey_l cust_payout_pub_key_l,
                         CommitmentRandomness_l revlock_commitment_randomness_l,
                         PublicKeyHash_l cust_publickey_hash_l,
                         HMACKey_l hmac_key_l,
                         Mask_l paytoken_mask_l,
                         Mask_l merch_mask_l,
                         Mask_l escrow_mask_l,
                         EcdsaPartialSig_l sig1,
                         EcdsaPartialSig_l sig2,
                         CommitmentRandomness_l hmac_commitment_randomness_l,
                         CommitmentRandomness_l paytoken_mask_commitment_randomness_l,
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
                         PayToken_l *pt_return,
                         EcdsaSig_l *ct_escrow,
                         EcdsaSig_l *ct_merch);

extern void *load_circuit_file(const char *path);

char *merch_change_channel_status_to_confirmed_close(char *ser_escrow_txid, char *ser_merch_state);

char *merch_change_channel_status_to_open(char *ser_escrow_txid, char *ser_merch_state);

char *merch_change_channel_status_to_pending_close(char *ser_escrow_txid, char *ser_merch_state);

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

char *merch_clear_channel_status(char *ser_escrow_txid, char *ser_merch_state);

char *merch_sign_init_cust_close_txs(char *ser_funding_tx,
                                     char *ser_rev_lock,
                                     char *ser_cust_pk,
                                     char *ser_cust_close_pk,
                                     char *ser_self_delay,
                                     char *ser_merch_state,
                                     int64_t fee_cc,
                                     int64_t fee_mc,
                                     int64_t val_cpfp);

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

char *merchant_check_rev_lock(char *ser_rev_lock, char *ser_merch_state);

char *merchant_verify_merch_close_tx(char *ser_escrow_txid,
                                     char *ser_cust_pk,
                                     int64_t cust_bal_sats,
                                     int64_t merch_bal_sats,
                                     int64_t fee_mc,
                                     int64_t val_cpfp,
                                     char *ser_self_delay,
                                     char *ser_cust_sig,
                                     char *ser_merch_state);

char *mpc_activate_customer(char *ser_cust_state);

char *mpc_activate_customer_finalize(char *ser_pay_token, char *ser_cust_state);

char *mpc_activate_merchant(char *ser_channel_token, char *ser_state, char *ser_merch_state);

char *mpc_channel_setup(const char *channel_name,
                        uint16_t self_delay,
                        int64_t bal_min_cust,
                        int64_t bal_min_merch,
                        int64_t val_cpfp,
                        uint32_t third_party_support);

void mpc_free_string(char *pointer);

char *mpc_get_channel_id(char *ser_channel_token);

char *mpc_get_initial_state(char *ser_cust_state);

char *mpc_get_masked_tx_inputs(char *ser_session_id, uint32_t mpc_result, char *ser_merch_state);

char *mpc_init_customer(char *ser_merch_pk,
                        int64_t cust_bal,
                        int64_t merch_bal,
                        char *ser_tx_fee_info,
                        const char *name_ptr);

char *mpc_init_merchant(char *db_url_str, char *ser_channel_state, const char *name_ptr);

char *mpc_load_customer_wallet(char *ser_cust_state,
                               char *ser_channel_token,
                               char *ser_sk_c,
                               char *ser_payout_sk);

char *mpc_load_merchant_wallet(char *ser_merch_state,
                               char *ser_channel_state,
                               char *ser_sk_m,
                               char *ser_payout_sk,
                               char *ser_child_sk,
                               char *ser_dispute_sk);

char *mpc_pay_unmask_pay_token_customer(char *ser_pt_mask_bytes,
                                        char *ser_pt_mask_r,
                                        char *ser_cust_state);

char *mpc_pay_unmask_sigs_customer(char *ser_channel_state,
                                   char *ser_channel_token,
                                   char *ser_masked_tx_inputs,
                                   char *ser_cust_state);

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

char *mpc_pay_validate_rev_lock_merchant(char *ser_session_id,
                                         char *ser_revoked_state,
                                         char *ser_merch_state);

char *mpc_prepare_payment_customer(char *ser_channel_state, int64_t amount, char *ser_cust_state);

char *mpc_prepare_payment_merchant(char *ser_channel_state,
                                   char *ser_session_id,
                                   char *ser_nonce,
                                   char *ser_rev_lock_com,
                                   int64_t amount,
                                   char *ser_justification,
                                   char *ser_merch_state);

char *mpc_validate_channel_params(char *ser_channel_token,
                                  char *ser_init_state,
                                  char *ser_init_hash,
                                  char *ser_merch_state);

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
