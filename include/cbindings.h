#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef char *(*cb_send)(char *arg1, int arg2, void *arg3);

typedef struct {
  uint8_t _unused[0];
} Receive_return;

typedef Receive_return (*cb_receive)(void *arg1);

typedef struct {
  char r[256];
  char k_inv[256];
} EcdsaPartialSig_l;

#if defined(DEFINE_MPC_BITCOIN)
char *cust_form_escrow_transaction(char *ser_txid,
                                   uint32_t index,
                                   int64_t input_sats,
                                   int64_t output_sats,
                                   char *ser_cust_sk,
                                   char *ser_cust_pk,
                                   char *ser_merch_pk,
                                   char *ser_change_pk);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *cust_sign_init_cust_close_txs(char *ser_funding_tx,
                                    char *ser_channel_state,
                                    char *ser_channel_token,
                                    char *ser_escrow_sig,
                                    char *ser_merch_sig,
                                    char *ser_cust_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *customer_sign_merch_close_tx(char *ser_cust_sk, char *ser_merch_tx_preimage);
#endif

char *ffishim_bls12_channel_setup(const char *channel_name, uint32_t third_party_support);

char *ffishim_bls12_customer_close(char *ser_channel_state, char *ser_cust_state);

char *ffishim_bls12_establish_customer_final(char *ser_channel_state,
                                             char *ser_customer_state,
                                             char *ser_pay_token);

char *ffishim_bls12_establish_customer_generate_proof(char *ser_channel_token,
                                                      char *ser_customer_state);

char *ffishim_bls12_establish_merchant_issue_close_token(char *ser_channel_state,
                                                         char *ser_com,
                                                         char *ser_com_proof,
                                                         char *ser_channel_id,
                                                         int64_t init_cust_bal,
                                                         int64_t init_merch_bal,
                                                         char *ser_merch_state);

char *ffishim_bls12_establish_merchant_issue_pay_token(char *ser_channel_state,
                                                       char *ser_com,
                                                       char *ser_merch_state);

char *ffishim_bls12_generate_channel_id(char *ser_channel_token);

char *ffishim_bls12_init_customer(char *ser_channel_token,
                                  int64_t balance_customer,
                                  int64_t balance_merchant,
                                  const char *name_ptr);

char *ffishim_bls12_init_merchant(char *ser_channel_state, const char *name_ptr);

char *ffishim_bls12_merchant_close(char *ser_channel_state,
                                   char *ser_channel_token,
                                   const char *ser_address,
                                   char *ser_cust_close,
                                   char *ser_merch_state);

char *ffishim_bls12_pay_generate_payment_proof(char *ser_channel_state,
                                               char *ser_customer_state,
                                               int64_t amount);

char *ffishim_bls12_pay_generate_revoke_token(char *ser_channel_state,
                                              char *ser_cust_state,
                                              char *ser_new_cust_state,
                                              char *ser_close_token);

char *ffishim_bls12_pay_verify_multiple_payment_proofs(char *ser_channel_state,
                                                       char *ser_sender_pay_proof,
                                                       char *ser_receiver_pay_proof,
                                                       char *ser_merch_state);

char *ffishim_bls12_pay_verify_multiple_revoke_tokens(char *ser_sender_revoke_token,
                                                      char *ser_receiver_revoke_token,
                                                      char *ser_merch_state);

char *ffishim_bls12_pay_verify_payment_proof(char *ser_channel_state,
                                             char *ser_pay_proof,
                                             char *ser_merch_state);

char *ffishim_bls12_pay_verify_payment_token(char *ser_channel_state,
                                             char *ser_cust_state,
                                             char *ser_pay_token);

char *ffishim_bls12_pay_verify_revoke_token(char *ser_revoke_token, char *ser_merch_state);

char *ffishim_bls12_verify_close_token(char *ser_channel_state,
                                       char *ser_customer_state,
                                       char *ser_close_token);

char *ffishim_bls12_wtp_check_wpk(char *ser_wpk);

char *ffishim_bls12_wtp_verify_cust_close_message(char *ser_channel_token,
                                                  char *ser_wpk,
                                                  char *ser_close_msg,
                                                  char *ser_close_token);

char *ffishim_bls12_wtp_verify_merch_close_message(char *ser_channel_token,
                                                   char *ser_wpk,
                                                   char *ser_merch_close);

char *ffishim_bn256_channel_setup(const char *channel_name, uint32_t third_party_support);

char *ffishim_bn256_customer_close(char *ser_channel_state, char *ser_cust_state);

char *ffishim_bn256_establish_customer_final(char *ser_channel_state,
                                             char *ser_customer_state,
                                             char *ser_pay_token);

char *ffishim_bn256_establish_customer_generate_proof(char *ser_channel_token,
                                                      char *ser_customer_state);

char *ffishim_bn256_establish_merchant_issue_close_token(char *ser_channel_state,
                                                         char *ser_com,
                                                         char *ser_com_proof,
                                                         char *ser_channel_id,
                                                         int64_t init_cust_bal,
                                                         int64_t init_merch_bal,
                                                         char *ser_merch_state);

char *ffishim_bn256_establish_merchant_issue_pay_token(char *ser_channel_state,
                                                       char *ser_com,
                                                       char *ser_merch_state);

char *ffishim_bn256_generate_channel_id(char *ser_channel_token);

char *ffishim_bn256_init_customer(char *ser_channel_token,
                                  int64_t balance_customer,
                                  int64_t balance_merchant,
                                  const char *name_ptr);

char *ffishim_bn256_init_merchant(char *ser_channel_state, const char *name_ptr);

char *ffishim_bn256_merchant_close(char *ser_channel_state,
                                   char *ser_channel_token,
                                   const char *ser_address,
                                   char *ser_cust_close,
                                   char *ser_merch_state);

char *ffishim_bn256_pay_generate_payment_proof(char *ser_channel_state,
                                               char *ser_customer_state,
                                               int64_t amount);

char *ffishim_bn256_pay_generate_revoke_token(char *ser_channel_state,
                                              char *ser_cust_state,
                                              char *ser_new_cust_state,
                                              char *ser_close_token);

char *ffishim_bn256_pay_verify_multiple_payment_proofs(char *ser_channel_state,
                                                       char *ser_sender_pay_proof,
                                                       char *ser_receiver_pay_proof,
                                                       char *ser_merch_state);

char *ffishim_bn256_pay_verify_multiple_revoke_tokens(char *ser_sender_revoke_token,
                                                      char *ser_receiver_revoke_token,
                                                      char *ser_merch_state);

char *ffishim_bn256_pay_verify_payment_proof(char *ser_channel_state,
                                             char *ser_pay_proof,
                                             char *ser_merch_state);

char *ffishim_bn256_pay_verify_payment_token(char *ser_channel_state,
                                             char *ser_cust_state,
                                             char *ser_pay_token);

char *ffishim_bn256_pay_verify_revoke_token(char *ser_revoke_token, char *ser_merch_state);

char *ffishim_bn256_verify_close_token(char *ser_channel_state,
                                       char *ser_customer_state,
                                       char *ser_close_token);

char *ffishim_bn256_wtp_check_wpk(char *ser_wpk);

char *ffishim_bn256_wtp_verify_cust_close_message(char *ser_channel_token,
                                                  char *ser_wpk,
                                                  char *ser_close_msg,
                                                  char *ser_close_token);

char *ffishim_bn256_wtp_verify_merch_close_message(char *ser_channel_token,
                                                   char *ser_wpk,
                                                   char *ser_merch_close);

void ffishim_free_string(char *pointer);

#if defined(DEFINE_MPC_BITCOIN)
char *form_merch_close_transaction(char *ser_escrow_txid,
                                   char *ser_cust_pk,
                                   char *ser_merch_pk,
                                   char *ser_merch_close_pk,
                                   int64_t cust_bal_sats,
                                   int64_t merch_bal_sats,
                                   char *ser_self_delay);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *merch_sign_init_cust_close_txs(char *ser_funding_tx,
                                     char *ser_rev_lock,
                                     char *ser_cust_pk,
                                     char *ser_cust_close_pk,
                                     char *ser_self_delay,
                                     char *ser_merch_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *merchant_sign_merch_close_tx(char *ser_escrow_txid,
                                   char *ser_cust_pk,
                                   char *ser_merch_pk,
                                   char *ser_merch_close_pk,
                                   int64_t cust_bal_sats,
                                   int64_t merch_bal_sats,
                                   char *ser_self_delay,
                                   char *ser_cust_sig,
                                   char *ser_merch_sk);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_activate_customer(char *ser_cust_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_activate_customer_finalize(char *ser_pay_token, char *ser_cust_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_activate_merchant(char *ser_channel_token, char *ser_state, char *ser_merch_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_channel_setup(const char *channel_name, uint32_t third_party_support);
#endif

#if defined(DEFINE_MPC_BITCOIN)
void mpc_free_string(char *pointer);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_get_initial_state(char *ser_cust_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_init_customer(char *ser_pk_m, int64_t cust_bal, int64_t merch_bal, const char *name_ptr);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_init_merchant(char *ser_channel_state, const char *name_ptr);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_pay_customer(void *peer,
                       cb_send callback_send,
                       cb_receive callback_recv,
                       char *ser_channel_state,
                       char *ser_channel_token,
                       char *ser_start_state,
                       char *ser_end_state,
                       char *ser_pay_token_mask_com,
                       char *ser_rev_lock_com,
                       int64_t amount,
                       char *ser_cust_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_pay_merchant(void *peer,
                       cb_send callback_send,
                       cb_receive callback_recv,
                       char *ser_channel_state,
                       char *ser_nonce,
                       char *ser_pay_token_mask_com,
                       char *ser_rev_lock_com,
                       int64_t amount,
                       char *ser_merch_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_pay_unmask_pay_token_customer(char *ser_pt_mask_bytes,
                                        char *ser_pt_mask_r,
                                        char *ser_cust_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_pay_unmask_tx_customer(char *ser_channel_state,
                                 char *ser_channel_token,
                                 char *ser_masked_tx_inputs,
                                 char *ser_cust_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_pay_validate_rev_lock_merchant(char *ser_revoked_state, char *ser_merch_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_prepare_payment_customer(char *ser_channel_state, int64_t amount, char *ser_cust_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_prepare_payment_merchant(char *ser_nonce, char *ser_merch_state);
#endif

#if defined(DEFINE_MPC_BITCOIN)
char *mpc_validate_initial_state(char *ser_channel_token,
                                 char *ser_init_state,
                                 char *ser_init_hash,
                                 char *ser_merch_state);
#endif

extern void test_ecdsa_e2e(EcdsaPartialSig_l partial,
                           const char *hashedmsg,
                           uint32_t party,
                           const uint32_t (*digest)[8]);
