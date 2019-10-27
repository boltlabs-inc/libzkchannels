
//char* ffishim_bidirectional_wtp_check_wpk(const char *ser_wpk);
char* ffishim_bidirectional_channel_setup(const char *channel_name, third_party_support: u32);
char* ffishim_bidirectional_init_merchant(const char *ser_channel_state, int balance, const char *name_ptr);
char* ffishim_bidirectional_init_customer(const char *ser_channel_state, const char *ser_channel_token, int balance_customer,  int balance_merchant, const char *name_ptr);
char* ffishim_bidirectional_establish_customer_generate_proof(const char *ser_channel_token, const char *ser_customer_wallet);
char* ffishim_bidirectional_establish_merchant_issue_close_token(const char *ser_channel_state, const char *ser_com, const char *ser_com_proof, init_cust_bal, init_merch_bal, const char *ser_merch_state);
char* ffishim_bidirectional_establish_merchant_issue_pay_token(const char *ser_channel_state, const char *ser_com, const char *ser_merch_state);
char* ffishim_bidirectional_verify_close_token(const char *ser_channel_state, const char *ser_customer_wallet, const char *ser_close_token);
char* ffishim_bidirectional_establish_customer_final(const char *ser_channel_state, const char *ser_customer_wallet, const char *ser_pay_token);
char* ffishim_bidirectional_pay_generate_payment_proof(const char *ser_channel_state, const char *ser_customer_wallet, amount);
char* ffishim_bidirectional_pay_verify_payment_proof(const char *ser_channel_state, const char *ser_pay_proof, const char *ser_merch_state);
char* ffishim_bidirectional_pay_generate_revoke_token(const char *ser_channel_state, const char *ser_cust_state, const char *ser_new_cust_state, const char *ser_close_token);
char* ffishim_bidirectional_pay_verify_revoke_token(const char *ser_revoke_token, const char *ser_merch_state);
char* ffishim_bidirectional_pay_verify_payment_token(const char *ser_channel_state, const char *ser_cust_state, const char *ser_pay_token);
char* ffishim_bidirectional_customer_close(const char *ser_channel_state, const char *ser_cust_state);
char* ffishim_bidirectional_merchant_close(const char *ser_channel_state, const char *ser_channel_token, const char *ser_address, const char *ser_cust_close, const char *ser_merch_state);
char* ffishim_bidirectional_wtp_verify_cust_close_message(const char *ser_channel_token, const char *ser_wpk, const char *ser_close_msg, const char *ser_close_token);
char* ffishim_bidirectional_wtp_verify_merch_close_message(const char *ser_channel_token, const char *ser_wpk, const char *ser_merch_close);
