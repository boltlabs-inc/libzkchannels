#include "tokens.h"
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;

int main(int argc, char** argv) {
    setup_plain_prot(true, "tokens.circuit.txt");

    HMACKey_l hmac_key_l;
    Mask_l paytoken_mask_l;
    Mask_l merch_mask_l;
    Mask_l escrow_mask_l;
    EcdsaPartialSig_l dummy_sig;

    CommitmentRandomness_l hmac_commitment_randomness_l;
    CommitmentRandomness_l paytoken_mask_commitment_randomness_l;

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

    Balance_l epsilon_l;
    RevLockCommitment_l rlc_l;
    MaskCommitment_l paymask_com;
    HMACKeyCommitment_l key_com;
    // int port = 12345;
    BitcoinPublicKey_l merch_escrow_pub_key_l;
    BitcoinPublicKey_l merch_dispute_key_l;
    PublicKeyHash_l merch_publickey_hash;
    BitcoinPublicKey_l merch_payout_pub_key_l;
    Nonce_l nonce_l;
    Balance_l val_cpfp;
    Balance_l bal_min_cust;
    Balance_l bal_min_merch;
    uint16_t self_delay = 128;

    issue_tokens(/* CUSTOMER INPUTS */
                   old_state_l,
                   new_state_l,
                   fee_cc,
                   old_paytoken_l,
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
                   &pt_return,
                   &ct_escrow,
                   &ct_merch);
    finalize_plain_prot();
    return 0;
}