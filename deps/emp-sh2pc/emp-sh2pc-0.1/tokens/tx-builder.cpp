#include "tx-builder.h"
#include <vector>

using namespace std;

struct TxBuilderState {
    Integer output[5][16];
    int outer_pos = 0; //The index of the outer array 0-4
    int inner_pos = 0; //The index of the inner array 0-15
    int sub_pos = 0; //Because a value doesn't have to be perfectly aligned, but aligned by byte: 0,8,16,24
};

/**
 * Add an Integer to the tx_builder, this Integer should have 32 bits or less
 * @param tx_builder : the tx_builder that contains the tx up until this point
 * @param in : The Integer to append at the end of the transaction
 * @param nr_of_bits : The number of bits for the Integer 8, 16, 24, or 32
 */
void append_item(TxBuilderState *tx_builder, Integer in, int nr_of_bits = 32) {
    assert(nr_of_bits <= 32);
    int i = tx_builder->outer_pos;
    int j = tx_builder->inner_pos;
    int sub = tx_builder->sub_pos;
    if (in.size() != 32) {
        int shift = 32 - in.size();
        in.resize(32, false);
        in = in << shift;
    }
    if (sub > 0) {
        tx_builder->output[i][j] = tx_builder->output[i][j] | in >> sub;
    } else {
        tx_builder->output[i][j] = in;
    }
    int sub_inv = 32 - sub;
    if (sub_inv < nr_of_bits) {
        if (j == 15) {
            i++;
        }
        j = (j + 1) % 16;
        tx_builder->output[i][j] = in << sub_inv;
        tx_builder->sub_pos = (nr_of_bits - sub_inv) % 32;
    } else {
        tx_builder->sub_pos = (nr_of_bits + sub) % 32;
        if (tx_builder->sub_pos == 0) {
            if (j == 15) {
                i++;
            }
            j = (j + 1) % 16;
        }
    }
    tx_builder->outer_pos = i;
    tx_builder->inner_pos = j;
}

/**
 * Append a list of Integers (32-bits each) to the tx inside tx_builder
 * @param tx_builder : the tx_builder containing the tx up until this point
 * @param in : the array of integers to append to the transaction
 * @param nr_of_bits : Total number of bits that needs to be appended (n*32+x, where x can be 8, 16, or 24)
 */
void append_items(TxBuilderState *tx_builder, Integer *in, int nr_of_bits) {
    int len = nr_of_bits / 32;
    for (int k = 0; k < len; k++) {
        append_item(tx_builder, in[k]);
    }
    int overflow = nr_of_bits % 32;
    if (overflow != 0) {
        append_item(tx_builder, in[len], overflow);
    }
}

/**
 * Append a set of constants to the transaction
 * @param tx_builder : the tx_builder containing the tx up until this point
 * @param constants_in : a vector of constants to append (32-bits each)
 */
void append_constants(TxBuilderState *tx_builder, vector <Integer> constants_in) {
    for (Integer con : constants_in) {
        append_item(tx_builder, con);
    }
}

void append_tx_start(TxBuilderState *tx_builder, Integer txid1[8], Integer txid2[8], Constants constants) {
    append_constants(tx_builder, vector < Integer > {constants.xzerotwo});
    append_items(tx_builder, txid1, 8 * 32);

    append_constants(tx_builder, vector < Integer > {constants.xthreedot, constants.xcdot, constants.xninedot,
                                                     constants.xfdot, constants.xfourteendot, constants.xsevendot,
                                                     constants.xtwentytwoninedot, constants.xsevenzerosixdot});

    append_items(tx_builder, txid2, 8 * 32);

    append_constants(tx_builder, vector < Integer > {constants.zero});
}

// make sure new close transactions are well-formed
void validate_transactions(State_d new_state_d,
                           BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
                           PublicKeyHash_d cust_child_publickey_hash_d,
                           BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d,
                           BitcoinPublicKey_d merch_payout_pub_key_d,
                           PublicKeyHash_d merch_publickey_hash_d, Integer escrow_digest[8], Integer merch_digest[8],
                           Balance_d fee_cc_d, Integer k[64], Integer H[8], Balance_d val_cpfp_d, Integer self_delay_d,
                           Constants constants) {
    //Build output for customer with delay
    TxBuilderState customer_delayed_script_builder;

    //Add revocation lock
    append_item(&customer_delayed_script_builder, constants.xsixthreedot, 24);
    append_items(&customer_delayed_script_builder, new_state_d.rl.revlock, 8 * 32);
    append_item(&customer_delayed_script_builder, constants.xeighteight, 8);
    //Add merchant dispute key
    append_item(&customer_delayed_script_builder, constants.xtwentyone, 8);
    append_items(&customer_delayed_script_builder, merch_dispute_key_d.key, 8 * 32 + 8);
    append_item(&customer_delayed_script_builder, constants.xsixsevenzero, 8);

    //Add toSelfDelay
    append_item(&customer_delayed_script_builder, self_delay_d, self_delay_d.size());
    append_item(&customer_delayed_script_builder, constants.xbtwosevenfive, 16);
    //Add customer payout public key
    append_item(&customer_delayed_script_builder, constants.xtwentyone, 8);
    append_items(&customer_delayed_script_builder, cust_payout_pub_key_d.key, 8 * 32 + 8);
    append_item(&customer_delayed_script_builder, constants.xsixeightac, 16);

    //Add padding
    append_constants(&customer_delayed_script_builder,
                     vector < Integer > {constants.xeightfirstbyte, constants.zero, constants.zero});
    if (self_delay_d.size() == 24) {
        append_constants(&customer_delayed_script_builder,
                         vector < Integer > {constants.customerdelayerscriptpreimagelength});
    } else if (self_delay_d.size() == 16) {
        append_item(&customer_delayed_script_builder, constants.zero, 8);
        append_item(&customer_delayed_script_builder, constants.customerdelayerscriptpreimagelengthshort, 32);
    } else {
        append_item(&customer_delayed_script_builder, constants.zero, 16);
        append_item(&customer_delayed_script_builder, constants.customerdelayerscriptpreimagelengthveryshort, 32);
    }

    Integer customer_delayed_script_hash[8];

    computeSHA256_2d_noinit(customer_delayed_script_builder.output, customer_delayed_script_hash, k, H);


    // Doing math for the balance
    // For reference, see https://docs.google.com/document/d/1It_WOpSwUuZnuhVtyVJLXAHrZCsEy21o7ZiDqkVzYY4/edit#bookmark=id.p25f1i42y4ov
    // For the cust close from escrow tx, we want
    //  b_c - val_cpfp - fee_cc
    //  b_m
    //  val_cpdp
    // For the cust close from merch close tx we want
    //  b_c - val_cpfp - fee_cc
    //  b_m - fee_mc - val_cpfp
    //  val_cpdp

    Integer cust_balance_in_state_combined = combine_balance(new_state_d.balance_cust);
    Integer merch_balance_in_state_combined = combine_balance(new_state_d.balance_merch);
    Integer val_cpfp_combined = combine_balance(val_cpfp_d);
    Integer fee_cc_combined = combine_balance(fee_cc_d);
    Integer fee_mc_combined = combine_balance(new_state_d.fee_mc);

    Integer hash_outputs_escrow_cust_balance = cust_balance_in_state_combined - val_cpfp_combined - fee_cc_combined;
    Integer hash_outputs_escrow_merch_balance = merch_balance_in_state_combined;

    Integer hash_outputs_merch_cust_balance = cust_balance_in_state_combined - val_cpfp_combined - fee_cc_combined;
    Integer hash_outputs_merch_merch_balance = merch_balance_in_state_combined - val_cpfp_combined - fee_mc_combined;


    Balance_d hash_outputs_escrow_little_endian_balance_cust = convert_to_little_endian(
            split_integer_to_balance(hash_outputs_escrow_cust_balance, constants.fullFsixtyfour), constants);
    Balance_d hash_outputs_escrow_little_endian_balance_merch = convert_to_little_endian(
            split_integer_to_balance(hash_outputs_escrow_merch_balance, constants.fullFsixtyfour), constants);

    Balance_d hash_outputs_merch_little_endian_balance_cust = convert_to_little_endian(
            split_integer_to_balance(hash_outputs_merch_cust_balance, constants.fullFsixtyfour), constants);
    Balance_d hash_outputs_merch_little_endian_balance_merch = convert_to_little_endian(
            split_integer_to_balance(hash_outputs_merch_merch_balance, constants.fullFsixtyfour), constants);

    Balance_d val_cpfp_little_endian = convert_to_little_endian(val_cpfp_d, constants);
    // TODO finish maths

    //Outputs for cust-close-from-escrow transaction
    TxBuilderState outputs_escrow_builder;
    //Add customer balance output
    append_items(&outputs_escrow_builder, hash_outputs_escrow_little_endian_balance_cust.balance, 2 * 32);
    //Add customer output script with delay
    append_item(&outputs_escrow_builder, constants.xtwentytwodot, 24);
    append_items(&outputs_escrow_builder, customer_delayed_script_hash, 8 * 32);
    //Add merchant balance output
    append_items(&outputs_escrow_builder, hash_outputs_escrow_little_endian_balance_merch.balance, 2 * 32);
    append_item(&outputs_escrow_builder, constants.xsixteen, 8);
    //Add merchant public key
    append_item(&outputs_escrow_builder, constants.xzerozerofourteen, 16);
    append_items(&outputs_escrow_builder, merch_publickey_hash_d.hash, 5 * 32);
    append_item(&outputs_escrow_builder, constants.zero, 16);

    append_constants(&outputs_escrow_builder, vector < Integer > {constants.zero, constants.threesevensixa});
    //Add revocation lock
    append_item(&outputs_escrow_builder, constants.xfourtyone, 8);
    append_items(&outputs_escrow_builder, new_state_d.rl.revlock, 8 * 32);
    //Add customer payout public key
    append_items(&outputs_escrow_builder, cust_payout_pub_key_d.key, 8 * 32 + 8);
    //Add child-pays-for-parent balance
    append_items(&outputs_escrow_builder, val_cpfp_little_endian.balance, 2 * 32);
    append_item(&outputs_escrow_builder, constants.xsixteen, 16);
    //Add public key child-pays-for-parent
    append_item(&outputs_escrow_builder, constants.xfourteenzerozero, 8);
    append_items(&outputs_escrow_builder, cust_child_publickey_hash_d.hash, 5 * 32);
    append_item(&outputs_escrow_builder, constants.xeightfirstbyte, 24);

    append_constants(&outputs_escrow_builder, vector < Integer > {constants.zero, constants.hashoutputspreimagelength});

    Integer hash_outputs_escrow[8];

    computeDoubleSHA256_3d_noinit(outputs_escrow_builder.output, hash_outputs_escrow, k, H, constants);


    //Outputs for cust-close-from-merch transaction
    TxBuilderState outputs_merch_builder;
    //Add customer balance output
    append_items(&outputs_merch_builder, hash_outputs_merch_little_endian_balance_cust.balance, 2 * 32);
    //Add customer output script with delay
    append_item(&outputs_merch_builder, constants.xtwentytwodot, 24);
    append_items(&outputs_merch_builder, customer_delayed_script_hash, 8 * 32);
    //Add merchant balance output
    append_items(&outputs_merch_builder, hash_outputs_merch_little_endian_balance_merch.balance, 2 * 32);
    append_item(&outputs_merch_builder, constants.xsixteen, 8);
    //Add merchant public key
    append_item(&outputs_merch_builder, constants.xzerozerofourteen, 16);
    append_items(&outputs_merch_builder, merch_publickey_hash_d.hash, 5 * 32);
    append_item(&outputs_merch_builder, constants.zero, 16);

    append_constants(&outputs_merch_builder, vector < Integer > {constants.zero, constants.threesevensixa});
    //Add revocation lock
    append_item(&outputs_merch_builder, constants.xfourtyone, 8);
    append_items(&outputs_merch_builder, new_state_d.rl.revlock, 8 * 32);
    //Add customer payout public key
    append_items(&outputs_merch_builder, cust_payout_pub_key_d.key, 8 * 32 + 8);
    //Add child-pays-for-parent balance
    append_items(&outputs_merch_builder, val_cpfp_little_endian.balance, 2 * 32);
    append_item(&outputs_merch_builder, constants.xsixteen, 16);
    //Add public key child-pays-for-parent
    append_item(&outputs_merch_builder, constants.xfourteenzerozero, 8);
    append_items(&outputs_merch_builder, cust_child_publickey_hash_d.hash, 5 * 32);
    append_item(&outputs_merch_builder, constants.xeightfirstbyte, 24);

    append_constants(&outputs_merch_builder, vector < Integer > {constants.zero, constants.hashoutputspreimagelength});

    Integer hash_outputs_merch[8];

    computeDoubleSHA256_3d_noinit(outputs_merch_builder.output, hash_outputs_merch, k, H, constants);


    //START -----cust-close-from-escrow transaction-----
    TxBuilderState tx_builder_escrow;
    //Start cust-close-from-escrow transaction with input tx id and own tx id
    append_tx_start(&tx_builder_escrow, new_state_d.HashPrevOuts_escrow.txid, new_state_d.txid_escrow.txid, constants);
    //Add merchant public key to cust-close-from-escrow transaction
    append_item(&tx_builder_escrow, constants.xfoursevenfivedot, 24);
    append_items(&tx_builder_escrow, merch_escrow_pub_key_d.key, 8 * 32 + 8);
    //Add customer public key to cust-close-from-escrow transaction
    append_item(&tx_builder_escrow, constants.xtwentyone, 8);
    append_items(&tx_builder_escrow, cust_escrow_pub_key_d.key, 8 * 32 + 8);
    append_item(&tx_builder_escrow, constants.xfivetwoae, 16);

    Balance_d big_endian_total_amount = split_integer_to_balance(
            cust_balance_in_state_combined + merch_balance_in_state_combined, constants.fullFsixtyfour);
    Balance_d little_endian_total_amount = convert_to_little_endian(big_endian_total_amount, constants);
    //Add total input balance to cust-close-from-escrow transaction
    append_items(&tx_builder_escrow, little_endian_total_amount.balance, 2 * 32);

    append_constants(&tx_builder_escrow, vector < Integer > {constants.fullFthirtytwo});

    //Add hash of outputs to cust-close-from-escrow transaction
    append_items(&tx_builder_escrow, hash_outputs_escrow, 8 * 32);
    //Add padding to cust-close-from-escrow transaction
    append_constants(&tx_builder_escrow,
                     vector < Integer > {constants.zero, constants.xzeroone, constants.xeightfirstbyte,
                                         constants.zero, constants.zero, constants.zero, constants.zero,
                                         constants.zero, constants.escrowtransactionpreimagelength});


    //Compute Hash of transaction
    computeDoubleSHA256_4d_noinit(tx_builder_escrow.output, escrow_digest, k, H, constants);
    //END -----cust-close-from-escrow transaction-----

    //START ----cust-close-from-merch transaction-----
    TxBuilderState tx_builder_merch;
    //Start cust-close-from-merch transaction with input tx id and own tx id
    append_tx_start(&tx_builder_merch, new_state_d.HashPrevOuts_merch.txid, new_state_d.txid_merch.txid, constants);

    // The script
    if (self_delay_d.size() == 24) {
        append_constants(&tx_builder_merch, vector < Integer > {constants.xseventwosixdot});
    } else if (self_delay_d.size() == 16) {
        append_constants(&tx_builder_merch, vector < Integer > {constants.xsevenonesixdot});
    } else {
        append_constants(&tx_builder_merch, vector < Integer > {constants.xsevenzerosixthreedot});
    }
    //Add merchant public key to cust-close-from-merch transaction
    append_items(&tx_builder_merch, merch_escrow_pub_key_d.key, 8 * 32 + 8);
    append_item(&tx_builder_merch, constants.xtwentyone, 8);

    //Add customer public key to cust-close-from-merch transaction
    append_items(&tx_builder_merch, cust_escrow_pub_key_d.key, 8 * 32 + 8);
    append_item(&tx_builder_merch, constants.xfiftytwo, 8);

    //Add toSelfDelay
    append_item(&tx_builder_merch, constants.xaedot, 16);
    append_item(&tx_builder_merch, self_delay_d, self_delay_d.size());
    append_item(&tx_builder_merch, constants.xbtwosevendot, 24);

    // Add merch-payout-key to cust-close-from-merch transaction
    append_items(&tx_builder_merch, merch_payout_pub_key_d.key, 8 * 32 + 8);
    append_item(&tx_builder_merch, constants.xacsixeight, 16);
    // Add total input amount to cust-close-from-merch transaction
    Balance_d big_endian_total_amount_merch = split_integer_to_balance(
            cust_balance_in_state_combined + merch_balance_in_state_combined - val_cpfp_combined - fee_mc_combined,
            constants.fullFsixtyfour);
    Balance_d little_endian_total_amount_merch = convert_to_little_endian(big_endian_total_amount_merch, constants);
    append_items(&tx_builder_merch, little_endian_total_amount_merch.balance, 2 * 32);
    append_item(&tx_builder_merch, constants.xff, 8);

    //Add hash of output script to cust-close-from-merch transaction
    append_item(&tx_builder_merch, constants.ffffffzerozero, 24);
    append_items(&tx_builder_merch, hash_outputs_merch, 8 * 32);
    append_item(&tx_builder_merch, constants.zero, 8);
    //Add padding to cust-close-from-merch transaction
    append_constants(&tx_builder_merch, vector < Integer > {constants.one, constants.xeightfourthbyte,
                                                            constants.zero, constants.zero, constants.zero,
                                                            constants.zero, constants.zero,
                                                            constants.zero, constants.zero, constants.zero,
                                                            constants.zero, constants.zero,
                                                            constants.zero});
    if (self_delay_d.size() == 24) {
        append_constants(&tx_builder_merch, vector < Integer > {constants.merchtransactionpreimagelength});
    } else if (self_delay_d.size() == 16) {
        append_item(&tx_builder_merch, constants.zero, 8);
        append_item(&tx_builder_merch, constants.merchtransactionpreimagelengthshort, 32);
    } else {
        append_item(&tx_builder_merch, constants.zero, 16);
        append_item(&tx_builder_merch, constants.merchtransactionpreimagelengthveryshort, 32);
    }

    computeDoubleSHA256_5d_noinit(tx_builder_merch.output, merch_digest, k, H, constants);
    //END -----cust-close-from-merch transaction-----
}