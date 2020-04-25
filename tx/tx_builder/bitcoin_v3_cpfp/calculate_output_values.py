import argparse

close_escrow_vbytes = 298
close_merch_vbytes = 299
merch_close_vbytes = 181
default_fee_rate = 10
default_cpfp_val = 500

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tx_type", required=True, help="close_escrow, close_merch, merch_close")
    parser.add_argument("--cust_bal",  required=True, help="customer balance")
    parser.add_argument("--merch_bal", required=True, help="merchant balance")
    parser.add_argument("--fee_rate", help="fee rate in satoshis per byte", default=default_fee_rate)
    parser.add_argument("--cpfp_val", help="child output value in satoshis", default=default_cpfp_val)
    args = parser.parse_args()

    cust_bal = int(args.cust_bal)
    merch_bal = int(args.merch_bal)
    tx_type = str(args.tx_type)
    fee_rate = int(args.fee_rate)
    cpfp_val = int(args.cpfp_val)

    fee_ce = close_escrow_vbytes*fee_rate
    fee_cm = close_merch_vbytes*fee_rate
    fee_mc = merch_close_vbytes*fee_rate

    # Channel must have enough to at least cover:
    # merch-close child, fee_mc, close-merch child, fee_mc, output0 min balance, output1 min balance,
    min_channel_val = cpfp_val + fee_mc + cpfp_val + fee_cm + cpfp_val + cpfp_val
    if cust_bal + merch_bal < min_channel_val:
        raise Exception("total channel capacity is too low")

    # Assign output values without accounting for potential dust outputs
    if tx_type == "close_escrow":
        input_amount = cust_bal + merch_bal
        output0 = cust_bal - cpfp_val - fee_ce
        output1 = merch_bal
        output3 = cpfp_val

    if tx_type == "close_merch":
        input_amount = cust_bal + merch_bal - cpfp_val - fee_mc
        output0 = cust_bal - cpfp_val - fee_cm
        output1 = merch_bal - cpfp_val - fee_mc
        output3 = cpfp_val

    if tx_type == "merch_close":
        input_amount = cust_bal + merch_bal
        output0 = cust_bal + merch_bal - cpfp_val - fee_mc
        output1 = cpfp_val

    # Rebalance output0 and output1 to prevent dust outputs
    if output0 < cpfp_val:
        diff = cpfp_val - output0
        output0 += diff
        output1 -= diff

    if output1 < cpfp_val:
        diff = cpfp_val - output1
        output1 += diff
        output0 -= diff

    if tx_type == "close_escrow" or tx_type == "close_merch":
        print("%s outputs" % tx_type)
        print("input_amount: %d, output[0] - cust delayed: %d, output[1] - to merch: %d, output[3] - cust child: %d, fee: %d" % (input_amount, output0, output1, output3, fee_cm))
    elif tx_type == "merch_close":
        print("%s outputs" % tx_type)
        print("input_amount: %d, output[0] - multisig: %d, output[1] - merch child: %d, fee: %d" % (input_amount, output0, output1, fee_cm))

main()
